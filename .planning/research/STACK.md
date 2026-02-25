# Stack Research: encfsr Reverse FUSE Filesystem

**Research Date:** 2026-02-24
**Question:** What patterns exist for implementing reverse/mirror FUSE filesystems in Rust? Are there existing crates or approaches for "encrypt-on-read" virtual filesystems? What are the key technical considerations for making the encrypted output deterministic and byte-for-byte compatible with encfs?

---

## Summary

No new crates are needed to add `encfsr`. The existing stack (`fuse_mt`, `openssl`, `aes-gcm-siv`, `argon2`, `clap`, `anyhow`) covers all requirements. The implementation is a second `[[bin]]` target that reuses the existing shared library. The core inversion is in the FUSE handler layer only: `open` reads from the plaintext source and uses `FileEncoder` instead of `FileDecoder` for `read`. Everything below that layer (`SslCipher`, `BlockCodec`, `EncfsConfig`) is unchanged.

---

## Findings

### 1. FUSE Crate: Stay With fuse_mt

**Recommendation:** Continue using `fuse_mt 0.6.3`. Do NOT switch to `fuser`.

**Rationale:**
The existing `FilesystemMT` trait is already implemented for ~30 FUSE operations in `src/fs.rs`. A new `EncFsReverse` struct can implement the same trait and share the path encryption and crypto layers. Switching to `fuser` (the other major Rust FUSE crate) would require reimplementing all 30+ operations with a different async-capable API design. The delta cost (two structs both implementing `FilesystemMT`) is much lower than a crate migration.

`fuse_mt 0.6.3` is what the project already pins in `Cargo.toml` and is confirmed working on Linux. The multi-thread support it provides (configurable via the thread count parameter to `FuseMT::new`) is directly usable for `encfsr` without changes.

**What NOT to use:**
- `fuser` (formerly `fuse-rs`): Would require a different trait. Feature-complete but migration cost is unjustified for adding a second binary.
- Raw FUSE via `libc`: Far too low-level. fuse_mt handles the kernel protocol, buffer management, and threading.

**Confidence:** High.

---

### 2. No "Encrypt-on-Read" Crate Exists for EncFS Compatibility

**Finding:** There is no Rust crate that provides an "encrypt-on-read" FUSE layer compatible with EncFS block format. No existing encfsr-equivalent exists in the Rust ecosystem that would be drop-in usable here.

The C++ encfs project does have a `--reverse` flag, and its implementation is the reference. The Rust approach must replicate that logic from first principles, using the existing crypto layer that is already EncFS-compatible.

**The inversion pattern from C++ encfs `--reverse`:**
- `readdir`: walk the **plaintext** source dir, return **encrypted** filenames
- `getattr`: stat the **plaintext** source file, return size adjusted to **encrypted** (physical) size
- `open`: open the **plaintext** source file
- `read`: read **plaintext** from the source file, run it through `FileEncoder` (encrypt), return ciphertext to the FUSE caller
- Write operations: return `EROFS` (read-only filesystem)

**Confidence:** High (based on C++ encfs source behavior and the existing Rust architecture).

---

### 3. The FileEncoder Is Already the Right Tool

**Finding:** `FileEncoder` in `src/crypto/file.rs` already implements the encrypt-on-write path used by the normal encfs mount. For `encfsr`, the same `FileEncoder` is used on the read path instead.

The key insight: `FileEncoder::write_at(plaintext, offset)` computes the encrypted bytes for a given plaintext+offset. In `encfsr`, when FUSE calls `read(fh, offset, size)`, the implementation:
1. Opens/holds the plaintext source file
2. Reads `size` bytes of plaintext at `offset` from source
3. Passes those bytes through `FileEncoder` encrypt logic to get ciphertext
4. Returns ciphertext to FUSE

However, `FileEncoder` currently implements `WriteAt` (writing encrypted output to a backing file). For `encfsr`, we need it to **produce** the encrypted bytes rather than write them to disk. Two options:

**Option A - In-memory backing store (recommended):** Implement a `ReadAt` + `WriteAt` type backed by a `Vec<u8>` that `FileEncoder` writes into; the `encfsr` `read` handler uses this to capture encrypted bytes without touching disk. This is zero-copy efficient for block-aligned reads.

**Option B - Refactor FileEncoder to expose encrypt_block directly:** Expose `BlockCodec::encrypt_block` (already public) directly and call it per-block in the `encfsr` handler. This avoids the in-memory buffer indirection but duplicates some offset calculation logic from `FileEncoder`.

**Option A is preferred** because it reuses `FileEncoder` as-is, keeps the block offset arithmetic in one place, and avoids divergence.

No new dependencies are needed for either option.

**Confidence:** High.

---

### 4. Virtual File Size: Encrypted > Plaintext

**Finding:** `BlockLayout::physical_size_from_logical` (in `src/crypto/block.rs`) already computes the encrypted file size from plaintext size. The `encfsr` `getattr` handler must use this to report the correct (larger) size.

The formula: `encrypted_size = header_size + ceil(plaintext_size / data_block_size) * block_size + (partial_block > 0 ? partial_block + overhead : 0)`

Where `header_size = 8` bytes (when `unique_iv = false`, the header stores IV=0 deterministically; still 8 bytes on disk), `block_size` is from config, and `overhead = block_mac_bytes`.

`FileEncoder::calculate_physical_size_with_mode` (a static method already used in `src/fs.rs`) is the right call — it already wraps `BlockLayout::physical_size_from_logical`.

**Confidence:** High (directly verified in existing code).

---

### 5. Determinism Requires unique_iv=false and externalIVChaining=false

**Finding (critical):** The guarantee that `encfsr` output is reproducible (same plaintext always produces same ciphertext) requires:

- `unique_iv = false`: When true, a random 8-byte IV is stored in the file header and mixed into every block IV. With `unique_iv = false`, file IV = 0, and the header still exists (8 bytes of zeros after encryption) but is deterministic given the key.
- `external_iv_chaining = false`: When true, the file IV is computed from the path IV (parent directory chain). This makes output depend on where a file lives, not just its content. With `external_iv_chaining = false`, file IV = 0 regardless of path.
- `block_mac_rand_bytes = 0`: Random bytes in the MAC would also break determinism. The existing EncFS V6 default sets this to 0.

**How to validate on startup:** Check `config.unique_iv == false && config.external_iv_chaining == false`. The config fields are already present in `EncfsConfig`. This check belongs in the `encfsr` binary's startup code (before mounting), not in the library.

Note: `chained_name_iv` (filename IV chaining from parent dir) does NOT break determinism as long as the path doesn't change. It is safe to allow. However, disabling it simplifies the implementation since path IVs won't need to propagate into file IVs. The requirement here is only about `unique_iv` and `external_iv_chaining`.

**Confidence:** High (verified against EncFS protocol documentation and existing config fields).

---

### 6. Reverse Path Resolution: Decrypt FUSE Path to Find Source File

**Finding:** When a FUSE caller accesses an encrypted filename (e.g., `MhAO8Ckgt67m1cSrFU9HHiNT`), `encfsr` must decrypt that name to find the plaintext source file (`DESIGN.md`).

The existing `EncFs::decrypt_path` method (line 98 in `src/fs.rs`) already implements this. It walks path components and calls `SslCipher::decrypt_filename` per component, chaining IVs if `chained_name_iv` is enabled.

For `encfsr`, the flow is:
1. FUSE request arrives with an encrypted path
2. Decrypt path → plaintext source path (using `decrypt_path`)
3. Operate on the plaintext source file

For `readdir`: walk the plaintext source directory, encrypt each filename, return encrypted names to FUSE.

The `encrypt_path` and `decrypt_path` methods are candidates for extraction to a shared module callable by both binaries, but no new dependencies are needed.

**Confidence:** High.

---

### 7. Cargo.toml: Second [[bin]] Target

**Recommendation:** Add `encfsr` as a second `[[bin]]` target in the existing `Cargo.toml`.

```toml
[[bin]]
name = "encfsr"
path = "src/encfsr.rs"
```

This is the pattern already used for `encfsctl`. No workspace restructuring is needed. Both binaries share the `encfs` library crate defined by `src/lib.rs`.

The `clap` dependency (already present at 4.5.57) handles the `encfsr` CLI with a new `Args` struct in `src/encfsr.rs`. The CLI shape mirrors `encfs` but with:
- Source dir (plaintext) and mount point arguments
- Config path flag (required, since the config lives in the source dir but the caller needs to specify it explicitly for clarity — or auto-detect `.encfs6.xml` / `.encfs7` in the source dir as a convenience)
- `--extpass` / `--stdinpass` / interactive password (same as `encfs`)
- No write-related flags

**Confidence:** High.

---

### 8. Open File Handle Strategy

**Finding:** The existing `EncFs` keeps a `HashMap<u64, Arc<FileHandle>>` where each `FileHandle` stores an open `File` and a `file_iv`. For `encfsr`, the handle stores:
- An open `File` for the **plaintext** source file
- `file_iv = 0` (always, since `unique_iv = false`)

The FUSE `open` handler in `encfsr`:
1. Decrypts the FUSE path to get the plaintext source path
2. Opens the plaintext file read-only
3. Stores the handle

The FUSE `read` handler:
1. Looks up the handle (plaintext file)
2. Reads plaintext bytes from the source at offset
3. Encrypts them via `FileEncoder` / `BlockCodec`
4. Returns ciphertext

No new crates needed for this pattern — it is identical to the existing handle map approach.

**Confidence:** High.

---

### 9. No Additional Crates Required

**Summary of new dependencies needed:** None.

All required functionality exists in the current dependency set:

| Requirement | Existing Solution |
|-------------|------------------|
| FUSE mounting | `fuse_mt 0.6.3` |
| Block encryption | `SslCipher` + `BlockCodec` via `openssl` |
| AEAD block encryption (V7) | `aes-gcm-siv 0.11.1` |
| Filename encryption | `SslCipher::encrypt_filename` / `decrypt_filename` |
| Config loading & validation | `EncfsConfig::load` + new startup check |
| CLI argument parsing | `clap 4.5.57` |
| Error handling | `anyhow 1.0.101` |
| File size calculation | `BlockLayout::physical_size_from_logical` |
| Daemonization | `daemonize 0.5` (optional for encfsr) |
| Logging | `log` + `env_logger` |
| Password input | `rpassword 7.4.0` |

**Confidence:** High.

---

## Key Technical Considerations

### Consideration 1: The Header in Reverse Mode

When `unique_iv = false`, the 8-byte file header is still present on disk in normal encfs. The header stores a zero IV encrypted with the external IV (which is also 0 when `external_iv_chaining = false`). The header bytes are deterministic because the IV is always 0.

In `encfsr`, the virtual encrypted file must start with this 8-byte header. The FUSE `read` for offset 0 must synthesize the header bytes rather than read them from the plaintext source. `SslCipher::encrypt_header` (which takes `external_iv = 0`) generates these bytes. Since IV=0 and external_iv=0, and the cipher key is fixed, this produces the same 8 bytes every time.

If `header_size = 0` (config has `unique_iv = false` AND no header configured — some legacy configs), skip header synthesis.

### Consideration 2: Block Boundary Alignment

The FUSE `read` request arrives with arbitrary `(offset, size)` that may not align to block boundaries. The `FileDecoder` in the normal encfs mount handles this by loading full blocks and slicing. For `encfsr`, `FileEncoder` similarly works on full blocks. When a FUSE read spans multiple blocks or starts mid-block, the `encfsr` handler must:
1. Identify which encrypted blocks span the requested range
2. For each block: read the corresponding plaintext bytes from source, encrypt the full block, return the requested slice

The existing `FileEncoder` offset arithmetic handles this correctly if used with the in-memory buffer approach described in Finding 3.

### Consideration 3: Partial Last Block

If the plaintext file size is not a multiple of `data_block_size`, the last encrypted block will be smaller than `block_size`. The `FileEncoder` already handles partial blocks (it encrypts whatever plaintext is provided, appending the MAC). The virtual encrypted file size must accurately reflect this partial block using `BlockLayout::physical_size_from_logical`.

### Consideration 4: EROFS for All Mutations

Every FUSE operation that mutates state must return `libc::EROFS`. The `FilesystemMT` trait requires implementing: `write`, `create`, `mkdir`, `unlink`, `rmdir`, `rename`, `truncate`, `chmod`, `chown`, `mknod`, `symlink`, `link`, `utimens`. All of these should return `Err(libc::EROFS)`. Only `read`, `readdir`, `open`, `release`, `opendir`, `releasedir`, `getattr`, `readlink`, `statfs`, `access` need real implementations.

### Consideration 5: Symlinks in Reverse Mode

In normal encfs, symlink targets are encrypted as filenames using the path IV. In `encfsr`, `readlink` receives an encrypted path (symlink name), decrypts it to find the plaintext symlink, reads the plaintext target, and returns the encrypted target. The `SslCipher::encrypt_filename` method handles this.

---

## What NOT to Do

- **Do NOT switch from fuse_mt to fuser**: Migration cost exceeds the benefit for this use case. fuser is more actively maintained but the existing codebase is invested in fuse_mt.
- **Do NOT add a streaming encryption crate** (e.g., `aes-ctr`, `chacha20`): The encfs block format uses CBC/CFB mode cipher + MAC, not a streaming cipher interface. The existing `SslCipher` handles this correctly through OpenSSL.
- **Do NOT support uniqueIV or externalIVChaining**: These features produce non-deterministic output incompatible with the core encfsr value proposition. Validation on startup is the right approach; no runtime toggle.
- **Do NOT cache encrypted file content**: The encrypted output is deterministic from the plaintext content + config + key. There is no benefit to caching since re-encryption of the same plaintext block always produces the same bytes. Caching would add memory pressure and complexity with no correctness gain.
- **Do NOT use async/tokio**: The existing codebase is fully synchronous. fuse_mt handles concurrency via OS threads. Adding async to the FUSE path for encfsr would require either bridging sync/async (complex) or a full tokio migration (out of scope).

---

## Version Verification Status

The following versions are from `Cargo.toml` (verified against the live project file):

| Dependency | Version in Cargo.toml | Role in encfsr |
|-----------|----------------------|----------------|
| `fuse_mt` | 0.6.3 | FUSE mounting (no change) |
| `openssl` | 0.10.75 | AES/Blowfish cipher, PBKDF2 (no change) |
| `aes-gcm-siv` | 0.11.1 | V7 block AEAD (no change) |
| `argon2` | 0.5 | Key derivation (no change) |
| `clap` | 4.5.57 | CLI args for encfsr binary |
| `anyhow` | 1.0.101 | Error handling |
| `daemonize` | 0.5 | Optional background mode |
| `rpassword` | 7.4.0 | Password prompt |
| `log` + `env_logger` | 0.4.29 / 0.11.8 | Logging |
| `libc` | 0.2.180 | FUSE error codes |

Note: Version currency against crates.io could not be verified in this session due to network restrictions. Versions are taken directly from the live `Cargo.toml`. All are recent major releases as of late 2025.

**Confidence on versions:** Medium (taken from live Cargo.toml, network verification unavailable).

---

*Research completed: 2026-02-24*
