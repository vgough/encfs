# encfsr

## What This Is

`encfsr` is a reverse EncFS virtual filesystem. Where normal encfs mounts an encrypted directory and presents decrypted files, encfsr mounts a plaintext directory and presents encrypted files. The resulting virtual filesystem is byte-for-byte compatible with what a normal encfs encrypted volume looks like on disk — meaning it can be decrypted by a standard encfs mount. The primary use case is encrypted backups: encrypt-on-the-fly during rsync/backup without needing to maintain a separate encrypted copy on disk.

## Core Value

The virtual encrypted filesystem produced by encfsr must be byte-for-byte identical to what encfs would have produced — so normal encfs can always decrypt it.

## Requirements

### Validated

- ✓ EncFS FUSE filesystem with configurable cipher — existing
- ✓ Path encryption/decryption (V4/V5/V6/V7 config formats) — existing
- ✓ Block-level file encryption with IV chaining modes — existing
- ✓ Key derivation (PBKDF2, Argon2id) — existing
- ✓ Multi-format config loading and validation — existing
- ✓ `encfsctl` utility for admin operations — existing

### Active

- [ ] `encfsr` binary: mounts a plaintext source dir as an encrypted virtual FS
- [ ] Reverse file content: read plaintext from source, return encrypted data to FUSE caller
- [ ] Reverse path resolution: decrypt FUSE request path to find plaintext source file
- [ ] Correct virtual `stat()` sizes: report encrypted (larger) size, not plaintext size
- [ ] Filename encryption in virtual FS: encrypted filenames visible to FUSE callers
- [ ] Config validation on startup: reject configs with `uniqueIV` or `externalIVChaining` enabled (they produce non-deterministic output)
- [ ] Shared library refactor: extract common cipher/fs logic so encfs and encfsr share a single implementation without duplication
- [ ] Read-only mount enforcement: encfsr mounts are read-only; writes return EROFS

### Out of Scope

- Write-through to plaintext source — not needed for backup use case; adds complexity
- Auto-generating config — user provides an existing encfs config to ensure key/cipher choice is deliberate
- New config format (V8) — use existing formats
- macOS support — not a target for this work

## Context

This is the Rust rewrite of the original C++ encfs. Current status is **alpha**: read-only mode is fully functional, write support is partially implemented. The core architecture is already cleanly layered:

- `src/fs.rs` — FUSE `FilesystemMT` implementation (~1000 lines)
- `src/crypto/file.rs` — `FileDecoder` (encrypted→plaintext reads) and `FileEncoder` (plaintext→encrypted writes)
- `src/crypto/ssl.rs` — `SslCipher`: all cryptographic operations
- `src/crypto/block.rs` — `BlockCodec`: per-block MAC/AEAD handling
- `src/config.rs` — `EncfsConfig`: unified config across formats

For encfsr, the key inversion is in `FileDecoder`/`FileEncoder`: instead of decoding (decrypting) on read, we need to encode (encrypt) on read. The `SslCipher`, `BlockCodec`, and `EncfsConfig` are unchanged.

The shared library approach means moving common logic to a Rust library crate (already partly done via `src/lib.rs`) and adding `encfsr` as a second `[[bin]]` target in `Cargo.toml`.

**Critical constraint:** encfsr must produce deterministic output. This requires:
- `uniqueIV = false` in the encfs config (no per-file random IVs)
- `externalIVChaining = false` (path IV not mixed into file IV)
- With these disabled, file IV = 0, block IVs are position-derived only

## Constraints

- **Compatibility**: Output must be decryptable by standard encfs with the same config
- **Config**: User supplies encfs config; encfsr validates it for determinism (no uniqueIV, no externalIVChaining)
- **Language**: Rust — consistent with existing codebase
- **Read-only**: The encfsr virtual mount is read-only (EROFS on any write attempt)
- **Shared code**: No duplicated cipher/path/block logic between encfs and encfsr binaries

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Separate binary (`encfsr`) not a flag | Cleaner user experience; separate CLI docs; no risk of breaking existing encfs invocations | — Pending |
| User-provided config (not auto-generated) | Forces deliberate key/cipher choice; avoids surprise configs that don't interoperate | — Pending |
| Shared library approach | Less maintenance surface; cipher bugs fixed once benefit both binaries | — Pending |
| Read-only mount | Reverse write-through is complex and not needed for backup use case | — Pending |
| Reject uniqueIV/externalIVChaining | Both produce non-deterministic file IVs which break the core value guarantee | — Pending |

---
*Last updated: 2026-02-24 after initialization*
