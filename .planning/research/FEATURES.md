# Features Research: encfsr (Reverse Encrypted FUSE Filesystem)

**Research Date:** 2026-02-24
**Research Type:** Project Research — Features dimension
**Question:** What features do reverse encrypted filesystem tools have? What's table stakes vs differentiating?

---

## Context

encfsr mounts a plaintext directory and presents a read-only encrypted virtual filesystem that is byte-for-byte compatible with what normal encfs would produce. The existing Rust encfs codebase already implements: AES-CBC block encryption, AES-GCM AEAD, filename encryption/encoding (base32/base64), config parsing (.encfs6.xml), a FUSE filesystem driver (read/write, forward direction), and the encfsctl utility.

The question is: what does encfsr need _beyond_ that foundation?

---

## Reference: What encfs --reverse Already Does (Original C++ Implementation)

The original C++ encfs --reverse mode provides:
- Read-only FUSE mount of plaintext dir presenting encrypted view
- Deterministic encryption when uniqueIV is disabled (required for rsync-friendly output)
- Virtual `.encfs6.xml` config file at the root of the encrypted view
- Encrypted filenames using the same cipher/encoding as forward encfs
- Encrypted file content using the same block cipher as forward encfs
- Directory structure mirroring (encrypted names, same hierarchy)
- Symlink encryption (target path is encrypted)
- Special files (devices, FIFOs) pass-through with encrypted names only
- File metadata (size, permissions, timestamps) reflected accurately (file size accounts for IV headers if uniqueIV is on; with uniqueIV off, size matches ciphertext size exactly)
- No write support — the encrypted view is always derived from the plaintext source

---

## Table Stakes (Must-Have or Users Leave)

These are features that define the minimum viable product. Missing any of these makes encfsr unusable for its stated purpose.

### 1. Read-Only FUSE Mount of Encrypted View
**What:** Mount plaintext dir, present encrypted filenames and encrypted content at mount point. All FUSE read operations (open, read, getattr, readdir, readlink) must work correctly.
**Why table stakes:** This is the core value proposition. Without it there is no product.
**Complexity:** Medium — the existing FUSE layer handles this for forward encfs. Reverse requires inverting the data-flow: encrypt on read rather than decrypt on read.
**Depends on:** Existing FUSE driver, existing crypto layer.

### 2. Byte-for-Byte Compatibility with Forward encfs Output
**What:** An encrypted file produced by encfsr must be byte-for-byte identical to the file that would appear in an encfs-encrypted directory containing the same plaintext. Users must be able to decrypt an encfsr-produced backup using standard encfs.
**Why table stakes:** If the encrypted output isn't compatible, users can't recover their data with the reference implementation. The entire trust model collapses.
**Complexity:** High — requires precise alignment of IV calculation, block boundaries, filename encoding, and the virtual config file format.
**Depends on:** uniqueIV=false config requirement, existing crypto primitives.

### 3. Virtual Config File (.encfs6.xml) in Encrypted View Root
**What:** A virtual `.encfs6.xml` must appear at the root of the encrypted mount so that the encrypted backup is self-describing and decryptable without side-channel config delivery.
**Why table stakes:** Without it, users must separately track the config file, making backup restoration fragile. The reference encfs --reverse includes this.
**Complexity:** Low — generate from the in-memory config at mount time; serve as a virtual file via FUSE.
**Depends on:** Config serialization (already exists in `config_proto.rs` / `config_binary.rs`).

### 4. Encrypted Filenames (Same Algorithm as Forward encfs)
**What:** Directory listings in the encrypted view show encrypted filenames using the same block-cipher-based filename encryption and base32/base64 encoding that forward encfs uses.
**Why table stakes:** Without filename encryption, an attacker with the encrypted backup can read the plaintext filenames, defeating the purpose of encryption.
**Complexity:** Low-Medium — filename encryption already exists in the forward direction; reverse direction reuses same primitives.
**Depends on:** Existing filename encryption code.

### 5. Correct File Size Reporting (getattr)
**What:** `stat()` on an encrypted file must return the correct ciphertext size. With uniqueIV=false (the required mode), ciphertext size equals plaintext size rounded up to block boundary. This is critical for rsync's delta algorithm and for tools that pre-allocate based on reported size.
**Why table stakes:** Incorrect sizes cause rsync to re-transfer entire files, breaking the primary use case. They also cause read errors if a reader allocates exactly the reported size.
**Complexity:** Medium — must account for block padding; no per-file IV header when uniqueIV=false, simplifying the calculation.
**Depends on:** Block cipher block size from config.

### 6. Deterministic Output (uniqueIV=false Mode)
**What:** Given the same plaintext and key, encfsr must always produce the same ciphertext. This requires CBC mode without per-file unique IVs.
**Why table stakes:** Without determinism, rsync cannot detect unchanged files and will re-transfer everything on each backup run, destroying the incremental backup use case.
**Complexity:** Low — this is a config constraint, not new code. The IV for each block is derived deterministically from the block index.
**Depends on:** Config validation at mount time (encfsr should refuse to mount if uniqueIV=true).

### 7. Recursive Directory Traversal (readdir + lookup)
**What:** The encrypted view must reflect the full directory hierarchy of the plaintext source, with all directory names encrypted.
**Why table stakes:** Backups are useless if they only capture the top-level directory.
**Complexity:** Low — mirrors existing FUSE readdir logic in reverse.
**Depends on:** Filename encryption (item 4 above).

### 8. Config Validation at Mount Time
**What:** encfsr must validate that the provided config has uniqueIV disabled and that the cipher/key settings are compatible with deterministic reverse operation. It should emit a clear error message if not.
**Why table stakes:** Silently mounting with uniqueIV=true would produce non-deterministic output that looks correct but breaks incremental backups. Users would not notice until their backup system fails.
**Complexity:** Low.
**Depends on:** Config parsing (already exists).

### 9. Symlink Handling
**What:** Symlinks in the plaintext directory must appear as symlinks in the encrypted view, with their target paths encrypted.
**Why table stakes:** Symlinks are common in Unix directory trees. A backup tool that silently drops or corrupts symlinks is unreliable.
**Complexity:** Medium — symlink targets must be encrypted as strings; readlink must encrypt the target, not return plaintext.
**Depends on:** String/filename encryption.

---

## Differentiators (Competitive Advantage)

These features are not strictly required for minimal viability but meaningfully differentiate encfsr from the original C++ encfs --reverse and from generic encrypted backup tools.

### 10. Hard Link Deduplication in Encrypted View
**What:** When the plaintext source contains hard links (multiple directory entries pointing to the same inode), the encrypted view should ideally preserve this relationship. At minimum, each hardlinked name should appear as a separate file with identical encrypted content.
**Why differentiating:** The original encfs --reverse does not handle hard links well. rsync and backup tools benefit from correct hard link preservation (avoids duplicating data in backup).
**Complexity:** High — requires inode tracking across the virtual filesystem. A simpler fallback is to present each name independently (no deduplication), matching original behavior.
**Depends on:** FUSE inode management.

### 11. Incremental-Friendly Output (Stable Inode Numbers)
**What:** Inode numbers in the encrypted view should be stable across remounts for the same plaintext file. If inode numbers change each mount, rsync's `--checksum` is required instead of its faster mtime+size comparison.
**Why differentiating:** Stable inodes enable rsync to operate in default mode (mtime+size), making backups faster. The original encfs --reverse uses synthetic inodes that may not be stable.
**Complexity:** Medium — can derive encrypted view inode from plaintext inode with a keyed hash to avoid information leakage.
**Depends on:** Inode mapping strategy.

### 12. Sparse File Support
**What:** If the plaintext source contains sparse files (files with holes), the encrypted view should either preserve sparseness or at least not expand sparse files to their full allocated size in memory during encryption.
**Why differentiating:** Sparse files are common in VM disk images and databases, which are exactly the files users want to back up. Expanding them would exhaust memory and produce enormous backups.
**Complexity:** High — requires detecting holes via SEEK_HOLE/SEEK_DATA and emitting zero-encrypted blocks for hole regions without reading them. Zero blocks encrypt deterministically (all-zero input + zero IV = fixed ciphertext).
**Depends on:** Deterministic encryption (item 6), OS hole-detection support.

### 13. Streaming Read Without Full-File Buffering
**What:** Encrypting a file for a read request should not require loading the entire file into memory. Encryption should be computed on-demand per block for the requested byte range.
**Why differentiating:** Users back up large files (multi-GB video, VM images, databases). Full-file buffering would make encfsr impractical for these cases and would not be apparent until the first large-file backup attempt.
**Complexity:** Medium — CBC mode requires processing blocks sequentially from the beginning of the file to compute correct IVs for arbitrary offsets, but only the blocks being read (and their preceding IV chain) need to be computed. With uniqueIV=false and block-indexed IVs, random access is possible without reading prior blocks.
**Depends on:** IV derivation strategy (block-index-based IV enables O(1) random access).

### 14. User-Friendly Error Messages for Common Misconfigurations
**What:** Clear, actionable error messages when: the config file has uniqueIV=true, the config file is missing, the password is wrong, the plaintext directory is inaccessible, or the mount point is already in use.
**Why differentiating:** The original encfs --reverse has cryptic error messages. Users who misconfigure the tool and get a silent failure or a panic will abandon it.
**Complexity:** Low.
**Depends on:** Config validation (item 8).

### 15. Null/Dry-Run Mode (Verify Compatibility Without Mounting)
**What:** A CLI flag (`--check` or `--verify`) that validates the config and tests that a sample file would encrypt correctly, without mounting the FUSE filesystem.
**Why differentiating:** Allows users to verify a backup chain is consistent (that the same config will produce the same output) without mounting. Useful in CI pipelines for encrypted backup integrity checks.
**Complexity:** Low — reuse crypto layer, skip FUSE mount.
**Depends on:** Config parsing, crypto layer.

### 16. Progress / Statistics Output
**What:** Optional verbose mode showing files being presented, bytes encrypted on read, and cache hit rates.
**Why differentiating:** rsync backup jobs run unattended; operators want visibility. The original encfs --reverse is silent.
**Complexity:** Low.
**Depends on:** Nothing new.

---

## Anti-Features (Deliberately NOT Build)

These are features that seem natural to add but should be consciously excluded to control scope, avoid correctness pitfalls, or maintain the tool's conceptual integrity.

### A1. Write Support
**What to avoid:** Allowing writes to the encrypted view (i.e., decrypting the encrypted content and writing back to plaintext).
**Why exclude:** encfsr is a read-only view. Adding write support blurs it with the forward encfs direction, introduces bidirectional consistency hazards, and doubles implementation complexity. Users who want a writable encrypted filesystem should use forward encfs.
**Risk if included:** Data corruption if a write races with a read; ambiguity about which direction is authoritative.

### A2. uniqueIV=true Support
**What to avoid:** Allowing encfsr to mount with uniqueIV enabled (per-file random IVs).
**Why exclude:** uniqueIV=true produces non-deterministic ciphertext. Every mount would produce different encrypted bytes for the same plaintext file. rsync would see every file as changed on every backup run, making the incremental backup use case impossible. The feature would silently work but produce useless backups.
**Risk if included:** Users would not notice the problem until they try to do incremental backups and find that rsync re-transfers everything every time.
**Correct behavior:** Refuse to mount with a clear error message directing the user to regenerate their config with uniqueIV=false.

### A3. Key Management / Password Prompts in Daemon Mode
**What to avoid:** Building a daemon with interactive password prompts, key caching daemons, or PAM integration.
**Why exclude:** encfsr is a tool for scripted backup pipelines. Interactive password prompts break automation. Key management is a solved problem (environment variables, secret managers, systemd credentials) that does not need to be reinvented here.
**Correct behavior:** Accept password via stdin or environment variable. Document integration patterns with secret managers.

### A4. Caching / Content-Addressable Store
**What to avoid:** Building a caching layer that stores previously-encrypted blocks to avoid re-encryption on re-read.
**Why exclude:** With uniqueIV=false and deterministic block-index IVs, re-encryption of the same block always produces the same bytes. There is no correctness benefit to caching, and the memory overhead would be significant for large backup jobs.
**Note:** If benchmarking reveals that re-encryption of large files is a bottleneck, a simple page-cache-friendly read pattern is the correct solution, not an application-level cache.

### A5. Compression Integration
**What to avoid:** Adding compression before encryption (like encfs's optional per-file compression).
**Why exclude:** Compressed-then-encrypted data has near-random byte distribution, making it incompatible with the goal of byte-for-byte compatibility with standard encfs. Additionally, compression interacts poorly with rsync's delta algorithm (a change to one byte can alter the entire compressed output).
**Note:** If users want compression, they should compress plaintext files before mounting with encfsr, or use a backup tool with deduplication (like borg or restic) instead.

### A6. GUI / Mount Manager
**What to avoid:** Building a graphical mount manager, tray icon, or desktop integration.
**Why exclude:** encfsr's users are sysadmins and developers running automated backup pipelines. A GUI adds maintenance burden with no benefit to the target user.

### A7. Encrypted Volume Creation / Key Generation
**What to avoid:** Building an encfs volume creation wizard into encfsr.
**Why exclude:** encfsr consumes an existing encfs config; it does not create one. Key/config generation belongs to the encfsctl tool (already exists) or to the forward encfs mount path. Mixing creation and reverse-mount concerns complicates the mental model.
**Correct behavior:** Document that users must create a config with uniqueIV=false using encfsctl or forward encfs, then use that config with encfsr.

---

## Feature Dependency Graph

```
Config Validation (8)
    └── required by all other features

Deterministic Output / uniqueIV=false (6)
    └── required by Byte Compatibility (2)
    └── required by Stable Inode Numbers (11)
    └── required by Sparse File Support (12)
    └── required by Streaming Read (13)

Virtual Config File (3)
    └── depends on Config Serialization [already exists]

Encrypted Filenames (4)
    └── required by Directory Traversal (7)
    └── required by Symlink Handling (9)

File Size Reporting (5)
    └── depends on Block Cipher Block Size from Config

Byte Compatibility (2)
    └── depends on Deterministic Output (6)
    └── depends on Encrypted Filenames (4)
    └── depends on Correct File Size Reporting (5)
    └── depends on Virtual Config File (3)

Read-Only FUSE Mount (1)
    └── depends on all of the above

Streaming Read (13)
    └── depends on Deterministic Output (6)
    └── enables Sparse File Support (12)

Hard Link Deduplication (10)
    └── independent; nice-to-have after core is working

Stable Inode Numbers (11)
    └── depends on Deterministic Output (6)
```

---

## What the Existing Codebase Already Provides

Based on the Rust codebase structure (`src/fs.rs`, `src/crypto/`, `src/config.rs`, `src/config_proto.rs`, `src/config_binary.rs`, `src/encfsctl.rs`):

- **Config parsing and validation** — `config.rs`, `config_proto.rs`, `config_binary.rs` handle `.encfs6.xml` reading. Config serialization may already exist for encfsctl.
- **Crypto layer** — `crypto/block.rs` (AES-CBC block encryption), `crypto/aead.rs` (AES-GCM), `crypto/file.rs` (file-level encryption), `crypto/ssl.rs` (OpenSSL bindings). The encryption primitives needed by encfsr exist and are tested.
- **FUSE driver** — `fs.rs` implements the FUSE filesystem for the forward direction. The driver framework, inode management, and FUSE op dispatch are already present.
- **Filename encryption** — Used by the forward direction; the same code path applies in reverse.
- **encfsctl** — Utility operations including info/show commands; config serialization likely available here.

What does NOT yet exist:
- Reverse data-flow in the FUSE read path (encrypt-on-read instead of decrypt-on-read)
- Virtual file injection (the `.encfs6.xml` virtual file)
- Config validation for reverse mode (reject uniqueIV=true)
- Correct ciphertext size computation for getattr in the reverse direction
- Symlink target encryption on readlink

---

## Summary Table

| Feature | Category | Complexity | Depends On |
|---|---|---|---|
| Read-only FUSE mount | Table Stakes | Medium | All core features |
| Byte-for-byte compatibility | Table Stakes | High | (6), (4), (5), (3) |
| Virtual .encfs6.xml | Table Stakes | Low | Config serialization |
| Encrypted filenames | Table Stakes | Low-Medium | Existing filename crypto |
| Correct ciphertext size (getattr) | Table Stakes | Medium | Block size from config |
| Deterministic output (uniqueIV=false) | Table Stakes | Low | Config validation |
| Recursive directory traversal | Table Stakes | Low | (4) |
| Config validation at mount | Table Stakes | Low | Config parsing |
| Symlink handling | Table Stakes | Medium | Filename encryption |
| Hard link deduplication | Differentiator | High | FUSE inode management |
| Stable inode numbers | Differentiator | Medium | (6) |
| Sparse file support | Differentiator | High | (6), OS SEEK_HOLE |
| Streaming read without buffering | Differentiator | Medium | Block-index IV |
| User-friendly error messages | Differentiator | Low | (8) |
| Null/dry-run verify mode | Differentiator | Low | Config + crypto |
| Progress/statistics output | Differentiator | Low | None |
| Write support | Anti-feature | — | — |
| uniqueIV=true support | Anti-feature | — | — |
| Key management daemon | Anti-feature | — | — |
| Application-level cache | Anti-feature | — | — |
| Compression integration | Anti-feature | — | — |
| GUI / mount manager | Anti-feature | — | — |
| Volume creation wizard | Anti-feature | — | — |
