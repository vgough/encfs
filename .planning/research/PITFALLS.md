# Pitfalls: Reverse Encrypted Filesystem (encfsr)

**Research Date:** 2026-02-24
**Dimension:** Pitfalls
**Milestone:** Subsequent (adding encfsr to existing Rust EncFS codebase)

---

## Overview

This document catalogs implementation traps specific to building `encfsr`: a read-only reverse FUSE filesystem that reads plaintext and presents encrypted output byte-for-byte identical to what standard encfs would produce. Three categories are covered: FUSE reverse/passthrough mistakes, EncFS compatibility pitfalls, and performance traps in read-heavy FUSE implementations.

---

## Category 1: FUSE Reverse/Passthrough Mistakes

### PITFALL-01: Reporting Plaintext Size in stat() / getattr()

**What goes wrong:** The virtual filesystem reports the plaintext file size (from the source) in `getattr()`. Callers (backup tools, rsync, kernel) use this to allocate read buffers and determine EOF. If the reported size is smaller than the actual encrypted bytes delivered on read, callers will silently truncate the backup. If larger, they will read past real EOF and receive zeros or errors.

**Warning signs:**
- `stat()` on a virtual file returns the same size as the source plaintext file
- Backup tool reports different file sizes than expected encrypted volume
- Read callbacks get called with offset beyond the reported size
- Integration test: `stat().st_size != FileEncoder::calculate_physical_size(plaintext_len, ...)`

**Prevention strategy:**
- In `getattr()` for regular files, always compute and return `FileEncoder::calculate_physical_size_with_mode(source_len, header_size, block_size, block_mac_bytes, block_mode)` — the same function already exposed in `src/crypto/file.rs:325`
- The existing `fs.rs` `getattr()` (line 1117-1128) does the inverse: it calls `calculate_logical_size_with_mode` to strip overhead from encrypted files. encfsr must invert this — call `calculate_physical_size_with_mode` to add overhead to plaintext sizes
- Unit test: for each block mode (Legacy, AesGcmSiv), verify `stat().st_size` matches `calculate_physical_size`

**Phase:** Core FUSE skeleton (Phase 1 / before any read path)

---

### PITFALL-02: Path Direction Error — Encrypting Instead of Decrypting Incoming Paths

**What goes wrong:** In normal encfs, FUSE receives plaintext paths and `encrypt_path()` maps them to encrypted on-disk paths. In encfsr, FUSE receives encrypted paths (from the caller) and must `decrypt_path()` to find the plaintext source file. Reusing `encrypt_path()` for incoming requests produces the wrong physical path; the source file will not be found and every operation returns ENOENT.

**Warning signs:**
- Every FUSE operation on a valid file returns ENOENT
- The translated path looks like a double-encrypted name
- `decrypt_path()` already exists in `src/fs.rs:98` and is marked `pub` — it was designed for this use case per the comment at line 96: "plaintext requests to encrypted paths via `encrypt_path`"
- Forgetting this causes silent wrong-file reads if a name collision exists

**Prevention strategy:**
- In encfsr, incoming FUSE paths are encrypted names; use `decrypt_path()` (not `encrypt_path()`) to resolve them to the plaintext source path
- In `readdir()`, the source directory contains plaintext names; encrypt each entry name via `encrypt_filename()` before returning it to the FUSE caller
- Write a path round-trip test: `encrypt_path(decrypt_path(p)) == p` for all test fixture paths

**Phase:** Path resolution (Phase 1 / FUSE skeleton)

---

### PITFALL-03: readdir() Returning Plaintext Names Instead of Encrypted Names

**What goes wrong:** `readdir()` opens the source (plaintext) directory and reads real filenames. If these are returned directly to the FUSE caller, the virtual filesystem exposes unencrypted names, breaking the entire purpose of encfsr and making the output unreadable by standard encfs (which expects encrypted filenames in the virtual FS).

**Warning signs:**
- Listing the virtual mount point shows plaintext filenames
- encfs cannot mount the resulting virtual FS (name decryption fails)
- The encrypted-path lookup in a subsequent open/getattr fails because the name was never encrypted

**Prevention strategy:**
- For each `DirEntry` in the source directory, call `cipher.encrypt_filename(entry_name_bytes, dir_iv)` and return the encrypted base64-encoded name to the FUSE caller
- The `dir_iv` is derived from the parent directory's path IV using `decrypt_path()` (or `encrypt_path()` — they return the same IV for the same path, since IV derivation is symmetric in this codebase)
- Match the behavior of the existing `readdir()` in `src/fs.rs:1152`, but invert source and output: source is plaintext, output is encrypted

**Phase:** Path resolution (Phase 1)

---

### PITFALL-04: Not Generating the Per-File Header When uniqueIV = false

**What goes wrong:** When `unique_iv = false`, `header_size()` returns 0 (see `src/config.rs:822`). This means no 8-byte random IV header is written. If encfsr writes a header anyway (treating it as uniqueIV=true), standard encfs will try to read the first 8 bytes as file data, misaligning all block boundaries and producing garbage on decrypt.

Conversely, if encfsr incorrectly treats `unique_iv = true` and skips the header, decryption will fail because encfs will look for the 8-byte header that is not there.

**Warning signs:**
- encfsr requires `unique_iv = false` (config validation rejects it otherwise)
- `config.header_size()` returns 0 for `unique_iv = false`
- If a non-zero header is prepended, block 0 starts at byte 8, but standard encfs expects it at byte 0
- File content decrypts to noise when opened with standard encfs

**Prevention strategy:**
- Always use `config.header_size()` to determine whether to produce a header; do not hard-code 8
- For encfsr (uniqueIV=false), `header_size()` = 0 — the first encrypted block starts at byte 0 of the virtual file
- When `header_size = 0`, `file_iv = 0` (no random per-file IV); block IVs are derived from block number XOR file_iv = block number only
- Startup config validation must `bail!` if `unique_iv = true` or `external_iv_chaining = true`

**Phase:** Config validation (Phase 0, before any encryption)

---

### PITFALL-05: File Handle Lifetime and Concurrency — Holding Source File Open

**What goes wrong:** FUSE is multi-threaded (fuse_mt uses multiple threads). encfsr must open the source plaintext file on `open()` and store it in the file handle map. If the source file is reopened on every `read()` call (stateless approach), the implementation is correct but slow and racy (source file could be replaced mid-read). Conversely, if file handles are not stored behind `Arc` and protected by a mutex, concurrent reads on the same fh can cause data races.

**Warning signs:**
- Use of `File::open()` inside the `read()` handler rather than `open()`
- File handle map not using `Arc<FileHandle>` (existing pattern in `src/fs.rs:1313`)
- Mutex not used around the file handle map (see `src/fs.rs:60` pattern)
- `.unwrap()` on mutex locks in the read path (see CONCERNS.md: panicking mutex operations in `src/crypto/file.rs:491`)

**Prevention strategy:**
- Follow the existing `EncFs` pattern exactly: store `Arc<FileHandle>` in `Mutex<HashMap<u64, Arc<FileHandle>>>` and clone the `Arc` before dropping the mutex lock before I/O
- For encfsr, `FileHandle` holds the plaintext source `File` plus `file_iv = 0` (no header)
- Use `.unwrap_or_else(|e| e.into_inner())` for mutex recovery (existing pattern at `src/fs.rs:60`)
- Do not call `read_at` while holding the handles mutex

**Phase:** FUSE read path (Phase 2)

---

### PITFALL-06: Incorrect EOF Handling — Returning Wrong Amount of Data

**What goes wrong:** A FUSE `read()` request specifies `(offset, size)` in terms of the virtual (encrypted) file's byte space. In encfsr, offset 0 in the virtual file corresponds to byte 0 of encrypted block 0, which is built from plaintext bytes 0..`block_size-overhead`. If the implementation passes the offset directly to `FileDecoder` on the source file (treating the virtual offset as a plaintext offset), it will return misaligned data.

**Warning signs:**
- Reading virtual file at offset > 0 returns wrong ciphertext
- File content when decrypted produces a byte shift matching the per-block overhead
- The last block reads beyond source EOF and must be zero-padded before encryption

**Prevention strategy:**
- For read at virtual offset `V`, determine which encrypted block(s) `V` falls into using `BlockCodec::layout` arithmetic (the same arithmetic used in `FileDecoder`/`FileEncoder`)
- Read the corresponding plaintext bytes from the source file (at plaintext offsets), encrypt them using `FileEncoder` logic, and return the encrypted bytes at virtual position `V`
- The existing `FileEncoder` already handles partial-block reads by zero-padding; reuse it by treating the source file as the "write input" and reading encrypted output
- Test: seek to every block boundary and mid-block offset; verify output matches encfs-encrypted reference

**Phase:** Read path implementation (Phase 2)

---

### PITFALL-07: Not Enforcing Read-Only at the FUSE Layer

**What goes wrong:** encfsr mounts are semantically read-only. If write-path FUSE handlers (`write`, `create`, `mkdir`, `unlink`, `rename`, etc.) are not stubbed to return `EROFS`, a caller may attempt to modify the virtual FS. This causes either a panic (unimplemented handler) or silent corruption of the source plaintext directory.

**Warning signs:**
- Default `fuse_mt` implementations may fall through to no-op rather than error
- A caller successfully creates a file in the virtual mount
- The source plaintext directory gains unexpected files

**Prevention strategy:**
- Implement all mutating FUSE operations to return `Err(libc::EROFS)` immediately
- Set the `MS_RDONLY` mount flag when calling fuse_mt mount (prevents the kernel from even forwarding writes in many configurations)
- Test: attempt `touch`, `mkdir`, `rm` on the virtual mount; verify all return EROFS or permission denied

**Phase:** FUSE skeleton (Phase 1)

---

## Category 2: EncFS Compatibility Pitfalls

### PITFALL-08: Block IV Derivation — file_iv Must Be 0, Not Random

**What goes wrong:** In the normal encfs write path with `unique_iv = false`, `file_iv = 0` and each block's IV is `block_num XOR file_iv = block_num`. If encfsr generates a random `file_iv` per open (or stores one in a header that doesn't exist for `unique_iv=false`), the resulting ciphertext differs from what encfs would produce for the same plaintext, breaking the byte-for-byte identity guarantee.

**Warning signs:**
- encfsr-produced file, when decrypted by standard encfs, produces wrong plaintext
- Encrypted output differs between two runs on the same source file
- Any call to `cipher.encrypt_header()` or `cipher.encrypt_header_with_iv()` in the read path when `unique_iv = false`

**Prevention strategy:**
- For encfsr (which mandates `unique_iv = false`): always use `file_iv = 0`
- In `SslCipher::encrypt_block`, the IV is `block_num XOR file_iv`; with `file_iv=0`, IV = block number — this is deterministic and matches standard encfs
- Do not call `cipher.encrypt_header()` (which generates a random IV); there is no header
- Reference: `src/crypto/ssl.rs:797` shows `iv64 = block_num ^ file_iv`; with file_iv=0 this equals block_num

**Phase:** Encryption implementation (Phase 2)

---

### PITFALL-09: Block Boundary Misalignment — Confusing Logical and Physical Block Offsets

**What goes wrong:** Each on-disk encrypted block is `block_size` bytes but contains only `block_size - overhead` bytes of plaintext (where `overhead = block_mac_bytes` for Legacy mode, or 16 bytes for AES-GCM-SIV). If a virtual read at byte offset `V` is satisfied by reading source bytes at `V` (ignoring overhead), every block after the first will be shifted by `N * overhead` bytes, producing garbled ciphertext.

**Warning signs:**
- Files longer than one block decrypt to wrong plaintext starting at block 1
- The offset calculation does not use `BlockCodec::layout` or `calculate_physical_size`
- Reading a virtual file at the second block boundary (byte `block_size`) returns ciphertext that does not decrypt to `plaintext[block_size - overhead]`

**Prevention strategy:**
- For virtual offset `V`, compute: `block_num = V / block_size`, `block_offset = V % block_size`
- The plaintext offset for block `block_num` is: `block_num * (block_size - overhead)`, plus `block_offset - overhead` (if after the MAC)
- Reuse `BlockCodec`'s `layout` field which encapsulates this arithmetic
- Comprehensive test: encrypt a 3-block file and verify block 1 and block 2 ciphertext independently

**Phase:** Encryption implementation (Phase 2)

---

### PITFALL-10: Filename Encoding Mismatch — Wrong Base64 Alphabet or Padding

**What goes wrong:** EncFS uses a URL-safe base64 alphabet (or a custom alphabet depending on config version) for encrypted filename encoding. If the encfsr implementation uses standard base64 or adds/omits padding characters, encrypted filenames will not match what encfs produces. The virtual directory listing will contain names that encfs cannot decrypt.

**Warning signs:**
- A filename encrypted by encfsr differs from the same filename encrypted by `encfsctl encode`
- Standard encfs returns "Failed to decrypt filename" when mounting the output of encfsr
- The base64 alphabet or padding is not identical to `SslCipher::encrypt_filename()`

**Prevention strategy:**
- Always call `cipher.encrypt_filename(name_bytes, dir_iv)` directly — never re-implement base64 encoding
- The `SslCipher` implementation in `src/crypto/ssl.rs` encapsulates the correct encoding; reuse it unconditionally
- Integration test: for each fixture file, verify `encfsctl decode (encfsr_encrypted_name) == original_name`

**Phase:** Path resolution (Phase 1)

---

### PITFALL-11: Config Validation Incomplete — Allowing Configs That Produce Non-Deterministic Output

**What goes wrong:** The project README and PROJECT.md state that `unique_iv = false` and `external_iv_chaining = false` are required for deterministic output. If startup validation only checks `unique_iv` but not `external_iv_chaining`, a config with `external_iv_chaining = true` will be accepted. This causes the file IV to be XOR'd with the path IV (see `src/fs.rs:1241-1244`), making the ciphertext path-dependent and non-deterministic across renames.

**Warning signs:**
- Startup accepts a config with `external_iv_chaining = true` without error
- The existing `src/config.rs:282` validation rejects `unique_iv=false` for non-V4 configs (this is the **inverse** of encfsr's requirement); encfsr needs its own validation
- Encrypted output changes when a source file is in a different directory

**Prevention strategy:**
- At encfsr startup, after loading config: `if config.unique_iv { bail!("encfsr requires uniqueIV=false") }` and `if config.external_iv_chaining { bail!("encfsr requires externalIVChaining=false") }`
- Also validate `chained_name_iv`: if true, path IV derivation requires parent encrypted names, which creates ordering constraints. Warn or reject
- Test: attempt to mount with each disallowed flag set; verify startup fails with a clear error message

**Phase:** Config validation (Phase 0)

---

### PITFALL-12: Block MAC Computation — Using Wrong Seed or Skipping MAC

**What goes wrong:** In Legacy block mode, each block starts with `block_mac_bytes` of MAC data computed from the plaintext using a keyed HMAC. If encfsr skips MAC generation (treating blocks as raw cipher output) or uses the wrong HMAC seed (e.g., wrong block number or file IV), the resulting MAC bytes will not match what encfs expects. Standard encfs will reject the block with a MAC verification error.

**Warning signs:**
- Standard encfs reports "block MAC mismatch" when decrypting encfsr output
- The encrypted file is the right size but contents are corrupted after decryption
- BlockCodec::encrypt_legacy_block is not called, or is called with wrong `block_num` or `file_iv`

**Prevention strategy:**
- Use `BlockCodec::encrypt_block(block_num, file_iv, plaintext)` for each block; never encrypt raw ciphertext without the MAC header
- With `file_iv = 0` (encfsr requirement), the MAC seed is deterministic: `block_num XOR 0 = block_num`
- For AES-GCM-SIV mode, the 16-byte tag replaces the legacy MAC; `SslCipher::encrypt_aes_gcm_siv_block` handles this correctly — reuse it
- Reference: `src/crypto/block.rs:171-172` dispatches to the correct encrypt function per mode

**Phase:** Encryption implementation (Phase 2)

---

### PITFALL-13: AES-GCM-SIV Nonce Collision When block_num Repeats Across Files

**What goes wrong:** `SslCipher::aes_gcm_siv_nonce()` (line 808-812) constructs the 12-byte nonce from `file_iv XOR (block_num >> 32)` and `block_num`. With `file_iv = 0` for all files, the nonce for block 0 of every file is identical. AES-GCM-SIV is designed to be nonce-misuse-resistant (different plaintexts with the same nonce do not leak the key), but repeated nonces with identical plaintexts will produce identical ciphertext, which may leak information about identical file contents.

This is not a decryptability failure — standard encfs will still decrypt the output correctly. However, it is a security property regression compared to a proper uniqueIV configuration.

**Warning signs:**
- Two different files with identical plaintext block 0 produce identical ciphertext block 0
- This is expected and intentional for encfsr (determinism requires it), but must be documented
- If future code adds a random `file_iv` to "improve security," it breaks determinism

**Prevention strategy:**
- Document explicitly: encfsr's determinism guarantee comes at the cost of nonce uniqueness across files; this is an accepted design trade-off
- Never add random per-file IVs to "fix" this: it breaks the core value guarantee
- The config validation (PITFALL-11) enforces the right constraints; document the security implications in the encfsr man page / help text

**Phase:** Design acknowledgment (Phase 0 / documentation)

---

### PITFALL-14: Symlink Target Encryption — Using Wrong IV

**What goes wrong:** In encfs, symlink targets are encrypted as filenames using the path IV of the symlink's containing directory. In encfsr, `readlink()` receives an encrypted path, decrypts it to find the source symlink, reads the plaintext target, then must re-encrypt the target as a filename using the correct directory IV. If the wrong IV is used (e.g., 0 instead of the directory's IV), the resulting encrypted symlink target cannot be decrypted by standard encfs.

**Warning signs:**
- Symlinks in the virtual FS appear but their targets are unreadable
- `encfsctl` reports "Failed to decrypt symlink target" on the encfsr output
- `readlink()` returns a target encrypted with IV=0 when it should use the directory's path IV

**Prevention strategy:**
- In encfsr's `readlink()`: use `decrypt_path(incoming_encrypted_path)` to get the source path AND the directory IV; read the source symlink target (plaintext); then call `cipher.encrypt_filename(target, dir_iv)` to produce the encrypted target for the FUSE caller
- Reference: the existing `src/fs.rs:1002-1013` `readlink()` does the inverse (decrypt on read); mirror that logic
- Test: create a symlink in the source, verify the virtual FS exposes a correctly-encrypted target that encfs can follow

**Phase:** Path resolution / read path (Phase 2)

---

## Category 3: Performance Traps in Read-Heavy FUSE Implementations

### PITFALL-15: Path Re-Encryption on Every FUSE Operation

**What goes wrong:** Every FUSE operation (getattr, open, read, readdir, readlink) calls path translation. In encfsr, this means calling `decrypt_path()` on the incoming encrypted path for each operation. The `decrypt_path()` function iterates path components and calls `cipher.decrypt_filename()` per component. For deeply nested paths, this is multiple AES operations per FUSE call with no caching.

CONCERNS.md (Performance Bottlenecks section) already flags this for the normal encfs path; for encfsr running as a backup source, the issue is amplified because backup tools perform many stat/open/read calls in sequence on the same paths.

**Warning signs:**
- `strace`/`perf` shows `decrypt_filename` called hundreds of times per second during a backup
- Latency per FUSE operation grows linearly with path depth
- Profiling shows >50% CPU time in `decrypt_filename` or `encrypt_filename` during a `tar` or `rsync` run

**Prevention strategy:**
- Implement a path translation cache: `HashMap<EncryptedPath, (PlaintextPath, PathIV)>` with a bounded LRU eviction policy (e.g., 1024 entries)
- The cache is safe because encfsr is read-only (no path invalidation from writes) and source files are not modified during mount (backup use case)
- Cache must be behind a `RwLock` to allow concurrent reads; writes take an exclusive lock only on cache miss
- Phase: implement without cache first (correctness), add cache as a follow-up optimization

**Phase:** Optimization (Phase 3, after correctness verified)

---

### PITFALL-16: Per-Read Block Re-Encryption — Not Reusing Block Results

**What goes wrong:** FUSE splits large reads into multiple smaller `read()` calls. If the block cipher is invoked separately for each FUSE `read()` call, blocks that span a FUSE boundary are encrypted twice (once for the tail of the first call, once for the head of the second). This is correct but wasteful.

More critically: if a caller performs many small overlapping reads (e.g., seeking to read file headers), each read that touches block 0 triggers full block encryption from plaintext. For large blocks (default 1024 bytes), this means 1024 bytes of AES work to return 16 bytes of ciphertext.

**Warning signs:**
- Sequential reads of a large file are slow despite the source being on a fast local disk
- CPU usage is proportional to `read_requests * block_size` rather than `total_bytes_read`
- `strace` shows many `read()` calls each returning < block_size bytes

**Prevention strategy:**
- `FileEncoder` (or an encfsr equivalent) should encrypt and cache the current block on first access, returning the relevant slice for subsequent reads within the same block
- The existing `FileDecoder` in `src/crypto/file.rs` already has a `last_block` caching field — examine this pattern and apply it to `FileEncoder` / encfsr's block cache
- Alternatively, rely on FUSE's page cache (`direct_io = false`) to coalesce reads at the kernel level; this is the simplest approach for a backup use case

**Phase:** Optimization (Phase 3)

---

### PITFALL-17: Blocking the FUSE Thread on Source File I/O

**What goes wrong:** `fuse_mt` creates a pool of threads (default: num_cpus) to handle FUSE requests concurrently. If a `read()` handler does synchronous blocking I/O on the source file using `read_at()`, and the source is on a slow network filesystem or spinning disk, all FUSE threads can be blocked waiting for I/O. This stalls the entire virtual filesystem.

**Warning signs:**
- Virtual FS becomes unresponsive during large reads
- `fuse_mt` thread pool fully occupied with threads in `read_at` syscall
- `ls` on the virtual mount hangs while a backup is in progress

**Prevention strategy:**
- For the backup use case, this is low priority (backup tools expect sequential I/O)
- However, do not hold any mutex (file handle map, path cache) while performing I/O — always clone the `Arc<FileHandle>` before dropping the lock, then perform I/O without any lock held (existing pattern in `src/fs.rs:1331-1337`)
- If the source is a network filesystem, recommend mounting with `-o allow_other` and a bounded thread count

**Phase:** FUSE read path (Phase 2)

---

### PITFALL-18: statfs() Reporting Wrong Block Count

**What goes wrong:** `statfs()` on the virtual mount returns the block count of the source filesystem. Because every encrypted file is larger than its source (by `header_size + N * overhead`), the virtual filesystem's apparent total size is larger than what `statfs` reports. Tools that check free space before writing (e.g., backup tools verifying destination capacity) may be misled.

**Warning signs:**
- `df` on the virtual mount reports less total space than the sum of encrypted file sizes
- Backup tool aborts with "not enough space" when copying from the virtual mount to a destination

**Prevention strategy:**
- In encfsr's `statfs()`, scale `f_blocks`, `f_bused`, and `f_bfree` to reflect the encrypted size rather than the plaintext source size
- For an approximation: multiply `f_blocks` by `block_size / (block_size - overhead)`; this overestimates slightly (ignores partial last blocks and header overhead)
- For a read-only virtual FS, `f_bavail = f_bfree = 0` is a safe and correct choice: no writes are possible, so no free space is available

**Phase:** FUSE skeleton (Phase 1)

---

## Summary Table

| # | Category | Pitfall | Phase |
|---|----------|---------|-------|
| 01 | FUSE | stat() reports plaintext size | Phase 1 |
| 02 | FUSE | Path direction error (encrypt vs decrypt) | Phase 1 |
| 03 | FUSE | readdir() exposes plaintext names | Phase 1 |
| 04 | FUSE | Writing header when uniqueIV=false | Phase 0 |
| 05 | FUSE | File handle concurrency | Phase 2 |
| 06 | FUSE | Incorrect EOF / offset handling | Phase 2 |
| 07 | FUSE | Missing EROFS enforcement | Phase 1 |
| 08 | Compat | Random file_iv instead of 0 | Phase 2 |
| 09 | Compat | Block boundary misalignment | Phase 2 |
| 10 | Compat | Filename base64 encoding mismatch | Phase 1 |
| 11 | Compat | Incomplete config validation | Phase 0 |
| 12 | Compat | Block MAC computation errors | Phase 2 |
| 13 | Compat | AES-GCM-SIV nonce collision (by design) | Phase 0 doc |
| 14 | Compat | Symlink target wrong IV | Phase 2 |
| 15 | Perf | Path re-encryption on every op | Phase 3 |
| 16 | Perf | Block re-encryption on overlapping reads | Phase 3 |
| 17 | Perf | Blocking FUSE thread on I/O | Phase 2 |
| 18 | Perf | statfs() wrong block count | Phase 1 |

---

*Research completed: 2026-02-24*
