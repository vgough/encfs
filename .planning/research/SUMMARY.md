# Project Research Summary

**Project:** encfsr — Reverse Encrypted FUSE Filesystem
**Domain:** Systems / Cryptographic FUSE Filesystem
**Researched:** 2026-02-24
**Confidence:** HIGH

## Executive Summary

encfsr is a read-only FUSE filesystem that mounts a plaintext directory and presents an encrypted virtual view byte-for-byte compatible with what forward encfs produces. It is the Rust equivalent of `encfs --reverse`. The implementation is a second binary (`encfsr`) added to the existing Rust EncFS codebase. All required crypto primitives, the FUSE driver framework, filename encryption, config parsing, and CLI tooling already exist — no new dependencies are needed. The implementation work is confined to: (1) a new `FileReverseReader` struct in `crypto/file.rs` that encrypts blocks on-the-fly for read requests, (2) a new `ReverseFilesystemMT` FUSE handler in `reverse_fs.rs` that inverts the normal path-translation and data-flow direction, and (3) a new binary entry point `src/reverse_main.rs` wired into `Cargo.toml`.

The single most important constraint is determinism: encfsr must be configured with `unique_iv = false` and `external_iv_chaining = false`. When these hold, the same plaintext always produces the same ciphertext, making encrypted output rsync-friendly for incremental backups. This constraint is not optional — the core use case (incremental encrypted backup via rsync) is impossible without it. Startup validation must enforce this and reject configs that would produce non-deterministic output with a clear error message. The security trade-off (nonce reuse across files with AES-GCM-SIV) is an accepted and documented design choice.

The key risk is subtle bugs at three intersection points: (1) block boundary arithmetic — FUSE read offsets are in ciphertext space but source reads are in plaintext space, and every block carries overhead bytes; (2) path direction — incoming FUSE paths must be decrypted (not encrypted) to find source files, while readdir output must be encrypted (not plaintext); and (3) the file header — with `unique_iv = false`, `header_size() = 0` and the first encrypted block starts at virtual byte 0. Getting any of these wrong produces silently incorrect output that decrypts to garbage. The mitigation is round-trip integration tests against the reference C++ encfs for each block mode (Legacy AES-CBC and AES-GCM-SIV).

## Key Findings

### Recommended Stack

The existing stack covers 100% of encfsr requirements. `fuse_mt 0.6.3` provides the `FilesystemMT` trait already implemented for all FUSE operations; `encfsr` adds a second struct implementing the same trait. `SslCipher` (via `openssl 0.10.75`) and `BlockCodec` provide all cipher operations. `FileEncoder` already implements the encrypt direction needed. `BlockLayout::physical_size_from_logical` computes encrypted file sizes. `clap 4.5.57` handles CLI. Do not switch from `fuse_mt` to `fuser` — migration cost far exceeds the benefit for adding a second binary to an already-working codebase.

**Core technologies:**
- `fuse_mt 0.6.3`: FUSE mounting — already integrated, multi-threaded, `FilesystemMT` trait reused by both binaries
- `openssl 0.10.75` via `SslCipher`: AES-CBC/CFB cipher, PBKDF2, filename encryption — provides all Legacy block mode crypto
- `aes-gcm-siv 0.11.1` via `BlockCodec`: V7 AEAD block encryption — unchanged from forward encfs
- `clap 4.5.57`: CLI argument parsing for the `encfsr` binary entry point
- `anyhow 1.0.101`: Error handling and startup validation bail-out messages
- Existing `BlockLayout` / `FileEncoder` in `crypto/file.rs`: Encrypted size computation and block-level encryption logic

### Expected Features

**Must have (table stakes):**
- Read-only FUSE mount presenting encrypted filenames and encrypted content — core value proposition, nothing works without this
- Byte-for-byte compatibility with forward encfs output — broken output means unusable backups; trust model collapses
- Virtual `.encfs6.xml` at encrypted view root — self-describing backup, required for autonomous restore
- Encrypted filenames using same algorithm as forward encfs — unencrypted names defeat the purpose
- Correct ciphertext size reporting in `getattr()` — wrong sizes break rsync delta algorithm and cause read errors
- Deterministic output (`unique_iv = false` enforced) — non-deterministic output destroys incremental backup use case
- Recursive directory traversal (`readdir` + `lookup`) — flat-directory backups are not useful
- Config validation at mount time — silently accepting `unique_iv = true` would produce useless non-deterministic backups
- Symlink handling with encrypted targets — common in Unix trees; silent corruption is unacceptable

**Should have (competitive):**
- Streaming read without full-file buffering — required for large files (multi-GB VMs, databases); discoverable failure
- Stable inode numbers across remounts — enables fast rsync mtime+size comparison instead of expensive --checksum
- User-friendly error messages for misconfigurations — original C++ encfs --reverse has cryptic errors
- Null/dry-run verify mode (`--check` flag) — useful for CI pipeline encrypted backup integrity checks
- Progress/statistics output in verbose mode — backup pipelines run unattended; operators need visibility

**Defer (v2+):**
- Hard link deduplication in encrypted view — high complexity, C++ encfs --reverse doesn't do this either
- Sparse file support (SEEK_HOLE/SEEK_DATA) — high complexity; zero-encrypted blocks work correctly but without hole preservation
- Path translation LRU cache — optimize after correctness verified; needed only if profiling shows >50% CPU in path translation
- BlockMapper extraction (refactoring) — clean up block boundary arithmetic duplication after both paths are tested

**Anti-features (never build):**
- Write support, `unique_iv = true` support, interactive key management daemon, application-level encryption cache, compression integration, GUI, volume creation wizard

### Architecture Approach

The architecture is additive: the existing codebase is not restructured. Three new artifacts are created. `FileReverseReader` is added to `crypto/file.rs` alongside `FileDecoder` and `FileEncoder` — it holds a plaintext source `File`, `file_iv = 0`, and a `BlockCodec`, and implements an `encrypt-on-read` path that maps virtual ciphertext offsets to plaintext source offsets, reads plaintext, encrypts per-block, and returns ciphertext slices. `ReverseFilesystemMT` in a new `reverse_fs.rs` implements the `FilesystemMT` trait: incoming FUSE paths are encrypted (use `decrypt_path()` to resolve to source), `readdir()` encrypts source plaintext names before returning them, `getattr()` returns `physical_size` not `stat().st_size`. All mutating FUSE ops return `EROFS`. `reverse_main.rs` is the binary entry point: parse CLI args, validate config (reject `unique_iv = true` and `external_iv_chaining = true`), mount via `fuse_mt::mount(ReverseFilesystemMT::new(config), ...)`.

**Major components:**
1. `FileReverseReader` (new, in `crypto/file.rs`) — block-aligned encrypt-on-read; maps virtual ciphertext offsets to plaintext, encrypts per-block with `file_iv = 0`
2. `ReverseFilesystemMT` (new, in `reverse_fs.rs`) — FUSE handler; path direction inverted vs `fs.rs`; `readdir` encrypts names, `read` delegates to `FileReverseReader`, `getattr` reports physical size
3. `reverse_main.rs` (new) — binary entry point; config validation; mount orchestration
4. `BlockCodec` / `SslCipher` / `EncfsConfig` (unchanged) — shared crypto layer consumed by both forward and reverse paths

### Critical Pitfalls

1. **stat() reports plaintext size instead of ciphertext size** — In `getattr()`, always call `FileEncoder::calculate_physical_size_with_mode(source_len, ...)` not `stat().st_size`; wrong size causes rsync to silently truncate or pad backups (PITFALL-01)

2. **Path direction error: encrypting incoming paths instead of decrypting them** — Incoming FUSE paths are encrypted names; use `decrypt_path()` to resolve to source; use `encrypt_filename()` only in `readdir()` output; getting this backwards causes universal ENOENT (PITFALL-02)

3. **Block boundary misalignment: treating ciphertext offset as plaintext offset** — Each encrypted block contains `block_size - overhead` bytes of plaintext; passing virtual ciphertext offset directly to source `read_at()` shifts every block after the first; use `BlockCodec` layout arithmetic to convert (PITFALL-09)

4. **Incomplete config validation: checking `unique_iv` but not `external_iv_chaining`** — `external_iv_chaining = true` makes file IV path-dependent; output changes on file rename; validate both flags at startup and bail with a clear error (PITFALL-11)

5. **File handle concurrency: reopening source on every read, or holding mutex during I/O** — Follow existing `EncFs` pattern exactly: store `Arc<FileHandle>` in `Mutex<HashMap>`, clone Arc before dropping lock, then perform I/O with no lock held (PITFALL-05)

## Implications for Roadmap

Based on combined research, the implementation has a clear dependency chain. Config validation must precede any crypto work; `FileReverseReader` must exist before `ReverseFilesystemMT` can be written; the FUSE handler must exist before the binary entry point is meaningful. Performance optimizations are correctness-independent and belong after integration testing.

### Phase 0: Config Validation and Constraints

**Rationale:** Config validation is a prerequisite for everything else. Getting it wrong produces silently incorrect output with no obvious failure signal. This work is also trivially small and de-risks the rest.
**Delivers:** Startup rejection of incompatible configs (`unique_iv = true`, `external_iv_chaining = true`) with actionable error messages; documentation of the AES-GCM-SIV nonce reuse trade-off.
**Addresses:** Table-stakes feature "Config validation at mount time"; anti-feature "unique_iv=true support must not exist"
**Avoids:** PITFALL-04 (wrong header), PITFALL-11 (incomplete validation), PITFALL-13 (nonce collision — document the trade-off)

### Phase 1: FUSE Skeleton (Read-Only Shell)

**Rationale:** Before implementing encryption, establish the correct FUSE skeleton with right-direction path translation and correct size reporting. A skeleton that returns dummy (zero) ciphertext but gets path resolution, size math, and EROFS enforcement right is a safe base for crypto work in Phase 2.
**Delivers:** `reverse_fs.rs` with `ReverseFilesystemMT` stub: correct `getattr` (ciphertext sizes), correct `readdir` (encrypted names), `read` returning zeros, all mutating ops returning EROFS, `statfs` with correct block counts, `reverse_main.rs` binary entry wired into `Cargo.toml`.
**Addresses:** Table-stakes features "Read-only FUSE mount", "Encrypted filenames", "Correct ciphertext size", "Recursive directory traversal"
**Avoids:** PITFALL-01 (size), PITFALL-02 (path direction), PITFALL-03 (plaintext names in readdir), PITFALL-07 (missing EROFS), PITFALL-10 (filename encoding mismatch), PITFALL-18 (statfs wrong blocks)

### Phase 2: Encryption On Read (Core Crypto Path)

**Rationale:** With the FUSE skeleton correct, replace the zero-returning `read` stub with real encryption. This is the highest-risk phase: block boundary arithmetic, IV derivation, MAC computation, and partial-block handling must all be correct simultaneously for byte-for-byte compatibility.
**Delivers:** `FileReverseReader` in `crypto/file.rs` with block-aligned encrypt-on-read; correct block IV derivation (`file_iv = 0`, `iv = block_num XOR 0`); correct MAC framing for both Legacy and AES-GCM-SIV modes; symlink target encryption in `readlink`; virtual `.encfs6.xml` file injection at root; file handle management following existing `Arc<FileHandle>` pattern.
**Addresses:** Table-stakes features "Byte-for-byte compatibility", "Virtual .encfs6.xml", "Symlink handling", "Streaming read without full-file buffering" (block-on-demand design from the start)
**Avoids:** PITFALL-05 (concurrency), PITFALL-06 (EOF/offset), PITFALL-08 (random file_iv), PITFALL-09 (block alignment), PITFALL-12 (MAC errors), PITFALL-14 (symlink IV), PITFALL-17 (mutex during I/O)
**Validation gate:** Round-trip integration test: encrypt a directory with encfsr, decrypt with reference encfs, verify byte identity for multi-block files, files with partial last block, and symlinks.

### Phase 3: Quality and Differentiators

**Rationale:** With correctness established, add the features that make encfsr production-ready for backup pipelines: stable inodes, user-friendly errors, verbose mode, and a `--check` dry-run flag. These are independent of each other and can be done in any order within this phase.
**Delivers:** Stable inode derivation (keyed hash of plaintext inode); actionable error messages for all common misconfigurations; verbose/statistics mode; `--check` flag for config and compatibility verification without mounting.
**Addresses:** Should-have features "Stable inode numbers", "User-friendly error messages", "Progress/statistics output", "Null/dry-run verify mode"

### Phase 4 (Optional): Performance Optimization

**Rationale:** The correctness-first implementation will have known performance limitations that only matter at scale. Address only after profiling real backup workloads.
**Delivers:** Path translation LRU cache (bounded `HashMap<EncryptedPath, (PlaintextPath, PathIV)>` behind `RwLock`); current-block cache in `FileReverseReader` (mirrors `FileDecoder.last_block` pattern); `BlockMapper` extraction to share block arithmetic between `FileDecoder`, `FileEncoder`, and `FileReverseReader`.
**Addresses:** Should-have "Sparse file support" can be explored here; differentiator "Hard link deduplication" if demand exists.
**Avoids:** PITFALL-15 (path re-encryption), PITFALL-16 (block re-encryption)

### Phase Ordering Rationale

- Config validation first because a wrong config produces silently broken output with no detectable error signal until an actual restore attempt fails.
- FUSE skeleton before crypto because path direction and size reporting errors are independent of encryption logic; validating the skeleton with zero-content reads isolates the two risk areas.
- All encryption work in one phase because the moving parts (IV, MAC, block math, offset mapping) are tightly coupled; partial implementation cannot be meaningfully tested in isolation.
- Quality and performance last because they are independent of correctness and add no new risk to the core path.

### Research Flags

Phases with standard patterns (research-phase not needed):
- **Phase 0 (Config Validation):** Straightforward field checks; patterns are well-established in existing codebase.
- **Phase 1 (FUSE Skeleton):** Existing `fs.rs` is the reference; mirror it with inverted direction. No novel patterns.
- **Phase 3 (Quality):** All standard patterns (LRU cache, error messages, verbose flag).

Phases likely benefiting from deeper research during planning:
- **Phase 2 (Encryption On Read):** The `FileReverseReader` block arithmetic is the novel piece. Before implementation, read `FileDecoder::read_at` carefully to understand the exact block-boundary seek pattern to mirror. Verify `header_size()` behavior for both config versions (V6 and V7/binary). Confirm that `SslCipher::encrypt_block` is callable with `file_iv = 0` without additional setup.
- **Phase 4 (Performance):** Sparse file support via `SEEK_HOLE`/`SEEK_DATA` has OS-specific behavior worth researching if pursued.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All technology choices directly verified against live `Cargo.toml`; no new dependencies identified; rationale based on existing codebase structure |
| Features | HIGH | Feature set directly modeled on reference C++ encfs --reverse behavior; table stakes are unambiguous; differentiators are clearly secondary |
| Architecture | HIGH | Architecture is additive to existing well-understood code; component boundaries follow existing patterns exactly; build order has clear dependency chain |
| Pitfalls | HIGH | 18 specific pitfalls identified with precise code references (file:line) in the existing codebase; prevention strategies reference existing patterns |

**Overall confidence:** HIGH

### Gaps to Address

- **Config serialization for virtual `.encfs6.xml`:** Research confirmed that config serialization likely exists in `encfsctl.rs`, but did not verify the exact API. During Phase 2 planning, confirm `EncfsConfig` can be serialized back to XML format using the existing `config_proto.rs` or `config_binary.rs` path.
- **`FileEncoder` statefulness:** STACK.md identifies two options for using `FileEncoder` in reverse (in-memory buffer vs. direct `BlockCodec` calls). During Phase 2, read `FileEncoder`'s write implementation to confirm whether Option A (in-memory backing store) is straightforward or whether Option B (direct `BlockCodec::encrypt_block` calls) is cleaner. Either is correct; this is an implementation choice, not a risk.
- **`chained_name_iv` policy:** STACK.md notes that `chained_name_iv` does not break determinism but adds path IV propagation complexity. During Phase 0, decide whether to warn, reject, or silently support configs with `chained_name_iv = true`. Rejecting it is safe and simplifies Phase 1; supporting it matches the reference C++ behavior more closely.
- **Dependency version currency:** Versions were taken from the live `Cargo.toml` but not verified against crates.io (network unavailable during research). No blocking concern for implementation, but worth checking during setup.

## Sources

### Primary (HIGH confidence)
- Live codebase (`src/fs.rs`, `src/crypto/file.rs`, `src/crypto/block.rs`, `src/crypto/ssl.rs`, `src/config.rs`) — direct code inspection; all findings tied to specific files and line numbers
- `Cargo.toml` — dependency versions and existing binary targets confirmed directly
- C++ encfs `--reverse` mode behavior — documented in encfs project README and observed behavioral specification used to derive feature requirements

### Secondary (MEDIUM confidence)
- `fuse_mt` crate documentation — FUSE operation semantics and `FilesystemMT` trait requirements
- EncFS protocol documentation — IV derivation, block layout, header format for `unique_iv = false` configs

### Tertiary (LOW confidence)
- Dependency version currency against crates.io — network unavailable during research; versions taken from live `Cargo.toml` only

---
*Research completed: 2026-02-24*
*Ready for roadmap: yes*
