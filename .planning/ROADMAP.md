# Roadmap: encfsr

## Overview

encfsr is a new binary added to the existing Rust EncFS codebase. It mounts a plaintext directory and presents a read-only encrypted virtual filesystem byte-for-byte compatible with forward encfs output. The build has three natural delivery boundaries: (1) get the binary wired up with correct config validation and error handling so misconfigured invocations fail loudly; (2) build the FUSE skeleton with correct path direction, size reporting, and read-only enforcement so the mount structure is verified before any encryption logic exists; (3) implement the encryption core so reads return real ciphertext that round-trips through standard encfs. Each phase is independently verifiable; correctness gates before complexity.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation** - Binary wired up with config validation and actionable error messages
- [x] **Phase 2: FUSE Skeleton** - Read-only mount with correct path translation, encrypted filenames, and ciphertext sizes (stub crypto) (completed 2026-02-26)
- [ ] **Phase 3: Encryption Core** - Real on-the-fly block encryption producing byte-for-byte encfs-compatible output

## Phase Details

### Phase 1: Foundation
**Goal**: The `encfsr` binary exists, mounts can be attempted, and any misconfiguration is caught at startup with a clear message before any filesystem work begins
**Depends on**: Nothing (first phase)
**Requirements**: BIN-01, CONF-01, CONF-02, QUAL-01
**Success Criteria** (what must be TRUE):
  1. `cargo build` produces an `encfsr` binary alongside the existing `encfs` binary with no new dependencies required
  2. Running `encfsr` with a config that has `unique_iv = true` exits immediately with an error message that names the offending flag and tells the user what to set instead
  3. Running `encfsr` with a config that has `chained_name_iv = true` proceeds to mount without warning or rejection
  4. Running `encfsr` with a missing config file, inaccessible source directory, or other common misconfiguration exits with a message that says what to do, not just what failed
**Plans**: 1 plan

Plans:
- [x] 01-01-PLAN.md — Wire up encfsr binary (Cargo [[bin]], CLI, config validation, locale strings, integration tests)

### Phase 2: FUSE Skeleton
**Goal**: The virtual encrypted filesystem is mountable, presents encrypted filenames and correct ciphertext file sizes, rejects all writes, and resolves paths in the correct direction — with zero-content stubs for actual file data
**Depends on**: Phase 1
**Requirements**: FUSE-01, FUSE-02, FUSE-03, COMPAT-01
**Success Criteria** (what must be TRUE):
  1. Mounting encfsr on a plaintext directory produces a FUSE mount that `ls` can traverse, showing encrypted filenames matching the algorithm forward encfs would use
  2. `stat` on any file in the mounted virtual FS reports the ciphertext size (larger than the plaintext source), not the plaintext file size
  3. Any write operation (write, create, mkdir, rename, unlink, rmdir, truncate, setattr, symlink, link, mknod) returns `EROFS`; the mount is verifiably read-only
  4. Path resolution works in the correct direction: incoming FUSE requests (encrypted paths) are decrypted to locate source files; `readdir` output (plaintext source names) is encrypted before returning to callers
**Plans**: 2 plans

Plans:
- [x] 02-01-PLAN.md — Create ReverseFs FilesystemMT, wire fuse_mt::mount, implement readdir/getattr/read stubs
- [x] 02-02-PLAN.md — Integration tests for ReverseFs (EROFS subprocess tests, live FUSE mount tests for FUSE-01/02/03/COMPAT-01)

### Phase 3: Encryption Core
**Goal**: File reads return real ciphertext that is byte-for-byte identical to what forward encfs would have produced, verified by round-trip decryption; the virtual FS is self-describing via an injected config file
**Depends on**: Phase 2
**Requirements**: CRPT-01, CRPT-02, CRPT-03, CRPT-04, CRPT-05, COMPAT-02
**Success Criteria** (what must be TRUE):
  1. Mounting encfsr on a plaintext directory and then decrypting the virtual FS with standard encfs using the same config reproduces the original plaintext byte-for-byte, for files of all sizes including multi-block files and files with partial last blocks
  2. Reading any file from the mounted virtual FS does not buffer the entire file in memory; a multi-GB file can be read incrementally without exhausting RAM
  3. Symlink targets in the virtual FS are encrypted correctly such that standard encfs can resolve them after decryption
  4. A virtual `.encfs7` config file appears at the encrypted root of the mount, allowing the virtual FS to be decrypted autonomously without out-of-band config distribution
  5. AES-GCM-SIV (V7) block mode produces correct ciphertext; the mount works correctly with both V6 and V7 config formats
**Plans**: 2 plans

Plans:
- [ ] 03-01-PLAN.md — Implement FileReverseReader block encryption, virtual .encfs7 injection, readlink symlink encryption in reverse_fs.rs; wire config_bytes in encfsr.rs
- [ ] 03-02-PLAN.md — Round-trip integration tests: block boundaries, external IV chaining, V7 AES-GCM-SIV, symlinks, virtual config file, multi-GB streaming

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation | 1/1 | Complete | 2026-02-25 |
| 2. FUSE Skeleton | 2/2 | Complete   | 2026-02-26 |
| 3. Encryption Core | 0/2 | Not started | - |
