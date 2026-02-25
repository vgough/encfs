# Architecture Research: encfsr Reverse Mode Integration

## Research Scope

This document analyzes how `encfsr` (reverse encrypted filesystem) should integrate with the existing Rust EncFS architecture. The core inversion: normal encfs reads ciphertext and returns plaintext; encfsr reads plaintext and returns ciphertext.

**Question**: How should encfsr integrate with the existing architecture? What is the cleanest way to implement the "encrypt-on-read" inversion using the existing FileDecoder/FileEncoder abstractions? How should the shared library be structured to minimize code duplication?

---

## Component Map

### Existing Components

```
src/
├── main.rs              # encfs binary entry point (CLI parsing, mount setup)
├── lib.rs               # shared library exports
├── fs.rs                # FilesystemMT FUSE trait (~1000 lines) — the "brain"
├── config.rs            # EncfsConfig unified config (read from .encfs6.xml)
├── constants.rs         # Shared constants
├── config_binary.rs     # Binary config format reader
├── config_proto.rs      # Protobuf config format reader
└── crypto/
    ├── mod.rs           # Crypto module exports
    ├── file.rs          # FileDecoder + FileEncoder abstractions
    ├── ssl.rs           # SslCipher — all low-level crypto ops
    ├── block.rs         # BlockCodec — per-block MAC/AEAD framing
    └── aead.rs          # AEAD cipher support
```

### Proposed encfsr Components

```
src/
├── reverse_main.rs      # encfsr binary entry point (or: main.rs --reverse flag)
├── reverse_fs.rs        # ReverseFilesystemMT FUSE trait implementation
└── (reuse all crypto/* and config.rs unchanged)
```

---

## Component Boundaries

### What Each Component Owns

| Component | Responsibility | Does NOT own |
|-----------|---------------|--------------|
| `config.rs / EncfsConfig` | Filesystem configuration, key derivation, cipher selection | Mounting, path logic |
| `crypto/ssl.rs / SslCipher` | Raw cipher ops: encrypt_block, decrypt_block, encode_name, decode_name | File layout, offset math |
| `crypto/block.rs / BlockCodec` | Per-block framing: header/MAC prepend, block size arithmetic | File handles, buffering |
| `crypto/file.rs / FileDecoder` | Encrypted→plaintext reads: block boundary seeking, IV chaining | FUSE interface |
| `crypto/file.rs / FileEncoder` | Plaintext→encrypted writes: same block math, opposite direction | FUSE interface |
| `fs.rs / FilesystemMT` | FUSE ops: path translation (encrypted→plaintext), open FileDecoder, serve reads | Crypto internals |
| **`reverse_fs.rs / ReverseFilesystemMT`** | FUSE ops: path translation (encrypted→plaintext name), open source plaintext file, use FileEncoder logic to serve encrypted bytes | Crypto internals |

### Key Boundary: FileEncoder as a Read Source

The critical design insight is that `FileEncoder` currently writes. For encfsr, we need to *read* from it. The block math in `FileEncoder` (which maps plaintext offset → ciphertext offset and encrypts blocks) is exactly the logic needed when a FUSE read arrives for an encrypted virtual file.

This means encfsr does **not** need a new crypto layer. It needs a new FUSE handler that:
1. Translates the incoming encrypted virtual path → plaintext source path
2. Opens the plaintext source file for reading
3. Uses `FileEncoder`-style block math to encrypt the requested byte range on the fly
4. Returns the ciphertext bytes to the caller

---

## Data Flow

### Normal encfs Read Flow

```
FUSE read(encrypted_path, offset, size)
    │
    ▼
fs.rs: decrypt_path(encrypted_path) → plaintext_path
    │
    ▼
fs.rs: open(plaintext_path) in source dir → fd
    │
    ▼
fs.rs: FileDecoder::new(fd, config, iv_seed)
    │
    ▼
FileDecoder::read(offset, size)
    │   [maps plaintext offset → block boundaries]
    │   [reads encrypted blocks from fd]
    │   [decrypts each block via BlockCodec+SslCipher]
    │
    ▼
plaintext bytes → returned to FUSE caller
```

### encfsr Read Flow (Inverted)

```
FUSE read(encrypted_virtual_path, offset, size)
    │
    ▼
reverse_fs.rs: decrypt_name(encrypted_virtual_path) → plaintext_filename
    │
    ▼
reverse_fs.rs: open(plaintext_filename) in source dir → fd
    │
    ▼
reverse_fs.rs: FileReverseReader::new(fd, config, deterministic_iv_seed)
    │
    ▼
FileReverseReader::read(virtual_offset, size)
    │   [maps virtual ciphertext offset → block boundaries]
    │   [reads plaintext blocks from fd]
    │   [encrypts each block via BlockCodec+SslCipher]
    │   [returns ciphertext slice for requested range]
    │
    ▼
ciphertext bytes → returned to FUSE caller
```

### encfsr getattr / Size Flow

```
FUSE getattr(encrypted_virtual_path)
    │
    ▼
reverse_fs.rs: decrypt_name(encrypted_virtual_path) → plaintext_filename
    │
    ▼
stat(plaintext_filename) → plaintext_size
    │
    ▼
BlockCodec::encrypted_size(plaintext_size) → virtual_size
    │   [accounts for per-block headers/MACs and file header]
    │
    ▼
return stat with virtual_size → FUSE caller
```

### encfsr readdir Flow

```
FUSE readdir(encrypted_virtual_dir)
    │
    ▼
reverse_fs.rs: decrypt_name(encrypted_virtual_dir) → plaintext_dir
    │
    ▼
readdir(plaintext_dir) → [plaintext_entry_0, plaintext_entry_1, ...]
    │
    ▼
reverse_fs.rs: for each entry: encrypt_name(entry) → encrypted_virtual_name
    │
    ▼
return [encrypted_virtual_name_0, ...] → FUSE caller
```

---

## Design Decision: FileReverseReader vs. Repurposing FileEncoder

### Option A: FileReverseReader (New Struct, Shared Internals)

Create `FileReverseReader` in `crypto/file.rs` alongside `FileDecoder` and `FileEncoder`.

```rust
pub struct FileReverseReader {
    source_fd: File,          // plaintext source
    config: Arc<EncfsConfig>,
    block_codec: BlockCodec,
    iv_seed: u64,             // deterministic: derived from filename hash or inode
}

impl FileReverseReader {
    pub fn read(&self, virtual_offset: u64, size: u32) -> Result<Vec<u8>> {
        // 1. Map virtual_offset → block index + intra-block offset
        // 2. For each needed block:
        //    a. Read plaintext from source_fd at plaintext_block_offset
        //    b. Encrypt via block_codec.encode(plaintext_block, block_index, iv)
        //    c. Slice the ciphertext to the requested range
        // 3. Concatenate and return
    }

    pub fn virtual_size(&self, plaintext_size: u64) -> u64 {
        self.block_codec.encrypted_size(plaintext_size)
    }
}
```

**Pros**: Clean separation, explicit read-only interface, no mutation of FileEncoder state.
**Cons**: Some duplication of block-boundary math with FileEncoder.

### Option B: Extract BlockMapper Trait / Helper

Extract the block boundary arithmetic from `FileEncoder` and `FileDecoder` into a shared `BlockMapper` helper struct, then compose it in `FileReverseReader` and both existing types.

```rust
struct BlockMapper {
    block_size: u32,          // plaintext block size
    header_size: u32,         // per-block header (MAC etc.)
    file_header_size: u32,    // file-level header
}

impl BlockMapper {
    fn plaintext_to_encrypted_offset(&self, pt_offset: u64) -> u64 { ... }
    fn encrypted_to_plaintext_offset(&self, ct_offset: u64) -> u64 { ... }
    fn block_index_for_pt_offset(&self, pt_offset: u64) -> u64 { ... }
    fn encrypted_size(&self, plaintext_size: u64) -> u64 { ... }
    fn plaintext_size(&self, encrypted_size: u64) -> u64 { ... }
}
```

**Pros**: Eliminates duplication, makes size math testable in isolation, reduces risk of inconsistency.
**Cons**: More refactoring upfront; touches existing code.

### Recommendation: Option A first, Option B as follow-on

For minimal risk to the existing (working) encfs implementation:
1. Implement `FileReverseReader` in `crypto/file.rs` as a new struct with its own block math.
2. Add `ReverseFilesystemMT` in `reverse_fs.rs` using `FileReverseReader`.
3. Once both paths work correctly and are tested, extract `BlockMapper` to remove duplication.

---

## Design Decision: Deterministic IV

Normal encfs uses `uniqueIV` (random per-file IV stored in file header) and optionally `externalIVChaining`. Both make encryption non-deterministic or stateful — incompatible with a virtual read-only filesystem where the same bytes must be produced on every read.

For encfsr:
- **No uniqueIV**: IV must be derived deterministically from the filename or inode number.
- **No externalIVChaining**: Each block's IV depends only on block index + file-level IV seed.
- **IV seed derivation**: `iv_seed = SslCipher::encode_name_iv(plaintext_filename)` or a hash of the filename — must be stable across mounts.

The `EncfsConfig` struct and `SslCipher` already support operating without uniqueIV (this is the `--standard` config mode). `encfsr` should assert/enforce this constraint at mount time and refuse to mount if the config has uniqueIV enabled.

---

## Design Decision: Name Translation Direction

In normal encfs:
- Source dir has encrypted names
- FUSE reads decrypt them to produce plaintext names

In encfsr:
- Source dir has plaintext names
- FUSE reads encrypt them to produce encrypted virtual names
- Incoming FUSE requests come with encrypted virtual names that must be decrypted

This means `reverse_fs.rs` uses `SslCipher::decode_name` to interpret incoming FUSE paths (same direction as normal `fs.rs`), but uses `SslCipher::encode_name` when generating directory listings. The name-translation calls are the same underlying functions but called in opposite contexts.

---

## Design Decision: File Header in Virtual Files

Normal encfs encrypted files have a file header (containing the per-file IV seed when uniqueIV is enabled). In encfsr with deterministic IVs:
- The virtual file header should be **omitted** or **zero-length** (since there is no per-file IV to store).
- OR: The virtual file header can be a fixed deterministic sequence derived from the filename IV seed, to maintain wire-format compatibility with what a real encfs source dir would look like.

**Recommendation**: Produce a deterministic file header (even if just zeros or the IV seed bytes) so that the virtual encrypted files are byte-for-byte identical to what `encfs --standard` would produce when encrypting the same plaintext. This allows the encfsr virtual mount to be used as a valid encfs source directory.

---

## Shared Library Structure

### Current lib.rs exports

Based on the milestone context, `lib.rs` exports the types used by both `main.rs` and `encfsctl.rs`. For encfsr integration:

```
lib.rs (shared):
    pub mod config;          // EncfsConfig — unchanged
    pub mod crypto {
        pub mod ssl;         // SslCipher — unchanged
        pub mod block;       // BlockCodec — unchanged
        pub mod file;        // FileDecoder, FileEncoder, + new FileReverseReader
        pub mod aead;        // AEAD — unchanged
    }
    pub mod fs;              // FilesystemMT — unchanged
    pub mod reverse_fs;      // NEW: ReverseFilesystemMT
```

### Binary entry points

**Option 1: Separate binaries** (cleaner, easier to reason about)
```toml
# Cargo.toml
[[bin]]
name = "encfs"
path = "src/main.rs"

[[bin]]
name = "encfsr"
path = "src/reverse_main.rs"
```

**Option 2: Single binary with flag** (`encfs --reverse ...`)
```rust
// main.rs
if args.reverse {
    mount_reverse(args);
} else {
    mount_forward(args);
}
```

**Recommendation**: Separate binaries for separate concerns. `encfsr` can `use encfs_lib::reverse_fs::ReverseFilesystemMT` and share all crypto types.

---

## Build Order (Implementation Dependencies)

The components have a clear dependency chain. Build in this order to avoid blocking on unfinished dependencies:

### Phase 1: Foundation — FileReverseReader

**Files**: `src/crypto/file.rs` (add `FileReverseReader`)

Dependencies: `BlockCodec`, `SslCipher` — both already exist and unchanged.

Deliverables:
- `FileReverseReader::new(source_fd, config, iv_seed)`
- `FileReverseReader::read(virtual_offset, size) -> Vec<u8>` (encrypts plaintext blocks on demand)
- `FileReverseReader::virtual_size(plaintext_size) -> u64`
- Unit tests: encrypt then decrypt should round-trip, size math should match

### Phase 2: FUSE Handler — ReverseFilesystemMT

**Files**: `src/reverse_fs.rs` (new), `src/lib.rs` (add export)

Dependencies: `FileReverseReader` (Phase 1), `EncfsConfig`, `SslCipher::encode_name/decode_name`.

Deliverables:
- `ReverseFilesystemMT` implementing `FilesystemMT` trait
- `getattr`: decrypt virtual path → stat source → report virtual (inflated) size
- `readdir`: list source dir → encrypt each name → return encrypted names
- `read`: decrypt virtual path → open source → FileReverseReader → return ciphertext
- `open` / `release`: file handle management (can mirror `fs.rs` pattern)
- `readlink`: if source has symlinks, decide policy (skip or translate)

### Phase 3: Binary Entry Point — encfsr

**Files**: `src/reverse_main.rs` (new), `Cargo.toml` (new `[[bin]]`)

Dependencies: `ReverseFilesystemMT` (Phase 2), CLI arg parsing (can share with `main.rs`).

Deliverables:
- CLI parsing: source dir, mount point, config path
- Config validation: assert no uniqueIV, no externalIVChaining
- Mount via `fuse_mt::mount(ReverseFilesystemMT::new(config), mount_point, options)`

### Phase 4 (Optional): Refactoring — BlockMapper extraction

**Files**: `src/crypto/file.rs`, `src/crypto/block.rs`

Dependencies: Phases 1–3 complete and tested.

Deliverables:
- Extract `BlockMapper` helper with plaintext↔ciphertext offset arithmetic
- Refactor `FileDecoder`, `FileEncoder`, `FileReverseReader` to share `BlockMapper`
- No behavior change; validated by existing tests

---

## Component Interaction Diagram

```
                    ┌─────────────────────────────────────────┐
                    │           FUSE Kernel Interface          │
                    └────────────┬──────────────┬─────────────┘
                                 │              │
                    ┌────────────▼──┐    ┌──────▼──────────────┐
                    │ FilesystemMT  │    │ ReverseFilesystemMT  │
                    │  (fs.rs)      │    │  (reverse_fs.rs)     │
                    │               │    │                      │
                    │ encrypted src │    │ plaintext src        │
                    │ → plaintext   │    │ → encrypted virtual  │
                    └──────┬────────┘    └───────┬─────────────┘
                           │                     │
                    ┌──────▼────────┐    ┌───────▼─────────────┐
                    │  FileDecoder  │    │  FileReverseReader   │
                    │  (file.rs)    │    │  (file.rs)           │
                    │               │    │                      │
                    │ ciphertext →  │    │ plaintext →          │
                    │ plaintext     │    │ ciphertext           │
                    └──────┬────────┘    └───────┬─────────────┘
                           │                     │
                           └──────────┬──────────┘
                                      │
                             ┌────────▼─────────┐
                             │    BlockCodec     │
                             │    (block.rs)     │
                             │                  │
                             │ per-block framing │
                             │ MAC/AEAD, offsets │
                             └────────┬─────────┘
                                      │
                             ┌────────▼─────────┐
                             │    SslCipher      │
                             │    (ssl.rs)       │
                             │                  │
                             │ raw encrypt/      │
                             │ decrypt, name enc │
                             └────────┬─────────┘
                                      │
                             ┌────────▼─────────┐
                             │   EncfsConfig     │
                             │   (config.rs)     │
                             │                  │
                             │ key material,     │
                             │ cipher params     │
                             └──────────────────┘
```

---

## Key Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| New struct vs. repurpose FileEncoder | New `FileReverseReader` struct | FileEncoder is stateful for writes; reverse reads are stateless. Avoids risk to existing code. |
| uniqueIV | Disabled / asserted off | Required for determinism. Mount fails if config has uniqueIV. |
| IV seed source | Deterministic from filename | Stable across mounts, no state storage needed. |
| File header | Emit deterministic header | Wire-format compatibility with real encfs source dirs. |
| Name translation | `decode_name` on input, `encode_name` on readdir output | Same functions as forward encfs, just called in different contexts. |
| Binary structure | Separate `encfsr` binary | Clean separation; shared lib contains all reusable types. |
| Block math duplication | Accept in Phase 1, extract in Phase 4 | Minimize risk to working code; clean up after validation. |
| Size reporting | `BlockCodec::encrypted_size(plaintext_size)` in getattr | FUSE callers must see virtual (inflated) size to know how much to read. |

---

## Risks and Constraints

### Constraint: No externalIVChaining
externalIVChaining uses the encrypted filename bytes as part of the file-content IV, creating a dependency between name encoding and content encoding. encfsr must disable this or implement it carefully (the encrypted name is known at virtual-read time, so it is technically feasible but adds complexity).

### Risk: Block size mismatch in partial reads
FUSE may request arbitrary byte ranges. `FileReverseReader::read` must align reads to block boundaries, encrypt full blocks, then slice the result. This is the same challenge `FileDecoder` solves for decryption — the implementation pattern should mirror it exactly.

### Risk: Large file performance
Encrypting on-the-fly for every read means no caching of encrypted blocks. For large sequential reads this is fine; for random access to large files, callers may trigger repeated re-encryption of the same blocks. A block cache could be added later but is not needed for correctness.

### Risk: Config compatibility
The encfsr config is an ordinary encfs config file. Users may accidentally mount an encfsr source (plaintext) dir with regular encfs, producing garbled output. Mitigation: document clearly and potentially add a config flag `reverseEncryption = true`.

---

## Source Files to Create or Modify

| File | Action | Description |
|------|--------|-------------|
| `src/crypto/file.rs` | Modify | Add `FileReverseReader` struct and impl |
| `src/reverse_fs.rs` | Create | `ReverseFilesystemMT` implementing FUSE ops |
| `src/reverse_main.rs` | Create | `encfsr` binary entry point |
| `src/lib.rs` | Modify | Export `reverse_fs` module |
| `Cargo.toml` | Modify | Add `[[bin]]` for `encfsr` |
| `src/crypto/block.rs` | Maybe | Expose `encrypted_size` if not already public |
| `src/crypto/ssl.rs` | Maybe | Expose deterministic IV-from-name helper if not already public |
