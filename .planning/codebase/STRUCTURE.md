# Codebase Structure

**Analysis Date:** 2026-02-24

## Directory Layout

```
encfs/
├── src/                           # All source code
│   ├── main.rs                    # encfs binary entry point (FUSE mount)
│   ├── encfsctl.rs                # encfsctl binary entry point (admin tools)
│   ├── lib.rs                     # Library root, exports public modules
│   ├── fs.rs                      # FUSE filesystem impl (~1000 lines)
│   ├── config.rs                  # Config structures and XML/V6 parsing
│   ├── config_binary.rs           # V4/V5 binary format parsing
│   ├── config_proto.rs            # V7 protobuf format parsing
│   ├── constants.rs               # Global constants (KDF params, buffer sizes)
│   └── crypto/                    # Cryptographic operations
│       ├── mod.rs                 # Crypto module exports
│       ├── ssl.rs                 # SslCipher: key derivation and core encryption
│       ├── file.rs                # FileDecoder/FileEncoder: block-level I/O
│       ├── block.rs               # BlockCodec: per-block encryption modes
│       └── aead.rs                # AEAD tag handling (V7 format)
├── tests/                         # Integration and unit tests
│   ├── fixtures/                  # Test data (encrypted volumes, configs)
│   ├── live/                      # FUSE mount helper utilities
│   ├── mod.rs in live/            # LiveConfig and utilities
│   ├── *.rs                       # Individual test files (30+ tests)
│   └── live_mount.rs              # FUSE live mount test infrastructure
├── proto/                         # Protocol buffer definitions
│   └── encfs_config.proto         # V7 config protobuf schema
├── locales/                       # i18n translation files (YAML)
│   ├── en/                        # English strings
│   ├── fr/                        # French strings
│   ├── de/                        # German strings
│   ├── help.yml                   # Help text translations
│   ├── lib.yml                    # Library error messages
│   ├── main.yml                   # Main binary messages
│   └── ctl.yml                    # encfsctl messages
├── docs/                          # Documentation
│   ├── DESIGN.md                  # Technical design overview
│   └── PJDFSTEST_FAILURES_SUMMARY.md  # Test compatibility notes
├── Cargo.toml                     # Rust manifest with dependencies
├── Cargo.lock                     # Locked dependency versions
├── build.rs                       # Build script for proto compilation
├── Taskfile.yml                   # Task automation (test runners, etc)
├── README.md                      # User-facing documentation
├── INSTALL.md                     # Installation instructions
├── AGENTS.md                      # Agent/automation documentation
├── ChangeLog                      # Historical changes
├── AUTHORS                        # Contributors
└── COPYING.LGPL                   # License (LGPL)
```

## Directory Purposes

**src/:**
- Purpose: All Rust source code, split into core functionality and crypto
- Contains: Two binaries (encfs, encfsctl) and one library (encfs)
- Key files: `lib.rs` (public API), `fs.rs` (FUSE implementation), `config.rs` (configuration)

**src/crypto/:**
- Purpose: Cryptographic primitives and high-level encryption operations
- Contains: Key derivation, stream/block ciphers, file encryption, AEAD modes
- Key files: `ssl.rs` (main cipher), `file.rs` (file I/O), `block.rs` (block codecs)

**tests/:**
- Purpose: Integration tests, compatibility tests, and FUSE live mount tests
- Contains: Test fixtures, FUSE mount helpers, individual test scenarios
- Key files: `live/mod.rs` (mount infrastructure), individual test files for each feature

**tests/fixtures/:**
- Purpose: Pre-encrypted test volumes and configuration files
- Contains: EncFS v6 XML and v7 protobuf configs with known passwords/data
- Key files: `encfs6-std.xml`, `encfs6-paranoia.xml`, encrypted directory structures

**proto/:**
- Purpose: Protocol buffer schema definitions
- Contains: V7 configuration format schema (auto-compiled to Rust during build)
- Key files: `encfs_config.proto` (compiled by `build.rs` → `src/config_proto.rs`)

**locales/:**
- Purpose: Internationalization for user-facing messages
- Contains: YAML files mapping message keys to translated strings
- Key files: `help.yml` (CLI help), `lib.yml` (errors), `main.yml` (mount messages), `ctl.yml` (admin tool)

**docs/:**
- Purpose: Detailed technical documentation
- Contains: Architecture and design, test compatibility notes
- Key files: `DESIGN.md` (primary technical reference)

## Key File Locations

**Entry Points:**
- `src/main.rs`: encfs binary - mounts encrypted filesystem via FUSE
- `src/encfsctl.rs`: encfsctl binary - password management and admin utilities
- `src/lib.rs`: Library exports (config, crypto, fs, constants modules)

**Configuration:**
- `src/config.rs`: Main config struct, V6 XML loading, common logic
- `src/config_binary.rs`: V4/V5 legacy binary format parsing
- `src/config_proto.rs`: V7 protobuf format with AEAD key wrap

**Core Logic:**
- `src/fs.rs`: FUSE filesystem implementation - all 30+ operations
- `src/crypto/ssl.rs`: Cipher wrapper, key derivation, encryption operations
- `src/crypto/file.rs`: FileDecoder/FileEncoder for block-level I/O
- `src/crypto/block.rs`: BlockCodec, block layout calculations, MAC/AEAD handling

**Crypto Internals:**
- `src/crypto/aead.rs`: AES-GCM-SIV tag verification and encryption
- `src/constants.rs`: Global parameters (KDF iterations, buffer sizes)

**Testing:**
- `tests/live/mod.rs`: FUSE mount infrastructure and test utilities
- `tests/live_mount.rs`: Test setup for live mounting
- `tests/fixtures/`: Pre-configured test volumes and configs

## Naming Conventions

**Files:**
- Single concept per file: `config.rs`, `fs.rs`, `main.rs`
- Module files: `mod.rs` in subdirectories (e.g., `src/crypto/mod.rs`)
- Underscore for multi-word: `config_binary.rs`, `config_proto.rs`
- Test files: test name + `_test.rs` (e.g., `write_test.rs`, `permissions_test.rs`)

**Directories:**
- Lowercase, plural for collections: `src/`, `tests/`, `locales/`
- Feature modules: `crypto/`, `fixtures/` (descriptive names)

**Functions:**
- Snake_case throughout
- Private helpers prefixed when logical (no naming prefix convention)
- FUSE operation names match trait methods: `read()`, `write()`, `mkdir()`

**Types/Structs:**
- PascalCase: `EncFs`, `SslCipher`, `FileDecoder`, `BlockCodec`
- Enum variants: PascalCase: `BlockMode::AesGcmSiv`, `ConfigType::V7`

**Modules:**
- Lowercase snake_case: `config`, `crypto`, `fs`
- Re-exported in `lib.rs` as `pub mod`

## Where to Add New Code

**New Feature (e.g., new cipher algorithm):**
- Primary code: `src/crypto/ssl.rs` - add cipher variant to `SslCipher::new()`
- Tests: `tests/` - create `cipher_compat_test.rs` with test fixtures
- Config support: `src/config.rs` - update cipher interface detection if needed

**New FUSE Operation:**
- Implementation: `src/fs.rs` - add method to `impl FilesystemMT` (line 701+)
- Path handling: Use existing `encrypt_path()` helper, check permissions via `access()`
- Handle management: File handles via `self.handles` map; directory entries are stateless
- Tests: `tests/` - add operation-specific test file (e.g., `new_op_test.rs`)

**New Configuration Format:**
- Schema: `proto/encfs_config.proto` or new XML elements
- Parsing: Add to `src/config.rs` (XML) or new module (protobuf)
- Version enum: Add variant to `ConfigType` enum in `src/config.rs`
- Compatibility: Load in `EncfsConfig::load()` (line 180+)

**Utilities/Helpers:**
- Shared helpers: `src/constants.rs` for constants, new modules as needed
- Crypto helpers: `src/crypto/` subdirectory structure
- Test helpers: `tests/live/mod.rs` for common FUSE test infrastructure

**New Admin Command (encfsctl):**
- Subcommand: Add to `Commands` enum in `src/encfsctl.rs` (~line 100)
- Implementation: Implement handler function in same file
- Messages: Add help strings and error messages to `locales/ctl.yml`

## Special Directories

**target/:**
- Purpose: Build artifacts (debug, release, incremental)
- Generated: Yes (created by `cargo build`)
- Committed: No (.gitignored)

**fuzz/:**
- Purpose: Fuzzing infrastructure and corpus (for property-based testing)
- Generated: Partially (artifacts and corpus generated, targets are source)
- Committed: Targets only (src), not artifacts

**coverage/:**
- Purpose: Code coverage reports
- Generated: Yes (created by coverage tools)
- Committed: No

**build output (proto generated):**
- Purpose: Runtime generation during build
- Generated: Yes (build.rs compiles proto → .rs)
- Committed: No (generated in target/)

## Build Configuration

**Cargo.toml Structure:**
- `[workspace]`: Single-package workspace (allows `fuzz/` as separate member)
- `[dependencies]`: Runtime deps (fuse_mt, openssl, serde, etc.)
- `[dev-dependencies]`: Test-only (tar for fixture manipulation)
- `[build-dependencies]`: Build-time (prost-build, protoc-bin-vendored)
- `[[bin]]`: Two binaries defined (encfs, encfsctl)

**Build Script:**
- `build.rs`: Compiles `proto/encfs_config.proto` using vendored protoc

## Test Organization

**Unit Tests:**
- Location: Inline `#[test]` modules in `src/lib.rs` (crypto verification tests)
- Pattern: Test decrypt operations on known plaintext using fixtures

**Integration Tests:**
- Location: `tests/` directory, each file is separate test crate
- Infrastructure: `tests/live/mod.rs` provides `LiveConfig`, mount helpers
- Pattern: Mount real filesystem, perform operations, verify encrypted results
- Gating: Tests skip if `ENCFS_LIVE_TESTS` env var not set (requires FUSE kernel)

**Fixture Management:**
- Location: `tests/fixtures/` with pre-encrypted volumes
- Creation: One-time setup with known passwords for reproducible testing
- Usage: Loaded by `live::load_live_config()` (tests/live/mod.rs:69)

## Code Dependencies and Layers

**High-level dependencies:**
```
encfs (binary) → lib.rs public API
  ├→ config (load & parse)
  ├→ crypto::ssl (derive key, initialize cipher)
  ├→ fs::EncFs (mount FUSE)
  └→ std, fuse_mt

encfsctl (binary) → lib.rs public API
  ├→ config (load/save, inspect)
  ├→ crypto::ssl (key derivation for passwd change)
  └→ std
```

**Internal layer dependencies:**
```
fs.rs (FUSE ops) → crypto/ssl.rs (encrypt/decrypt paths, files)
                → crypto/file.rs (block-level I/O)
                → crypto/block.rs (per-block encryption)

crypto/file.rs → crypto/block.rs → crypto/ssl.rs
              → config.rs (params)

config.rs → config_binary.rs (V4/V5 parsing)
         → config_proto.rs (V7 parsing)
         → crypto/ssl.rs (key unwrapping)
```

---

*Structure analysis: 2026-02-24*
