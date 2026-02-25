# Coding Conventions

**Analysis Date:** 2026-02-24

## Naming Patterns

**Files:**
- Snake case for all Rust source files: `config.rs`, `ssl.rs`, `file.rs`, `aead.rs`
- Test files appended with `_test.rs`: `write_test.rs`, `config_check.rs`, `argon2_integration_test.rs`
- Live/integration test helpers in `live/mod.rs` with no suffix
- Generated files from protobuf: `config_proto.rs` (included from build output)

**Functions:**
- Snake case: `encrypt_filename()`, `derive_key()`, `decrypt_header()`, `file_codec_params()`, `expected_physical_size()`
- Helper functions for i18n prefixed with `help_` then the main function name: `help_main_about()`, `help_main_foreground()`, `help_main_verbose()`
- Test functions prefixed with `test_` for integration tests: `test_virtual_driver_write()`, `test_argon2id_config_creation_and_loading()`
- Live mount test functions prefixed with `live_`: `live_smoke_mount_unmount_standard()`, `live_basic_io_standard()`, `run_basic_io()` (helper)
- Private helper functions typically have leading `_` for parsed arguments: `_req: RequestInfo`

**Variables:**
- Snake case throughout: `cipher`, `config_path`, `mount_point`, `file_handle`, `encrypted_name`, `decrypted_content`
- Single letter or short abbreviations where context is clear: `e` for errors, `p` for paths, `f` for files, `n` for count
- Descriptive names for loop variables: `entries`, `component` (not `i`, `j`)
- Constants use uppercase: `V7_MAGIC`, `DEFAULT_SALT_SIZE`, `FILE_BUFFER_SIZE`

**Types:**
- Pascal case for structs: `EncfsConfig`, `FileHandle`, `PathInfo`, `SslCipher`, `BoostSerialization`
- Pascal case for enums: `ConfigType`, `KdfAlgorithm`, `NameEncoding`, `LiveConfigKind`
- Pascal case for enum variants: `Prehistoric`, `V6`, `Pbkdf2`, `Argon2id`, `Standard`, `Paranoia`

## Code Style

**Formatting:**
- Rust `cargo fmt` (standard rustfmt)
- Line length appears to be around 100-120 characters based on existing code
- Indentation: 4 spaces

**Linting:**
- `cargo clippy --all-targets --all-features -- -D warnings`
- Clippy is enforced with `-D warnings` flag to deny all warnings
- All warnings must be resolved before code can be committed

## Import Organization

**Order:**
1. Standard library imports: `use std::fs;`, `use std::path::{Path, PathBuf};`
2. External crate imports: `use anyhow::{Context, Result};`, `use log::{debug, error, info, warn};`
3. Internal crate imports: `use crate::config;`, `use crate::crypto::ssl::SslCipher;`
4. Module-level declarations: `mod live;`, `pub mod config;`

**Path Aliases:**
- No path aliases or shortened imports observed
- Full paths used consistently: `encfs::config`, `encfs::crypto::file::FileDecoder`
- Imports within same crate use `crate::` prefix: `crate::config::EncfsConfig`, `crate::fs::EncFs`

## Error Handling

**Patterns:**
- Primary error handling via `anyhow` crate: `use anyhow::{Context, Result};`
- All fallible functions return `Result<T>` or `Result<T, libc::c_int>` (for FUSE operations)
- `.context()` used to add context strings to errors: `.context("Failed to open config file")?`
- `.with_context()` with closure for lazy evaluation: `.with_context(|| format!("open {:?}", path))?`
- `anyhow::anyhow!()` for creating errors with formatted messages: `Err(anyhow::anyhow!("Missing keySize"))?`
- `libc::EIO` and similar error codes returned for FUSE operations that need specific OS error codes
- Panics acceptable for test setup failures: `panic!("Test fixtures not found at {:?}", config_path);`
- `unwrap_or_else()` with fallback for lock guards: `self.handles.lock().unwrap_or_else(|e| e.into_inner())`
- Graceful handling of poisoned mutexes via fallback instead of panicking

## Logging

**Framework:** `log` crate with `env_logger` initialization

**Patterns:**
- Use `log::` macros directly: `info!()`, `debug!()`, `warn!()`, `error!()`
- Logging set up once at startup with conditional verbosity:
  ```rust
  let mut builder = env_logger::Builder::from_default_env();
  if verbose {
      builder.filter_level(log::LevelFilter::Debug);
  } else if std::env::var("RUST_LOG").is_err() {
      builder.filter_level(log::LevelFilter::Info);
  }
  builder.init();
  ```
- Internationalization for log messages via `rust_i18n::t!()` macro: `info!("{}", t!("main.mounting", root = ..., mount_point = ...))`
- Debug messages use `debug!()` for detailed encryption/decryption operations
- Error messages use `error!()` with full context and enum codes for FUSE errors
- Test logging initialized with `env_logger::builder().is_test(true).try_init();`

## Comments

**When to Comment:**
- Top-level module documentation via doc comments: `/// The main FUSE filesystem implementation.`
- Public API documentation: `/// Encrypts a plaintext path (from FUSE request) to an encrypted path (on disk).`
- Complex algorithms documented: `/// Legacy key derivation for EncFS cipher interface version 2. Uses BytesToKey algorithm with SHA1 and 16 rounds.`
- Implementation details for non-obvious logic: comments explaining IV chaining behavior, file format handling
- Business logic explained at function level rather than line-by-line comments

**JSDoc/TSDoc:**
- Not applicable (Rust project uses doc comments instead)
- Rust uses `///` for documentation comments above functions and types
- `//!` at module level for module-level documentation

## Function Design

**Size:**
- Functions are generally 20-100 lines for complex operations
- Larger functions like `load()` (100+ lines) handle multiple format versions but maintain clarity through clear section comments
- Helper functions extracted for repeated patterns: `pattern_bytes()`, `read_all()`, `expected_physical_size()`

**Parameters:**
- Functions pass owned values or references appropriately: `path: &Path`, `iface: &Interface`, `password: &str`
- Generic over types when appropriate: `FileDecoder<R: Read + Seek + FileExt>`
- RequestInfo and path types passed for FUSE operations: `fn create(&self, req: RequestInfo, parent: &Path, name: &OsStr, ...)`

**Return Values:**
- Functions return `Result<T>` for all fallible operations
- FUSE operations return `ResultEmpty`, `ResultEntry`, `ResultCreate`, etc. from `fuse_mt` crate
- Specific error codes returned when needed: `Err(libc::EINVAL)`, `Err(libc::EIO)`
- Tests return `Result<()>` for easy error propagation

## Module Design

**Exports:**
- Public types and functions declared with `pub`
- Implementation details kept private (default privacy)
- Modules export clean public APIs: `pub mod config;`, `pub mod fs;`, `pub mod crypto;`
- Internal-only modules like `crypto::block` provide detailed implementation without exposing intermediate types

**Barrel Files:**
- `src/crypto/mod.rs` acts as barrel file: declares `pub mod aead; pub mod block; pub mod file; pub mod ssl;`
- Top-level `src/lib.rs` exports main public modules and provides `init_locale()` function
- `tests/live/mod.rs` provides test utilities exported to test modules via `mod live;`

## Struct/Type Conventions

**Struct Fields:**
- Private fields by default: `struct FileHandle { file: File, file_iv: u64 }`
- Public fields used sparingly: `pub struct EncFs { pub root: PathBuf, pub cipher: SslCipher, ... }`
- Serde derive for serialization: `#[derive(Serialize, Deserialize)]` for config types
- Custom serde attributes for XML/protobuf: `#[serde(rename_all = "camelCase")]`, `#[serde(rename = "cipherAlg")]`

**Derive Macros:**
- Standard derives: `#[derive(Debug, Clone)]` for most types
- `#[derive(Default)]` for types with sensible defaults
- `#[derive(PartialEq, Eq)]` for comparison types
- Serde derives: `#[derive(Serialize, Deserialize)]` for config serialization

---

*Convention analysis: 2026-02-24*
