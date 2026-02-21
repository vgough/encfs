# AGENTS.md - Guide for AI Agents Working in EncFS

This document provides comprehensive information for AI agents working in the EncFS codebase. It covers commands, patterns, conventions, gotchas, and project-specific context.

## Project Overview

**EncFS** is an encrypted virtual filesystem that runs in userspace using FUSE. This is a **Rust port** of the original C++ implementation, aiming for compatibility with existing EncFS filesystems while providing memory safety and modern code practices.

- **Language**: Rust (Edition 2024)
- **Primary Goal**: Read/write compatibility with legacy EncFS filesystems
- **Status**: Alpha (v2.0.0-alpha.3) - functional for read/write but still maturing

### Key Characteristics
- Encrypts individual files (not block devices)
- Uses FUSE for filesystem operations
- Supports multiple config formats (V4, V5, V6)
- OpenSSL for legacy cryptographic operations
- Modern cryptography (AES-GCM-SIV, Argon2) for new setups
- Internationalization support

## Essential Commands

### Build Commands
```bash
# Build debug binaries
cargo build
# or using task runner
task build

# Build release binaries
cargo build --release
# or
task build-release

# Clean build artifacts
cargo clean
# or
task clean
```

### Testing Commands
```bash
# Run all tests (unit + integration, excluding live mount tests)
cargo test
# or
task test

# Run live mount tests (requires FUSE, Linux, and ENCFS_LIVE_TESTS=1)
ENCFS_LIVE_TESTS=1 cargo test --test live_mount -- --ignored --test-threads=1
# or
task test-live

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture
```

**Important**: Live mount tests (`live_mount.rs`) are marked with `#[ignore]` and require:
- `ENCFS_LIVE_TESTS=1` environment variable
- FUSE kernel module loaded (`sudo modprobe fuse`)
- Single-threaded execution (`--test-threads=1`)
- Linux or FreeBSD (macOS support via fuse-t)

### Code Quality Commands
```bash
# Format code
cargo fmt
# or
task fmt

# Check formatting (CI-friendly, doesn't modify files)
cargo fmt -- --check
# or
task fmt-check

# Run clippy lints (fails on warnings in CI)
cargo clippy --all-targets --all-features -- -D warnings
# or
task clippy
```

### Running the Binaries
```bash
# Mount an encrypted filesystem
./target/debug/encfs /path/to/encrypted /path/to/mountpoint

# With options
./target/debug/encfs -f -v /path/to/encrypted /path/to/mountpoint

# Control utility
./target/debug/encfsctl info /path/to/encrypted
./target/debug/encfsctl decode /path/to/encrypted encrypted_filename
./target/debug/encfsctl cat /path/to/encrypted encrypted_filename
```

### Installation
```bash
# Install to ~/.cargo/bin
cargo install --path .
```

## Project Structure

```
encfs/
├── src/                      # Rust source code
│   ├── main.rs              # Main encfs binary (FUSE mount)
│   ├── encfsctl.rs          # Control utility binary
│   ├── lib.rs               # Library entry point
│   ├── config.rs            # Config file parsing (V4/V5/V6)
│   ├── config_binary.rs     # Binary config format parser
│   ├── constants.rs         # Global constants
│   ├── fs.rs                # FUSE filesystem implementation
│   └── crypto/              # Cryptographic operations
│       ├── mod.rs           # Crypto module exports
│       ├── ssl.rs           # OpenSSL cipher wrapper
│       └── file.rs          # File encryption/decryption
├── tests/                   # Integration tests
│   ├── fixtures/            # Test data (encrypted files)
│   ├── live_mount.rs        # Live FUSE mount tests (ignored by default)
│   └── *.rs                 # Other integration tests
├── locales/                 # i18n translation files (YAML)
│   ├── main.yml            # Main binary translations
│   ├── ctl.yml             # encfsctl translations
│   └── help.yml            # Help text translations
├── Cargo.toml              # Rust dependencies
├── Taskfile.yml            # Task runner config (alternative to make)
└── .github/workflows/      # CI configuration
```

## Code Organization

### Module Hierarchy

1. **`lib.rs`**: Library entry point
   - Exports all public modules
   - Initializes i18n system
   - Contains integration tests

2. **`config.rs`**: Configuration file handling
   - `EncfsConfig`: Main config struct
   - `ConfigType`: Enum for V3/V4/V5/V6 formats
   - `Interface`: Cipher/naming algorithm interface
   - Supports XML (V6) and binary (V4/V5) formats
   - XML uses Boost Serialization format for compatibility

3. **`config_binary.rs`**: Binary config parser
   - `ConfigReader`: Reads V4/V5 binary configs
   - `ConfigVar`: Variable-length encoded values

4. **`crypto/` namespace**: Cryptographic operations
   - **`ssl.rs`**: OpenSSL cipher wrapper (legacy modes)
   - **`aead.rs`** / **`block.rs`**: Modern authenticated encryption (AES-GCM-SIV)
   - **`file.rs`**: File-level encryption, handles block boundaries, MACs, headers

5. **`fs.rs`**: FUSE filesystem implementation
   - `EncFs`: Main filesystem struct
   - Implements `FilesystemMT` trait from `fuse_mt`
   - Path encryption/decryption with IV chaining
   - File handle management
   - All FUSE operations (read, write, readdir, etc.)

7. **`main.rs`**: Main encfs binary
   - CLI argument parsing with `clap`
   - Password handling (prompt, stdin, extpass)
   - Daemonization support
   - FUSE mount setup

8. **`encfsctl.rs`**: Control utility
   - Subcommands: info, passwd, decode, encode, cat, ls, showkey, export
   - Standalone utility for inspecting/manipulating encrypted filesystems

## Naming Conventions

### Rust Standard Conventions
- **Types/Structs/Enums**: `PascalCase` (e.g., `EncfsConfig`, `SslCipher`)
- **Functions/Variables**: `snake_case` (e.g., `decrypt_filename`, `block_size`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `DEFAULT_SALT_SIZE`)
- **Modules**: `snake_case` (e.g., `config_binary`)

### Project-Specific Naming
- **IV**: Initialization Vector (used throughout crypto code)
- **MAC**: Message Authentication Code
- **KDF**: Key Derivation Function (PBKDF2)
- **Volume Key**: The master key used to encrypt files (encrypted by user password)
- **User Key**: Key derived from user password
- **File IV**: Per-file initialization vector (stored in file header if `unique_iv` enabled)
- **Path IV**: IV derived from path components (used with `chained_name_iv`)

### File Naming
- Test files: `*_test.rs` (e.g., `write_test.rs`)
- Integration tests: Top-level in `tests/` directory
- Fixtures: `tests/fixtures/` for test data

## Testing Patterns

### Test Organization
1. **Unit tests**: `#[cfg(test)] mod tests` at bottom of source files
2. **Integration tests**: Separate files in `tests/` directory
3. **Live mount tests**: `tests/live_mount.rs` with `#[ignore]` attribute

### Common Test Patterns

```rust
// Integration test with fixtures
#[test]
fn test_decrypt_filenames() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");
    let config = EncfsConfig::load(&config_path)?;
    // ... test logic
    Ok(())
}

// Live mount test (ignored by default)
#[test]
#[ignore]
fn live_smoke_mount_unmount_standard() -> Result<()> {
    require_live();  // Checks ENCFS_LIVE_TESTS env var
    if !live_enabled() {
        return Ok(());
    }
    // ... test logic
    Ok(())
}
```

### Test Fixtures
- `tests/fixtures/encfs6-std.xml`: Standard mode config
- `tests/fixtures/encfs6-paranoia.xml`: Paranoia mode config
- `tests/fixtures/MhAO8Ckgt67m1cSrFU9HHiNT`: Encrypted file (decrypts to "DESIGN.md")
- `tests/fixtures/U,-Aj0Ha7VZMhbnuv-vx1DZu/`: Encrypted directory (paranoia mode)

### Running Tests in CI
- GitHub Actions: `.github/workflows/ci.yml`
- Cirrus CI: `.cirrus.yml` (FreeBSD testing)
- CI runs: clippy, build, test, live_mount tests

## Important Gotchas and Non-Obvious Patterns

### 1. Config Format Compatibility
- **V6 (XML)**: Current format, `.encfs6.xml` file
- **V5 (Binary)**: Legacy format, `.encfs5` file - READ ONLY (save not implemented)
- **V4 (Binary)**: Older format, `.encfs4` file - READ ONLY
- **V3**: Not supported (will error)

The code must maintain compatibility with all three formats for reading existing filesystems.

### 2. IV Chaining Modes
Two types of IV chaining affect how paths are encrypted:

- **`chained_name_iv`**: Each directory's IV is derived from parent's IV + encrypted name
  - Standard mode: enabled
  - Affects path encryption/decryption order
  
- **`external_iv_chaining`**: File IVs are derived from path IV
  - Paranoia mode: enabled
  - Means file headers must be decrypted with path IV, not just 0

**Critical**: When decrypting files in paranoia mode, you MUST use the path IV from `decrypt_path()`, not 0!

### 3. File Structure
Encrypted files have this structure:
```
[Header: 8 bytes if unique_iv] [Block 0] [Block 1] ... [Block N]
```

Each block (if MACs enabled):
```
[MAC: block_mac_bytes] [Random: block_mac_rand_bytes] [Data: remaining]
```

**Note**: `block_mac_rand_bytes` is not yet supported (must be 0).

### 4. Filename Encryption
- Base64 encoded (URL-safe variant without padding)
- Uses stream cipher mode
- IV is derived from HMAC of plaintext name (deterministic)
- With `chained_name_iv`, also depends on parent directory's IV

### 5. Error Handling
- Use `anyhow::Result` for application code
- Use `libc::c_int` error codes for FUSE operations
- Map Rust errors to errno values in `fs.rs`

### 6. Internationalization
- Uses `rust-i18n` crate
- Translations in `locales/*.yml` files
- Macro: `t!("key.subkey", param = value)`
- Locale initialized from `LANG` environment variable
- Help text functions must return `String` (evaluated at runtime after locale init)

### 7. FUSE Integration
- Uses `fuse_mt` crate (multi-threaded FUSE)
- Implements `FilesystemMT` trait
- File handles stored in `HashMap<u64, Arc<FileHandle>>`
- Thread-safe via `Mutex` guards
- Single-threaded mode available via `-s` flag

### 8. Password Handling
Three methods (in order of precedence):
1. `--extpass <program>`: Run external program, read stdout
2. `--stdinpass`: Read from stdin
3. Default: Interactive prompt via `rpassword`

### 9. Validation Requirements
The `EncfsConfig::validate()` method enforces:
- `plain_data` must be false (not supported)
- `unique_iv` must be true (except V4)
- `block_mac_rand_bytes` must be 0 (not implemented yet)
- `key_size` must be positive and multiple of 8
- `block_size` must be positive
- `block_mac_bytes` must be 0-8
- Block size must be larger than MAC overhead

### 10. Legacy C++ Code
- Located in `legacy/` directory
- Uses CMake build system
- May be removed in future
- Useful for reference but not actively maintained
- Do NOT modify legacy code unless explicitly requested

### 11. Logging
- Uses `env_logger` crate
- Controlled by `RUST_LOG` environment variable
- `-v` flag sets debug level
- `-d` flag sets debug + foreground mode

### 12. Daemonization
- Uses `daemonize` crate
- Automatic unless `-f` (foreground) or `-d` (debug) flag
- Happens after password validation, before FUSE mount

## Dependencies

### Core Dependencies
- **fuse_mt** (0.6.3): Multi-threaded FUSE bindings
- **openssl** (0.10.75): Cryptographic operations
- **clap** (4.5.57): CLI argument parsing
- **anyhow** (1.0.101): Error handling
- **serde** (1.0.228): Serialization/deserialization
- **quick-xml** (0.39.0): XML parsing for V6 configs
- **base64** (0.22.1): Base64 encoding for filenames
- **rust-i18n** (3): Internationalization
- **log** (0.4.29) + **env_logger** (0.11.8): Logging
- **rpassword** (7.4.0): Password prompts
- **daemonize** (0.5): Background daemon support
- **libc** (0.2.180): POSIX system calls
- **chrono** (0.4): Date/time handling
- **argon2** (0.5) / **aes-gcm-siv** (0.11.1) / **sha2** (0.10): Modern cryptography
- **prost** (0.14.3): Protobuf serialization support

### System Dependencies
- **FUSE**: libfuse-dev (Linux), fusefs-libs (FreeBSD), fuse-t (macOS)
- **OpenSSL**: libssl-dev
- **pkg-config**: For finding system libraries

## CI/CD

### GitHub Actions (`.github/workflows/ci.yml`)
Runs on: `ubuntu-latest`
Steps:
1. Install dependencies (fuse, libfuse-dev, pkg-config, libssl-dev)
2. Load fuse module
3. Run clippy (fails on warnings)
4. Build release
5. Run tests
6. Run live mount tests

### Cirrus CI (`.cirrus.yml`)
Runs on: `FreeBSD 15.0`
Steps:
1. Install Rust, FUSE, OpenSSL
2. Load fusefs kernel module
3. Build release
4. Run tests
5. Run live mount tests
Status: `allow_failures: true`

## Common Workflows

### Adding a New Feature
1. Implement in appropriate module (`src/*.rs`)
2. Add unit tests in same file
3. Add integration test in `tests/` if needed
4. Update translations in `locales/*.yml` if user-facing
5. Run `cargo fmt` and `cargo clippy`
6. Run `cargo test`
7. Test manually with real encrypted filesystem

### Fixing a Bug
1. Add a failing test that reproduces the bug
2. Fix the bug
3. Verify test passes
4. Check for similar issues elsewhere
5. Run full test suite

### Updating Dependencies
1. Edit `Cargo.toml`
2. Run `cargo update`
3. Run full test suite
4. Check for deprecation warnings with clippy

### Adding Translations
1. Add keys to `locales/main.yml`, `locales/ctl.yml`, or `locales/help.yml`
2. Provide translations for en, fr, de
3. Use `t!("key.subkey")` macro in code
4. For clap help text, create helper function returning `String`

## Security Considerations

### Known Weaknesses (Inherited from EncFS Design)
See `ISSUES.md` for detailed analysis. Key issues:
- 64-bit IVs (should be 128-bit)
- 64-bit MACs (should be 128-bit+)
- Same key for encryption and authentication
- Stream cipher for last file block
- File holes not authenticated
- Information leakage between decryption and MAC check

**Note**: These are protocol-level issues that can't be fixed without breaking compatibility. The Rust port inherits these limitations.

### Implementation Security
- Rust's memory safety prevents many C++ vulnerabilities
- Use `anyhow::Result` to ensure errors are handled
- Avoid `unwrap()` in production code paths
- Use `?` operator for error propagation
- Validate all config values in `EncfsConfig::validate()`

## Performance Notes

- Block size affects performance (default 4096 bytes for new filesystems)
- MACs/Tags add overhead per block + performance penalty (~16 bytes for AES-GCM-SIV)
- Multi-threaded FUSE by default (use `-s` for single-threaded debugging)
- File buffer size: 128 KB (`FILE_BUFFER_SIZE`)
- Performance over NFS is known to be poor (upstream issue)

## Debugging Tips

### Enable Debug Logging
```bash
RUST_LOG=debug ./target/debug/encfs -f /encrypted /mount
```

### Run in Foreground
```bash
./target/debug/encfs -f /encrypted /mount
```

### Single-threaded Mode (easier debugging)
```bash
./target/debug/encfs -s -f /encrypted /mount
```

### Inspect Config
```bash
./target/debug/encfsctl info /encrypted
```

### Decode Filenames
```bash
./target/debug/encfsctl decode /encrypted encrypted_filename
```

### Decrypt File Contents
```bash
./target/debug/encfsctl cat /encrypted encrypted_filename
```

### Check FUSE Module
```bash
lsmod | grep fuse
sudo modprobe fuse  # if not loaded
```

### Unmount
```bash
fusermount -u /mount  # Linux
umount /mount         # macOS/FreeBSD
```

## Code Style

### General Rust Style
- Follow Rust standard style (enforced by `cargo fmt`)
- Use `rustfmt.toml` if present (currently uses defaults)
- Max line length: 100 characters (Rust default)
- Use `clippy` recommendations (CI fails on warnings)

### Project-Specific Style
- Prefer `anyhow::Result` over `Result<T, E>` in application code
- Use `?` operator for error propagation
- Add context to errors: `.context("description")?`
- Log errors before returning them from FUSE operations
- Use `debug!`, `info!`, `warn!`, `error!` macros for logging
- Document public APIs with `///` doc comments
- Use `//` for implementation comments

### Error Handling in FUSE Operations
```rust
fn some_fuse_op(&self, path: &Path) -> ResultEntry {
    let (encrypted_path, iv) = self.encrypt_path(path).map_err(|e| {
        error!("Failed to encrypt path: {}", e);
        e  // Return errno
    })?;
    // ... rest of implementation
}
```

## Additional Resources

- **README.md**: Project overview and status
- **DESIGN.md**: Technical overview of EncFS encryption
- **INSTALL.md**: Build and installation instructions
- **Cargo.toml**: Dependencies and metadata
- **Taskfile.yml**: Available task commands

## Quick Reference

### Most Common Commands
```bash
cargo build              # Build
cargo test               # Test
cargo clippy             # Lint
cargo fmt                # Format
task test-live           # Live mount tests
```

### Most Important Files
- `src/fs.rs`: FUSE implementation
- `src/config.rs`: Config parsing
- `src/crypto/ssl.rs`: Cryptography
- `tests/live_mount.rs`: Integration tests

### Most Common Issues
1. **Live tests fail**: Check `ENCFS_LIVE_TESTS=1` and FUSE module loaded
2. **Build fails on OpenSSL**: Install libssl-dev
3. **Build fails on FUSE**: Install libfuse-dev

---

**Last Updated**: February 21, 2026
**EncFS Version**: 2.0.0-alpha.3
**Rust Edition**: 2024

