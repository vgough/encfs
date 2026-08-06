# AGENTS.md - Guide for AI Agents Working in EncFS

This document provides comprehensive information for AI agents working in the EncFS codebase. It covers commands, patterns, conventions, gotchas, and project-specific context.

## Project Overview

**EncFS** is an encrypted virtual filesystem that runs in userspace using FUSE. This is a **Rust port** of the original C++ implementation, aiming for compatibility with existing EncFS filesystems while providing memory safety and modern code practices.

- **Language**: Rust (Edition 2024)
- **Primary Goal**: Read/write compatibility with legacy EncFS filesystems
- **Status**: Beta (v2.0.0-beta.6) - functional for read/write but still maturing

### Key Characteristics
- Encrypts individual files (not block devices)
- Uses FUSE for filesystem operations
- Supports multiple config formats (V4, V5, V6, V7 - see Config Format Compatibility below)
- RustCrypto-based cryptographic operations (AES, Blowfish, SHA1, PBKDF2, Argon2, AES-GCM, AES-GCM-SIV)
- Modern cryptography (AES-GCM-SIV, Argon2) for new setups
- Internationalization support

For stack/dependency details, the full module map, data flow, and security architecture, see `architecture.md`. This document focuses on commands, conventions, and agent-relevant gotchas.

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
- Linux or FreeBSD (macOS support via macFUSE)

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

# Reverse encryption: plaintext source -> encrypted virtual view
./target/debug/encfsr /path/to/source/.encfs7 /path/to/source /path/to/mountpoint

# Opt in to writes through the encrypted reverse view
./target/debug/encfsr --write /path/to/source/.encfs7 /path/to/source /path/to/mountpoint
```

### Installation
```bash
# Install to ~/.cargo/bin
cargo install --path .
```

## Project Structure

Top-level layout: `src/` (Rust source), `tests/` (integration tests, `fixtures/`
test data, `live_mount.rs` ignored-by-default live tests), `locales/` (i18n
YAML), `Cargo.toml`, `Taskfile.yml`, `.github/workflows/` (CI).

Quick pointers for the modules agents touch most:
- `src/fs.rs`: forward-mode FUSE filesystem (`EncFs`, implements `typed_fuse::PathFilesystem`)
- `src/reverse_fs.rs` / `src/encfsr.rs`: reverse-mode FUSE (encrypted view of a
  plaintext source dir); requires a V7 config with `unique_iv = false`
  (`encfsctl new --no-unique-iv <source-dir>`); `--write` stages and validates
  ciphertext before committing it to the plaintext source
- `src/config.rs`: `EncfsConfig`, `ConfigType` (V3 unsupported, V4/V5 binary
  read-only, V6 XML, V7 protobuf), config validation
- `src/crypto/`: `cipher.rs` (trait), `ssl.rs` (sole impl: legacy CBC/CFB+MAC
  and V7 AES-GCM-SIV), `block.rs` (per-block layout/mode selection), `aead.rs`
  (V7 volume-key wrap only), `file.rs` (block boundaries, header IV, dispatch)

See `architecture.md`'s Module Map for the complete file list (including
`security.rs`, `config_binary.rs`, `config_proto.rs`) and Data Flow for how a
FUSE op moves through these layers.

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
- **V7 (Protobuf)**: Current default for new filesystems, `.encfs7` file. Argon2id KDF, AES-256-GCM key wrap, AES-GCM-SIV per-block crypto.
- **V6 (XML)**: `.encfs6.xml` file. Still fully supported (read/write).
- **V5 (Binary)**: Legacy format, `.encfs5` file - READ ONLY (save not implemented)
- **V4 (Binary)**: Older format, `.encfs4` file - READ ONLY
- **V3 and earlier**: Not supported (will error)

The code must maintain compatibility with all formats for reading existing filesystems. See `architecture.md`'s Data Model section for on-disk layout details.

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
Encrypted files share the header layout `[Header: 8 bytes if unique_iv] [Block 0] [Block 1] ... [Block N]`,
but block contents differ by format:
- **Legacy (V4-V6)**: `[MAC: block_mac_bytes] [Random: block_mac_rand_bytes] [Data]`. `block_mac_rand_bytes` is not yet supported (must be 0).
- **V7 (AES-GCM-SIV)**: `[Ciphertext][16-byte tag]`, always authenticated.

See `architecture.md`'s Data Model section for full byte-level detail.

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
- Uses the sibling `typed-fuse` crate and its synchronous `PathFilesystem` adapter
- File and directory handles are typed values owned by the FUSE runtime
- Multi-threaded by default, with a single-threaded mode for debugging
- Single-threaded mode available via `-s` flag

### 8. Password Handling
Three methods (in order of precedence):
1. `--extpass <program>`: Run external program, read stdout
2. `--stdinpass`: Read from stdin
3. Default: Interactive prompt via `rpassword`

### 9. Reverse Mode Writes
- `encfsr` only accepts V7 configs and rejects `unique_iv = true`.
- Use `--write` explicitly; regular reverse mounts remain read-only.
- `encfsctl new --no-unique-iv` remains compatible with V7 AES-GCM-SIV tags,
  filename IV chaining, and external IV chaining.
- Incomplete or invalid ciphertext is rejected during flush/close without
  applying it to the plaintext source. Direct source changes while a write is
  staged cause the commit to fail with a conflict.

### 10. Validation Requirements
The `EncfsConfig::validate()` method (`src/config.rs`) enforces:
- `plain_data` must be false (not supported)
- `unique_iv` may be true or false (filesystem supports both)
- `block_mac_rand_bytes` must be 0 (not implemented yet)
- `key_size` must be positive and multiple of 8
- `block_size` must be positive and larger than the block's crypto overhead
- `block_mac_bytes` must be 0-8 for legacy formats, or exactly 16 (the AES-GCM-SIV tag) for V7

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

See `architecture.md`'s Stack & Dependencies table for the full crate list and versions.
System dependency: **FUSE 3.12+** (libfuse3-dev on Linux, a compatible fuse3 package on
FreeBSD, macFUSE on macOS).

## CI/CD

### GitHub Actions (`.github/workflows/ci.yml`)
Runs on: `ubuntu-latest`
Steps:
1. Install dependencies (fuse3, libfuse3-dev, pkg-config, libssl-dev)
2. Load fuse module
3. Run clippy (fails on warnings)
4. Build release
5. Run tests
6. Run live mount tests

### Cirrus CI (`.cirrus.yml`)
Runs on: `FreeBSD 15.0`
Steps:
1. Install Rust, FUSE
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
1. Add keys to `locales/main.yml`, `locales/ctl.yml`, `locales/help.yml`, or `locales/lib.yml`
2. Provide translations for en, fr, de
3. Use `t!("key.subkey")` macro in code
4. For clap help text, create helper function returning `String`

## Security Considerations

Legacy formats (V4-V6) inherit protocol-level weaknesses (64-bit IVs/MACs, key
reuse for encryption+auth, unauthenticated file holes) that can't be fixed
without breaking compatibility; V7 (AES-GCM-SIV) does not have these
limitations. See `architecture.md`'s Security and Constraints & Trade-offs
sections for the full picture.

### Implementation Security (coding practices for agents)
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

- **architecture.md**: Stack, module map, data flow, security architecture, tech debt
- **README.md**: Project overview and status
- **docs/DESIGN.md**: Technical overview of EncFS encryption
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
- `src/fs.rs`: forward-mode FUSE implementation
- `src/reverse_fs.rs`: reverse-mode FUSE implementation
- `src/config.rs`: Config parsing
- `src/crypto/ssl.rs`: Cryptography (legacy + V7 AES-GCM-SIV)
- `tests/live_mount.rs`: Integration tests

### Most Common Issues
1. **Live tests fail**: Check `ENCFS_LIVE_TESTS=1` and FUSE module loaded
2. **Build fails on FUSE**: Install the FUSE 3 development package and ensure `fuse3.pc` is visible to pkg-config

---

**Last Updated**: August 4, 2026
**EncFS Version**: 2.0.0-beta.6
**Rust Edition**: 2024
