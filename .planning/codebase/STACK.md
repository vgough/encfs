# Technology Stack

**Analysis Date:** 2026-02-24

## Languages

**Primary:**
- Rust 2024 Edition - Core encrypted filesystem implementation
- Protocol Buffers (proto3) - Configuration serialization format for V7 configs

**Secondary:**
- Shell - Build configuration and CI/CD orchestration
- YAML - CI/CD workflow definitions

## Runtime

**Environment:**
- Linux (primary) - Ubuntu latest on GitHub Actions
- FreeBSD (supported) - Cirrus CI integration
- macOS (experimental) - Commented out in CI, requires fuse-t
- FUSE (Filesystem in Userspace) - Kernel module for userspace filesystem mounting

**Package Manager:**
- Cargo - Rust package manager
- Lockfile: `Cargo.lock` present (version 4)

## Frameworks

**Core:**
- `fuse_mt` 0.6.3 - Multi-threaded FUSE binding for Rust
- `clap` 4.5.57 - Command-line argument parsing (with derive feature)
- `rust-i18n` 3 - Internationalization framework

**Cryptography:**
- `openssl` 0.10.75 - Legacy cipher support, PBKDF2 key derivation, message hashing
- `aes-gcm-siv` 0.11.1 - Modern AEAD block cipher (V7 config format)
- `argon2` 0.5 - Argon2id key derivation function
- `sha2` 0.10 - SHA-256 hashing

**Testing:**
- `libfuzzer-sys` 0.4 - Fuzzing framework (fuzz target: `fuzz_file_ops.rs`)
- `arbitrary` 1 - Random input generation for fuzzing

**Build/Dev:**
- `prost-build` 0.14.3 - Protocol Buffer compiler for Rust
- `protoc-bin-vendored` 2.27 - Vendored protoc binary

**Serialization:**
- `serde` 1.0.228 - Serialization framework (with derive feature)
- `quick-xml` 0.39.0 - XML parsing for legacy EncFS6 config files
- `base64` 0.22.1 - Base64 encoding/decoding

**Utilities:**
- `anyhow` 1.0.101 - Error handling
- `log` 0.4.29 - Logging framework
- `env_logger` 0.11.8 - Environment-based logger initialization
- `daemonize` 0.5 - Process daemonization
- `chrono` 0.4 - Date/time handling
- `rpassword` 7.4.0 - Interactive password prompts
- `libc` 0.2.180 - C library bindings (Unix system calls)

**Test Dependencies:**
- `tar` 0.4 - TAR archive support for test fixtures

## Configuration

**Environment:**
- `RUST_LOG` - Controls logging level (defaults to Info, overridden to Debug by -v/--verbose flag)
- `ENCFS_LIVE_TESTS` - Enables live mount tests (integration tests requiring FUSE mounting)
- `CARGO_TERM_COLOR` - Cargo output coloring (set to "always" in CI)
- `RootDir` - Passed to external password programs via `--extpass`
- `PKG_CONFIG_PATH` - Library discovery for OpenSSL and FUSE (macOS workaround)

**Build:**
- `build.rs` - Build script that:
  - Sets `PROTOC` environment variable to vendored protoc binary path
  - Compiles `proto/encfs_config.proto` to Rust code

**Localization:**
- i18n configuration in `Cargo.toml`:
  - `default-locale`: "en"
  - `available-locales`: ["en", "fr", "de"]
  - Locale files in `locales/` directory (YAML format based on `rust-i18n`)

## Platform Requirements

**Development:**
- Linux/FreeBSD: `libfuse` (or `fusefs-libs` on FreeBSD), `libssl-dev`, `pkg-config`, Rust toolchain
- macOS: `fuse-t` package, `pkg-config`, Rust toolchain
- Nightly Rust compiler (specified in `fuzz/rust-toolchain.toml`)

**Production:**
- Linux: FUSE kernel module (`fuse.ko`), OpenSSL libraries
- FreeBSD: `fusefs-libs` package, OpenSSL
- macOS: `fuse-t` or equivalent FUSE implementation
- Target architectures: x86_64 Linux (primary), x86_64 FreeBSD, arm64 macOS (experimental)

## Key Dependencies

**Critical:**
- `fuse_mt` - Core filesystem mounting without native kernel module development
- `openssl` - Provides legacy cipher algorithms (AES, Blowfish) and PBKDF2 for backward compatibility
- `aes-gcm-siv` - New authenticated encryption for V7 config format (replaces raw block MACs)
- `argon2` - Modern KDF to replace PBKDF2 for new volumes

**Infrastructure:**
- `prost` 0.14.3 - Protocol Buffer message parsing/serialization
- `quick-xml` - XML config parsing for V6 and legacy V5 format support
- `serde`/`base64` - Serialization support for legacy XML and binary formats

## Dependency Vulnerabilities

No active security advisories detected, but project is marked **ALPHA** status:
- Legacy C++ code removed; Rust rewrite in progress
- Read-only mode fully functional; write operations partially implemented
- Truncate with holes support added in recent commits
- New V7 config format requires careful testing before trusting important data

---

*Stack analysis: 2026-02-24*
