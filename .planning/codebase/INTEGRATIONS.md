# External Integrations

**Analysis Date:** 2026-02-24

## APIs & External Services

**Filesystem Operations:**
- FUSE (Filesystem in Userspace) - Via `fuse_mt` crate
  - SDK/Client: `fuse_mt` 0.6.3
  - Interaction: Mounts encrypted directory at specified mount point
  - Authentication: File permissions inherited from underlying encrypted storage

## Data Storage

**Configuration Files:**
- **V7 Config Format** (Binary Protocol Buffer)
  - File: `.encfs7` (v7-config-file)
  - Storage: Protocol Buffers compiled via `prost` from `proto/encfs_config.proto`
  - Content: Encrypted volume key (AES-256-GCM wrapped), Argon2 KDF parameters, cipher configuration
  - Connection: File-based (no remote integration)

- **V6 Config Format** (XML)
  - File: `.encfs6.xml`
  - Storage: XML with embedded base64-encoded binary data
  - Parsing: `quick-xml` crate with serde integration
  - Content: Legacy EncFS6 configuration and key material

- **V5/Legacy Config Format** (Binary)
  - File: `.encfs5`
  - Storage: Binary format parsed via `config_binary.rs`
  - Backward compatibility: Supported but deprecated

**Storage Mechanism:**
- **Local filesystem only** - No remote storage backend
- Config files stored in root encrypted directory
- Per-file configuration: Individual file IVs stored in 8-byte file headers
- No database backend required

## Encryption & Key Management

**Volume Encryption:**
- No external KMS (Key Management Service) integration
- Key derivation:
  - Modern: Argon2id (configurable memory cost, time cost, parallelism)
  - Legacy: PBKDF2-HMAC-SHA1 (for backward compatibility)
- Key storage: Encrypted with AES-256-GCM in V7 config, XOR obfuscated in V6

**Cipher Algorithms:**
- Block ciphers: AES (128/192/256-bit keys), Blowfish (legacy)
- Stream/Block modes:
  - Legacy: Stream ciphers with per-block MACs
  - V7: AES-GCM-SIV for authenticated encryption

**Password Input:**
- No OAuth/OIDC - Password-only authentication
- Methods:
  - Interactive prompt via `rpassword` crate
  - External program via `--extpass` flag (spawns subprocess)
  - stdin via `--stdinpass` flag
  - Password not stored; used only for key derivation

## Data Storage

**File Storage:**
- **Local filesystem only** - No cloud or remote integration
- Files stored encrypted in raw filesystem
- Filename encryption: Both content and filenames are encrypted
- File encoding: Stream or block cipher modes, configurable
- Sparse file support: Optional via `allow_holes` feature flag

**In-Memory State:**
- Cipher state: `SslCipher` struct holding key material
- No persistent session storage
- No cache backend (non-persistent encryption/decryption)

## Logging & Observability

**Logging:**
- Framework: `log` crate (facade) + `env_logger` (implementation)
- Output: stderr via environment variable configuration
- Log levels: Error, Warn, Info (default), Debug, Trace
- Control: `RUST_LOG` environment variable or CLI flags (-v, -d)
- Sample output locations:
  - `src/main.rs` - Mount operations, daemonization
  - `src/encfsctl.rs` - Control utility operations
  - `src/fs.rs` - Filesystem operations

**Error Handling:**
- Framework: `anyhow` for context-aware error propagation
- Pattern: `Result<T>` with `.context()` for error messages
- Internationalization: Error messages translated via `rust-i18n`
- No error reporting to external services

## CI/CD & Deployment

**Hosting:**
- GitHub Actions (primary) - Ubuntu latest
- Cirrus CI (secondary) - FreeBSD testing, allows failures
- No container registry, no release automation detected

**CI Pipeline:**
- Platform: GitHub Actions `.github/workflows/ci.yml`
- Triggers: Push to master, pull requests
- Steps:
  1. Install system dependencies (`fuse`, `libfuse-dev`, `pkg-config`, `libssl-dev`)
  2. Load FUSE kernel module
  3. Lint check with `cargo clippy`
  4. Build release binary
  5. Run unit/integration tests
  6. Run live mount tests (requires FUSE support)

**Testing:**
- Unit tests: Inline `#[test]` in source files
- Integration tests: Live filesystem mounting tests
- Fuzzing: `cargo-fuzz` harness in `fuzz/fuzz_targets/fuzz_file_ops.rs`

**Deployment:**
- No automated deployment detected
- Binary artifacts: Built via `cargo build --release`
- Release: Manual via GitHub releases (not automated in workflows)

## Webhooks & Callbacks

**Incoming:**
- None detected

**Outgoing:**
- External password program: Spawned via `--extpass` flag
  - Subprocess: `sh -c <program>`
  - Environment: `RootDir` passed with root directory path
  - Output: Reads password from stdout
  - Location: `src/main.rs` lines 147-157

## Secrets & Credentials

**Secrets Location:**
- `.env` - Not used; no .env file present
- Volume encryption password: Never stored
- Config files (`.encfs7`, `.encfs6.xml`, `.encfs5`):
  - Encrypted key material stored in file
  - Not committed to git (stored in user's encrypted directories only)

**Secret Handling:**
- Password: Read at mount time only, never persisted
- Key material: Derived from password via KDF, stored encrypted in config
- No API keys, tokens, or credentials in codebase
- No external secret management integration

## Language & Localization

**Supported Languages:**
- English (en) - Default
- French (fr) - Auto-generated
- German (de) - Auto-generated

**Implementation:**
- Framework: `rust-i18n` crate
- Locale detection: `LANG` environment variable parsing
- Fallback chain: Specific locale → base language → English
- Locale files: `locales/` directory (YAML format)
- Coverage:
  - Help text for CLI arguments
  - Error messages
  - Status messages

**Locale File Locations:**
- Main: `src/main.rs`, `src/lib.rs` - `rust_i18n::i18n!("locales")`

---

*Integration audit: 2026-02-24*
