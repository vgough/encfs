# EncFS - Architecture

An encrypted virtual filesystem that runs in userspace using FUSE, implemented in Rust for compatibility with legacy EncFS and memory safety.

<!--
Living Architecture Template v1.0
Source: https://github.com/ceaksan/living-architecture
Last verified: 2026-08-04
-->

For command reference, testing patterns, and coding conventions, see `AGENTS.md`. For the full crypto/format design rationale, see `docs/DESIGN.md`.

## Stack & Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `typed-fuse` | git | Typed libfuse3 bindings and path adapter |
| `clap` | 4.6.1 | CLI argument parsing |
| `anyhow` | 1.0.102 | Error handling |
| `serde` | 1.0.228 | Serialization/deserialization |
| `quick-xml` | 0.40.1 | XML parsing for V6 configs |
| `prost` + `prost-build`/`protoc-bin-vendored` | 0.14.4 | Protobuf codec for V7 configs; `build.rs` compiles `proto/encfs_config.proto` into `config_proto.rs` (vendored `protoc`, no system install needed) |
| `base64` | 0.22.1 | Base64 (URL-safe, no padding) encoding for filenames |
| `rust-i18n` | 4 | Internationalization |
| `log` & `env_logger` | 0.4.32 / 0.11.10 | Logging |
| `rpassword` | 7.5.4 | Password prompts |
| `daemonize` | 0.5 | Background daemon support |
| `libc` | 0.2.186 | POSIX syscalls; also backs `security.rs` process hardening |
| `chrono` | 0.4 | Date/time handling |
| `aes` / `blowfish` / `cbc` / `cfb-mode` | (various) | Legacy (V4-V6 compatible) block/stream ciphers, used by `crypto/ssl.rs` |
| `aes-gcm` | 0.10 | AEAD wrap of the volume key for V7 configs (`crypto/aead.rs`) |
| `aes-gcm-siv` | 0.11.1 | V7 per-block authenticated encryption, implemented inside `crypto/ssl.rs` (not a separate cipher module) |
| `argon2` | 0.5 | KDF for V7 configs (Argon2id) |
| `pbkdf2` / `hmac` / `sha1` / `sha2` | (various) | Legacy KDF (PBKDF2-HMAC-SHA1), name-IV derivation, and V7 config-hash AAD (SHA-256) |
| `zeroize` | 1 | Zeroes key material on drop |
| `getrandom` | 0.4 | CSPRNG for salts/nonces |
| `sysinfo` | 0.39.6 | Runtime info (e.g. `encfsctl speed` sizing) |
| `tempfile` | 3 | Staged writes in reverse mode |

### Infrastructure

| Layer | Technology | Detail |
|-------|-----------|--------|
| Runtime | FUSE (Filesystem in Userspace) | Requires libfuse3-dev (Linux), compatible fuse3 package (FreeBSD), or macFUSE (macOS) |
| Language | Rust | Edition 2024 |
| CI/CD | GitHub Actions / Cirrus CI | Ubuntu-latest / FreeBSD 15.0 testing with live mounts |

## Module Map

```
encfs/
├── src/
│   ├── main.rs               # encfs binary: forward FUSE mount
│   ├── encfsctl.rs           # Control utility binary (info/passwd/decode/encode/cat/ls/new/...)
│   ├── encfsr.rs             # Reverse-mode FUSE binary
│   ├── lib.rs                # Library entry point, i18n init, integration tests
│   ├── security.rs           # Process hardening (core dumps, ptrace, mlockall)
│   ├── config.rs             # Config parsing/validation (V4/V5/V6/V7), key derivation & unwrap
│   ├── config_binary.rs      # Binary config format parser (V4/V5)
│   ├── config_proto.rs       # `prost`-generated V7 protobuf bindings (build-time, see build.rs)
│   ├── constants.rs          # Global constants (defaults, buffer sizes)
│   ├── fs.rs                 # Forward-mode FUSE filesystem implementation
│   ├── reverse_fs.rs         # Reverse-mode FUSE implementation (staged, validated writes)
│   └── crypto/
│       ├── mod.rs            # Crypto module exports
│       ├── cipher.rs         # `Cipher` trait: object-safe facade over volume crypto
│       ├── ssl.rs            # Sole `Cipher` impl (RustCrypto) — both legacy CBC/CFB+MAC and V7 AES-GCM-SIV block modes
│       ├── block.rs          # `BlockMode`/`BlockLayout`: per-block overhead and mode selection from config
│       ├── aead.rs           # V7 volume-key wrap only (AES-256-GCM, config hash as AAD)
│       └── file.rs           # File-level codec: header IV, block boundaries, read/write dispatch to `Cipher`
├── tests/                    # Integration tests (`*_test.rs`), `common/` and `live/` shared helpers
│   ├── fixtures/              # Test data (encrypted files)
│   └── live_mount.rs           # Live FUSE mount tests (`#[ignore]`, needs ENCFS_LIVE_TESTS=1)
├── locales/                  # i18n translation files (YAML): main.yml, ctl.yml, help.yml, lib.yml
└── .github/workflows/        # CI configuration
```

## Data Flow

```
Forward mount (encfs):
  FUSE op → typed-fuse PathFilesystem adapter (fs.rs)
    → path encrypt/decrypt (IV chaining: chained_name_iv / external_iv_chaining)
    → crypto/file.rs (header IV, block boundaries)
    → dyn Cipher (crypto/cipher.rs trait, crypto/ssl.rs impl — legacy CBC/CFB+MAC
      or V7 AES-GCM-SIV, mode picked via crypto/block.rs::BlockMode)
    → backing filesystem I/O

Reverse mount (encfsr, V7 configs only):
  FUSE op on plaintext source → reverse_fs.rs encrypts on the fly for reads;
    `--write` stages ciphertext + validates authenticated blocks before
    committing to the plaintext source on flush/close
```

## Route / API Structure

*Not Applicable: EncFS is a CLI application and FUSE filesystem, not a web API.*
See `AGENTS.md` for full flag reference. Summary:

```
encfs [opts] /path/to/encrypted /path/to/mountpoint       # forward mount
encfsctl <info|passwd|decode|encode|cat|ls|showcruft|autopasswd|export|new|speed> ...
encfsr [--write] /path/to/source/.encfs7 /path/to/source /path/to/mountpoint
```

## Data Model

| Component | Purpose |
|-------|---------|
| File Header | 0, 8, or 12 bytes — see below. Contains the per-file IV when present. |
| File Blocks | Encrypted chunks of file data |

Encrypted file layout: `[Header: 0/8/12 bytes] [Block 0] [Block 1] ... [Block N]`

Header size (`EncfsConfig::header_size()`) is conditional:
- `unique_iv = false` (headerless, including all reverse-mode configs): 0 bytes. The file IV is derived from the path instead (64-bit).
- `unique_iv = true`, narrow (default before this ADR, or `--legacy-file-iv` / any V4-V6 / pre-ADR V7 config): 8 bytes, a random 64-bit file IV.
- `unique_iv = true`, wide (`wide_file_iv = true`, the default for new V7/AES-GCM-SIV filesystems): 12 bytes, a random 96-bit file IV. Requires V7 + AES-GCM-SIV block mode; see ADR 0001.

Do not conflate the 64-bit *file seed* (the header/path-derived value above) with the 96-bit *AES-GCM-SIV nonce* every block uses: even the narrow 64-bit seed produces a full 96-bit nonce by mixing in the 64-bit block number, so AES-GCM-SIV always receives 96 nonce bits — widening the file IV increases how many of those bits are unpredictable per file, not the nonce length itself.

- **Legacy (V4-V6):** block = `[MAC: block_mac_bytes (0-8)] [Random: block_mac_rand_bytes] [Data]`. `block_mac_rand_bytes` must be 0 (not implemented). MAC is optional.
- **V7 (AES-GCM-SIV, default for new filesystems):** block = `[Ciphertext][16-byte tag]`; nonce/AAD derived from file IV + block number (narrow: 12-byte nonce / 16-byte AAD; wide: 12-byte nonce / 20-byte AAD — see ADR 0001 for the exact byte layout). Authentication is always on, no separate MAC/Random fields.

Full rationale and byte-level detail: `docs/DESIGN.md`.

## Configuration & Environment

| Variable | Purpose | Secret |
|----------|---------|--------|
| `ENCFS_LIVE_TESTS` | If set to 1, enables live FUSE mount tests during `cargo test`. | No |
| `RUST_LOG` | Controls env_logger output levels (e.g., `debug`). | No |
| `LANG` | System locale, used to initialize translations via `rust-i18n`. | No |
| `NO_COLOR` | Disables ANSI color in `encfsctl` output when set (any value). | No |

## Security

- Memory safety enforced via Rust, mitigating C++-inherited buffer overflows.
- **Process hardening (`security.rs`):** `harden_process()` runs at startup in `encfs`/`encfsr` — disables core dumps (`RLIMIT_CORE=0`) and marks the process non-dumpable (`prctl`/`procctl`/`ptrace` per-platform). `lock_memory()` (`mlockall`) exists but is **not** called automatically — opt in explicitly if key material must be pinned out of swap.
- **Key derivation:** V7 uses Argon2id (64 MiB memory, 3 iterations, 4 threads by default); legacy formats use PBKDF2-HMAC-SHA1.
- **V7 config integrity:** the volume key is AES-256-GCM wrapped with the SHA-256 hash of the rest of the config as AAD (`crypto/aead.rs`, `config.rs`) — any tampering with cipher/KDF/feature-flag fields fails decryption.
- Backward-compatibility formats (V4/V5 binary) are **read-only**.
- Path IV usage in paranoia mode (`external_iv_chaining` enabled): file headers must be decrypted with the path IV, not 0.
- Filename encryption: Base64 (URL-safe, no padding) over a stream or block cipher; IV derived from HMAC of the plaintext name (plus parent IV under `chained_name_iv`).
- Config validation (`EncfsConfig::validate`, `config.rs`): `plain_data` must be false, `block_mac_rand_bytes` must be 0, `key_size` positive and a multiple of 8, `block_mac_bytes` in `0..=8` for legacy or exactly 16 for V7 AES-GCM-SIV, block size must exceed the block's crypto overhead.

## Constraints & Trade-offs

| Decision | Reason | Trade-off |
|----------|--------|-----------|
| 64-bit IVs and MACs (legacy V4-V6) | Read/write compatibility with legacy C++ EncFS formats | Cryptographically weaker than modern standards; superseded by V7 for new filesystems |
| Single key for encryption/auth (legacy) | Backward compatibility | Cryptographic weakness (key reuse); V7 uses AEAD instead |
| Stream cipher for last file block (legacy) | Backward compatibility | May leak information, lacking full authenticated encryption |
| V4/V5 configurations as Read-Only | Reduce complexity while allowing data recovery | Cannot create new filesystems using these legacy formats |

## Known Tech Debt

- **Concurrency/correctness:** tracked live in `TODO.md` (per-file `RwLock`, `flock`, `fsync` are fixed; directory rename under IV chaining is still a non-atomic copy+delete race, and hard links can break per-file IV when `header_size == 0`).
- **Legacy protocol weaknesses (High):** weak IVs, 64-bit MACs, unauthenticated file holes — inherent to the V4-V6 wire format and unfixable without breaking backward compatibility. V7 (AES-GCM-SIV) does not have these limitations; see Security above.
- **Incomplete Features (Medium):** `block_mac_rand_bytes` is not yet supported and must be 0.
- **Performance (Low):** Performance over NFS is known to be poor due to upstream FUSE limitations.

## Code Hotspots

| File | Changes | Risk |
|------|---------|------|
| `src/fs.rs` | Forward-mode FUSE adapter, handles all filesystem operations | High (core logic, error mapping, concurrency — see `TODO.md`) |
| `src/crypto/ssl.rs` | Sole `Cipher` impl: legacy CBC/CFB+MAC and V7 AES-GCM-SIV block crypto | High (cryptographic correctness for every read/write) |
| `src/crypto/file.rs` | Block-boundary logic, header reading, dispatch to `Cipher` | High (cryptographic data integrity) |
| `src/reverse_fs.rs` | Reverse-mode staged/validated writes back to plaintext source | High (transactional correctness, newer code path) |
| `src/config.rs` | Config schema evolution, multi-format parsing (V4/V5/V6/V7), key derivation/unwrap | Medium |

---

## Optional Modules

### i18n

- **Locales:** `main.yml` (binary), `ctl.yml` (utility), `help.yml` (CLI help text), `lib.yml` (library-level strings).
- **Macro:** `t!("key.subkey", param = value)`
- **Initialization:** Reads `LANG` environment variable.
- **Note:** Help text functions return `String` for late evaluation after locale initialization.

<!-- Other modules from the template have been omitted as they are not relevant to this project. -->
