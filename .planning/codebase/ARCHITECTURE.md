# Architecture

**Analysis Date:** 2026-02-24

## Pattern Overview

**Overall:** Layered encryption filesystem via FUSE with pluggable crypto backends.

**Key Characteristics:**
- Userspace FUSE filesystem translating plaintext requests to encrypted operations
- Multi-layer abstraction: FUSE API → Path encryption → Block encryption → OpenSSL/AEAD
- Support for multiple config formats (XML v6, Protobuf v7) with backward compatibility
- Symmetric encryption with configurable cipher algorithms (AES, Blowfish) and key derivation (PBKDF2, Argon2id)
- IV chaining modes for enhanced security (standard chaining, external chaining, no chaining)

## Layers

**FUSE Filesystem Interface:**
- Purpose: Translate POSIX filesystem operations from VFS to encrypted operations on raw storage
- Location: `src/fs.rs` implements `FilesystemMT` trait
- Contains: FUSE operation handlers (read, write, create, mkdir, rename, symlink, etc.)
- Depends on: `SslCipher` for encryption, `EncfsConfig` for parameters, file handle management
- Used by: `fuse_mt` crate to mount virtual filesystem

**Path Encryption Layer:**
- Purpose: Encrypt/decrypt directory paths component-by-component with optional IV chaining
- Location: Methods `encrypt_path()` and `decrypt_path()` in `src/fs.rs` (lines 63-120)
- Contains: Path component iteration, filename encryption, IV chaining logic
- Depends on: `SslCipher::encrypt_filename()` and `decrypt_filename()`
- Used by: All FUSE operations to map logical paths to physical encrypted paths

**File Content Layer:**
- Purpose: Handle block-by-block encryption/decryption and MAC verification for file data
- Location: `src/crypto/file.rs` with `FileDecoder` and `FileEncoder` structs
- Contains: Block-level I/O with ReadAt/WriteAt traits, header processing, sparse file handling
- Depends on: `BlockCodec` for per-block encryption, `SslCipher` for cipher operations
- Used by: FUSE read/write handlers, file operations

**Cipher/Key Derivation Layer:**
- Purpose: Core cryptographic operations including key derivation, file/name encryption, and block encryption
- Location: `src/crypto/ssl.rs` (`SslCipher`), `src/crypto/block.rs` (`BlockCodec`), `src/crypto/aead.rs`
- Contains: Key derivation (PBKDF2, Argon2id), AES/Blowfish operations, block MAC/AEAD handling
- Depends on: OpenSSL (libssl), aes-gcm-siv crate
- Used by: File and path encryption layers

**Configuration Layer:**
- Purpose: Load, validate, and manage EncFS configuration in multiple formats
- Location: `src/config.rs` (main), `src/config_binary.rs` (V4/V5), `src/config_proto.rs` (V7 protobuf)
- Contains: Config format detection, parsing, key unwrapping, compatibility logic
- Depends on: `quick-xml` for XML parsing, `prost` for protobuf
- Used by: Main entry point to initialize cipher and filesystem parameters

**Control Utility Layer:**
- Purpose: Administrative operations outside mounted filesystem (password change, config inspection)
- Location: `src/encfsctl.rs`
- Contains: Password management, config export/import, filename encoding/decoding utilities
- Depends on: Config and crypto layers
- Used by: Users for maintenance operations

## Data Flow

**File Read Operation:**

1. FUSE request arrives with logical path and offset
2. `read()` handler in `FilesystemMT` impl encrypts path → physical path with IV
3. Opens file handle from map or creates new one
4. `FileDecoder` is initialized with file, file IV from header, config params
5. Reads encrypted blocks from physical file at computed offsets
6. `BlockCodec` decrypts each block: strip legacy MAC or verify AEAD tag
7. Stream-decrypt or block-decrypt data within each block
8. Return plaintext data to FUSE kernel driver

**File Write Operation:**

1. FUSE request with logical path, plaintext data, offset
2. Encrypt path → physical path with IV
3. If file header not yet initialized, read existing file or create new one
4. `FileEncoder` encrypts plaintext data block by block
5. Each block: compute IV from position, apply stream or block cipher, compute/append MAC
6. Write encrypted blocks at computed physical offsets
7. If external IV chaining enabled, recompute file IVs from path IV
8. Update file size metadata

**Path Encryption with IV Chaining:**

- Standard mode: Each directory's IV = hash(parent_IV + encrypted_name)
- External chaining: File's data IV also depends on path IV
- No chaining: All IVs reset to 0 for each component

**State Management:**
- File handles cached in `EncFs.handles: Mutex<HashMap<u64, Arc<FileHandle>>>`
- Each handle stores file descriptor and decrypted file IV
- File IVs retrieved from 8-byte header on first access
- Plaintext path information used only during FUSE operation handling

## Key Abstractions

**SslCipher:**
- Purpose: Encapsulates all cryptographic operations and key material
- Examples: `src/crypto/ssl.rs` (~400 lines), used throughout crypto layer
- Pattern: Stateful cipher wrapper with key loaded once, reused for all operations

**BlockCodec:**
- Purpose: Abstracts legacy MAC block format vs. V7 AES-GCM-SIV per-block encryption
- Examples: `src/crypto/block.rs`, instantiated per file in `FileDecoder`/`FileEncoder`
- Pattern: Enum `BlockMode` with mode-specific overhead calculation and en/decryption

**FileDecoder/FileEncoder:**
- Purpose: Streaming decrypt/encrypt with sparse file handling and MAC verification
- Examples: `src/crypto/file.rs` (~300 lines combined)
- Pattern: Generic over file-like types implementing `ReadAt`/`WriteAt` traits

**EncfsConfig:**
- Purpose: Unified representation of config across formats (V4/V5/V6/V7)
- Examples: `src/config.rs`, serde-based deserialization with format-specific loaders
- Pattern: Config type enum + conditional field presence (e.g., Argon2 params only for v7)

**FilesystemMT:**
- Purpose: FUSE trait implementation mapping VFS operations to encrypted operations
- Examples: `src/fs.rs` (~1000 lines), implements 30+ FUSE operations
- Pattern: Each operation validates/encrypts paths, delegates to underlying filesystem

## Entry Points

**encfs (main binary):**
- Location: `src/main.rs`
- Triggers: User runs `encfs /root/encrypted /mnt/plain`
- Responsibilities: Parse CLI args, load config, derive master key from password, mount FUSE filesystem, handle daemonization

**encfsctl (utility binary):**
- Location: `src/encfsctl.rs`
- Triggers: User runs `encfsctl info|passwd|decode|encode ...`
- Responsibilities: Manage configuration, change passwords, inspect/manipulate encrypted names

**Library Init:**
- Location: `src/lib.rs`
- Triggers: Both binaries call `encfs::init_locale()` and `encfs::init_logger()`
- Responsibilities: Set up internationalization, expose public modules (config, crypto, fs)

## Error Handling

**Strategy:** Result types throughout with context propagation via `anyhow::Context`.

**Patterns:**
- FUSE operations return `libc::c_int` error codes (EIO, EACCES, EINVAL, etc.)
- Crypto operations return `anyhow::Result<T>` with descriptive error messages
- File I/O wrapped in `map_err()` to convert OS errors to FUSE codes
- Password derivation failures logged and communicated to user
- Decryption failures: log filename and error, return EIO to prevent data corruption

## Cross-Cutting Concerns

**Logging:** `log` crate with `env_logger` frontend. Debug logs for every FUSE operation, info for setup phase.

**Validation:**
- Config validation on load: cipher algorithm support, block size > overhead, KDF parameters
- Path component validation: UTF-8 encoding, length limits from cipher
- File IV validation: stored header IV must be decryptable with path IV

**Authentication:**
- Password retrieved via `rpassword` (interactive), `extpass` (external program), or stdin
- Derives user key via KDF, then unwraps master key from config
- Incorrect password detected when HMAC verification fails on key unwrapping

**Permissions:**
- Preserved from underlying encrypted files
- FUSE `access()` handler applies standard POSIX permission logic
- Symlink targets encrypted per-path-IV to preserve permissions through renames

**Internationalization:**
- `rust_i18n` crate with locale files in `locales/` (YAML format)
- User messages translated for en/fr/de
- Locale auto-detected from `LANG` environment variable

## Configuration Version Support

- **V4/V5 (binary):** Loaded via `config_binary.rs`, legacy format, write support
- **V6 (XML):** Loaded via `config.rs` with `quick-xml`, most common, write support
- **V7 (Protobuf):** Loaded via `config_proto.rs`, new tamper-resistant format with AEAD key wrap, read/write support
- **Cipher:** Detects format on load, auto-selects V7 for new volumes

## Parallel File Operations

- File handles managed in thread-safe `Mutex<HashMap>`
- Each `FileHandle` wraps a `File` object (reference counted via `Arc`)
- FUSE-MT framework handles request multiplexing across threads (1 or num_cpus threads)
- No global encryption state beyond cipher key (immutable after init)

---

*Architecture analysis: 2026-02-24*
