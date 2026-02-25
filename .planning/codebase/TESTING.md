# Testing Patterns

**Analysis Date:** 2026-02-24

## Test Framework

**Runner:**
- `cargo test` - Built-in Rust test runner (no external test framework dependency)
- Config: `Cargo.toml` specifies `[dev-dependencies]` including `tar = "0.4"` for test fixtures

**Assertion Library:**
- Built-in Rust `assert!()` macro and variants: `assert_eq!()`, `assert_ne!()`
- `anyhow::Result<T>` used for test error propagation instead of panics

**Run Commands:**
```bash
cargo test                    # Run all unit and integration tests (excludes live mount tests)
ENCFS_LIVE_TESTS=1 cargo test --test live_mount -- --ignored --test-threads=1  # Run live FUSE mount tests
cargo fmt -- --check         # Check formatting
cargo clippy --all-targets --all-features -- -D warnings  # Run linter
cargo tarpaulin --out lcov --output-dir coverage  # Generate coverage report
```

## Test File Organization

**Location:**
- Unit tests co-located with source code in `#[cfg(test)] mod tests { }` blocks: see `src/lib.rs` (lines 30-194)
- Integration tests in separate `tests/` directory at crate root
- Live mount FUSE integration tests in `tests/live_mount.rs` (requires Linux+FUSE)
- Virtual driver tests in `tests/write_test.rs` (no mount required)
- Config tests in `tests/config_*.rs` files (multiple config format tests)

**Naming:**
- Unit tests: `#[test]` followed by `test_<description>()`
- Integration tests: `<description>_test.rs`
- Live mount tests: `live_<description>()` with `#[test]` and `#[ignore]` decorators
- Test fixtures loaded from `tests/fixtures/` directory

**Structure:**
```
tests/
├── config_check.rs              # Config validation tests
├── config_compatibility.rs      # Config format compatibility
├── config_v5_save_test.rs      # V5 format save tests
├── write_test.rs               # File write operations
├── live_mount.rs               # FUSE mount integration tests
├── argon2_integration_test.rs  # Argon2 KDF integration
├── live/                        # Test helpers/utilities
│   └── mod.rs                  # Shared test infrastructure
└── fixtures/                    # Test data
    ├── encfs6-std.xml          # Standard config fixture
    ├── encfs6-paranoia.xml     # Paranoia mode config
    └── [encrypted test files]
```

## Test Structure

**Suite Organization:**
```rust
#[cfg(test)]
mod tests {
    use super::*;  // Import parent module items
    use std::path::PathBuf;
    use anyhow::Result;

    #[test]
    fn test_decrypt_filenames() -> Result<()> {
        // Test body with early returns via ? operator
        Ok(())
    }
}
```

**Patterns:**
- Unit tests use `-> anyhow::Result<()>` return type for error propagation
- Integration tests may return `Result<()>` or panic on errors
- Setup code runs inline or via helper functions: `unique_temp_dir()`, `load_live_config()`
- Teardown via RAII: `MountGuard::mount()` unmounts automatically when dropped
- Environment detection: `live_enabled()` checks `ENCFS_LIVE_TESTS` env var to conditionally run expensive tests
- Live tests require mutex serialization: `let _guard = live_lock()` to prevent parallel mounts

## Mocking

**Framework:** No external mocking framework used

**Patterns:**
```rust
// Create cipher directly for testing without loading config file
let iface = Interface {
    name: "ssl/aes".to_string(),
    major: 3,
    minor: 0,
    age: 0,
};
let cipher = SslCipher::new(&iface, 192).unwrap();
let mut cipher = cipher;
let user_key = vec![1u8; 24];
let user_iv = vec![2u8; 16];
cipher.set_key(&user_key, &user_iv);

// Create config manually for testing specific scenarios
let config = encfs::config::EncfsConfig {
    config_type: encfs::config::ConfigType::V6,
    creator: "test".to_string(),
    version: 20100713,
    cipher_iface: iface.clone(),
    // ... other fields
};

// Create EncFs instance directly
let fs = EncFs::new(root.clone(), cipher, config);
```

**What to Mock:**
- Crypto operations: Create `SslCipher` directly with test vectors instead of loading from config
- Filesystem operations: Use temporary directories with `unique_temp_dir()` prefix
- Config loading: Manually construct `EncfsConfig` structs with test values
- FUSE requests: Create `RequestInfo` structs directly with test values: `RequestInfo { unique: 1, pid: 1, gid: 0, uid: 0 }`

**What NOT to Mock:**
- Actual file I/O when testing crypto - verify encrypted files are valid
- Network operations - not applicable (filesystem only)
- System time - use actual `SystemTime` where needed for tests
- Actual FUSE operations in live tests - mount and use real FUSE to catch integration issues

## Fixtures and Factories

**Test Data:**
```rust
// Pattern-based data generation
fn pattern_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(17))
        .collect()
}

// Fixture loading
pub fn load_live_config(kind: LiveConfigKind) -> Result<LiveConfig> {
    let fixture_path = fixtures_dir().join(kind.fixture_filename());
    let cfg = EncfsConfig::load(&fixture_path)?;
    Ok(LiveConfig { kind, password: "test", ... })
}

// Temporary directory creation with unique naming
pub fn unique_temp_dir(prefix: &str) -> Result<PathBuf> {
    let pid = std::process::id();
    let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let dir = std::env::temp_dir()
        .join(format!("{}_{}_{}_{}", prefix, pid, nanos, n));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}
```

**Location:**
- Test fixtures in `tests/fixtures/` - XML config files and encrypted test data
- Helper functions in `tests/live/mod.rs` - `load_live_config()`, `unique_temp_dir()`, `data_block_size()`, `MountGuard`
- Pattern generators inline in test files: `pattern_bytes()`

## Coverage

**Requirements:** No explicit coverage requirement enforced, but coverage tooling available

**View Coverage:**
```bash
cargo tarpaulin --out lcov --output-dir coverage
```
- Generates LCOV reports for coverage analysis
- Builds coverage artifacts in `coverage/` directory
- Coverage report generated but not enforced as blocking check

## Test Types

**Unit Tests:**
- Scope: Individual functions and small modules
- Location: Embedded in source files via `#[cfg(test)] mod tests {}`
- Example: `test_decrypt_filenames()` in `src/lib.rs` tests config loading and file decryption
- Approach: Direct function calls with test data, immediate assertions
- Focus: Cryptographic operations, config parsing, encoding/decoding logic

**Integration Tests:**
- Scope: Multiple modules interacting, config loading, file operations
- Location: `tests/` directory as separate binaries
- Example: `test_virtual_driver_write()` in `tests/write_test.rs` creates EncFs instance and performs write operations
- Approach: Construct realistic scenarios with config files and filesystem operations
- Focus: Config format compatibility, multi-format support (V5, V6, V7), file I/O correctness

**E2E Tests:**
- Framework: FUSE mount tests via `live_mount.rs` - requires Linux and FUSE kernel support
- Scope: Full encrypted filesystem from mount point perspective
- Example: `live_basic_io_standard()` mounts filesystem and performs reads/writes
- Approach: Mounts encrypted root to mount point, uses standard file operations via mount point
- Special: Tests marked with `#[ignore]` by default, enabled via `ENCFS_LIVE_TESTS=1`
- Threading: Run single-threaded with `--test-threads=1` to avoid concurrent mount conflicts

## Common Patterns

**Async Testing:**
Not applicable - Rust async not used in this codebase. All operations are synchronous.

**Error Testing:**
```rust
#[test]
fn test_missing_config_returns_error() {
    let encfs_bin = std::env::var("CARGO_BIN_EXE_encfs")
        .ok()
        .map(PathBuf::from)
        .expect("Could not find encfs binary");

    let root = live::unique_temp_dir("config_check_missing")?;
    let mount_point = root.join("mnt");
    let backing = root.join("backing");

    fs::create_dir(&mount_point)?;
    fs::create_dir(&backing)?;

    let output = Command::new(&encfs_bin)
        .arg("-f")
        .arg(&backing)
        .arg(&mount_point)
        .output()?;

    // Clean up
    let _ = fs::remove_dir_all(&root);

    // Assert error path
    assert!(
        !output.status.success(),
        "encfs should fail if no config file is found"
    );
}
```

**File I/O Testing:**
```rust
#[test]
fn test_virtual_driver_write() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_write_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    // Setup
    let iface = Interface { /* ... */ };
    let cipher = SslCipher::new(&iface, 192).unwrap();
    let config = encfs::config::EncfsConfig { /* ... */ };
    let fs = EncFs::new(tmp.clone(), cipher, config);

    // Create file
    let req = RequestInfo { unique: 1, pid: 1, gid: 0, uid: 0 };
    let parent = PathBuf::from("");
    let name = OsStr::new("test.txt");
    let create_res = fs.create(req, &parent, name, 0o644, 0).expect("create failed");

    // Write data
    let data = b"hello world".to_vec();
    let written = fs.write(req, &parent.join("test.txt"), create_res.fh, 0, data.clone(), 0)
        .expect("write failed");
    assert_eq!(written, data.len() as u32);

    // Verify via decryption
    // ... additional assertions
}
```

**Live Mount Testing Pattern:**
```rust
#[test]
#[ignore]  // Run only with ENCFS_LIVE_TESTS=1
fn live_basic_io_standard() -> Result<()> {
    require_live();  // Early exit if not enabled
    if !live_enabled() {
        return Ok(());
    }

    let cfg = load_live_config(live::LiveConfigKind::Standard)?;
    let mount = MountGuard::mount(cfg, false)?;  // Automatically unmounts on drop

    let p = mount.mount_point.join("basic.txt");
    let payload = b"hello live encfs\n";
    fs::write(&p, payload)?;
    let got = fs::read(&p)?;
    assert_eq!(got, payload);

    Ok(())
}
```

## Testing Infrastructure

**Environment Configuration:**
- `ENCFS_LIVE_TESTS` - Enable live FUSE mount tests (default: disabled)
- `ENCFS_LIVE_MOUNT_TIMEOUT_SECS` - Timeout for mount operations (default: 30 seconds)
- `RUST_LOG` - Control logging level during tests
- `CARGO_BIN_EXE_encfs` - Set by cargo to encfs binary location

**Test Organization:**
- Live test mutex: `LIVE_MUTEX` serializes mount/unmount to prevent conflicts
- Temporary directory counter: `TMP_COUNTER` ensures unique temp paths across tests
- Mount guard: `MountGuard` RAII pattern automatically unmounts on exit

---

*Testing analysis: 2026-02-24*
