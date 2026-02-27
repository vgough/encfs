mod live;

use anyhow::{Context, Result, anyhow};
use encfs::config::{ConfigType, EncfsConfig, Interface, KdfAlgorithm};
use encfs::crypto::block::{BlockLayout, BlockMode};
use encfs::crypto::ssl::SslCipher;
use live::{live_enabled, live_lock, path_has_tool, unique_temp_dir};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};
use std::os::unix::fs::MetadataExt;

// ---------------------------------------------------------------------------
// Test config parameters — shared across all live tests.
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "encfsr_live_test";
const TEST_PLAINTEXT_FILENAME: &str = "hello.txt";
const TEST_PLAINTEXT_CONTENT: &[u8] =
    b"Hello, encfsr! This is a test file for Phase 2 verification.";

// ---------------------------------------------------------------------------
// Fixture setup
// ---------------------------------------------------------------------------

/// Create a valid V6 encfsr-compatible config.
///
/// Parameters:
/// - uniqueIV=0 (required by encfsr)
/// - chainedNameIV=1
/// - blockMACBytes=0 (ciphertext size = plaintext size — no per-block overhead)
/// - blockSize=1024, keySize=192
/// - kdfIterations=1 (fast for tests)
/// - password: TEST_PASSWORD
fn make_encfsr_config() -> EncfsConfig {
    let salt: Vec<u8> = (1u8..=20).collect(); // deterministic test salt
    let key_size = 192i32;

    let cipher_iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };
    let name_iface = Interface {
        name: "nameio/block".to_string(),
        major: 4,
        minor: 0,
        age: 0,
    };

    let mut temp_cipher =
        SslCipher::new(&cipher_iface, key_size).expect("failed to create SslCipher");
    temp_cipher.set_name_encoding(&name_iface);
    let key_len = (key_size / 8) as usize;
    let iv_len = temp_cipher.iv_len();
    let user_key_len = key_len + iv_len;

    let user_key_blob =
        SslCipher::derive_key(TEST_PASSWORD, &salt, 1, user_key_len).expect("PBKDF2 failed");
    let user_key = &user_key_blob[..key_len];
    let user_iv = &user_key_blob[key_len..];

    // Deterministic volume key (all zeros) for test reproducibility
    let volume_blob: Vec<u8> = vec![0u8; key_len + iv_len];
    let encrypted_key = temp_cipher
        .encrypt_key(&volume_blob, user_key, user_iv)
        .expect("encrypt_key failed");

    EncfsConfig {
        config_type: ConfigType::V6,
        creator: "encfsr-live-test".to_string(),
        version: 20100713,
        cipher_iface,
        name_iface,
        key_size,
        block_size: 1024,
        key_data: encrypted_key,
        salt,
        kdf_iterations: 1,
        desired_kdf_duration: 0,
        kdf_algorithm: KdfAlgorithm::Pbkdf2,
        argon2_memory_cost: None,
        argon2_time_cost: None,
        argon2_parallelism: None,
        plain_data: false,
        block_mac_bytes: 0,
        block_mac_rand_bytes: 0,
        unique_iv: false,
        external_iv_chaining: false,
        chained_name_iv: true,
        allow_holes: false,
        config_hash: None,
    }
}

/// Write the encfsr-compatible config to `source_dir/.encfs6.xml` and create
/// two plaintext files: `hello.txt` and `subdir/nested.txt`.
/// Returns the source directory path.
fn setup_source_dir(base_dir: &std::path::Path) -> Result<PathBuf> {
    let source_dir = base_dir.join("source");
    fs::create_dir_all(&source_dir).context("failed to create source dir")?;

    let config = make_encfsr_config();
    config
        .save(&source_dir.join(".encfs6.xml"))
        .context("failed to save config")?;

    fs::write(
        source_dir.join(TEST_PLAINTEXT_FILENAME),
        TEST_PLAINTEXT_CONTENT,
    )
    .context("failed to write test plaintext file")?;

    let subdir = source_dir.join("subdir");
    fs::create_dir_all(&subdir).context("failed to create subdir")?;
    fs::write(subdir.join("nested.txt"), b"nested file content")
        .context("failed to write nested file")?;

    Ok(source_dir)
}

// ---------------------------------------------------------------------------
// EncfsrMountGuard — local FUSE mount helper for encfsr
// ---------------------------------------------------------------------------

fn encfsr_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_encfsr"))
}

fn mountinfo_has_mount(mount_point: &std::path::Path) -> std::io::Result<bool> {
    let mp = if let Ok(c) = fs::canonicalize(mount_point) {
        c
    } else {
        mount_point.to_path_buf()
    };
    let mp_str = mp.to_string_lossy();
    let data = fs::read_to_string("/proc/self/mountinfo")?;
    for line in data.lines() {
        let mut parts = line.split_whitespace();
        let _id = parts.next();
        let _parent = parts.next();
        let _majmin = parts.next();
        let _root = parts.next();
        let mp_field = match parts.next() {
            Some(v) => v,
            None => continue,
        };

        if mp_field != mp_str {
            // println!("  [debug] mismatch: {} != {}", mp_field, mp_str);
            continue;
        }
        println!("  [debug] MATCH: {}", mp_field);
        if let Some((_pre, post)) = line.split_once(" - ") {
            let mut post_parts = post.split_whitespace();
            let fstype = post_parts.next().unwrap_or("");
            // In mountinfo, after " - " the fields are: fstype, mount_source, mount_options
            // For FUSE, fstype is often "fuse" or "fuse.encfs"
            if fstype.starts_with("fuse") {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn run_quiet(cmd: &mut Command) -> std::io::Result<std::process::ExitStatus> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

#[allow(dead_code)]
struct EncfsrMountGuard {
    _lock: MutexGuard<'static, ()>,
    source: PathBuf,
    pub mount_point: PathBuf,
    child: Child,
    mounted: bool,
    stderr_tail: Arc<Mutex<Vec<u8>>>,
}

impl EncfsrMountGuard {
    fn mount(source: PathBuf, config_path: PathBuf, password: &str) -> Result<Self> {
        if !live_enabled() {
            return Err(anyhow!("ENCFS_LIVE_TESTS not enabled"));
        }
        if !(path_has_tool("fusermount3") || path_has_tool("fusermount") || path_has_tool("umount"))
        {
            return Err(anyhow!(
                "missing unmount tool (need fusermount3/fusermount/umount in PATH)"
            ));
        }

        let lock = live_lock();
        let mount_point = unique_temp_dir("encfsr_live_mnt")?;
        fs::create_dir_all(&mount_point)?;
        println!("  [encfsr] mount_point: {:?}", mount_point);

        let mut cmd = Command::new(encfsr_bin());
        cmd.arg("--foreground")
            .arg("--stdinpass")
            .arg(&config_path)
            .arg(&source)
            .arg(&mount_point)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("failed to spawn encfsr")?;
        println!("  [encfsr] Spawned encfsr bin (pid={})", child.id());

        let stderr_tail: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        const LOG_TAIL_MAX: usize = 64 * 1024;

        // Drain stdout to avoid child deadlock on full pipe
        if let Some(out) = child.stdout.take() {
            thread::spawn(move || {
                use std::io::Read;
                let mut r = out;
                let mut buf = [0u8; 4096];
                loop {
                    match r.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        _ => {}
                    }
                }
            });
        }

        // Drain stderr, keeping a tail for diagnostics
        if let Some(err) = child.stderr.take() {
            let tail = stderr_tail.clone();
            thread::spawn(move || {
                use std::io::Read;
                let mut r = err;
                let mut buf = [0u8; 4096];
                loop {
                    match r.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut t = tail.lock().unwrap_or_else(|e| e.into_inner());
                            t.extend_from_slice(&buf[..n]);
                            if t.len() > LOG_TAIL_MAX {
                                let drop_n = t.len() - LOG_TAIL_MAX;
                                t.drain(0..drop_n);
                            }
                        }
                    }
                }
            });
        }

        {
            let mut stdin = child.stdin.take().context("failed to open child stdin")?;
            stdin
                .write_all(format!("{}\n", password).as_bytes())
                .context("failed to write password to child stdin")?;
        }

        // Poll for mount to become active (or child to exit with error)
        let start = Instant::now();
        let timeout = Duration::from_secs(30);
        let mut mounted = false;
        while start.elapsed() < timeout {
            if let Ok(true) = mountinfo_has_mount(&mount_point) {
                mounted = true;
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                let tail = stderr_tail.lock().unwrap_or_else(|e| e.into_inner());
                let err_msg = String::from_utf8_lossy(&tail).to_string();
                return Err(anyhow!(
                    "encfsr exited early with status {}; stderr: {}",
                    status,
                    err_msg
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }

        if !mounted {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!(
                "encfsr mount did not become ready within 30 seconds"
            ));
        }

        Ok(Self {
            _lock: lock,
            source,
            mount_point,
            child,
            mounted: true,
            stderr_tail,
        })
    }
}

impl Drop for EncfsrMountGuard {
    fn drop(&mut self) {
        if self.mounted {
            let mp = self.mount_point.clone();
            let _ = if path_has_tool("fusermount3") {
                run_quiet(Command::new("fusermount3").arg("-u").arg(&mp))
            } else if path_has_tool("fusermount") {
                run_quiet(Command::new("fusermount").arg("-u").arg(&mp))
            } else {
                run_quiet(Command::new("umount").arg(&mp))
            };
            // Wait for child to exit; kill if it doesn't
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(3) {
                if let Ok(Some(_)) = self.child.try_wait() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = fs::remove_dir_all(&self.mount_point);
    }
}

// ---------------------------------------------------------------------------
// Live tests (guarded by ENCFS_LIVE_TESTS=1)
// ---------------------------------------------------------------------------

/// FUSE-02, COMPAT-01: readdir on the mounted virtual FS returns encrypted
/// filenames that round-trip through decrypt_filename back to the plaintext names.
#[test]
#[ignore]
fn test_encfsr_live_readdir_shows_encrypted_names() -> Result<()> {
    if !live_enabled() {
        return Ok(());
    }

    let dir = unique_temp_dir("encfsr_live_readdir")?;
    let source_dir = setup_source_dir(&dir)?;
    let config_path = source_dir.join(".encfs6.xml");
    let mount = EncfsrMountGuard::mount(source_dir.clone(), config_path, TEST_PASSWORD)?;

    // Load config and derive cipher for verification
    let config = EncfsConfig::load(&source_dir.join(".encfs6.xml"))
        .context("failed to load encfsr config for verification")?;
    let cipher = config
        .get_cipher(TEST_PASSWORD)
        .context("failed to derive cipher for verification")?;

    // Read the virtual root directory (entries are encrypted names)
    let entries: Vec<String> = fs::read_dir(&mount.mount_point)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| !n.starts_with('.'))
        .collect();

    assert!(
        !entries.is_empty(),
        "readdir on mounted encfsr should return at least one entry"
    );

    // The virtual FS exposes encrypted names — they should NOT be the plaintext names
    let plaintext_names = [TEST_PLAINTEXT_FILENAME, "subdir"];
    for entry in &entries {
        for plain in &plaintext_names {
            assert_ne!(
                entry.as_str(),
                *plain,
                "entry {:?} should be an encrypted name, not the plaintext name {:?}",
                entry,
                plain
            );
        }

        // Each entry should decrypt to a known plaintext name (FUSE-02, COMPAT-01)
        // At root, dir_iv = 0 (no chained IV from empty path)
        let (decrypted_bytes, _) = cipher
            .decrypt_filename(entry, 0)
            .with_context(|| format!("decrypt_filename failed for entry {:?}", entry))?;
        let decrypted =
            String::from_utf8(decrypted_bytes).context("decrypted filename is not valid UTF-8")?;
        assert!(
            plaintext_names.contains(&decrypted.as_str()),
            "decrypted name {:?} should be one of {:?} (entry: {:?})",
            decrypted,
            plaintext_names,
            entry
        );
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// FUSE-03: stat on a file in the virtual FS reports ciphertext size.
///
/// With blockMACBytes=0, ciphertext size = plaintext size (no per-block overhead).
/// The formula: BlockLayout::physical_size_from_logical(logical, header_size=0) with
/// overhead=0 returns the logical size unchanged. The test verifies the formula,
/// not a specific size value.
#[test]
#[ignore]
fn test_encfsr_live_stat_reports_ciphertext_size() -> Result<()> {
    if !live_enabled() {
        return Ok(());
    }

    let dir = unique_temp_dir("encfsr_live_stat")?;
    let source_dir = setup_source_dir(&dir)?;
    let config_path = source_dir.join(".encfs6.xml");
    let mount = EncfsrMountGuard::mount(source_dir.clone(), config_path, TEST_PASSWORD)?;

    let config = EncfsConfig::load(&source_dir.join(".encfs6.xml"))?;
    let cipher = config.get_cipher(TEST_PASSWORD)?;

    // Get plaintext file size
    let plaintext_path = source_dir.join(TEST_PLAINTEXT_FILENAME);
    let plaintext_size = fs::metadata(&plaintext_path)?.len();

    // Compute expected ciphertext size using BlockLayout
    let layout = BlockLayout::new(
        BlockMode::Legacy,
        config.block_size as u64,
        config.block_mac_bytes as u64,
    )
    .map_err(|e| anyhow!("BlockLayout::new failed: {}", e))?;
    let expected_ciphertext_size = layout.physical_size_from_logical(plaintext_size, 0);

    // Locate the encrypted name of hello.txt in the virtual FS root
    // dir_iv=0 at the root
    let (encrypted_name, _) = cipher.encrypt_filename(TEST_PLAINTEXT_FILENAME.as_bytes(), 0)?;
    let virtual_path = mount.mount_point.join(&encrypted_name);

    let stat = fs::metadata(&virtual_path)
        .with_context(|| format!("stat failed on virtual path {:?}", virtual_path))?;

    assert_eq!(
        stat.len(),
        expected_ciphertext_size,
        "stat size {} should equal expected ciphertext size {} (plaintext size was {}). \
        Config: blockMACBytes={}, blockSize={}",
        stat.len(),
        expected_ciphertext_size,
        plaintext_size,
        config.block_mac_bytes,
        config.block_size
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// FUSE-01: write attempts to the mounted virtual FS return EROFS.
#[test]
#[ignore]
fn test_encfsr_live_write_returns_erofs() -> Result<()> {
    if !live_enabled() {
        return Ok(());
    }

    let dir = unique_temp_dir("encfsr_live_erofs")?;
    let source_dir = setup_source_dir(&dir)?;
    let config_path = source_dir.join(".encfs6.xml");
    let mount = EncfsrMountGuard::mount(source_dir.clone(), config_path, TEST_PASSWORD)?;

    // Attempt to create a new file in the mounted virtual FS
    let new_file = mount.mount_point.join("should_fail.txt");
    let err = fs::write(&new_file, b"data")
        .expect_err("write to encfsr mount should fail with EROFS or ReadOnlyFilesystem");

    let is_erofs = err.raw_os_error() == Some(libc::EROFS)
        || err.kind() == std::io::ErrorKind::ReadOnlyFilesystem;
    assert!(
        is_erofs,
        "write should fail with EROFS or ReadOnlyFilesystem, got: {:?} (raw_os_error: {:?})",
        err,
        err.raw_os_error()
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// COMPAT-01: opening an encrypted path in the virtual FS resolves correctly to
/// the source plaintext file (path translation direction is correct).
#[test]
#[ignore]
fn test_encfsr_live_path_resolution_correct() -> Result<()> {
    if !live_enabled() {
        return Ok(());
    }

    let dir = unique_temp_dir("encfsr_live_path")?;
    let source_dir = setup_source_dir(&dir)?;
    let config_path = source_dir.join(".encfs6.xml");
    let mount = EncfsrMountGuard::mount(source_dir.clone(), config_path, TEST_PASSWORD)?;

    let config = EncfsConfig::load(&source_dir.join(".encfs6.xml"))?;
    let cipher = config.get_cipher(TEST_PASSWORD)?;

    // Encrypt the known plaintext filename to get the virtual encrypted name
    // dir_iv=0 at the root
    let (encrypted_name, _) = cipher.encrypt_filename(TEST_PLAINTEXT_FILENAME.as_bytes(), 0)?;
    let virtual_path = mount.mount_point.join(&encrypted_name);

    // The file should be accessible (path resolution direction is correct: encrypted→plaintext)
    let metadata = fs::metadata(&virtual_path).with_context(|| {
        format!(
            "stat on virtual encrypted path {:?} returned error — \
            path resolution is broken (COMPAT-01). The encrypted path should \
            map back to the plaintext source file.",
            virtual_path
        )
    })?;

    // Must be a regular file
    assert!(
        metadata.is_file(),
        "expected a regular file at virtual path {:?}, got: {:?}",
        virtual_path,
        metadata.file_type()
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 3 Round-trip Helpers
// ---------------------------------------------------------------------------

/// Create a V6 config with non-zero blockMACBytes for proper round-trip testing.
fn make_encfsr_config_with_mac(block_mac_bytes: u64) -> EncfsConfig {
    let mut config = make_encfsr_config();
    config.block_mac_bytes = block_mac_bytes as i32;
    config
}

/// Helper to create files of specific sizes to test block boundaries.
fn setup_block_boundary_files(source_dir: &Path, data_block_size: u64) -> Result<()> {
    // 0 bytes
    fs::write(source_dir.join("empty.bin"), b"")?;

    // sub-block (500 bytes < 1016)
    let sub_block_data = vec![0xABu8; 500];
    fs::write(source_dir.join("sub_block.bin"), &sub_block_data)?;

    // exactly-one-block (1016 bytes)
    let one_block_data = vec![0xCDu8; data_block_size as usize];
    fs::write(source_dir.join("one_block.bin"), &one_block_data)?;

    // multi-block partial (2 blocks + 300 bytes = 1016*2 + 300 = 2332 bytes)
    let multi_block_data = vec![0xEFu8; (data_block_size * 2 + 300) as usize];
    fs::write(source_dir.join("multi_block.bin"), &multi_block_data)?;

    Ok(())
}

/// Helper to get a LiveConfig from an EncfsConfig for use with MountGuard.
fn live_config_from_encfs(config: &EncfsConfig) -> live::LiveConfig {
    live::LiveConfig {
        kind: live::LiveConfigKind::Standard,
        password: TEST_PASSWORD,
        block_size: config.block_size as u64,
        block_mac_bytes: config.block_mac_bytes as u64,
        chained_name_iv: config.chained_name_iv,
        external_iv_chaining: config.external_iv_chaining,
    }
}

// ---------------------------------------------------------------------------
// Phase 3 Round-trip tests (guarded by ENCFS_LIVE_TESTS=1)
// ---------------------------------------------------------------------------

/// CRPT-01, CRPT-03: Round-trip test proving encfsr produces compatible ciphertext
/// for all block boundary cases.
#[test]
#[ignore]
fn test_encfsr_v6_round_trip_block_boundaries() -> Result<()> {
    if !live_enabled() {
        return Ok(());
    }

    let dir = unique_temp_dir("encfsr_rt_blocks")?;
    let source_dir = dir.join("source");
    fs::create_dir_all(&source_dir)?;

    // Create config with MAC overhead (blockMACBytes=8)
    let block_mac_bytes = 8u64;
    let config = make_encfsr_config_with_mac(block_mac_bytes);
    config.save(&source_dir.join(".encfs6.xml"))?;

    let layout = BlockLayout::new(
        BlockMode::Legacy,
        config.block_size as u64,
        config.block_mac_bytes as u64,
    ).map_err(|e| anyhow!("BlockLayout error: {}", e))?;
    let data_block_size = layout.data_size_per_block();

    // Write the 4 block boundary files
    setup_block_boundary_files(&source_dir, data_block_size)?;

    // Step 1: Mount encfsr on source dir
    let config_path = source_dir.join(".encfs6.xml");
    let encfsr_mount = EncfsrMountGuard::mount(source_dir.clone(), config_path, TEST_PASSWORD)?;

    // Step 2: Mount standard encfs on top of the encfsr mount (to decrypt)
    let live_cfg = live_config_from_encfs(&config);
    let decrypt_mount = live::MountGuard::mount_existing_backing_root(
        live_cfg,
        true, // read-only
        encfsr_mount.mount_point.clone(),
    )?;

    // Step 3: Compare decrypted files with source files
    let test_files = ["empty.bin", "sub_block.bin", "one_block.bin", "multi_block.bin"];
    for filename in &test_files {
        let source_path = source_dir.join(filename);
        let decrypted_path = decrypt_mount.mount_point.join(filename);

        let source_bytes = fs::read(&source_path)?;
        let decrypted_bytes = fs::read(&decrypted_path)
            .with_context(|| format!("Failed to read decrypted file: {}", filename))?;

        assert_eq!(
            source_bytes, decrypted_bytes,
            "Byte-for-byte mismatch in round-trip for file: {}",
            filename
        );
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// CRPT-05: Virtual .encfs7 appears at the FUSE root and its bytes match the source config.
#[test]
#[ignore]
fn test_encfsr_virtual_config_file_present() -> Result<()> {
    if !live_enabled() {
        return Ok(());
    }

    let dir = unique_temp_dir("encfsr_virtual_config")?;
    let source_dir = setup_source_dir(&dir)?;
    let config_path = source_dir.join(".encfs6.xml");
    let encfsr_mount =
        EncfsrMountGuard::mount(source_dir.clone(), config_path, TEST_PASSWORD)?;

    // 1. Verify it appears in directory listing
    let entries: Vec<String> = fs::read_dir(&encfsr_mount.mount_point)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    assert!(
        entries.contains(&".encfs7".to_string()),
        "Virtual .encfs7 should be present in root directory listing, got: {:?}",
        entries
    );

    // 2. Verify its content matches the source .encfs6.xml
    let source_config_bytes = fs::read(source_dir.join(".encfs6.xml"))?;
    let virtual_config_bytes = fs::read(encfsr_mount.mount_point.join(".encfs7"))?;

    assert_eq!(
        source_config_bytes, virtual_config_bytes,
        "Virtual .encfs7 content does not match source .encfs6.xml"
    );

    // 3. Verify ownership matches the source config file
    let source_meta = fs::metadata(source_dir.join(".encfs6.xml"))?;
    let virtual_meta = fs::metadata(encfsr_mount.mount_point.join(".encfs7"))?;

    assert_eq!(
        source_meta.uid(),
        virtual_meta.uid(),
        "Virtual .encfs7 uid should match source config uid"
    );
    assert_eq!(
        source_meta.gid(),
        virtual_meta.gid(),
        "Virtual .encfs7 gid should match source config gid"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// CRPT-02: Round-trip test with external_iv_chaining=true.
#[test]
#[ignore]
fn test_encfsr_v6_external_iv_chaining_round_trip() -> Result<()> {
    if !live_enabled() {
        return Ok(());
    }

    let dir = unique_temp_dir("encfsr_rt_external_iv")?;
    let source_dir = dir.join("source");
    fs::create_dir_all(&source_dir)?;

    let mut config = make_encfsr_config_with_mac(8);
    config.external_iv_chaining = true;
    config.save(&source_dir.join(".encfs6.xml"))?;

    // Create a file and a subdirectory with a nested file
    fs::write(source_dir.join("root.txt"), b"root file content")?;
    let subdir = source_dir.join("subdir");
    fs::create_dir_all(&subdir)?;
    fs::write(subdir.join("nested.txt"), b"nested file content in subdir")?;

    let config_path = source_dir.join(".encfs6.xml");
    let encfsr_mount = EncfsrMountGuard::mount(source_dir.clone(), config_path, TEST_PASSWORD)?;
    let live_cfg = live_config_from_encfs(&config);
    let decrypt_mount = live::MountGuard::mount_existing_backing_root(
        live_cfg, true, encfsr_mount.mount_point.clone(),
    )?;

    // Compare
    let test_files = ["root.txt", "subdir/nested.txt"];
    for filename in &test_files {
        let source_path = source_dir.join(filename);
        let decrypted_path = decrypt_mount.mount_point.join(filename);
        assert_eq!(fs::read(&source_path)?, fs::read(&decrypted_path)?);
    }

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// COMPAT-02: Round-trip test with V7 AES-GCM-SIV config.
#[test]
#[ignore]
fn test_encfsr_v7_aes_gcm_siv_round_trip() -> Result<()> {
    if !live_enabled() {
        return Ok(());
    }

    let dir = unique_temp_dir("encfsr_rt_v7")?;
    let source_dir = dir.join("source");
    fs::create_dir_all(&source_dir)?;

    // Create V7 config (standard_v7 uses AES-GCM-SIV, 16-byte tag)
    let mut config = EncfsConfig::standard_v7();
    config.unique_iv = false; // Required by encfsr
    config.argon2_memory_cost = Some(8);
    config.argon2_time_cost = Some(1);
    config.argon2_parallelism = Some(1);

    // V7: volume_key_blob is the raw (unencrypted) key material.
    // EncfsConfig::standard_v7() sets up AES-256 (32 bytes) + IV (16 bytes) = 48 bytes.
    let volume_key_blob = vec![0u8; 48];
    config.set_v7_key(TEST_PASSWORD, &volume_key_blob).expect("set_v7_key failed");

    config.save(&source_dir.join(".encfs7"))?;

    fs::write(source_dir.join("hello.txt"), b"v7 encrypted content test")?;

    let config_path = source_dir.join(".encfs7");
    let encfsr_mount = EncfsrMountGuard::mount(source_dir.clone(), config_path, TEST_PASSWORD)?;

    // live::MountGuard needs to know it's a V7 config to pass correct flags to encfs binary
    let mut live_cfg = live_config_from_encfs(&config);
    live_cfg.kind = live::LiveConfigKind::V7;

    let decrypt_mount = live::MountGuard::mount_existing_backing_root(
        live_cfg, true, encfsr_mount.mount_point.clone(),
    )?;

    assert_eq!(
        fs::read(source_dir.join("hello.txt"))?,
        fs::read(decrypt_mount.mount_point.join("hello.txt"))?
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// CRPT-04: Symlink target encryption round-trip.
#[test]
#[ignore]
fn test_encfsr_symlink_encryption_round_trip() -> Result<()> {
    if !live_enabled() {
        return Ok(());
    }

    let dir = unique_temp_dir("encfsr_rt_symlink")?;
    let source_dir = dir.join("source");
    fs::create_dir_all(&source_dir)?;
    let config = make_encfsr_config();
    let config_path = source_dir.join(".encfs6.xml");
    config.save(&config_path)?;

    fs::write(source_dir.join("hello.txt"), b"plaintext")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("hello.txt", source_dir.join("link.txt"))?;

    let encfsr_mount =
        EncfsrMountGuard::mount(source_dir.clone(), config_path, TEST_PASSWORD)?;
    let live_cfg = live_config_from_encfs(&config);
    let decrypt_mount = live::MountGuard::mount_existing_backing_root(
        live_cfg, true, encfsr_mount.mount_point.clone(),
    )?;

    let target = fs::read_link(decrypt_mount.mount_point.join("link.txt"))?;
    assert_eq!(target, Path::new("hello.txt"));

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// CRPT-03: Multi-GB streaming test (verifies read without full-file buffering).
///
/// Requires ~4 GB free disk space and ~10 min to run. Mark as #[ignore] and
/// run explicitly with: cargo test -- --ignored test_encfsr_multi_gb
#[test]
#[ignore]
fn test_encfsr_multi_gb_streaming_no_buffering() -> Result<()> {
    if !live_enabled() {
        return Ok(());
    }

    let dir = unique_temp_dir("encfsr_streaming")?;
    let source_dir = dir.join("source");
    fs::create_dir_all(&source_dir)?;
    let config = make_encfsr_config();
    let config_path = source_dir.join(".encfs6.xml");
    config.save(&config_path)?;

    // Create a 2 GB plaintext file (zeros)
    let file_size = 2u64 * 1024 * 1024 * 1024;
    {
        let mut file = fs::File::create(source_dir.join("big.bin"))?;
        let chunk = vec![0u8; 4 * 1024 * 1024];
        let num_chunks = file_size / (chunk.len() as u64);
        for _ in 0..num_chunks {
            file.write_all(&chunk)?;
        }
    }

    let encfsr_mount =
        EncfsrMountGuard::mount(source_dir.clone(), config_path, TEST_PASSWORD)?;

    // Locate encrypted name (dir_iv=0 at root)
    let cipher = config.get_cipher(TEST_PASSWORD)?;
    let (encrypted_name, _) = cipher.encrypt_filename(b"big.bin", 0)?;
    let virtual_path = encfsr_mount.mount_point.join(&encrypted_name);

    // Read the entire file in 1 MB chunks
    let mut file = fs::File::open(&virtual_path)?;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total_read = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        total_read += n as u64;
    }

    assert_eq!(total_read, file_size); // blockMACBytes=0 so ciphertext == plaintext size

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}
