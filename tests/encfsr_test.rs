mod live;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn encfsr_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_encfsr"))
}

/// Write a minimal V6 XML config to `.encfs6.xml` in `dir`.
/// unique_iv: true = <uniqueIV>1</uniqueIV>, false = <uniqueIV>0</uniqueIV>
/// chained_name_iv: true = <chainedNameIV>1</chainedNameIV>
///
/// Note: The encoded key in this fixture is from tests/unique_iv_check.rs.
/// When unique_iv=0, the library's validate() rejects the config before
/// attempting decryption, so the password never matters for that case.
#[allow(dead_code)]
fn write_test_config(dir: &std::path::Path, unique_iv: bool) {
    let unique_iv_val = if unique_iv { 1 } else { 0 };
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE boost_serialization>
<boost_serialization signature="serialization::archive" version="7">
    <cfg class_id="0" tracking_level="0" version="20">
        <version>20100713</version>
        <creator>EncFS Test</creator>
        <cipherAlg class_id="1" tracking_level="0" version="0">
            <name>ssl/aes</name>
            <major>3</major>
            <minor>0</minor>
        </cipherAlg>
        <nameAlg>
            <name>nameio/block</name>
            <major>4</major>
            <minor>0</minor>
        </nameAlg>
        <keySize>192</keySize>
        <blockSize>1024</blockSize>
        <plainData>0</plainData>
        <uniqueIV>{unique_iv_val}</uniqueIV>
        <chainedNameIV>1</chainedNameIV>
        <externalIVChaining>0</externalIVChaining>
        <blockMACBytes>0</blockMACBytes>
        <blockMACRandBytes>0</blockMACRandBytes>
        <allowHoles>1</allowHoles>
        <encodedKeySize>44</encodedKeySize>
        <encodedKeyData>
+qPhkOEwsxhmeghgGYlexofVLdT39dHDAW0MSNV0xPoeMa4qBihM1X9FdD4=
        </encodedKeyData>
        <saltLen>20</saltLen>
        <saltData>
tccFKejCQQ9w0b9oEaATUZ0eFWE=
        </saltData>
        <kdfIterations>500000</kdfIterations>
        <desiredKDFDuration>500</desiredKDFDuration>
    </cfg>
</boost_serialization>
"#
    );
    let config_path = dir.join(".encfs6.xml");
    let mut f = std::fs::File::create(&config_path).expect("failed to create test config");
    f.write_all(xml.as_bytes())
        .expect("failed to write test config");
}

/// Copy the standard fixture config (uniqueIV=1, password="test") into `dir`.
#[allow(dead_code)]
fn copy_std_fixture(dir: &std::path::Path) {
    let fixture_path = live::fixtures_dir().join("encfs6-std.xml");
    std::fs::copy(&fixture_path, dir.join(".encfs6.xml"))
        .expect("failed to copy encfs6-std.xml fixture");
}

/// Create a minimal V7 config for encfsr tests. Saves to `path` (e.g. `dir.join("config.encfs7")`).
/// `unique_iv` and `password` are set as given; volume key is zeros (test only).
fn write_v7_config(path: &Path, unique_iv: bool, password: &str) {
    use encfs::config::EncfsConfig;

    let mut config = EncfsConfig::standard_v7();
    config.unique_iv = unique_iv;
    // Volume key blob: 32-byte key + 16-byte IV (AES-256, stream cipher IV)
    let volume_key_blob = vec![0u8; 32 + 16];
    config
        .set_v7_key(password, &volume_key_blob)
        .expect("set_v7_key failed");
    config.save(path).expect("save V7 config failed");
}

/// Create a valid V6 encfsr-compatible config in `dir/.encfs6.xml`.
///
/// The config has:
/// - uniqueIV=0 (required by encfsr)
/// - chainedNameIV=1
/// - blockMACBytes=0 (ciphertext size = plaintext size)
/// - blockSize=1024
/// - keySize=192 (AES-192)
/// - kdfIterations=1 (fast, for tests only)
/// - password: `password`
///
/// Returns the password used. Call with `password = "encfsr_test"` or similar.
#[allow(dead_code)]
fn write_valid_encfsr_config(dir: &Path, password: &str) {
    use encfs::config::{ConfigType, EncfsConfig, Interface, KdfAlgorithm};
    use encfs::crypto::ssl::SslCipher;

    let salt: Vec<u8> = (1u8..=20).collect(); // deterministic test salt
    let key_size = 192i32;
    let block_size = 1024i32;

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

    // Derive user key with PBKDF2
    let mut temp_cipher = SslCipher::new(&cipher_iface, key_size).expect("failed to create cipher");
    temp_cipher.set_name_encoding(&name_iface);
    let key_len = (key_size / 8) as usize;
    let iv_len = temp_cipher.iv_len();
    let user_key_len = key_len + iv_len;

    let user_key_blob =
        SslCipher::derive_key(password, &salt, 1, user_key_len).expect("PBKDF2 failed");
    let user_key = &user_key_blob[..key_len];
    let user_iv = &user_key_blob[key_len..];

    // Create a deterministic volume key (all zeros for test reproducibility)
    let volume_key = vec![0u8; key_len];
    let volume_iv = vec![0u8; iv_len];
    let mut volume_blob = Vec::with_capacity(key_len + iv_len);
    volume_blob.extend_from_slice(&volume_key);
    volume_blob.extend_from_slice(&volume_iv);

    // Encrypt the volume key blob
    let encrypted_key = temp_cipher
        .encrypt_key(&volume_blob, user_key, user_iv)
        .expect("encrypt_key failed");

    // Build EncfsConfig
    let config = EncfsConfig {
        config_type: ConfigType::V6,
        creator: "encfsr-test".to_string(),
        version: 20100713,
        cipher_iface: cipher_iface.clone(),
        name_iface: name_iface.clone(),
        key_size,
        block_size,
        key_data: encrypted_key,
        salt: salt.clone(),
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
    };

    let config_path = dir.join(".encfs6.xml");
    config
        .save(&config_path)
        .expect("failed to save encfsr test config");
}

/// Run encfsr with the given args, optionally piping `stdin_data` to stdin.
/// Returns (exit_status_success, stdout, stderr).
fn run_encfsr(args: &[&str], stdin_data: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(encfsr_bin());
    for arg in args {
        cmd.arg(arg);
    }

    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn encfsr");

    if let Some(data) = stdin_data {
        let mut stdin = child.stdin.take().expect("failed to get stdin");
        stdin
            .write_all(data.as_bytes())
            .expect("failed to write to stdin");
        // stdin is dropped here, closing the pipe
    }

    let output = child.wait_with_output().expect("failed to wait for encfsr");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (output.status.success(), stdout, stderr)
}

#[test]
fn test_encfsr_help() {
    let (success, stdout, stderr) = run_encfsr(&["--help"], None);
    assert!(
        success,
        "encfsr --help should exit 0. stdout: {stdout}, stderr: {stderr}"
    );
}

#[test]
fn test_encfsr_version() {
    let (success, stdout, stderr) = run_encfsr(&["--version"], None);
    assert!(
        success,
        "encfsr --version should exit 0. stdout: {stdout}, stderr: {stderr}"
    );
    // Version string should contain at least one digit
    assert!(
        stdout.chars().any(|c| c.is_ascii_digit()),
        "encfsr --version should print a version number. stdout: {stdout}"
    );
}

#[test]
fn test_encfsr_missing_source_dir() {
    let dir =
        live::unique_temp_dir("encfsr_test_missing_source").expect("failed to create temp dir");
    let config_path = dir.join("config.encfs7");
    let nonexistent = dir.join("nonexistent_source");
    let mount_dir = dir.join("mnt");

    write_v7_config(&config_path, false, "test");

    let (success, _stdout, stderr) = run_encfsr(
        &[
            config_path.to_str().unwrap(),
            nonexistent.to_str().unwrap(),
            mount_dir.to_str().unwrap(),
        ],
        None,
    );

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !success,
        "encfsr with nonexistent source should exit 1. stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr should contain 'error:'. stderr: {stderr}"
    );
    assert!(
        stderr.contains(nonexistent.to_str().unwrap()),
        "stderr should contain the failing path. stderr: {stderr}"
    );
}

#[test]
fn test_encfsr_no_config_file() {
    let dir = live::unique_temp_dir("encfsr_test_no_config").expect("failed to create temp dir");
    let source_dir = dir.join("source");
    let mount_dir = dir.join("mnt");
    let config_path = source_dir.join(".encfs6.xml"); // does not exist
    std::fs::create_dir_all(&source_dir).expect("failed to create source dir");

    let (success, _stdout, stderr) = run_encfsr(
        &[
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            mount_dir.to_str().unwrap(),
        ],
        None,
    );

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !success,
        "encfsr with no config file should exit 1. stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr should contain 'error:'. stderr: {stderr}"
    );
    assert!(
        stderr.contains(source_dir.to_str().unwrap()),
        "stderr should contain the source path (config path is under source). stderr: {stderr}"
    );
}

#[test]
fn test_encfsr_rejects_unique_iv_true() {
    // V7 config with uniqueIV=1; encfsr loads it, then CONF-01 check fires.
    let dir = live::unique_temp_dir("encfsr_test_rejects_uiv").expect("failed to create temp dir");
    let source_dir = dir.join("source");
    let mount_dir = dir.join("mnt");
    let config_path = dir.join("config.encfs7");
    std::fs::create_dir_all(&source_dir).expect("failed to create source dir");

    write_v7_config(&config_path, true, "test");

    let (success, _stdout, stderr) = run_encfsr(
        &[
            "--stdinpass",
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            mount_dir.to_str().unwrap(),
        ],
        Some("test\n"),
    );

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !success,
        "encfsr with uniqueIV=1 config should exit 1. stderr: {stderr}"
    );
    assert!(
        stderr.contains("error: unique_iv = true is not supported"),
        "stderr should contain the CONF-01 rejection message. stderr: {stderr}"
    );
}

#[test]
fn test_encfsr_allows_chained_name_iv() {
    // V7 config with uniqueIV=0; encfsr accepts it (CONF-02: no CONF-01 message).
    let dir = live::unique_temp_dir("encfsr_test_chained_iv").expect("failed to create temp dir");
    let source_dir = dir.join("source");
    let mount_dir = dir.join("mnt");
    let config_path = dir.join("config.encfs7");
    std::fs::create_dir_all(&source_dir).expect("failed to create source dir");

    write_v7_config(&config_path, false, "test");

    let (_success, _stdout, stderr) = run_encfsr(
        &[
            "--stdinpass",
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            mount_dir.to_str().unwrap(),
        ],
        Some("test\n"),
    );

    let _ = std::fs::remove_dir_all(&dir);

    // The critical CONF-02 assertion: encfsr must NOT report the CONF-01 message
    // for a config that has uniqueIV=0.
    assert!(
        !stderr.contains("unique_iv = true is not supported"),
        "encfsr with uniqueIV=0 should NOT report the CONF-01 unique_iv message. stderr: {stderr}"
    );
}

#[test]
fn test_encfsr_fuse_opts_accepted() {
    // encfsr <config> <source> <mnt> -o allow_other: clap must accept trailing -o allow_other,
    // then we fail on the missing source (not on a parse error).
    let dir = live::unique_temp_dir("encfsr_test_fuse_opts").expect("failed to create temp dir");
    let config_path = dir.join("config.encfs7");
    let nonexistent = dir.join("nonexistent_source");
    let mount_dir = dir.join("mnt");

    write_v7_config(&config_path, false, "test");

    let (success, _stdout, stderr) = run_encfsr(
        &[
            config_path.to_str().unwrap(),
            nonexistent.to_str().unwrap(),
            mount_dir.to_str().unwrap(),
            "--",
            "-o",
            "allow_other",
        ],
        None,
    );

    let _ = std::fs::remove_dir_all(&dir);

    // Should exit 1 (nonexistent source), but not due to clap parse error
    assert!(
        !success,
        "encfsr with nonexistent source should exit 1. stderr: {stderr}"
    );
    assert!(
        !stderr.contains("unrecognized"),
        "stderr should NOT contain 'unrecognized' (clap parse error). stderr: {stderr}"
    );
    assert!(
        !stderr.contains("unexpected argument"),
        "stderr should NOT contain 'unexpected argument' (clap parse error). stderr: {stderr}"
    );
    assert!(
        stderr.contains("error:"),
        "stderr should contain 'error:' (source validation error). stderr: {stderr}"
    );
}

#[test]
fn test_encfsr_proceeds_to_mount_attempt() {
    // Phase 2 regression test: encfsr with a valid V7 uniqueIV=0 config should
    // attempt to mount (and fail at fuse_mt::mount due to nonexistent mount point),
    // rather than printing the Phase 1 "not yet implemented" placeholder.
    //
    // The critical assertion: stderr does NOT contain "not yet implemented".
    let dir =
        live::unique_temp_dir("encfsr_test_mount_attempt").expect("failed to create temp dir");
    let source_dir = dir.join("source");
    let config_path = dir.join("config.encfs7");
    let mount_dir = dir.join("mnt");
    std::fs::create_dir_all(&source_dir).expect("failed to create source dir");

    write_v7_config(&config_path, false, "encfsr_test");

    let (_success, _stdout, stderr) = run_encfsr(
        &[
            "--stdinpass",
            config_path.to_str().unwrap(),
            source_dir.to_str().unwrap(),
            mount_dir.to_str().unwrap(),
        ],
        Some("encfsr_test\n"),
    );

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !stderr.contains("not yet implemented"),
        "encfsr should no longer print the Phase 1 placeholder. stderr: {stderr}"
    );
}
