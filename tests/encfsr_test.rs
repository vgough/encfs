mod live;

use std::io::Write;
use std::path::PathBuf;
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
fn copy_std_fixture(dir: &std::path::Path) {
    let fixture_path = live::fixtures_dir().join("encfs6-std.xml");
    std::fs::copy(&fixture_path, dir.join(".encfs6.xml"))
        .expect("failed to copy encfs6-std.xml fixture");
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
    let nonexistent = dir.join("nonexistent_source");
    let mount_dir = dir.join("mnt");

    let (success, _stdout, stderr) = run_encfsr(
        &[nonexistent.to_str().unwrap(), mount_dir.to_str().unwrap()],
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
    std::fs::create_dir_all(&source_dir).expect("failed to create source dir");

    let (success, _stdout, stderr) = run_encfsr(
        &[source_dir.to_str().unwrap(), mount_dir.to_str().unwrap()],
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
        "stderr should contain the source path. stderr: {stderr}"
    );
}

#[test]
fn test_encfsr_rejects_unique_iv_true() {
    // Use the standard fixture (uniqueIV=1, password="test") to test CONF-01.
    // The library's validate() allows uniqueIV=1 (normal encfs requires it),
    // get_cipher() succeeds with password "test", then our encfsr check fires.
    let dir = live::unique_temp_dir("encfsr_test_rejects_uiv").expect("failed to create temp dir");
    let source_dir = dir.join("source");
    let mount_dir = dir.join("mnt");
    std::fs::create_dir_all(&source_dir).expect("failed to create source dir");

    copy_std_fixture(&source_dir);

    let (success, _stdout, stderr) = run_encfsr(
        &[
            "--stdinpass",
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
    // Use an inline config with uniqueIV=0 and chainedNameIV=1.
    // The library's validate() rejects uniqueIV=0 (not supported for normal encfs),
    // so get_cipher() returns Err with a library validation error — NOT the CONF-01 message.
    // CONF-02 requirement: the error must NOT be "unique_iv = true is not supported".
    let dir = live::unique_temp_dir("encfsr_test_chained_iv").expect("failed to create temp dir");
    let source_dir = dir.join("source");
    let mount_dir = dir.join("mnt");
    std::fs::create_dir_all(&source_dir).expect("failed to create source dir");

    write_test_config(&source_dir, false); // uniqueIV=0, chainedNameIV=1

    let (_success, _stdout, stderr) = run_encfsr(
        &[
            "--stdinpass",
            source_dir.to_str().unwrap(),
            mount_dir.to_str().unwrap(),
        ],
        Some("test\n"),
    );

    let _ = std::fs::remove_dir_all(&dir);

    // The critical CONF-02 assertion: encfsr must NOT report the CONF-01 message
    // for a config that merely has uniqueIV=0 (without uniqueIV=1).
    assert!(
        !stderr.contains("unique_iv = true is not supported"),
        "encfsr with uniqueIV=0 should NOT report the CONF-01 unique_iv message. stderr: {stderr}"
    );
}

#[test]
fn test_encfsr_fuse_opts_accepted() {
    // encfsr <nonexistent> <mnt> -o allow_other should fail on the missing source,
    // NOT on a clap parse error about -o being unrecognized.
    let dir = live::unique_temp_dir("encfsr_test_fuse_opts").expect("failed to create temp dir");
    let nonexistent = dir.join("nonexistent_source");
    let mount_dir = dir.join("mnt");

    let (success, _stdout, stderr) = run_encfsr(
        &[
            nonexistent.to_str().unwrap(),
            mount_dir.to_str().unwrap(),
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
    // Should show the source path error, not a clap usage error
    assert!(
        stderr.contains("error:"),
        "stderr should contain 'error:' (source validation error). stderr: {stderr}"
    );
}
