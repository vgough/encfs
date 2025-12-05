mod live;

use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_missing_config_returns_error() {
    // If we can't find the binary, we can't run the test.
    // This replicates logic from live/mod.rs but simplifies it.
    let encfs_bin = std::env::var("CARGO_BIN_EXE_encfs")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            // Fallback for when running via cargo test not finding the env var (unlikely in recent cargo)
            Some(PathBuf::from(env!("CARGO_BIN_EXE_encfs")))
        })
        .expect("Could not find encfs binary");

    // Use a unique temp dir for this test
    let root = live::unique_temp_dir("config_check_missing").expect("Failed to create temp dir");
    let mount_point = root.join("mnt");
    let backing = root.join("backing");

    std::fs::create_dir(&mount_point).expect("failed to create mount point");
    std::fs::create_dir(&backing).expect("failed to create backing dir");

    // Run encfs -f <backing> <mount_point>
    let output = Command::new(&encfs_bin)
        .arg("-f")
        .arg(&backing)
        .arg(&mount_point)
        .output()
        .expect("Failed to run encfs");

    // Clean up
    let _ = std::fs::remove_dir_all(&root);

    // It should fail because no config file exists in `backing`.
    // Currently (before fix), this asserts false (it succeeds).
    assert!(
        !output.status.success(),
        "encfs should fail (exit non-zero) if no config file is found. Stdout: {}, Stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
