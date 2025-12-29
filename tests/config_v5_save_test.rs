use anyhow::Result;
use encfs::config::{ConfigType, EncfsConfig};
use std::fs;
use std::path::Path;

#[test]
fn test_v5_config_save_errors_correctly() -> Result<()> {
    // This test verifies that we don't silently save V5 configs to .encfs6.xml
    // when the version number implies a newer version.

    // Setup - use the V5 fixture
    let fixture_path = Path::new("tests/fixtures/encfs142/.encfs5");
    if !fixture_path.exists() {
        println!("Skipping test: fixture not found");
        return Ok(());
    }

    let temp_dir = std::env::temp_dir().join(format!("encfs_v5_save_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir)?;
    let config_path = temp_dir.join(".encfs5");
    fs::copy(fixture_path, &config_path)?;

    // Load the V5 config
    let mut config = EncfsConfig::load(&config_path)?;
    assert_eq!(config.config_type, ConfigType::V5);

    // Simulate a newer version that triggered the bug
    config.version = 20100713;

    // Attempt to save
    let result = config.save(&config_path);

    // Check 1: We strongly expect an error because V5 writing is not implemented
    assert!(result.is_err(), "Save should fail for V5 config");
    let err = result.err().unwrap();
    assert!(
        err.to_string().contains("not yet implemented"),
        "Error should be about unimplemented V5 save, got: {}",
        err
    );

    // Check 2: We must NOT have created .encfs6.xml silently
    let xml_path = temp_dir.join(".encfs6.xml");
    assert!(
        !xml_path.exists(),
        "Should not silently save to .encfs6.xml"
    );

    // Check 3: The original file should not have been overwritten with XML
    // (Though since it failed, it shouldn't have been touched, but verifying it's still binary/unchanged is good)
    let content = fs::read(&config_path)?;
    // V5 config doesn't start with XML tag
    assert!(!String::from_utf8_lossy(&content).starts_with("<?xml"));

    // Cleanup
    let _ = fs::remove_dir_all(temp_dir);

    Ok(())
}
