use anyhow::Result;
use encfs::config::{ConfigType, EncfsConfig, Interface, KdfAlgorithm};
use encfs::constants::{
    DEFAULT_ARGON2_MEMORY_COST, DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_TIME_COST,
};
use encfs::crypto::ssl::SslCipher;
use std::fs;
use std::path::PathBuf;

/// Test creating and loading a config with Argon2id KDF
#[test]
fn test_argon2id_config_creation_and_loading() -> Result<()> {
    let password = "test_password_123";

    // Create cipher interface
    let cipher_iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };

    // Create cipher for key generation
    let cipher = SslCipher::new(&cipher_iface, 256)?;
    let key_len = 32; // 256 bits / 8
    let iv_len = cipher.iv_len();
    let user_key_len = key_len + iv_len;

    // Generate salt
    let salt = b"test_salt_20bytes!!".to_vec();

    // Derive user key using Argon2id
    let user_key_blob = SslCipher::derive_key_argon2id(
        password,
        &salt,
        DEFAULT_ARGON2_MEMORY_COST,
        DEFAULT_ARGON2_TIME_COST,
        DEFAULT_ARGON2_PARALLELISM,
        user_key_len,
    )?;

    let user_key = &user_key_blob[..key_len];
    let user_iv = &user_key_blob[key_len..];

    // Create volume key
    let volume_key = vec![0x42u8; key_len];
    let volume_iv = vec![0x24u8; iv_len];
    let mut volume_blob = Vec::with_capacity(key_len + iv_len);
    volume_blob.extend_from_slice(&volume_key);
    volume_blob.extend_from_slice(&volume_iv);

    // Encrypt volume key
    let encrypted_key = cipher.encrypt_key(&volume_blob, user_key, user_iv)?;

    // Create config with Argon2id
    let config = EncfsConfig {
        config_type: ConfigType::V6,
        creator: "EncFS 2.0.0-alpha.1".to_string(),
        version: 20100713,
        cipher_iface: cipher_iface.clone(),
        name_iface: Interface {
            name: "nameio/block".to_string(),
            major: 4,
            minor: 0,
            age: 0,
        },
        key_size: 256,
        block_size: 1024,
        key_data: encrypted_key,
        salt: salt.clone(),
        kdf_iterations: 0, // Not used for Argon2
        desired_kdf_duration: 500,
        kdf_algorithm: KdfAlgorithm::Argon2id,
        argon2_memory_cost: Some(DEFAULT_ARGON2_MEMORY_COST),
        argon2_time_cost: Some(DEFAULT_ARGON2_TIME_COST),
        argon2_parallelism: Some(DEFAULT_ARGON2_PARALLELISM),
        plain_data: false,
        block_mac_bytes: 8,
        block_mac_rand_bytes: 0,
        unique_iv: true,
        external_iv_chaining: false,
        chained_name_iv: true,
        allow_holes: true,
    };

    // Save config to temp file
    let temp_dir = std::env::temp_dir();
    let config_path = temp_dir.join(format!("argon2_test_{}.xml", std::process::id()));
    config.save(&config_path)?;

    // Load config back
    let loaded_config = EncfsConfig::load(&config_path)?;

    // Verify loaded config has Argon2id settings
    assert_eq!(loaded_config.kdf_algorithm, KdfAlgorithm::Argon2id);
    assert_eq!(
        loaded_config.argon2_memory_cost,
        Some(DEFAULT_ARGON2_MEMORY_COST)
    );
    assert_eq!(
        loaded_config.argon2_time_cost,
        Some(DEFAULT_ARGON2_TIME_COST)
    );
    assert_eq!(
        loaded_config.argon2_parallelism,
        Some(DEFAULT_ARGON2_PARALLELISM)
    );

    // Verify we can get cipher with correct password
    let loaded_cipher = loaded_config.get_cipher(password)?;
    assert!(loaded_cipher.iv_len() > 0);

    // Verify wrong password fails
    assert!(loaded_config.get_cipher("wrong_password").is_err());

    // Cleanup
    let _ = fs::remove_file(config_path);

    Ok(())
}

/// Test backward compatibility - PBKDF2 configs should still work
#[test]
fn test_pbkdf2_backward_compatibility() -> Result<()> {
    let fixture_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/encfs6-std.xml");

    if !fixture_path.exists() {
        // Skip if fixture not available
        return Ok(());
    }

    // Load existing PBKDF2 config
    let config = EncfsConfig::load(&fixture_path)?;

    // Should default to PBKDF2
    assert_eq!(config.kdf_algorithm, KdfAlgorithm::Pbkdf2);
    assert!(config.kdf_iterations > 0);
    assert_eq!(config.argon2_memory_cost, None);
    assert_eq!(config.argon2_time_cost, None);
    assert_eq!(config.argon2_parallelism, None);

    Ok(())
}

/// Test that Argon2id produces different keys with different parameters
#[test]
fn test_argon2_parameter_sensitivity() -> Result<()> {
    let password = "test_password";
    let salt = b"test_salt_20bytes!!";
    let key_len = 32;

    // Base key
    let key1 = SslCipher::derive_key_argon2id(
        password,
        salt,
        DEFAULT_ARGON2_MEMORY_COST,
        DEFAULT_ARGON2_TIME_COST,
        DEFAULT_ARGON2_PARALLELISM,
        key_len,
    )?;

    // Different memory cost
    let key2 = SslCipher::derive_key_argon2id(
        password,
        salt,
        DEFAULT_ARGON2_MEMORY_COST / 2,
        DEFAULT_ARGON2_TIME_COST,
        DEFAULT_ARGON2_PARALLELISM,
        key_len,
    )?;

    // Different time cost
    let key3 = SslCipher::derive_key_argon2id(
        password,
        salt,
        DEFAULT_ARGON2_MEMORY_COST,
        DEFAULT_ARGON2_TIME_COST + 1,
        DEFAULT_ARGON2_PARALLELISM,
        key_len,
    )?;

    // All keys should be different
    assert_ne!(
        key1, key2,
        "Different memory cost should produce different key"
    );
    assert_ne!(
        key1, key3,
        "Different time cost should produce different key"
    );
    assert_ne!(
        key2, key3,
        "Different parameters should produce different keys"
    );

    Ok(())
}
