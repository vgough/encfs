use anyhow::Result;
use encfs::config::{ConfigType, EncfsConfig, Interface, KdfAlgorithm};
use encfs::constants::{
    DEFAULT_ARGON2_MEMORY_COST, DEFAULT_ARGON2_PARALLELISM, DEFAULT_ARGON2_TIME_COST,
};
use encfs::crypto::ssl::SslCipher;
use std::fs;

/// Test that a PBKDF2 config can be upgraded to Argon2id
#[test]
fn test_upgrade_pbkdf2_to_argon2() -> Result<()> {
    let password = "test_password_123";
    let new_password = "new_password_456";

    // Create cipher interface
    let cipher_iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };

    // Create initial PBKDF2 config
    let cipher = SslCipher::new(&cipher_iface, 192)?;
    let key_len = 24; // 192 bits / 8
    let iv_len = cipher.iv_len();
    let user_key_len = key_len + iv_len;

    // Generate salt
    let salt = b"test_salt_20bytes!!".to_vec();
    let kdf_iterations = 100_000;

    // Derive user key using PBKDF2
    let user_key_blob = SslCipher::derive_key(password, &salt, kdf_iterations, user_key_len)?;

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

    // Create PBKDF2 config
    let mut config = EncfsConfig {
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
        key_size: 192,
        block_size: 1024,
        key_data: encrypted_key,
        salt: salt.clone(),
        kdf_iterations,
        desired_kdf_duration: 500,
        kdf_algorithm: KdfAlgorithm::Pbkdf2,
        argon2_memory_cost: None,
        argon2_time_cost: None,
        argon2_parallelism: None,
        plain_data: false,
        block_mac_bytes: 8,
        block_mac_rand_bytes: 0,
        unique_iv: true,
        external_iv_chaining: false,
        chained_name_iv: true,
        allow_holes: true,
        config_hash: None,
    };

    // Verify original config uses PBKDF2
    assert_eq!(config.kdf_algorithm, KdfAlgorithm::Pbkdf2);
    assert_eq!(config.argon2_memory_cost, None);

    // Verify we can decrypt with PBKDF2
    let _original_cipher = config.get_cipher(password)?;

    // Simulate passwd --upgrade: decrypt with old password, then re-encrypt with Argon2

    // 1. Decrypt volume key with old password (PBKDF2)
    let old_user_key_blob =
        SslCipher::derive_key(password, &config.salt, config.kdf_iterations, user_key_len)?;
    let old_user_key = &old_user_key_blob[..key_len];
    let old_user_iv = &old_user_key_blob[key_len..];

    let decrypted_volume_blob = cipher.decrypt_key(&config.key_data, old_user_key, old_user_iv)?;

    // 2. Generate new salt for Argon2
    use openssl::rand::rand_bytes;
    let mut new_salt = vec![0u8; 20];
    rand_bytes(&mut new_salt)?;

    // 3. Upgrade to Argon2id
    config.kdf_algorithm = KdfAlgorithm::Argon2id;
    config.argon2_memory_cost = Some(DEFAULT_ARGON2_MEMORY_COST);
    config.argon2_time_cost = Some(DEFAULT_ARGON2_TIME_COST);
    config.argon2_parallelism = Some(DEFAULT_ARGON2_PARALLELISM);
    config.salt = new_salt.clone();

    // 4. Derive new user key with Argon2id
    let new_user_key_blob = SslCipher::derive_key_argon2id(
        new_password,
        &new_salt,
        DEFAULT_ARGON2_MEMORY_COST,
        DEFAULT_ARGON2_TIME_COST,
        DEFAULT_ARGON2_PARALLELISM,
        user_key_len,
    )?;

    let new_user_key = &new_user_key_blob[..key_len];
    let new_user_iv = &new_user_key_blob[key_len..];

    // 5. Re-encrypt volume key with new user key
    let new_encrypted_key =
        cipher.encrypt_key(&decrypted_volume_blob, new_user_key, new_user_iv)?;
    config.key_data = new_encrypted_key;

    // Verify upgraded config
    assert_eq!(config.kdf_algorithm, KdfAlgorithm::Argon2id);
    assert_eq!(config.argon2_memory_cost, Some(DEFAULT_ARGON2_MEMORY_COST));
    assert_eq!(config.argon2_time_cost, Some(DEFAULT_ARGON2_TIME_COST));
    assert_eq!(config.argon2_parallelism, Some(DEFAULT_ARGON2_PARALLELISM));

    // Verify old password no longer works
    assert!(config.get_cipher(password).is_err());

    // Verify new password works with Argon2id
    let upgraded_cipher = config.get_cipher(new_password)?;
    assert!(upgraded_cipher.iv_len() > 0);

    // Save and reload to ensure persistence
    let temp_dir = std::env::temp_dir();
    let config_path = temp_dir.join(format!("passwd_upgrade_test_{}.xml", std::process::id()));
    config.save(&config_path)?;

    let loaded_config = EncfsConfig::load(&config_path)?;
    assert_eq!(loaded_config.kdf_algorithm, KdfAlgorithm::Argon2id);
    assert!(loaded_config.get_cipher(new_password).is_ok());

    // Cleanup
    let _ = fs::remove_file(config_path);

    Ok(())
}
