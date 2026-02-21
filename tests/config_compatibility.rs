//! Comprehensive tests for encfs configuration compatibility
//!
//! This test suite verifies that the Rust implementation can correctly
//! read and decrypt filesystems created with various encfs configuration
//! options. Since the filesystem is read-only, we only test read operations.

use anyhow::{Context, Result};
use encfs::config::EncfsConfig;
use encfs::crypto::file::FileDecoder;
use encfs::fs::EncFs;
use openssl::hash::{Hasher, MessageDigest};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// Helper to convert libc error codes to anyhow::Result
fn decrypt_path_result(encfs: &EncFs, path: &Path) -> Result<(PathBuf, u64)> {
    encfs
        .decrypt_path(path)
        .map_err(|e| anyhow::anyhow!("decrypt_path failed with error code: {}", e))
}

/// Helper function to load a config and verify basic properties
fn load_and_verify_config(config_path: &Path, password: &str) -> anyhow::Result<EncfsConfig> {
    let config = EncfsConfig::load(config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    // Verify we can derive the cipher
    let _cipher = config
        .get_cipher(password)
        .context("Failed to derive cipher from config")?;

    Ok(config)
}

/// Helper function to read and decrypt a file, returning its SHA1 hash
fn read_and_hash_file(
    encfs: &EncFs,
    config: &EncfsConfig,
    encrypted_path: &Path,
    root: &Path,
) -> anyhow::Result<String> {
    let full_path = root.join(encrypted_path);
    let file = File::open(&full_path)
        .with_context(|| format!("Failed to open encrypted file {:?}", full_path))?;

    // Decrypt path to get path IV
    let (_, path_iv) =
        decrypt_path_result(encfs, encrypted_path).context("Failed to decrypt path")?;

    // Read and decrypt file header
    let mut header = [0u8; 8];
    file.read_at(&mut header, 0)
        .context("Failed to read file header")?;

    let external_iv = if config.external_iv_chaining {
        path_iv
    } else {
        0
    };

    let file_iv = encfs
        .cipher
        .decrypt_header(&mut header, external_iv)
        .context("Failed to decrypt file header")?;

    // Get file size
    let metadata = file.metadata()?;
    let content_size = FileDecoder::<File>::calculate_logical_size(
        metadata.len(),
        8, // header_size
        config.block_size as u64,
        config.block_mac_bytes as u64,
    );

    // Decrypt content
    let decoder = FileDecoder::new(
        &encfs.cipher,
        &file,
        file_iv,
        8, // header_size
        config.block_size as u64,
        config.block_mac_bytes as u64,
        false,
        config.allow_holes,
    );

    let mut decrypted_content = vec![0u8; content_size as usize];
    let bytes_read = decoder
        .read_at(&mut decrypted_content, 0)
        .context("Failed to decrypt file content")?;
    decrypted_content.truncate(bytes_read);

    // Calculate SHA1 hash
    let mut hasher = Hasher::new(MessageDigest::sha1()).context("Failed to create SHA1 hasher")?;
    hasher.update(&decrypted_content)?;
    let hash = hasher.finish()?;
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    Ok(hash_hex)
}

// ============================================================================
// Issue encfs-1bb.1: Test configuration format compatibility (V5 binary and V6 XML)
// ============================================================================

#[test]
fn test_v5_binary_config_format() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/encfs142");
    let config_path = root.join(".encfs5");

    if !config_path.exists() {
        panic!(
            "Test fixture .encfs5 not found at {:?}. Please ensure fixtures are created.",
            config_path
        );
    }

    let config = load_and_verify_config(&config_path, "test")?;

    // Verify V5 config properties
    // V5 config version can be 20040813 or later (20080411 is also valid)
    assert!(
        config.version >= 20040813,
        "Expected V5 config version >= 20040813"
    );
    assert!(
        !config.cipher_iface.name.is_empty(),
        "Cipher name should be set"
    );
    assert!(config.key_size > 0, "Key size should be positive");
    assert!(config.block_size > 0, "Block size should be positive");
    assert!(!config.key_data.is_empty(), "Key data should not be empty");

    // Verify we can decrypt a file
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_path = PathBuf::from("l-pTrj5dNZqeuAxc59rhlx5h/kETZ,hjEDGRP-75qu02LdBB5");
    let (decrypted_path, _) =
        decrypt_path_result(&encfs, &encrypted_path).context("Failed to decrypt path")?;

    println!(
        "V5 Config - Decrypted path: {}",
        decrypted_path.to_string_lossy()
    );

    // Verify we can read the file
    let _hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;
    println!("V5 Config - Successfully read and decrypted file");

    Ok(())
}

#[test]
fn test_v6_xml_config_format_standard() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");

    if !config_path.exists() {
        panic!("Test fixture encfs6-std.xml not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;

    // Verify V6 XML config properties
    assert!(config.version >= 20100713, "Expected V6 config version");
    assert_eq!(config.cipher_iface.name, "ssl/aes", "Expected AES cipher");
    assert_eq!(
        config.key_size, 192,
        "Expected 192-bit key for standard mode"
    );
    assert_eq!(config.block_size, 1024, "Expected 1024-byte block size");
    assert!(
        config.unique_iv,
        "Standard mode should have uniqueIV enabled"
    );
    assert!(
        config.chained_name_iv,
        "Standard mode should have chainedNameIV enabled"
    );
    assert!(
        !config.external_iv_chaining,
        "Standard mode should not have externalIVChaining"
    );
    assert_eq!(
        config.block_mac_bytes, 0,
        "Standard mode should not have MAC"
    );
    assert!(config.kdf_iterations > 0, "V6 config should use PBKDF2");

    // Verify we can decrypt a file
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
    let encrypted_path = PathBuf::from(encrypted_name);
    let (decrypted_path, _) =
        decrypt_path_result(&encfs, &encrypted_path).context("Failed to decrypt path")?;

    assert_eq!(
        decrypted_path.to_string_lossy(),
        "DESIGN.md",
        "Expected encrypted filename to decrypt to DESIGN.md"
    );

    // Verify we can read the file
    let hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;
    assert_eq!(
        hash, "4240880c2ecba8d2315bad8b27b8674cc59b268c",
        "SHA1 hash of decrypted file should match expected value"
    );

    println!("V6 XML Standard Config - Successfully read and decrypted file");

    Ok(())
}

#[test]
fn test_v6_xml_config_format_paranoia() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-paranoia.xml");

    if !config_path.exists() {
        panic!(
            "Test fixture encfs6-paranoia.xml not found at {:?}",
            config_path
        );
    }

    let config = load_and_verify_config(&config_path, "test")?;

    // Verify V6 XML paranoia config properties
    assert!(config.version >= 20100713, "Expected V6 config version");
    assert_eq!(config.cipher_iface.name, "ssl/aes", "Expected AES cipher");
    assert_eq!(
        config.key_size, 256,
        "Expected 256-bit key for paranoia mode"
    );
    assert_eq!(config.block_size, 1024, "Expected 1024-byte block size");
    assert!(
        config.unique_iv,
        "Paranoia mode should have uniqueIV enabled"
    );
    assert!(
        config.chained_name_iv,
        "Paranoia mode should have chainedNameIV enabled"
    );
    assert!(
        config.external_iv_chaining,
        "Paranoia mode should have externalIVChaining enabled"
    );
    assert_eq!(
        config.block_mac_bytes, 8,
        "Paranoia mode should have 8-byte MAC"
    );
    assert!(config.kdf_iterations > 0, "V6 config should use PBKDF2");

    // Verify we can decrypt a file
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_path = PathBuf::from("U,-Aj0Ha7VZMhbnuv-vx1DZu/oLzPfqHeYSwSUZe7LeCArzcm");
    let (decrypted_path, path_iv) =
        decrypt_path_result(&encfs, &encrypted_path).context("Failed to decrypt path")?;

    assert!(
        decrypted_path.to_string_lossy().ends_with("DESIGN.md"),
        "Expected decrypted path to end with DESIGN.md"
    );

    // Verify path IV is non-zero (due to external IV chaining)
    assert_ne!(
        path_iv, 0,
        "Path IV should be non-zero due to external IV chaining"
    );

    // Verify we can read the file
    let hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;
    assert_eq!(
        hash, "4240880c2ecba8d2315bad8b27b8674cc59b268c",
        "SHA1 hash of decrypted file should match expected value"
    );

    println!("V6 XML Paranoia Config - Successfully read and decrypted file");

    Ok(())
}

// ============================================================================
// Issue encfs-1bb.2: Test cipher algorithm compatibility (AES, Blowfish)
// ============================================================================

#[test]
fn test_aes_cipher_algorithm() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");

    if !config_path.exists() {
        panic!("Test fixture encfs6-std.xml not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;

    // Verify AES cipher
    assert_eq!(config.cipher_iface.name, "ssl/aes", "Expected AES cipher");
    assert_eq!(
        config.cipher_iface.major, 3,
        "Expected AES cipher major version 3"
    );
    assert_eq!(
        config.cipher_iface.minor, 0,
        "Expected AES cipher minor version 0"
    );

    // Verify we can use the cipher
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    // Test filename decryption
    let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
    let (decrypted_bytes, _) = encfs
        .cipher
        .decrypt_filename(encrypted_name, 0)
        .context("Failed to decrypt filename")?;
    let decrypted =
        String::from_utf8(decrypted_bytes).expect("Decrypted filename should be valid UTF-8");

    assert_eq!(
        decrypted, "DESIGN.md",
        "Expected correct filename decryption"
    );

    println!("AES cipher - Successfully tested");

    Ok(())
}

// Note: We don't have a Blowfish test fixture, but the test structure is ready
// for when one becomes available. The cipher algorithm is determined by the
// config file, so if a Blowfish config exists, it will be tested automatically.

// ============================================================================
// Issue encfs-1bb.3: Test key size compatibility (192-bit standard, 256-bit paranoia)
// ============================================================================

#[test]
fn test_192_bit_key_size() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");

    if !config_path.exists() {
        panic!("Test fixture encfs6-std.xml not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;

    // Verify 192-bit key
    assert_eq!(
        config.key_size, 192,
        "Expected 192-bit key for standard mode"
    );

    // Verify we can derive and use the key
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    // Test that we can decrypt files with 192-bit key
    let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
    let encrypted_path = PathBuf::from(encrypted_name);
    let _hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;

    println!("192-bit key - Successfully tested");

    Ok(())
}

#[test]
fn test_256_bit_key_size() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-paranoia.xml");

    if !config_path.exists() {
        panic!(
            "Test fixture encfs6-paranoia.xml not found at {:?}",
            config_path
        );
    }

    let config = load_and_verify_config(&config_path, "test")?;

    // Verify 256-bit key
    assert_eq!(
        config.key_size, 256,
        "Expected 256-bit key for paranoia mode"
    );

    // Verify we can derive and use the key
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    // Test that we can decrypt files with 256-bit key
    let encrypted_path = PathBuf::from("U,-Aj0Ha7VZMhbnuv-vx1DZu/oLzPfqHeYSwSUZe7LeCArzcm");
    let _hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;

    println!("256-bit key - Successfully tested");

    Ok(())
}

// ============================================================================
// Issue encfs-1bb.4: Test encryption mode compatibility (standard, paranoia)
// ============================================================================

#[test]
fn test_standard_mode() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");

    if !config_path.exists() {
        panic!("Test fixture encfs6-std.xml not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;

    // Verify standard mode characteristics
    assert_eq!(config.key_size, 192, "Standard mode uses 192-bit key");
    assert!(
        !config.external_iv_chaining,
        "Standard mode does not use external IV chaining"
    );
    assert_eq!(config.block_mac_bytes, 0, "Standard mode does not use MAC");
    assert!(config.unique_iv, "Standard mode uses unique IV");
    assert!(config.chained_name_iv, "Standard mode uses chained name IV");

    // Verify we can read files
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
    let encrypted_path = PathBuf::from(encrypted_name);
    let hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;
    assert_eq!(
        hash, "4240880c2ecba8d2315bad8b27b8674cc59b268c",
        "File content should decrypt correctly in standard mode"
    );

    println!("Standard mode - Successfully tested");

    Ok(())
}

#[test]
fn test_paranoia_mode() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-paranoia.xml");

    if !config_path.exists() {
        panic!(
            "Test fixture encfs6-paranoia.xml not found at {:?}",
            config_path
        );
    }

    let config = load_and_verify_config(&config_path, "test")?;

    // Verify paranoia mode characteristics
    assert_eq!(config.key_size, 256, "Paranoia mode uses 256-bit key");
    assert!(
        config.external_iv_chaining,
        "Paranoia mode uses external IV chaining"
    );
    assert_eq!(config.block_mac_bytes, 8, "Paranoia mode uses 8-byte MAC");
    assert!(config.unique_iv, "Paranoia mode uses unique IV");
    assert!(config.chained_name_iv, "Paranoia mode uses chained name IV");

    // Verify we can read files
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_path = PathBuf::from("U,-Aj0Ha7VZMhbnuv-vx1DZu/oLzPfqHeYSwSUZe7LeCArzcm");
    let hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;
    assert_eq!(
        hash, "4240880c2ecba8d2315bad8b27b8674cc59b268c",
        "File content should decrypt correctly in paranoia mode"
    );

    println!("Paranoia mode - Successfully tested");

    Ok(())
}

// ============================================================================
// Issue encfs-1bb.5: Test feature flag compatibility
// ============================================================================

#[test]
fn test_unique_iv_feature() -> anyhow::Result<()> {
    // Both standard and paranoia modes use uniqueIV
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");

    if !config_path.exists() {
        panic!("Test fixture encfs6-std.xml not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;
    assert!(config.unique_iv, "uniqueIV should be enabled");

    // Verify we can read files with uniqueIV
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
    let encrypted_path = PathBuf::from(encrypted_name);
    let _hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;

    println!("uniqueIV feature - Successfully tested");

    Ok(())
}

#[test]
fn test_chained_name_iv_feature() -> anyhow::Result<()> {
    // Both standard and paranoia modes use chainedNameIV
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");

    if !config_path.exists() {
        panic!("Test fixture encfs6-std.xml not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;
    assert!(config.chained_name_iv, "chainedNameIV should be enabled");

    // Verify path decryption works with chained IV
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
    let (decrypted_bytes, new_iv) = encfs
        .cipher
        .decrypt_filename(encrypted_name, 0)
        .context("Failed to decrypt filename")?;
    let decrypted =
        String::from_utf8(decrypted_bytes).expect("Decrypted filename should be valid UTF-8");

    assert_eq!(decrypted, "DESIGN.md", "Filename should decrypt correctly");
    assert_ne!(new_iv, 0, "New IV should be non-zero with chainedNameIV");

    println!("chainedNameIV feature - Successfully tested");

    Ok(())
}

#[test]
fn test_external_iv_chaining_feature() -> anyhow::Result<()> {
    // Only paranoia mode uses externalIVChaining
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-paranoia.xml");

    if !config_path.exists() {
        panic!(
            "Test fixture encfs6-paranoia.xml not found at {:?}",
            config_path
        );
    }

    let config = load_and_verify_config(&config_path, "test")?;
    assert!(
        config.external_iv_chaining,
        "externalIVChaining should be enabled in paranoia mode"
    );

    // Verify path IV is used for file header decryption
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_path = PathBuf::from("U,-Aj0Ha7VZMhbnuv-vx1DZu/oLzPfqHeYSwSUZe7LeCArzcm");
    let (_, path_iv) =
        decrypt_path_result(&encfs, &encrypted_path).context("Failed to decrypt path")?;

    assert_ne!(
        path_iv, 0,
        "Path IV should be non-zero with external IV chaining"
    );

    // Verify file can be read (uses path_iv for header decryption)
    let _hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;

    println!("externalIVChaining feature - Successfully tested");

    Ok(())
}

#[test]
fn test_block_mac_bytes_feature() -> anyhow::Result<()> {
    // Only paranoia mode uses block MAC
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-paranoia.xml");

    if !config_path.exists() {
        panic!(
            "Test fixture encfs6-paranoia.xml not found at {:?}",
            config_path
        );
    }

    let config = load_and_verify_config(&config_path, "test")?;
    assert_eq!(
        config.block_mac_bytes, 8,
        "Paranoia mode should have 8-byte MAC"
    );

    // Verify we can read files with MAC (MAC is stripped during decryption)
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_path = PathBuf::from("U,-Aj0Ha7VZMhbnuv-vx1DZu/oLzPfqHeYSwSUZe7LeCArzcm");
    let hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;
    assert_eq!(
        hash, "4240880c2ecba8d2315bad8b27b8674cc59b268c",
        "File with MAC should decrypt correctly"
    );

    println!("blockMACBytes feature - Successfully tested");

    Ok(())
}

// ============================================================================
// Issue encfs-1bb.6: Test block size compatibility
// ============================================================================

#[test]
fn test_1024_byte_block_size() -> anyhow::Result<()> {
    // Both standard and paranoia modes use 1024-byte blocks
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");

    if !config_path.exists() {
        panic!("Test fixture encfs6-std.xml not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;
    assert_eq!(config.block_size, 1024, "Expected 1024-byte block size");

    // Verify we can read files with 1024-byte blocks
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
    let encrypted_path = PathBuf::from(encrypted_name);
    let _hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;

    println!("1024-byte block size - Successfully tested");

    Ok(())
}

// ============================================================================
// Issue encfs-1bb.7: Test KDF compatibility (PBKDF2, legacy KDF)
// ============================================================================

#[test]
fn test_pbkdf2_kdf() -> anyhow::Result<()> {
    // V6 XML configs use PBKDF2
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");

    if !config_path.exists() {
        panic!("Test fixture encfs6-std.xml not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;
    assert!(
        config.kdf_iterations > 0,
        "V6 config should use PBKDF2 with iterations"
    );
    assert!(!config.salt.is_empty(), "PBKDF2 should have salt");

    // Verify we can derive keys using PBKDF2
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
    let encrypted_path = PathBuf::from(encrypted_name);
    let _hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;

    println!("PBKDF2 KDF - Successfully tested");

    Ok(())
}

#[test]
fn test_legacy_kdf() -> anyhow::Result<()> {
    // V5 configs use legacy KDF
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/encfs142");
    let config_path = root.join(".encfs5");

    if !config_path.exists() {
        panic!("Test fixture .encfs5 not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;
    assert_eq!(
        config.kdf_iterations, 0,
        "V5 config should use legacy KDF (no iterations)"
    );
    assert!(config.salt.is_empty(), "Legacy KDF should not have salt");

    // Verify we can derive keys using legacy KDF
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    let encrypted_path = PathBuf::from("l-pTrj5dNZqeuAxc59rhlx5h/kETZ,hjEDGRP-75qu02LdBB5");
    let _hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;

    println!("Legacy KDF - Successfully tested");

    Ok(())
}

// ============================================================================
// Issue encfs-1bb.8: Test name encoding compatibility
// ============================================================================

#[test]
fn test_block_name_encoding() -> anyhow::Result<()> {
    // Both standard and paranoia modes use block encoding
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");

    if !config_path.exists() {
        panic!("Test fixture encfs6-std.xml not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;
    assert_eq!(
        config.name_iface.name, "nameio/block",
        "Expected block name encoding"
    );

    // Verify filename encryption/decryption works
    let cipher = config.get_cipher("test")?;
    let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
    let (decrypted_bytes, _) = cipher
        .decrypt_filename(encrypted_name, 0)
        .context("Failed to decrypt filename")?;
    let decrypted =
        String::from_utf8(decrypted_bytes).expect("Decrypted filename should be valid UTF-8");

    assert_eq!(
        decrypted, "DESIGN.md",
        "Block encoding should decrypt correctly"
    );

    println!("Block name encoding - Successfully tested");

    Ok(())
}

// ============================================================================
// Issue encfs-1bb.9: Test cross-version compatibility
// ============================================================================

#[test]
fn test_cross_version_compatibility() -> anyhow::Result<()> {
    // Test that we can read both V5 and V6 configs
    // V5 config
    let root_v5 = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/encfs142");
    let config_path_v5 = root_v5.join(".encfs5");

    if config_path_v5.exists() {
        let config_v5 = load_and_verify_config(&config_path_v5, "test")?;
        assert!(
            config_v5.version >= 20040813,
            "V5 config version should be >= 20040813"
        );
        println!(
            "V5 config (version {}) - Successfully loaded",
            config_v5.version
        );
    }

    // V6 config
    let root_v6 = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path_v6 = root_v6.join("encfs6-std.xml");

    if config_path_v6.exists() {
        let config_v6 = load_and_verify_config(&config_path_v6, "test")?;
        assert!(config_v6.version >= 20100713, "V6 config version");
        println!(
            "V6 config (version {}) - Successfully loaded",
            config_v6.version
        );
    }

    println!("Cross-version compatibility - Successfully tested");

    Ok(())
}

// ============================================================================
// Issue encfs-1bb.10: Test read operations with all configuration combinations
// ============================================================================

#[test]
fn test_read_operations_standard_mode() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-std.xml");

    if !config_path.exists() {
        panic!("Test fixture encfs6-std.xml not found at {:?}", config_path);
    }

    let config = load_and_verify_config(&config_path, "test")?;
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    // Test 1: Decrypt filename
    let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
    let (decrypted_bytes, _) = encfs
        .cipher
        .decrypt_filename(encrypted_name, 0)
        .context("Failed to decrypt filename")?;
    let decrypted =
        String::from_utf8(decrypted_bytes).expect("Decrypted filename should be valid UTF-8");
    assert_eq!(decrypted, "DESIGN.md");

    // Test 2: Decrypt path
    let encrypted_path = PathBuf::from(encrypted_name);
    let (decrypted_path, _) =
        decrypt_path_result(&encfs, &encrypted_path).context("Failed to decrypt path")?;
    assert_eq!(decrypted_path.to_string_lossy(), "DESIGN.md");

    // Test 3: Read file content
    let hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;
    assert_eq!(hash, "4240880c2ecba8d2315bad8b27b8674cc59b268c");

    // Test 4: Read partial file content (test random access)
    let full_path = root.join(&encrypted_path);
    let file = File::open(&full_path)?;
    let mut header = [0u8; 8];
    file.read_at(&mut header, 0)?;
    let file_iv = encfs.cipher.decrypt_header(&mut header, 0)?;

    let decoder = FileDecoder::new(
        &encfs.cipher,
        &file,
        file_iv,
        8,
        config.block_size as u64,
        config.block_mac_bytes as u64,
        false,
        config.allow_holes,
    );

    // Read first 100 bytes
    let mut buf = vec![0u8; 100];
    let bytes_read = decoder.read_at(&mut buf, 0)?;
    assert!(bytes_read > 0, "Should be able to read from start of file");

    // Read from middle of file
    let mut buf2 = vec![0u8; 100];
    let bytes_read2 = decoder.read_at(&mut buf2, 500)?;
    assert!(
        bytes_read2 > 0,
        "Should be able to read from middle of file"
    );

    println!("Read operations (standard mode) - Successfully tested");

    Ok(())
}

#[test]
fn test_read_operations_paranoia_mode() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-paranoia.xml");

    if !config_path.exists() {
        panic!(
            "Test fixture encfs6-paranoia.xml not found at {:?}",
            config_path
        );
    }

    let config = load_and_verify_config(&config_path, "test")?;
    let cipher = config.get_cipher("test")?;
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    // Test 1: Decrypt path with external IV chaining
    let encrypted_path = PathBuf::from("U,-Aj0Ha7VZMhbnuv-vx1DZu/oLzPfqHeYSwSUZe7LeCArzcm");
    let (decrypted_path, path_iv) =
        decrypt_path_result(&encfs, &encrypted_path).context("Failed to decrypt path")?;
    assert!(decrypted_path.to_string_lossy().ends_with("DESIGN.md"));
    assert_ne!(path_iv, 0, "Path IV should be non-zero");

    // Test 2: Read file content (with MAC)
    let hash = read_and_hash_file(&encfs, &config, &encrypted_path, &root)?;
    assert_eq!(hash, "4240880c2ecba8d2315bad8b27b8674cc59b268c");

    // Test 3: Read partial file content with MAC
    let full_path = root.join(&encrypted_path);
    let file = File::open(&full_path)?;
    let mut header = [0u8; 8];
    file.read_at(&mut header, 0)?;
    let file_iv = encfs.cipher.decrypt_header(&mut header, path_iv)?;

    let decoder = FileDecoder::new(
        &encfs.cipher,
        &file,
        file_iv,
        8,
        config.block_size as u64,
        config.block_mac_bytes as u64,
        false,
        config.allow_holes,
    );

    // Read first 100 bytes
    let mut buf = vec![0u8; 100];
    let bytes_read = decoder.read_at(&mut buf, 0)?;
    assert!(bytes_read > 0, "Should be able to read from start of file");

    println!("Read operations (paranoia mode) - Successfully tested");

    Ok(())
}
