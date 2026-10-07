//! Test reproducing Issue #706:
//! Difference in filenames between rust implementation and C++ 1.9.5
//! for encfs6 when chainedNameIV is disabled (chainedNameIV = 0).
//!
//! In C++ EncFS v1.9.5:
//! When `chainedNameIV` is false, `NameIO::_encodePath` and `_decodePath` pass
//! `iv = nullptr` into `encodeName` / `decodeName`.
//! In `SSL_Cipher::_checksum_64`, if `chainedIV == nullptr`, HMAC-SHA1 is computed
//! over `data` only (no IV bytes appended).
//!
//! In Rust EncFS:
//! `encrypt_filename` and `decrypt_filename` unconditionally accept `iv: u64`.
//! `mac_64` always appends `iv.to_le_bytes()` to the HMAC input. When `chained_name_iv`
//! is false, `iv` is kept at 0, so Rust computes HMAC over `data || [0u8; 8]`.
//! This causes Rust master to produce the ciphertext matching `chainedNameIV = 1`
//! for root entries (e.g. `1QpokPhaq2sP9fqnVyHb63oP` for `file_2`), rather than the
//! C++ v1.9.5 unchained filename (`w3kY9smoitBQoQpRpJ,0XN97`).
//! Rust also fails to decrypt filesystems created by C++ with `chainedNameIV = 0`.
//!
//! Fixed by omitting the IV from the filename MAC for legacy (V4-V6) configs
//! without `chained_name_iv`. V7 keeps the zero-IV MAC so existing
//! `encfsctl new --no-chained-iv` volumes stay readable.

use anyhow::Context;
use encfs::config::EncfsConfig;
use encfs::fs::EncFs;
use std::path::{Path, PathBuf};

#[test]
fn test_reproduce_issue_706_unchained_filename_encoding() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-direct-nochain.xml");

    let config = EncfsConfig::load(&config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    assert!(
        !config.chained_name_iv,
        "chained_name_iv must be false in direct-nochain fixture"
    );

    let cipher = config
        .get_cipher("test")
        .context("Failed to derive cipher with password 'test'")?;
    let encfs = EncFs::new(root, cipher, config);

    // Test 1: Plaintext "file_2" encoding
    // Under C++ v1.9.5, encoding "file_2" yields "w3kY9smoitBQoQpRpJ,0XN97".
    // Currently on Rust master, this produces "1QpokPhaq2sP9fqnVyHb63oP" (the chained-IV root value).
    let (encrypted_path, _) = encfs
        .encrypt_path(Path::new("file_2"))
        .map_err(|e| anyhow::anyhow!("encrypt_path failed with error {}", e))?;

    let encrypted_filename = encrypted_path
        .file_name()
        .and_then(|s| s.to_str())
        .context("Invalid filename")?;

    // Reproduction assertion for encryption:
    assert_eq!(
        encrypted_filename, "w3kY9smoitBQoQpRpJ,0XN97",
        "Issue #706: filename encoding mismatch when chained_name_iv = false"
    );

    Ok(())
}

#[test]
fn test_reproduce_issue_706_unchained_filename_decoding() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-direct-nochain.xml");

    let config = EncfsConfig::load(&config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    assert!(
        !config.chained_name_iv,
        "chained_name_iv must be false in direct-nochain fixture"
    );

    let cipher = config
        .get_cipher("test")
        .context("Failed to derive cipher with password 'test'")?;
    let encfs = EncFs::new(root, cipher, config);

    // Test 2: Ciphertext "w3kY9smoitBQoQpRpJ,0XN97" decoding
    // Under C++ v1.9.5, decoding "w3kY9smoitBQoQpRpJ,0XN97" yields "file_2".
    // Currently on Rust master, this fails with libc::EIO (checksum mismatch: expected 7c01, got 0357).
    let (decrypted_path, _) = encfs
        .decrypt_path(Path::new("w3kY9smoitBQoQpRpJ,0XN97"))
        .map_err(|e| anyhow::anyhow!("decrypt_path failed with error {}", e))?;

    let decrypted_filename = decrypted_path
        .file_name()
        .and_then(|s| s.to_str())
        .context("Invalid filename")?;

    // Reproduction assertion for decryption:
    assert_eq!(
        decrypted_filename, "file_2",
        "Issue #706: failed to decrypt filename created by C++ v1.9.5 with chainedNameIV = 0"
    );

    Ok(())
}

#[test]
fn test_verify_cpp_algorithm_produces_expected_ciphertext() -> anyhow::Result<()> {
    use encfs::crypto::ssl::SslCipher;

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config_path = root.join("encfs6-direct-nochain.xml");
    let config = EncfsConfig::load(&config_path)?;

    // Derive volume key with password "test"
    let user_key = SslCipher::derive_key("test", &config.salt, config.kdf_iterations, 48)?;
    let raw_key = config.key_data.clone();
    let temp_cipher = SslCipher::new(&config.cipher_iface, config.key_size)?;
    let volume_key = temp_cipher.decrypt_key(&raw_key, &user_key[..32], &user_key[32..48])?;

    // Volume key is 32 bytes key + 16 bytes IV
    let key = &volume_key[..32];
    let iv = &volume_key[32..48];

    // Follow C++ BlockNameIO::encodeName with iv == nullptr:
    let plaintext_name = b"file_2";
    let bs = 16; // AES block size
    let padding = bs - (plaintext_name.len() % bs); // 16 - 6 = 10

    let mut data = Vec::with_capacity(2 + plaintext_name.len() + padding);
    data.push(0);
    data.push(0);
    data.extend_from_slice(plaintext_name);
    for _ in 0..padding {
        data.push(padding as u8);
    }

    // In C++, when iv == nullptr, MAC_16 calls _checksum_64 which computes
    // HMAC-SHA1(key, data) without appending any IV.
    // In Rust, this is exactly SslCipher::mac_64_no_iv_with_key(&data[2..], key):
    let mac64 = SslCipher::mac_64_no_iv_with_key(&data[2..], key)?;
    let mac32 = ((mac64 >> 32) as u32) ^ (mac64 as u32);
    let checksum = ((mac32 >> 16) as u16) ^ (mac32 as u16);

    data[0] = (checksum >> 8) as u8;
    data[1] = (checksum & 0xff) as u8;

    // In C++, when iv == nullptr, tmpIV = 0, so seed is checksum ^ 0 = checksum
    let name_iv = checksum as u64;

    let mut block_data = data[2..].to_vec();
    temp_cipher.block_encode(&mut block_data, name_iv, key, iv)?;
    data.splice(2.., block_data);

    let encoded = SslCipher::filename_base64_encode(&data)?;

    // VERIFY: This matches C++ v1.9.5 output EXACTLY!
    assert_eq!(
        encoded, "w3kY9smoitBQoQpRpJ,0XN97",
        "The C++ v1.9.5 algorithm (HMAC without IV) must produce w3kY9smoitBQoQpRpJ,0XN97"
    );

    // Also verify decoding w3kY9smoitBQoQpRpJ,0XN97 with the C++ unchained algorithm:
    let decoded_data = SslCipher::filename_base64_decode("w3kY9smoitBQoQpRpJ,0XN97")?;
    let decoded_checksum = ((decoded_data[0] as u16) << 8) | (decoded_data[1] as u16);
    let mut decrypted_block = decoded_data[2..].to_vec();
    temp_cipher.legacy_block_decode(&mut decrypted_block, decoded_checksum as u64, key, iv)?;

    let dec_mac64 = SslCipher::mac_64_no_iv_with_key(&decrypted_block, key)?;
    let dec_mac32 = ((dec_mac64 >> 32) as u32) ^ (dec_mac64 as u32);
    let dec_checksum = ((dec_mac32 >> 16) as u16) ^ (dec_mac32 as u16);
    assert_eq!(
        dec_checksum, decoded_checksum,
        "Checksums must match when computed without IV"
    );

    let pad = decrypted_block[decrypted_block.len() - 1] as usize;
    let plaintext = &decrypted_block[..decrypted_block.len() - pad];
    assert_eq!(
        std::str::from_utf8(plaintext)?,
        "file_2",
        "Decrypted plaintext must match 'file_2'"
    );

    Ok(())
}

/// V7 is Rust-only, and its unchained volumes were always written with the
/// zero-IV MAC; the issue #706 fix must not change their filenames.
#[test]
fn test_v7_unchained_names_keep_zero_iv_mac() -> anyhow::Result<()> {
    let mut config = EncfsConfig::standard_v7();
    config.use_chained_name_iv();
    config.chained_name_iv = false;
    config.external_iv_chaining = false;
    config.argon2_memory_cost = Some(8);
    config.argon2_time_cost = Some(1);
    config.argon2_parallelism = Some(1);
    config.salt = vec![7u8; 16];
    let volume_key = vec![0x5au8; (config.key_size / 8) as usize + 16];
    config.set_v7_key("pw", &volume_key)?;

    let mut reference = encfs::crypto::ssl::SslCipher::new(&config.cipher_iface, config.key_size)?;
    reference.set_key(&volume_key[..32], &volume_key[32..48]);
    reference.set_name_encoding(&config.name_iface);
    let (zero_iv_name, _) = reference.encrypt_filename(b"file_2", 0)?;

    let cipher = config.get_cipher("pw")?;
    let encfs = EncFs::new(PathBuf::from("/nonexistent"), cipher, config);
    let (encrypted_path, _) = encfs
        .encrypt_path(Path::new("file_2"))
        .map_err(|e| anyhow::anyhow!("encrypt_path failed with error {}", e))?;

    assert_eq!(
        encrypted_path.file_name().and_then(|s| s.to_str()),
        Some(zero_iv_name.as_str())
    );
    Ok(())
}
