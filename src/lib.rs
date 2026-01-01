pub mod config;
pub mod config_binary;
pub mod constants;
pub mod crypto;
pub mod fs;

#[cfg(feature = "gettext")]
///
/// Helper class to handle i18n-specific helper functions, or dummies wrappers to disable
/// that functionality if no gettext is to be used.
///
pub mod i18n {
    use gettextrs::{bindtextdomain, setlocale, textdomain, LocaleCategory};
    pub fn init() {
        setlocale(LocaleCategory::LcAll, "");
        let locale_dir = concat!(env!("OUT_DIR"), "/po");
        // actually make it customizable at build time
        let locale_dir = option_env!("ENCFS_LOCALE_DIR").unwrap_or(locale_dir);

        bindtextdomain("encfs", locale_dir).unwrap();
        textdomain("encfs").unwrap();
    }
}

#[cfg(not(feature = "gettext"))]
pub mod i18n {
    pub fn init() {}
}

#[cfg(feature = "gettext")]
pub use i18n_format::{i18n_format, i18n_nformat};

#[cfg(not(feature = "gettext"))]
pub use i18n_format::no_gettext::{i18n_format, i18n_nformat};

#[cfg(test)]
mod tests {
    use openssl::hash::{Hasher, MessageDigest};
    use std::fs::File;
    use std::os::unix::fs::FileExt;
    use std::path::PathBuf;

    #[test]
    fn test_decrypt_filenames() -> anyhow::Result<()> {
        // Use local test fixtures directory
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let config_path = root.join("encfs6-std.xml");

        if !config_path.exists() {
            panic!("Test fixtures not found at {:?}", config_path);
        }

        let config = crate::config::EncfsConfig::load(&config_path)?;
        let password = "test";
        let cipher = config.get_cipher(password)?;

        println!("Successfully decrypted volume key");

        // Test the known encrypted filename
        let encrypted_name = "MhAO8Ckgt67m1cSrFU9HHiNT";
        let iv = 0; // Root directory IV is 0
        let (decrypted_bytes, _) = cipher.decrypt_filename(encrypted_name, iv)?;
        let decrypted =
            String::from_utf8(decrypted_bytes).expect("Decrypted filename should be valid UTF-8");

        println!("Decrypted: {} -> {}", encrypted_name, decrypted);
        assert_eq!(
            decrypted, "DESIGN.md",
            "Expected encrypted filename to decrypt to DESIGN.md"
        );

        // Read and decrypt the file content
        let encrypted_file_path = root.join(encrypted_name);
        let file = File::open(&encrypted_file_path)?;

        // Read and decrypt file header to get file IV
        let mut header = [0u8; 8];
        file.read_at(&mut header, 0)?;
        let file_iv = cipher.decrypt_header(&mut header, 0)?;
        println!("File IV: {:016x}", file_iv);

        // Get file size (excluding header)
        let metadata = file.metadata()?;
        let encrypted_size = metadata.len();
        let content_size = encrypted_size - 8; // subtract header size

        // Use FileDecoder to read and decrypt
        let decoder = crate::crypto::file::FileDecoder::new(
            &cipher,
            &file,
            file_iv,
            8, // header_size
            config.block_size as u64,
            config.block_mac_bytes as u64,
        );

        let mut decrypted_content = vec![0u8; content_size as usize];
        let bytes_read = decoder.read_at(&mut decrypted_content, 0)?;
        decrypted_content.truncate(bytes_read);

        println!("Decrypted {} bytes of content", decrypted_content.len());

        // Calculate SHA1 hash of decrypted content
        let mut hasher = Hasher::new(MessageDigest::sha1())?;
        hasher.update(&decrypted_content)?;
        let hash = hasher.finish()?;
        let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

        println!("SHA1 hash: {}", hash_hex);

        // Verify the expected hash
        let expected_hash = "4240880c2ecba8d2315bad8b27b8674cc59b268c";
        assert_eq!(
            hash_hex, expected_hash,
            "SHA1 hash of decrypted file content should match expected value"
        );

        println!("File content verification successful!");

        Ok(())
    }

    #[test]
    fn test_paranoia_mode() -> anyhow::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let config_path = root.join("encfs6-paranoia.xml");

        if !config_path.exists() {
            panic!("Test fixtures not found at {:?}", config_path);
        }

        let config = crate::config::EncfsConfig::load(&config_path)?;
        let password = "test";
        let cipher = config.get_cipher(password)?;

        // Setup EncFs to use decrypt_path
        let encfs = crate::fs::EncFs::new(root.clone(), cipher, config.clone());

        // Encrypted path components
        // Directory: U,-Aj0Ha7VZMhbnuv-vx1DZu
        // File: oLzPfqHeYSwSUZe7LeCArzcm
        let encrypted_rel_path = PathBuf::from("U,-Aj0Ha7VZMhbnuv-vx1DZu/oLzPfqHeYSwSUZe7LeCArzcm");

        let (decrypted_path, path_iv) = encfs
            .decrypt_path(&encrypted_rel_path)
            .expect("decrypt_path failed");
        let decrypted_lossy = decrypted_path.to_string_lossy();
        println!("Decrypted path: {}", decrypted_lossy);

        assert!(decrypted_lossy.ends_with("DESIGN.md"));

        // Verify path IV is non-zero (due to chaining)
        println!("Path IV: {:016x}", path_iv);
        assert!(path_iv != 0, "Path IV should be non-zero due to chaining");

        // Read and decrypt the file content
        let encrypted_file_path = root.join(encrypted_rel_path);
        let file = File::open(&encrypted_file_path)?;

        // Read file header and decrypt to get file_iv
        let mut header = [0u8; 8];
        file.read_at(&mut header, 0)?;

        // Use path_iv for external IV chaining (paranoia mode)
        let file_iv = encfs.cipher.decrypt_header(&mut header, path_iv)?;
        println!("File IV from header: {:016x}", file_iv);

        let metadata = file.metadata()?;
        let content_size = metadata.len() - 8;

        let decoder = crate::crypto::file::FileDecoder::new(
            &encfs.cipher,
            &file,
            file_iv,
            8,
            config.block_size as u64,
            config.block_mac_bytes as u64,
        );

        let mut decrypted_content = vec![0u8; content_size as usize];
        let bytes_read = decoder.read_at(&mut decrypted_content, 0)?;
        decrypted_content.truncate(bytes_read);

        println!("Decrypted {} bytes of content", decrypted_content.len());

        // Calculate SHA1 hash of decrypted content
        let mut hasher = Hasher::new(MessageDigest::sha1())?;
        hasher.update(&decrypted_content)?;
        let hash = hasher.finish()?;
        let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

        println!("SHA1 hash: {}", hash_hex);

        // Verify the hash matches the expected value (same as std test - same content)
        assert_eq!(
            hash_hex, "4240880c2ecba8d2315bad8b27b8674cc59b268c",
            "SHA1 hash of decrypted paranoia-mode file content should match expected value"
        );

        Ok(())
    }
}
