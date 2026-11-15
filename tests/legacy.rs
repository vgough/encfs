use anyhow::Context;
use encfs::config::EncfsConfig;
use encfs::crypto::file::FileDecoder;
use encfs::fs::EncFs;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use typed_fuse::PathFilesystem;

mod common;
use common::node;
use common::volume::{Volume, req};

#[test]
fn test_legacy_v5_decode() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/encfs142");
    let config_path = root.join(".encfs5");

    if !config_path.exists() {
        // If the fixture wasn't created, we can't run.
        panic!(
            "Test fixture .encfs5 not found at {:?}. Please ensure fixtures are created.",
            config_path
        );
    }

    println!("Loading config from {:?}", config_path);
    let config = EncfsConfig::load(&config_path).context("Failed to load V5 config")?;

    // Check some properties
    println!("Config version: {}", config.version);
    println!("Block size: {}", config.block_size);
    println!("Key size: {}", config.key_size);
    println!("Cipher: {}", config.cipher_iface.name);
    println!("Cipher Major: {}", config.cipher_iface.major);
    println!("Key data len: {}", config.key_data.len());
    println!(
        "Key data prefix: {:02x?}",
        &config.key_data[..std::cmp::min(10, config.key_data.len())]
    );

    // Check KDF (256-bit key = 32 bytes, 16-byte IV)
    let derived = encfs::crypto::ssl::SslCipher::derive_key_legacy("test", 32, 16).unwrap();
    println!("Derived key (legacy): {:02x?}", derived);

    let password = "test";
    println!("Trying password: {}", password);
    let cipher = config
        .get_cipher(password)
        .context("Failed to derive key")?;
    println!("Cipher initialized");

    // Initialize EncFs to use decrypt_path logic
    let encfs = EncFs::new(root.clone(), cipher, config.clone());

    // Encrypted path in the fixture: l-pTrj5dNZqeuAxc59rhlx5h/kETZ,hjEDGRP-75qu02LdBB5
    // Note: filenames might vary if I copied them wrongly, but previous `ls` confirmed the names.
    let encrypted_rel_path = PathBuf::from("l-pTrj5dNZqeuAxc59rhlx5h/kETZ,hjEDGRP-75qu02LdBB5");

    // 1. Decrypt path
    println!("Decrypting path: {:?}", encrypted_rel_path);
    let (decrypted_path, path_iv) = encfs
        .decrypt_path(&encrypted_rel_path)
        .map_err(|e| anyhow::anyhow!("decrypt_path failed with error {}", e))?;

    let decrypted_str = decrypted_path.to_string_lossy();
    println!("Decrypted path: {}", decrypted_str);

    // Expect reasonable ASCII path
    // "test-folder/test-file" or similar?
    // Not critical what it is, as long as it succeeds and is valid UTF-8.

    // 2. Decrypt content
    let encrypted_full_path = root.join(&encrypted_rel_path);
    let file = File::open(&encrypted_full_path).context("Failed to open encrypted file")?;

    // Read header
    let mut header = [0u8; 8];
    file.read_at(&mut header, 0)
        .context("Failed to read header")?;

    // Determine IV for header
    let iv_for_header = if config.external_iv_chaining {
        path_iv
    } else {
        0
    };

    println!("Decrypting file header with IV {}", iv_for_header);
    let file_iv = encfs
        .cipher
        .decrypt_header(&mut header, iv_for_header)
        .context("Failed to decrypt header")?;
    println!("File IV: {:x}", file_iv.as_u128());

    let metadata = file.metadata()?;
    // Assuming 8 byte header
    let header_size = 8;
    let content_len = metadata.len() - header_size;

    println!("Decrypting content (size: {})", content_len);

    let decoder = FileDecoder::new(
        encfs.cipher.as_ref(),
        &file,
        file_iv,
        header_size,
        config.block_size as u64,
        config.block_mac_bytes as u64,
        false,
        config.allow_holes,
    );

    let mut plaintext = vec![0u8; content_len as usize];
    let n = decoder
        .read_at(&mut plaintext, 0)
        .context("Failed to decrypt content")?;
    plaintext.truncate(n);

    let content = String::from_utf8(plaintext).context("Content is not valid UTF-8")?;
    println!("Decrypted content length: {}", content.len());

    // Check if it looks like expected content
    // Usually these are text files.
    if content.len() < 100 {
        println!("Content: {}", content);
    } else {
        println!("Content starts with: {}", &content[..100]);
    }

    Ok(())
}

/// C++ EncFS writes a file's header with its first data, so a file made
/// with `touch` is empty on disk even where every file has a header. It
/// opens and reads as empty, and a writable open then gives it a header.
/// A file cut off inside its header is still an error.
#[test]
fn empty_files_without_a_header_read_as_empty() {
    let mut vol = Volume::new(EncfsConfig::test_default());
    assert!(vol.config.header_size() > 0);
    vol.write_file("/empty", b"");
    vol.write_file("/cut", b"");
    let set_len = |path: &str, len| {
        std::fs::OpenOptions::new()
            .write(true)
            .open(vol.backing(path))
            .unwrap()
            .set_len(len)
            .unwrap()
    };
    set_len("/empty", 0);
    set_len("/cut", 3);
    vol.remount();

    assert_eq!(vol.read_file("/empty"), b"");
    let open = |path: &str, flags| {
        let file = node(&vol.fs, &vol.root_state, path, &req());
        vol.fs
            .open(file.as_node(), flags, &req())
            .map(|opened| vol.fs.release(file.as_node(), opened.handle, &req()))
    };
    assert!(open("/cut", libc::O_RDONLY).is_err());

    let file = node(&vol.fs, &vol.root_state, "/empty", &req());
    let opened = vol.fs.open(file.as_node(), libc::O_RDWR, &req()).unwrap();
    vol.fs
        .write(file.as_node(), &opened.handle, b"now with data", 0, &req())
        .unwrap();
    vol.fs
        .release(file.as_node(), opened.handle, &req())
        .unwrap();
    vol.remount();
    assert_eq!(vol.read_file("/empty"), b"now with data");
}
