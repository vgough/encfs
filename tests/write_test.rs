use encfs::config::Interface;
use encfs::crypto::file::FileDecoder;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use fuse_mt::{FilesystemMT, RequestInfo};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

#[test]
fn test_virtual_driver_write() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_write_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let root = tmp.clone();

    // Setup Cipher
    let iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };
    let cipher = SslCipher::new(&iface, 192).unwrap();
    let mut cipher = cipher;
    let user_key = vec![1u8; 24];
    let user_iv = vec![2u8; 16];
    cipher.set_key(&user_key, &user_iv);

    let config = encfs::config::EncfsConfig {
        config_type: encfs::config::ConfigType::V6,
        creator: "test".to_string(),
        version: 20100713,
        cipher_iface: iface.clone(),
        name_iface: encfs::config::Interface::default(),
        key_size: 192,
        block_size: 1024,
        key_data: vec![],
        salt: vec![],
        kdf_iterations: 0,
        desired_kdf_duration: 0,
        kdf_algorithm: encfs::config::KdfAlgorithm::Pbkdf2,
        argon2_memory_cost: None,
        argon2_time_cost: None,
        argon2_parallelism: None,
        plain_data: false,
        block_mac_bytes: 8,
        block_mac_rand_bytes: 0,
        unique_iv: true,
        external_iv_chaining: false,
        chained_name_iv: true,
        allow_holes: false,
        config_hash: None,
    };
    let fs = EncFs::new(root.clone(), cipher, config);

    // Create a second cipher instance for verification since SslCipher is not Clone (holds OpenSsl state)
    let verify_cipher = SslCipher::new(&iface, 192).unwrap();
    let mut verify_cipher = verify_cipher;
    verify_cipher.set_key(&user_key, &user_iv);

    let req = RequestInfo {
        unique: 1,
        pid: 1,
        gid: 0,
        uid: 0,
    };

    let parent = PathBuf::from("");
    let name = OsStr::new("test.txt");

    // Create
    let create_res = fs
        .create(req, &parent, name, 0o644, 0)
        .expect("create failed");
    let fh = create_res.fh;

    // Write "hello world"
    let data = b"hello world".to_vec();
    // Use proper path for logging
    let path = parent.join("test.txt");
    let written = fs
        .write(req, &path, fh, 0, data.clone(), 0)
        .expect("write failed");
    assert_eq!(written, data.len() as u32);

    // Verify via FileDecoder (manually, to bypass fuse_mt::CallbackResult issue)
    // Find the encrypted file in the root directory
    let mut entries = fs::read_dir(&tmp).unwrap();
    let entry = entries.next().unwrap().unwrap();
    let real_path = entry.path();
    println!("Found file at: {:?}", real_path);
    let file = std::fs::File::open(&real_path).unwrap();
    let mut header = [0u8; 8];
    FileExt::read_at(&file, &mut header, 0).unwrap();

    // We essentially need to decrypt the header to get file_iv
    // In fs.rs create(), external_iv is path_iv if chaining enabled.
    // EncFs::new(..., chained_name_iv=true, external_iv_chaining=false) in this test.
    // So external_iv is 0.
    let file_iv = verify_cipher
        .decrypt_header(&mut header, 0)
        .expect("decrypt header failed");

    let decoder = FileDecoder::new(
        &verify_cipher,
        &file,
        file_iv,
        8,    // header_size
        1024, // block_size
        8,    // block_mac_bytes
        false,
        false,
    );

    let mut read_data = vec![0u8; data.len()];
    let read_len = decoder
        .read_at(&mut read_data, 0)
        .expect("manual read failed");
    assert_eq!(read_len, data.len());
    assert_eq!(read_data, data);

    // Release (close)
    fs.release(req, &path, fh, 0, 0, true).unwrap();

    // Verify persistence by opening again
    // We didn't implement 'lookup' which FUSE uses to get FH?
    // Usually FUSE calls lookup -> open?
    // But `EncFs::open` takes path.
    // EncFs `open`: `encrypt_path` -> `File::open`.

    let open_res = fs.open(req, &path, 0).expect("open failed");
    let _fh2 = open_res.0;

    // Verify again after re-opening (persistence check)
    // We already verified on-disk content with FileDecoder.
    // We can just skip the second read or use FileDecoder again.
    let file2 = std::fs::File::open(&real_path).unwrap();
    let decoder2 = FileDecoder::new(&verify_cipher, &file2, file_iv, 8, 1024, 8, false, false);
    let mut read_data2 = vec![0u8; data.len()];
    decoder2.read_at(&mut read_data2, 0).unwrap();
    assert_eq!(read_data2, data);

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
