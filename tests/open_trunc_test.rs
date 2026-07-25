use encfs::config::Interface;
use encfs::crypto::file::FileDecoder; // Import FileDecoder
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use typed_fuse::{Caller, PathFilesystem};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::FileExt; // For read_at
use std::path::PathBuf;

#[test]
fn test_open_trunc_header_regeneration() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_open_trunc_test");
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

    // We need a verify cipher because SslCipher is not Clone (holds OpenSSL state)
    let verify_cipher = SslCipher::new(&iface, 192).unwrap();
    let mut verify_cipher = verify_cipher;
    verify_cipher.set_key(&user_key, &user_iv);

    let config = encfs::config::EncfsConfig::test_default();
    let fs = EncFs::new(root.clone(), Box::new(cipher), config);

    let req = Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    };

    let parent = PathBuf::from("");
    let name = OsStr::new("trunc_test");

    // 1. Create and Write initial data
    let (_, create_res) = fs
        .create(&parent, name, 0o644, 0, 0, &req)
        .expect("create failed");
    let fh = create_res.handle;
    let data = b"Initial Data".to_vec();
    let path = parent.join(name);
    fs.write(Some(&path), &fh, &data, 0, &req)
        .expect("write failed");
    fs.release(Some(&path), fh, &req).unwrap();

    // Verify physical file size is > 8 (header + data)
    let mut entries = fs::read_dir(&tmp).unwrap();
    let entry = entries.next().unwrap().unwrap();
    let real_path = entry.path();
    let meta = fs::metadata(&real_path).unwrap();
    assert!(meta.len() > 8, "File should have header and data");

    // 2. Open with O_TRUNC
    let flags = libc::O_WRONLY | libc::O_TRUNC;
    let open_res = fs.open(&path, flags, &req).expect("open failed (trunc)");
    let fh2 = open_res.handle;

    // 3. Verify physical file size IMMEDIATELY after open
    let meta_trunc = fs::metadata(&real_path).unwrap();
    println!("Physical size after open(O_TRUNC): {}", meta_trunc.len());

    assert_eq!(
        meta_trunc.len(),
        8,
        "File opened with O_TRUNC should have a new header (8 bytes)"
    );

    // 4. Write new data
    let new_data = b"New Data".to_vec();
    fs.write(Some(&path), &fh2, &new_data, 0, &req)
        .expect("write failed (trunc)");
    fs.release(Some(&path), fh2, &req).unwrap();

    // 5. Read verification using FileDecoder
    // Note: fs::read requires handle or open checks. verify via disk is robust.
    let file = std::fs::File::open(&real_path).unwrap();
    let mut header = [0u8; 8];
    FileExt::read_at(&file, &mut header, 0).unwrap();

    // We expect header to be valid. Decrypt it.
    // External IV is 0 because external_iv_chaining is false.
    let file_iv = verify_cipher
        .decrypt_header(&mut header, 0)
        .expect("failed to decrypt header - corrupt or missing?");

    // If header was missing/zero, decrypt_header might fail or produce garbage IV.
    // If it produces garbage IV, read will produce garbage.

    let decoder = FileDecoder::new(&verify_cipher, &file, file_iv, 8, 1024, 8, false, false);

    let mut read_buf = vec![0u8; new_data.len()];
    decoder.read_at(&mut read_buf, 0).expect("read failed");

    assert_eq!(read_buf, new_data);

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
