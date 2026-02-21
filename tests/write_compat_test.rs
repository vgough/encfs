use encfs::config::Interface;
use encfs::crypto::file::FileDecoder;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use fuse_mt::{FilesystemMT, RequestInfo};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

fn setup_test_fs(
    test_name: &str,
    major: i32,
    key_size: i32,
    block_size: u64,
    block_mac_bytes: u64,
    chained_name_iv: bool,
    external_iv_chaining: bool,
) -> (EncFs, PathBuf, SslCipher, Vec<u8>, Vec<u8>, u64) {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join(test_name);
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let root = tmp.clone();

    // Setup Cipher
    let iface = Interface {
        name: "ssl/aes".to_string(),
        major,
        minor: 0,
        age: 0,
    };
    let cipher = SslCipher::new(&iface, key_size).unwrap();
    let mut cipher = cipher;

    // Key length must match cipher expectation
    // 192 bits = 24 bytes, 256 bits = 32 bytes
    let key_bytes = (key_size / 8) as usize;
    let user_key = vec![1u8; key_bytes];
    let user_iv = vec![2u8; 16];
    cipher.set_key(&user_key, &user_iv);

    let mut config = encfs::config::EncfsConfig::test_default();
    config.cipher_iface.major = major;
    config.key_size = key_size;
    config.block_size = block_size as i32;
    config.block_mac_bytes = block_mac_bytes as i32;
    config.chained_name_iv = chained_name_iv;
    config.external_iv_chaining = external_iv_chaining;

    let fs = EncFs::new(root.clone(), cipher, config);

    // Create verify cipher matches
    let verify_cipher = SslCipher::new(&iface, key_size).unwrap();
    let mut verify_cipher = verify_cipher;
    verify_cipher.set_key(&user_key, &user_iv);

    (fs, tmp, verify_cipher, user_key, user_iv, block_mac_bytes)
}

#[test]
fn test_write_legacy_v2() {
    // Legacy: Major 2, No Chained Name IV (usually), No MAC, No ExtIV
    let (fs, tmp, verify_cipher, _, _, block_mac_bytes) = setup_test_fs(
        "encfs_write_legacy",
        2,
        192,
        1024,
        0,
        false, // chained_name_iv
        false, // external_iv_chaining
    );

    // Need to reconstruct decoder properly
    let req = RequestInfo {
        unique: 1,
        pid: 1,
        gid: 0,
        uid: 0,
    };
    let parent = PathBuf::from("");
    let name = OsStr::new("test.txt");
    let create_res = fs
        .create(req, &parent, name, 0o644, 0)
        .expect("create failed");
    let fh = create_res.fh;
    let data = b"legacy hello".to_vec();
    let path = parent.join("test.txt");
    fs.write(req, &path, fh, 0, data.clone(), 0)
        .expect("write failed");

    // Verification
    let mut entries = fs::read_dir(&tmp).unwrap();
    let entry = entries.next().unwrap().unwrap();
    let real_path = entry.path();
    let file = std::fs::File::open(&real_path).unwrap();
    let mut header = [0u8; 8];
    FileExt::read_at(&file, &mut header, 0).unwrap();

    let file_iv = verify_cipher.decrypt_header(&mut header, 0).unwrap();
    let decoder = FileDecoder::new(
        &verify_cipher,
        &file,
        file_iv,
        8,
        1024,
        block_mac_bytes,
        false,
        false,
    );
    let mut read_data = vec![0u8; data.len()];
    decoder.read_at(&mut read_data, 0).unwrap();
    assert_eq!(read_data, data);

    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_write_paranoia() {
    // Paranoia: Major 3, AES-256, MAC 8 bytes, Chained IV, Ext IV Chaining
    let (fs, tmp, verify_cipher, _, _, block_mac_bytes) = setup_test_fs(
        "encfs_write_paranoia",
        3,
        256,
        1024,
        8,
        true, // chained_name_iv
        true, // external_iv_chaining
    );

    let req = RequestInfo {
        unique: 1,
        pid: 1,
        gid: 0,
        uid: 0,
    };
    let parent = PathBuf::from("");
    let name = OsStr::new("test_paranoia.txt");
    let create_res = fs
        .create(req, &parent, name, 0o644, 0)
        .expect("create failed");
    let fh = create_res.fh;
    let data = b"paranoia hello".to_vec();
    let path = parent.join("test_paranoia.txt");
    fs.write(req, &path, fh, 0, data.clone(), 0)
        .expect("write failed");

    // Verification
    let mut entries = fs::read_dir(&tmp).unwrap();
    let entry = entries.next().unwrap().unwrap();
    let real_path = entry.path();
    let file = std::fs::File::open(&real_path).unwrap();
    let mut header = [0u8; 8];
    FileExt::read_at(&file, &mut header, 0).unwrap();

    // Recover Name IV for External IV
    let filename = real_path.file_name().unwrap().to_str().unwrap();
    let (_, name_iv) = verify_cipher.decrypt_filename(filename, 0).unwrap();

    let file_iv = verify_cipher.decrypt_header(&mut header, name_iv).unwrap();
    let decoder = FileDecoder::new(
        &verify_cipher,
        &file,
        file_iv,
        8,
        1024,
        block_mac_bytes,
        false,
        false,
    );
    let mut read_data = vec![0u8; data.len()];
    decoder.read_at(&mut read_data, 0).unwrap();
    assert_eq!(read_data, data);

    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_fstat_support() {
    // Setup standardized FS
    let (fs, tmp, _, _, _, _) = setup_test_fs("encfs_fstat", 3, 256, 1024, 8, true, true);

    let req = RequestInfo {
        unique: 1,
        pid: 1,
        gid: 0,
        uid: 0,
    };
    let parent = PathBuf::from("");
    let name = OsStr::new("fstat_test.txt");

    // Create file
    let create_res = fs
        .create(req, &parent, name, 0o644, 0)
        .expect("create failed");
    let fh = create_res.fh;

    let logical_data = b"fstat testing";
    let path = parent.join("fstat_test.txt");

    // Write data
    fs.write(req, &path, fh, 0, logical_data.to_vec(), 0)
        .expect("write failed");

    // 1. Getattr with FH (fstat)
    let (_, attr_fh) = fs
        .getattr(req, &path, Some(fh))
        .expect("getattr with fh failed");
    assert_eq!(attr_fh.size, logical_data.len() as u64);

    // 2. Getattr without FH (stat/lstat)
    let (_, attr_path) = fs
        .getattr(req, &path, None)
        .expect("getattr without fh failed");
    assert_eq!(attr_path.size, logical_data.len() as u64);

    // 3. Unlink file but keep open
    fs.unlink(req, &parent, name).expect("unlink failed");

    // 4. Getattr without FH should fail now
    let res = fs.getattr(req, &path, None);
    assert!(res.is_err(), "getattr path should fail after unlink");

    // 5. Getattr with FH (fstat) should still work on unlinked open file
    let (_, attr_fh_unlinked) = fs
        .getattr(req, &path, Some(fh))
        .expect("getattr with fh failed after unlink");
    assert_eq!(attr_fh_unlinked.size, logical_data.len() as u64);

    // Cleanup
    // Close checks valid handle, though release implementation is simple removal
    fs.release(req, &path, fh, 0, 0, false).unwrap();

    // Verify directory is empty (file was unlinked)
    let count = std::fs::read_dir(&tmp).unwrap().count();
    assert_eq!(count, 0);

    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_statfs_support() {
    let (fs, tmp, _, _, _, _) = setup_test_fs("encfs_statfs", 3, 256, 1024, 8, true, true);
    let req = RequestInfo {
        unique: 1,
        pid: 1,
        gid: 0,
        uid: 0,
    };

    // Check statfs on root
    let stat = fs
        .statfs(req, std::path::Path::new("/"))
        .expect("statfs failed");

    // Check reasonable values (should match tmp dir filesystem)
    assert!(stat.blocks > 0);
    assert!(stat.bfree <= stat.blocks);
    // bsize is usually 4096, but depends on FS.
    assert!(stat.bsize > 0);

    fs::remove_dir_all(&tmp).unwrap();
}
