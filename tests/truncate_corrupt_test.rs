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
fn test_truncate_corrupts_partial_block() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_truncate_corrupt_test");
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
    let user_key = vec![1u8; 24]; // 192 bits
    let user_iv = vec![2u8; 16];
    cipher.set_key(&user_key, &user_iv);

    // Create a second cipher instance for verification
    let verify_cipher = SslCipher::new(&iface, 192).unwrap();
    let mut verify_cipher = verify_cipher;
    verify_cipher.set_key(&user_key, &user_iv);

    // chained_name_iv=true, external_iv_chaining=true (as in original issue description "full blocks are encrypted with CBC mode")
    // Wait, CBC/CFB switch happens regardless of chaining.
    // But external_iv_chaining affects how file IV is derived/stored?
    // In EncFs, file IV is stored in header regardless.
    // external_iv_chaining affects filename encryption and maybe directory IVs.
    // Let's use standard defaults: chained_name_iv=true, external_iv_chaining=false usually?
    // The issue report mentions "The issue is that full blocks are encrypted with CBC mode, but decrypt_block_inplace uses CFB mode when data.len() < block_size".
    // This happens in FileDecoder/Encoder regardless of IV chaining settings essentially, locally to the block.

    // I'll stick to what write_test.rs used: true, false.
    let fs = EncFs::new(root.clone(), cipher, 1024, 8, true, false);

    let req = RequestInfo {
        unique: 1,
        pid: 1,
        gid: 0,
        uid: 0,
    };

    let parent = PathBuf::from("");
    let filename = "corrupt_test.bin";
    let name = OsStr::new(filename);
    let path = parent.join(filename);

    // 1. Create file
    let create_res = fs
        .create(req, &parent, name, 0o644, 0)
        .expect("create failed");
    let fh = create_res.fh;

    // 2. Write Data > 1 block (1024 bytes)
    // Write 1024 + 50 bytes.
    let data_len = 1074;
    let data: Vec<u8> = (0..data_len).map(|i| (i % 255) as u8).collect();

    // Write in one go
    let written = fs
        .write(req, &path, fh, 0, data.clone(), 0)
        .expect("write failed");
    assert_eq!(written, data.len() as u32);

    // Release to flush
    fs.release(req, &path, fh, 0, 0, true).unwrap();

    // 3. Truncate to a partial block size (e.g. 500 bytes)
    // This will force the first block (which was full 1024) to be truncated to 500.
    // The code should read the block, truncate to 500, and write back.
    // Due to the bug, it might decrypt the first 500 bytes of the CBC block using CFB, resulting in garbage,
    // and then write that garbage back.
    let target_size = 500;
    fs.truncate(req, &path, None, target_size).unwrap();

    // 4. Verify content
    // We need to read the physical file and decrypt it.

    // Find physical path
    // Since we don't know the exact encrypted name easily (random IV), we list dir.
    let mut entries = fs::read_dir(&tmp).unwrap();
    let entry = entries.next().unwrap().unwrap();
    let real_path = entry.path();

    let file = std::fs::File::open(&real_path).unwrap();
    let mut header = [0u8; 8];
    FileExt::read_at(&file, &mut header, 0).unwrap();

    // Decrypt header
    // external_iv=0 since external_iv_chaining=false.
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
    );

    let mut read_data = vec![0u8; target_size as usize];
    let read_len = decoder
        .read_at(&mut read_data, 0)
        .expect("read verification failed");

    assert_eq!(read_len, target_size as usize);

    // Compare with expected data (first 500 bytes of original)
    if read_data != data[..target_size as usize] {
        // Find first difference
        let mismatch_idx = read_data.iter().zip(data.iter()).position(|(a, b)| a != b);
        if let Some(idx) = mismatch_idx {
            panic!(
                "Data corrupted at index {}: expected {}, got {}",
                idx, data[idx], read_data[idx]
            );
        }
    }

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
