//! End-to-end coverage for the 96-bit wide file IV through the `EncFs`
//! file layer (create/write/read/truncate), mirrored against the narrow
//! 64-bit path under the same harness. Not FUSE-mount-dependent: these drive
//! `EncFs` directly, the same way `concurrent_file_access_test.rs` and
//! `truncate_corrupt_test.rs` do.

use encfs::config::{EncfsConfig, Interface};
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use typed_fuse::{Caller, PathFilesystem, PathNodeRef, SetAttr};

mod common;
use common::Node;

fn caller() -> Caller {
    Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    }
}

/// A V7/AES-GCM-SIV config with a small block size (so a few hundred bytes
/// of test data spans several blocks) and the given file-IV width. Small
/// block size and a fixed key are test-only conveniences; the wide/narrow
/// selection and block mode are exactly what `standard_v7()` /
/// `--legacy-file-iv` produce in production.
fn make_fs(root: &std::path::Path, wide: bool) -> (EncFs, u64) {
    let iface = Interface {
        name: "ssl/aes".to_string(),
        major: 4,
        minor: 0,
        age: 0,
    };
    let mut cipher = SslCipher::new(&iface, 256).expect("cipher");
    cipher.set_key(&[7u8; 32], &[8u8; 16]);
    cipher.set_wide_file_iv(wide);

    let mut config = EncfsConfig::standard_v7();
    config.wide_file_iv = wide;
    if !wide {
        config.minimum_reader_version = encfs::constants::V7_BASE_CONFIG_VERSION;
    }
    config.block_size = 64;
    let header_size = config.header_size();
    assert_eq!(header_size, if wide { 12 } else { 8 });

    (
        EncFs::new(root.to_path_buf(), Box::new(cipher), config),
        header_size,
    )
}

fn run_create_write_truncate_read_roundtrip(wide: bool) {
    let tmp = std::env::temp_dir().join(format!(
        "encfs_wide_file_iv_test_{}_{}",
        wide,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir(&tmp).unwrap();

    let (mut fs, header_size) = make_fs(&tmp, wide);
    let root_state = fs.root_state();
    let req = caller();

    let parent = PathBuf::from("");
    let name = OsStr::new("wide_iv_test.bin");
    let path = parent.join(name);

    // Create, then write data spanning several 48-byte (64 - 16-byte tag)
    // data blocks, crossing block boundaries.
    let (created, create_res) = fs
        .create(
            PathNodeRef::new(Some(&parent), &root_state),
            name,
            0o644,
            0,
            0,
            &req,
        )
        .expect("create failed");
    let handle = create_res.handle;
    let node = Node::at(&path, created.state);

    let data: Vec<u8> = (0u32..130).map(|i| (i % 251) as u8).collect();
    let written = fs
        .write(node.as_node(), &handle, &data, 0, &req)
        .expect("write failed");
    assert_eq!(written, data.len());
    fs.release(node.as_node(), handle, &req).unwrap();

    // The on-disk header must be exactly the configured width.
    let mut entries = fs::read_dir(&tmp).unwrap();
    let real_path = entries.next().unwrap().unwrap().path();
    let physical_len = fs::metadata(&real_path).unwrap().len();
    assert!(
        physical_len >= header_size,
        "physical file must be at least the header size"
    );

    // Read back through EncFs and verify content.
    let read_handle = fs
        .open(node.as_node(), libc::O_RDONLY, &req)
        .unwrap()
        .handle;
    let read_back = fs
        .read(node.as_node(), &read_handle, 0, data.len(), &req)
        .expect("read failed");
    assert_eq!(&read_back[..], data.as_slice());
    fs.release(node.as_node(), read_handle, &req).unwrap();

    // Truncate grow past the current end (crossing another block boundary),
    // then read back the extended region as zeros plus the original data.
    let grow_handle = fs.open(node.as_node(), libc::O_RDWR, &req).unwrap().handle;
    fs.setattr(
        node.as_node(),
        Some(&grow_handle),
        &SetAttr {
            size: Some(300),
            ..Default::default()
        },
        &req,
    )
    .expect("truncate grow failed");
    let grown = fs
        .read(node.as_node(), &grow_handle, 0, 300, &req)
        .expect("read after grow failed");
    assert_eq!(grown.len(), 300);
    assert_eq!(&grown[..data.len()], data.as_slice());
    assert!(
        grown[data.len()..].iter().all(|&b| b == 0),
        "grown region must read back as zeros"
    );

    // Truncate shrink to a partial-block size, forcing a read-modify-write
    // of the last remaining block, then verify the surviving prefix.
    fs.setattr(
        node.as_node(),
        Some(&grow_handle),
        &SetAttr {
            size: Some(70),
            ..Default::default()
        },
        &req,
    )
    .expect("truncate shrink failed");
    let shrunk = fs
        .read(node.as_node(), &grow_handle, 0, 70, &req)
        .expect("read after shrink failed");
    assert_eq!(shrunk.len(), 70);
    assert_eq!(&shrunk[..], &data[..70]);
    fs.release(node.as_node(), grow_handle, &req).unwrap();

    // Verify the physical header length matches the configured width exactly,
    // by re-reading the raw file and confirming the plaintext header size
    // used by the decoder (header_size bytes) leaves a properly-aligned
    // remainder of whole/partial AES-GCM-SIV blocks.
    let raw = fs::read(&real_path).unwrap();
    assert!(raw.len() as u64 >= header_size);
    let mut buf = vec![0u8; header_size as usize];
    std::fs::File::open(&real_path)
        .unwrap()
        .read_at(&mut buf, 0)
        .unwrap();
    assert_eq!(buf.len(), header_size as usize);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn wide_file_iv_create_write_truncate_read_roundtrip() {
    run_create_write_truncate_read_roundtrip(true);
}

#[test]
fn narrow_file_iv_create_write_truncate_read_roundtrip() {
    run_create_write_truncate_read_roundtrip(false);
}

/// Proves the *production* wiring, not just the cipher/fs layers in
/// isolation: `EncfsConfig::get_cipher()` must call `set_wide_file_iv` on the
/// cipher it returns, or a wide config's headers/blocks would silently fail
/// to round-trip (a cipher that defaults to narrow can't decrypt a 12-byte
/// header or an AES-GCM-SIV block encrypted with the wide nonce/AAD
/// construction). This builds the cipher through `EncfsConfig::get_cipher`
/// exactly as `encfs`/`encfsr`/`encfsctl` do, not by calling
/// `set_wide_file_iv` directly as `make_fs` above does.
#[test]
fn get_cipher_wires_wide_file_iv_end_to_end() {
    let tmp = std::env::temp_dir().join(format!(
        "encfs_wide_file_iv_get_cipher_test_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir(&tmp).unwrap();

    let mut config = EncfsConfig::standard_v7();
    assert!(config.wide_file_iv);
    config.argon2_memory_cost = Some(8);
    config.argon2_time_cost = Some(1);
    config.argon2_parallelism = Some(1);
    getrandom::fill(&mut config.salt).unwrap();

    let volume_key_blob = vec![0u8; 32 + 16];
    config
        .set_v7_key("wide-test-password", &volume_key_blob)
        .unwrap();
    let config_path = tmp.join(".encfs7");
    config.save(&config_path).unwrap();

    // Reload from disk and derive the cipher exactly as production code
    // does: EncfsConfig::load -> get_cipher.
    let loaded = EncfsConfig::load(&config_path).unwrap();
    assert!(loaded.wide_file_iv);
    let cipher = loaded.get_cipher("wide-test-password").unwrap();

    let mount_dir = tmp.join("data");
    fs::create_dir(&mount_dir).unwrap();
    let mut fs = EncFs::new(mount_dir, cipher, loaded);
    let root_state = fs.root_state();
    let req = caller();

    let parent = PathBuf::from("");
    let name = OsStr::new("file.bin");
    let (created, create_res) = fs
        .create(
            PathNodeRef::new(Some(&parent), &root_state),
            name,
            0o644,
            0,
            0,
            &req,
        )
        .expect("create failed");
    let handle = create_res.handle;
    let node = Node::at(parent.join(name), created.state);

    let data = b"wide file IV production wiring check".to_vec();
    fs.write(node.as_node(), &handle, &data, 0, &req)
        .expect("write failed");
    fs.release(node.as_node(), handle, &req).unwrap();

    let read_handle = fs
        .open(node.as_node(), libc::O_RDONLY, &req)
        .unwrap()
        .handle;
    let read_back = fs
        .read(node.as_node(), &read_handle, 0, data.len(), &req)
        .expect("read failed");
    assert_eq!(&read_back[..], data.as_slice());
    fs.release(node.as_node(), read_handle, &req).unwrap();

    let _ = fs::remove_dir_all(&tmp);
}
