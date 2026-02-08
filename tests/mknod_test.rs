//! Tests for mknod/mkfifo support: creating FIFOs and special files on the EncFS mount,
//! and that getattr/readdir return the correct file type.

use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use fuse_mt::{FileType, FilesystemMT, RequestInfo};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

/// S_IFIFO from POSIX (named pipe)
const S_IFIFO: u32 = 0o010000;

fn setup_fs(root: &Path) -> EncFs {
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

    let config = encfs::config::EncfsConfig::test_default();
    EncFs::new(root.to_path_buf(), cipher, config)
}

fn req() -> RequestInfo {
    RequestInfo {
        unique: 1,
        pid: 1,
        gid: 0,
        uid: 0,
    }
}

#[test]
fn test_mknod_fifo_getattr_returns_named_pipe() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_mknod_fifo_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let fs = setup_fs(&tmp);
    let r = req();

    let parent = PathBuf::from("");
    let name = OsStr::new("myfifo");
    let mode = S_IFIFO | 0o755;

    // Create FIFO via mknod
    fs.mknod(r, &parent, name, mode, 0).expect("mknod FIFO failed");

    let path = parent.join("myfifo");

    // getattr should return NamedPipe (FIFO) type
    let (ttl, attr) = fs.getattr(r, &path, None).expect("getattr failed");
    assert_eq!(attr.kind, FileType::NamedPipe, "getattr should report NamedPipe for FIFO");
    assert_eq!(attr.perm & 0o777, 0o755, "FIFO permission bits should be 0755");
    let _ = ttl;

    // Backend should contain an encrypted FIFO
    let entries: Vec<_> = fs::read_dir(&tmp)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_name().to_str().unwrap_or("").starts_with('.'))
        .collect();
    assert_eq!(entries.len(), 1, "Expected exactly one entry (the FIFO)");
    let meta = entries[0].metadata().unwrap();
    assert!(
        meta.file_type().is_fifo(),
        "Backend entry should be a FIFO (named pipe)"
    );

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn test_mknod_fifo_readdir_reports_named_pipe() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_mknod_readdir_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let fs = setup_fs(&tmp);
    let r = req();

    let parent = PathBuf::from("");
    fs.mknod(r, &parent, OsStr::new("pipe"), S_IFIFO | 0o600, 0).expect("mknod FIFO failed");

    let dir_path = PathBuf::from("");
    let entries = fs.readdir(r, &dir_path, 0).expect("readdir failed");

    let pipe_entry = entries
        .iter()
        .find(|e| e.name.as_os_str() == OsStr::new("pipe"))
        .expect("readdir should list 'pipe'");
    assert_eq!(
        pipe_entry.kind,
        FileType::NamedPipe,
        "readdir should report NamedPipe for FIFO"
    );

    fs::remove_dir_all(&tmp).ok();
}
