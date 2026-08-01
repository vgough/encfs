use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};
use typed_fuse::{Caller, PathFilesystem, PathNodeRef, SetAttr, TimeOrNow};

mod common;
use common::{Node, node};

fn setup_fs(root: &Path, external_iv_chaining: bool) -> EncFs {
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

    let mut config = encfs::config::EncfsConfig::test_default();
    config.external_iv_chaining = external_iv_chaining;
    EncFs::new(root.to_path_buf(), Box::new(cipher), config)
}

fn req() -> Caller {
    Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    }
}

#[test]
fn test_rename_directory_preserves_timestamps() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_rename_timestamp_dir_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let mut fs = setup_fs(&tmp, false);
    let root = fs.root_state();
    let r = req();

    // Create a directory "/dir"
    let dir = fs
        .mkdir(
            PathNodeRef::new(Some(Path::new("/")), &root),
            OsStr::new("dir"),
            0o755,
            0,
            &r,
        )
        .expect("mkdir dir failed");
    let dir = Node::at("/dir", dir.state);

    // Create a file "/dir/file.txt"
    let created = fs
        .create(
            dir.as_node(),
            OsStr::new("file.txt"),
            0o644,
            0,
            libc::O_CREAT | libc::O_RDWR,
            &r,
        )
        .expect("create file failed");
    let file = Node::at(PathBuf::from("/dir/file.txt"), created.0.state);
    let _ = fs.release(file.as_node(), created.1.handle, &r);

    // Set specific custom timestamps on /dir and /dir/file.txt
    let past_atime = UNIX_EPOCH + Duration::new(1_500_000_000, 123_456_000);
    let past_mtime = UNIX_EPOCH + Duration::new(1_500_000_000, 987_654_000);

    let set_attr = SetAttr {
        atime: Some(TimeOrNow::SpecificTime(past_atime)),
        mtime: Some(TimeOrNow::SpecificTime(past_mtime)),
        ..Default::default()
    };

    let setattr_file = fs.setattr(file.as_node(), None, &set_attr, &r);
    assert!(
        setattr_file.is_ok(),
        "setattr file failed: {:?}",
        setattr_file.err()
    );

    let setattr_dir = fs.setattr(dir.as_node(), None, &set_attr, &r);
    assert!(
        setattr_dir.is_ok(),
        "setattr dir failed: {:?}",
        setattr_dir.err()
    );

    // Rename "/dir" -> "/renamed_dir"
    let rename_res = fs.rename(
        PathNodeRef::new(Some(Path::new("/")), &root),
        OsStr::new("dir"),
        PathNodeRef::new(Some(Path::new("/")), &root),
        OsStr::new("renamed_dir"),
        &r,
    );
    assert!(
        rename_res.is_ok(),
        "rename dir failed: {:?}",
        rename_res.err()
    );

    // Check timestamps of renamed directory
    let renamed_dir = node(&fs, &root, "/renamed_dir", &r);
    let dir_attr = fs
        .getattr(renamed_dir.as_node(), None, &r)
        .expect("getattr renamed_dir failed");
    assert_eq!(
        dir_attr.atime, past_atime,
        "directory atime lost across rename"
    );
    assert_eq!(
        dir_attr.mtime, past_mtime,
        "directory mtime lost across rename"
    );

    // Check timestamps of child file
    let renamed_file = node(&fs, &root, "/renamed_dir/file.txt", &r);
    let file_attr = fs
        .getattr(renamed_file.as_node(), None, &r)
        .expect("getattr file.txt failed");
    assert_eq!(file_attr.atime, past_atime, "file atime lost across rename");
    assert_eq!(file_attr.mtime, past_mtime, "file mtime lost across rename");

    // Cleanup
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_rename_file_external_iv_chaining_preserves_timestamps() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_rename_timestamp_extiv_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let mut fs = setup_fs(&tmp, true);
    let root = fs.root_state();
    let r = req();

    // Create a file "/file.txt"
    let created = fs
        .create(
            PathNodeRef::new(Some(Path::new("/")), &root),
            OsStr::new("file.txt"),
            0o644,
            0,
            libc::O_CREAT | libc::O_RDWR,
            &r,
        )
        .expect("create file failed");
    let file = Node::at(PathBuf::from("/file.txt"), created.0.state);
    let _ = fs.release(file.as_node(), created.1.handle, &r);

    let past_atime = UNIX_EPOCH + Duration::new(1_600_000_000, 111_222_000);
    let past_mtime = UNIX_EPOCH + Duration::new(1_600_000_000, 333_444_000);

    let set_attr = SetAttr {
        atime: Some(TimeOrNow::SpecificTime(past_atime)),
        mtime: Some(TimeOrNow::SpecificTime(past_mtime)),
        ..Default::default()
    };

    let setattr_res = fs.setattr(file.as_node(), None, &set_attr, &r);
    assert!(
        setattr_res.is_ok(),
        "setattr file failed: {:?}",
        setattr_res.err()
    );

    // Rename "/file.txt" -> "/renamed.txt" with external_iv_chaining=true
    let rename_res = fs.rename(
        PathNodeRef::new(Some(Path::new("/")), &root),
        OsStr::new("file.txt"),
        PathNodeRef::new(Some(Path::new("/")), &root),
        OsStr::new("renamed.txt"),
        &r,
    );
    assert!(
        rename_res.is_ok(),
        "rename file with ext IV failed: {:?}",
        rename_res.err()
    );

    let renamed_file = node(&fs, &root, "/renamed.txt", &r);
    let file_attr = fs
        .getattr(renamed_file.as_node(), None, &r)
        .expect("getattr renamed.txt failed");
    assert_eq!(
        file_attr.atime, past_atime,
        "file atime lost across ext IV rename"
    );
    assert_eq!(
        file_attr.mtime, past_mtime,
        "file mtime lost across ext IV rename"
    );

    // Cleanup
    let _ = fs::remove_dir_all(&tmp);
}
