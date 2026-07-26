use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};
use typed_fuse::{Caller, PathFilesystem, SetAttr, TimeOrNow};

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

    let fs = setup_fs(&tmp, false);
    let r = req();

    // Create a directory "/dir"
    fs.mkdir(Path::new("/"), OsStr::new("dir"), 0o755, 0, &r)
        .expect("mkdir dir failed");

    // Create a file "/dir/file.txt"
    let created = fs
        .create(
            Path::new("/dir"),
            OsStr::new("file.txt"),
            0o644,
            0,
            libc::O_CREAT | libc::O_RDWR,
            &r,
        )
        .expect("create file failed");
    let file_path = PathBuf::from("/dir/file.txt");
    let _ = fs.release(Some(&file_path), created.1.handle, &r);

    // Set specific custom timestamps on /dir and /dir/file.txt
    let past_atime = UNIX_EPOCH + Duration::new(1_500_000_000, 123_456_000);
    let past_mtime = UNIX_EPOCH + Duration::new(1_500_000_000, 987_654_000);

    let set_attr = SetAttr {
        atime: Some(TimeOrNow::SpecificTime(past_atime)),
        mtime: Some(TimeOrNow::SpecificTime(past_mtime)),
        ..Default::default()
    };

    let setattr_file = fs.setattr(Some(&file_path), None, &set_attr, &r);
    assert!(
        setattr_file.is_ok(),
        "setattr file failed: {:?}",
        setattr_file.err()
    );

    let setattr_dir = fs.setattr(Some(Path::new("/dir")), None, &set_attr, &r);
    assert!(
        setattr_dir.is_ok(),
        "setattr dir failed: {:?}",
        setattr_dir.err()
    );

    // Rename "/dir" -> "/renamed_dir"
    let rename_res = fs.rename(
        Path::new("/"),
        OsStr::new("dir"),
        Path::new("/"),
        OsStr::new("renamed_dir"),
        &r,
    );
    assert!(
        rename_res.is_ok(),
        "rename dir failed: {:?}",
        rename_res.err()
    );

    // Check timestamps of renamed directory
    let dir_attr = fs
        .getattr(Some(Path::new("/renamed_dir")), None, &r)
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
    let file_attr = fs
        .getattr(Some(Path::new("/renamed_dir/file.txt")), None, &r)
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

    let fs = setup_fs(&tmp, true);
    let r = req();

    // Create a file "/file.txt"
    let created = fs
        .create(
            Path::new("/"),
            OsStr::new("file.txt"),
            0o644,
            0,
            libc::O_CREAT | libc::O_RDWR,
            &r,
        )
        .expect("create file failed");
    let file_path = PathBuf::from("/file.txt");
    let _ = fs.release(Some(&file_path), created.1.handle, &r);

    let past_atime = UNIX_EPOCH + Duration::new(1_600_000_000, 111_222_000);
    let past_mtime = UNIX_EPOCH + Duration::new(1_600_000_000, 333_444_000);

    let set_attr = SetAttr {
        atime: Some(TimeOrNow::SpecificTime(past_atime)),
        mtime: Some(TimeOrNow::SpecificTime(past_mtime)),
        ..Default::default()
    };

    let setattr_res = fs.setattr(Some(&file_path), None, &set_attr, &r);
    assert!(
        setattr_res.is_ok(),
        "setattr file failed: {:?}",
        setattr_res.err()
    );

    // Rename "/file.txt" -> "/renamed.txt" with external_iv_chaining=true
    let rename_res = fs.rename(
        Path::new("/"),
        OsStr::new("file.txt"),
        Path::new("/"),
        OsStr::new("renamed.txt"),
        &r,
    );
    assert!(
        rename_res.is_ok(),
        "rename file with ext IV failed: {:?}",
        rename_res.err()
    );

    let file_attr = fs
        .getattr(Some(Path::new("/renamed.txt")), None, &r)
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
