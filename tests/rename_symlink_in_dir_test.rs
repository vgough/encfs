use asyncfuse::path::PathFilesystem;
use asyncfuse::path::Request;
/// Test for: Rename fails for directories containing symlinks with IV chaining
///
/// When `chained_name_iv` is enabled and a directory containing symlinks is renamed,
/// the `copy_recursive` function fails with ENOSYS because it doesn't handle symlinks -
/// it only handles files and directories. The standalone symlink rename (lines 194-238
/// in fs.rs) correctly re-encrypts the symlink target with the new path IV, but this
/// logic isn't applied during recursive directory copies.
use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

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

    // chained_name_iv=true triggers the bug
    let config = encfs::config::EncfsConfig::test_default();
    EncFs::new(root.to_path_buf(), Box::new(cipher), config)
}

fn req() -> Request {
    Request {
        unique: 1,
        pid: 1,
        gid: 0,
        uid: 0,
    }
}

#[tokio::test]
async fn test_rename_directory_containing_symlink_with_chained_name_iv() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_rename_symlink_dir_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let fs = setup_fs(&tmp);
    let r = req();

    // Create a directory "parent"
    let parent_path = PathBuf::from("/parent");
    fs.mkdir(r, OsStr::new("/"), OsStr::new("parent"), 0o755, 0)
        .await
        .expect("mkdir parent failed");

    // Create a symlink inside the directory
    let target = Path::new("some_target");
    fs.symlink(
        r,
        parent_path.as_os_str(),
        OsStr::new("link"),
        target.as_os_str(),
    )
    .await
    .expect("symlink inside dir failed");

    // Create a regular file inside the directory for comparison
    let created = fs
        .create(
            r,
            parent_path.as_os_str(),
            OsStr::new("file.txt"),
            0o644,
            (libc::O_CREAT | libc::O_RDWR) as u32,
        )
        .await
        .expect("create file failed");
    let _ = fs
        .release(
            r,
            Some(PathBuf::from("/parent/file.txt").as_os_str()),
            created.fh,
            0,
            0,
            true,
        )
        .await;

    // Verify the symlink can be read before rename
    let readlink_result = fs
        .readlink(r, PathBuf::from("/parent/link").as_os_str())
        .await;
    assert!(
        readlink_result.is_ok(),
        "readlink before rename failed: {:?}",
        readlink_result.err()
    );
    let target_bytes = readlink_result.unwrap().data;
    assert_eq!(
        String::from_utf8_lossy(&target_bytes),
        "some_target",
        "symlink target mismatch before rename"
    );

    // Rename the directory containing the symlink
    // This is the operation that triggers the bug (ENOSYS due to symlink handling)
    let rename_result = fs
        .rename(
            r,
            OsStr::new("/"),
            OsStr::new("parent"),
            OsStr::new("/"),
            OsStr::new("renamed_parent"),
        )
        .await;

    assert!(
        rename_result.is_ok(),
        "rename directory with symlink failed: error code {:?}",
        rename_result.err()
    );

    // Verify the symlink target can still be read after rename
    let readlink_after = fs
        .readlink(r, PathBuf::from("/renamed_parent/link").as_os_str())
        .await;
    assert!(
        readlink_after.is_ok(),
        "readlink after rename failed: {:?}",
        readlink_after.err()
    );
    let target_after = readlink_after.unwrap().data;
    assert_eq!(
        String::from_utf8_lossy(&target_after),
        "some_target",
        "symlink target should be 'some_target' after rename, but was '{}'",
        String::from_utf8_lossy(&target_after)
    );

    // Verify the old path no longer exists
    let old_path_result = fs
        .getattr(r, Some(PathBuf::from("/parent").as_os_str()), None, 0)
        .await;
    assert!(
        old_path_result.is_err(),
        "old path should not exist after rename"
    );

    // Verify the regular file also works after rename
    let file_attr = fs
        .getattr(
            r,
            Some(PathBuf::from("/renamed_parent/file.txt").as_os_str()),
            None,
            0,
        )
        .await;
    assert!(
        file_attr.is_ok(),
        "regular file should exist after rename: {:?}",
        file_attr.err()
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

#[tokio::test]
async fn test_rename_nested_directory_with_symlinks_chained_name_iv() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_rename_nested_symlink_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let fs = setup_fs(&tmp);
    let r = req();

    // Create nested directories: /outer/inner
    fs.mkdir(r, OsStr::new("/"), OsStr::new("outer"), 0o755, 0)
        .await
        .expect("mkdir outer failed");
    fs.mkdir(r, OsStr::new("/outer"), OsStr::new("inner"), 0o755, 0)
        .await
        .expect("mkdir inner failed");

    // Create symlinks at different levels
    fs.symlink(
        r,
        PathBuf::from("/outer").as_os_str(),
        OsStr::new("link1"),
        Path::new("../some_target").as_os_str(),
    )
    .await
    .expect("symlink in outer failed");
    fs.symlink(
        r,
        PathBuf::from("/outer/inner").as_os_str(),
        OsStr::new("link2"),
        Path::new("../../other_target").as_os_str(),
    )
    .await
    .expect("symlink in inner failed");

    // Verify symlinks before rename
    let link1_before = fs
        .readlink(r, PathBuf::from("/outer/link1").as_os_str())
        .await
        .expect("readlink link1 before failed")
        .data;
    let link2_before = fs
        .readlink(r, PathBuf::from("/outer/inner/link2").as_os_str())
        .await
        .expect("readlink link2 before failed")
        .data;
    assert_eq!(String::from_utf8_lossy(&link1_before), "../some_target");
    assert_eq!(String::from_utf8_lossy(&link2_before), "../../other_target");

    // Rename the outer directory
    let rename_result = fs
        .rename(
            r,
            OsStr::new("/"),
            OsStr::new("outer"),
            OsStr::new("/"),
            OsStr::new("moved"),
        )
        .await;

    assert!(
        rename_result.is_ok(),
        "rename nested directory with symlinks failed: error code {:?}",
        rename_result.err()
    );

    // Verify symlinks after rename
    let link1_after = fs
        .readlink(r, PathBuf::from("/moved/link1").as_os_str())
        .await;
    assert!(
        link1_after.is_ok(),
        "readlink link1 after failed: {:?}",
        link1_after.err()
    );
    assert_eq!(
        String::from_utf8_lossy(&link1_after.unwrap().data),
        "../some_target"
    );

    let link2_after = fs
        .readlink(r, PathBuf::from("/moved/inner/link2").as_os_str())
        .await;
    assert!(
        link2_after.is_ok(),
        "readlink link2 after failed: {:?}",
        link2_after.err()
    );
    assert_eq!(
        String::from_utf8_lossy(&link2_after.unwrap().data),
        "../../other_target"
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
