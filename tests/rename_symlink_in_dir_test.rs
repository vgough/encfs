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
use typed_fuse::{Caller, PathFilesystem};

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

fn req() -> Caller {
    Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    }
}

#[test]
fn test_rename_directory_containing_symlink_with_chained_name_iv() {
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
    fs.mkdir(Path::new("/"), OsStr::new("parent"), 0o755, 0, &r)
        .expect("mkdir parent failed");

    // Create a symlink inside the directory
    let target = Path::new("some_target");
    fs.symlink(&parent_path, OsStr::new("link"), target, &r)
        .expect("symlink inside dir failed");

    // Create a regular file inside the directory for comparison
    let created = fs
        .create(
            &parent_path,
            OsStr::new("file.txt"),
            0o644,
            0,
            libc::O_CREAT | libc::O_RDWR,
            &r,
        )
        .expect("create file failed");
    let created_path = PathBuf::from("/parent/file.txt");
    let _ = fs.release(Some(&created_path), created.1.handle, &r);

    // Verify the symlink can be read before rename
    let readlink_result = fs.readlink(Path::new("/parent/link"), &r);
    assert!(
        readlink_result.is_ok(),
        "readlink before rename failed: {:?}",
        readlink_result.err()
    );
    let target_bytes = readlink_result.unwrap();
    assert_eq!(
        target_bytes,
        Path::new("some_target"),
        "symlink target mismatch before rename"
    );

    // Rename the directory containing the symlink
    // This is the operation that triggers the bug (ENOSYS due to symlink handling)
    let rename_result = fs.rename(
        Path::new("/"),
        OsStr::new("parent"),
        Path::new("/"),
        OsStr::new("renamed_parent"),
        &r,
    );

    assert!(
        rename_result.is_ok(),
        "rename directory with symlink failed: error code {:?}",
        rename_result.err()
    );

    // Verify the symlink target can still be read after rename
    let readlink_after = fs.readlink(Path::new("/renamed_parent/link"), &r);
    assert!(
        readlink_after.is_ok(),
        "readlink after rename failed: {:?}",
        readlink_after.err()
    );
    let target_after = readlink_after.unwrap();
    assert_eq!(
        target_after,
        Path::new("some_target"),
        "symlink target should be 'some_target' after rename, but was '{}'",
        target_after.display()
    );

    // Verify the old path no longer exists
    let old_path_result = fs.getattr(Some(Path::new("/parent")), None, &r);
    assert!(
        old_path_result.is_err(),
        "old path should not exist after rename"
    );

    // Verify the regular file also works after rename
    let file_attr = fs.getattr(Some(Path::new("/renamed_parent/file.txt")), None, &r);
    assert!(
        file_attr.is_ok(),
        "regular file should exist after rename: {:?}",
        file_attr.err()
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_rename_nested_directory_with_symlinks_chained_name_iv() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_rename_nested_symlink_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let fs = setup_fs(&tmp);
    let r = req();

    // Create nested directories: /outer/inner
    fs.mkdir(Path::new("/"), OsStr::new("outer"), 0o755, 0, &r)
        .expect("mkdir outer failed");
    fs.mkdir(Path::new("/outer"), OsStr::new("inner"), 0o755, 0, &r)
        .expect("mkdir inner failed");

    // Create symlinks at different levels
    fs.symlink(
        Path::new("/outer"),
        OsStr::new("link1"),
        Path::new("../some_target"),
        &r,
    )
    .expect("symlink in outer failed");
    fs.symlink(
        Path::new("/outer/inner"),
        OsStr::new("link2"),
        Path::new("../../other_target"),
        &r,
    )
    .expect("symlink in inner failed");

    // Verify symlinks before rename
    let link1_before = fs
        .readlink(Path::new("/outer/link1"), &r)
        .expect("readlink link1 before failed");
    let link2_before = fs
        .readlink(Path::new("/outer/inner/link2"), &r)
        .expect("readlink link2 before failed");
    assert_eq!(link1_before, Path::new("../some_target"));
    assert_eq!(link2_before, Path::new("../../other_target"));

    // Rename the outer directory
    let rename_result = fs.rename(
        Path::new("/"),
        OsStr::new("outer"),
        Path::new("/"),
        OsStr::new("moved"),
        &r,
    );

    assert!(
        rename_result.is_ok(),
        "rename nested directory with symlinks failed: error code {:?}",
        rename_result.err()
    );

    // Verify symlinks after rename
    let link1_after = fs.readlink(Path::new("/moved/link1"), &r);
    assert!(
        link1_after.is_ok(),
        "readlink link1 after failed: {:?}",
        link1_after.err()
    );
    assert_eq!(link1_after.unwrap(), Path::new("../some_target"));

    let link2_after = fs.readlink(Path::new("/moved/inner/link2"), &r);
    assert!(
        link2_after.is_ok(),
        "readlink link2 after failed: {:?}",
        link2_after.err()
    );
    assert_eq!(link2_after.unwrap(), Path::new("../../other_target"));

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
