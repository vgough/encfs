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
use typed_fuse::{Caller, PathFilesystem, PathNodeRef};

mod common;
use common::{Node, node};

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

    let mut fs = setup_fs(&tmp);
    let root = fs.root_state();
    let r = req();

    // Create a directory "parent"
    let parent_dir = fs
        .mkdir(
            PathNodeRef::new(Some(Path::new("/")), &root),
            OsStr::new("parent"),
            0o755,
            0,
            &r,
        )
        .expect("mkdir parent failed");
    let parent_dir = Node::at(PathBuf::from("/parent"), parent_dir.state);

    // Create a symlink inside the directory
    let target = Path::new("some_target");
    let link = fs
        .symlink(parent_dir.as_node(), OsStr::new("link"), target, &r)
        .expect("symlink inside dir failed");
    let link = Node::at("/parent/link", link.state);

    // Create a regular file inside the directory for comparison
    let created = fs
        .create(
            parent_dir.as_node(),
            OsStr::new("file.txt"),
            0o644,
            0,
            libc::O_CREAT | libc::O_RDWR,
            &r,
        )
        .expect("create file failed");
    let created_file = Node::at(PathBuf::from("/parent/file.txt"), created.0.state);
    let _ = fs.release(created_file.as_node(), created.1.handle, &r);

    // Verify the symlink can be read before rename
    let readlink_result = fs.readlink(link.as_node(), &r);
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
        PathNodeRef::new(Some(Path::new("/")), &root),
        OsStr::new("parent"),
        PathNodeRef::new(Some(Path::new("/")), &root),
        OsStr::new("renamed_parent"),
        &r,
    );

    assert!(
        rename_result.is_ok(),
        "rename directory with symlink failed: error code {:?}",
        rename_result.err()
    );

    // Verify the symlink target can still be read after rename
    let moved_link = node(&fs, &root, "/renamed_parent/link", &r);
    let readlink_after = fs.readlink(moved_link.as_node(), &r);
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
    let old_path_result = fs.getattr(parent_dir.as_node(), None, &r);
    assert!(
        old_path_result.is_err(),
        "old path should not exist after rename"
    );

    // Verify the regular file also works after rename
    let moved_file = node(&fs, &root, "/renamed_parent/file.txt", &r);
    let file_attr = fs.getattr(moved_file.as_node(), None, &r);
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

    let mut fs = setup_fs(&tmp);
    let root = fs.root_state();
    let r = req();

    // Create nested directories: /outer/inner
    let outer = fs
        .mkdir(
            PathNodeRef::new(Some(Path::new("/")), &root),
            OsStr::new("outer"),
            0o755,
            0,
            &r,
        )
        .expect("mkdir outer failed");
    let outer = Node::at("/outer", outer.state);
    let inner = fs
        .mkdir(outer.as_node(), OsStr::new("inner"), 0o755, 0, &r)
        .expect("mkdir inner failed");
    let inner = Node::at("/outer/inner", inner.state);

    // Create symlinks at different levels
    let link1 = fs
        .symlink(
            outer.as_node(),
            OsStr::new("link1"),
            Path::new("../some_target"),
            &r,
        )
        .expect("symlink in outer failed");
    let link1 = Node::at("/outer/link1", link1.state);
    let link2 = fs
        .symlink(
            inner.as_node(),
            OsStr::new("link2"),
            Path::new("../../other_target"),
            &r,
        )
        .expect("symlink in inner failed");
    let link2 = Node::at("/outer/inner/link2", link2.state);

    // Verify symlinks before rename
    let link1_before = fs
        .readlink(link1.as_node(), &r)
        .expect("readlink link1 before failed");
    let link2_before = fs
        .readlink(link2.as_node(), &r)
        .expect("readlink link2 before failed");
    assert_eq!(link1_before, Path::new("../some_target"));
    assert_eq!(link2_before, Path::new("../../other_target"));

    // Rename the outer directory
    let rename_result = fs.rename(
        PathNodeRef::new(Some(Path::new("/")), &root),
        OsStr::new("outer"),
        PathNodeRef::new(Some(Path::new("/")), &root),
        OsStr::new("moved"),
        &r,
    );

    assert!(
        rename_result.is_ok(),
        "rename nested directory with symlinks failed: error code {:?}",
        rename_result.err()
    );

    // Verify symlinks after rename
    let moved_link1 = node(&fs, &root, "/moved/link1", &r);
    let link1_after = fs.readlink(moved_link1.as_node(), &r);
    assert!(
        link1_after.is_ok(),
        "readlink link1 after failed: {:?}",
        link1_after.err()
    );
    assert_eq!(link1_after.unwrap(), Path::new("../some_target"));

    let moved_link2 = node(&fs, &root, "/moved/inner/link2", &r);
    let link2_after = fs.readlink(moved_link2.as_node(), &r);
    assert!(
        link2_after.is_ok(),
        "readlink link2 after failed: {:?}",
        link2_after.err()
    );
    assert_eq!(link2_after.unwrap(), Path::new("../../other_target"));

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
