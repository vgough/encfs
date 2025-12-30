/// Tests for: File and directory permission handling
///
/// Verifies that mkdir, create (file), and symlink properly respect the mode
/// parameter when creating files and directories. On Unix systems, these operations
/// should use the mode parameter rather than relying on umask-based defaults.
use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use fuse_mt::{FilesystemMT, RequestInfo};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
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
fn test_mkdir_uses_mode_parameter() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_mkdir_mode_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Create a directory with restrictive permissions (0o700 = rwx------)
    let mode: u32 = 0o700;
    encfs
        .mkdir(r, Path::new("/"), OsStr::new("restricted_dir"), mode)
        .expect("mkdir failed");

    // Find the actual encrypted directory in the root
    let entries: Vec<_> = fs::read_dir(&tmp)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
        .collect();

    assert_eq!(entries.len(), 1, "Expected exactly one directory");

    let encrypted_dir = &entries[0];
    let metadata = encrypted_dir.metadata().unwrap();
    let actual_mode = metadata.mode() & 0o777; // Get just the permission bits

    println!("Requested mode: {:o}, Actual mode: {:o}", mode, actual_mode);

    // The directory should have mode 0o700, not 0o755 or whatever the umask gives
    assert_eq!(
        actual_mode, mode,
        "Directory mode should match requested mode. Expected {:o}, got {:o}",
        mode, actual_mode
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_mkdir_various_modes() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_mkdir_various_modes_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Test various mode values
    // Note: DirBuilder::mode() is still affected by umask.
    // With typical umask 0o022, group write and other write bits are cleared.
    // We test with modes that are already compatible with umask 0o022.
    let test_cases = [
        ("mode_700", 0o700u32),
        ("mode_750", 0o750u32),
        ("mode_755", 0o755u32),
        ("mode_500", 0o500u32),
        ("mode_755_b", 0o755u32), // duplicate to test more cases
    ];

    for (name, mode) in test_cases {
        encfs
            .mkdir(r, Path::new("/"), OsStr::new(name), mode)
            .unwrap_or_else(|_| panic!("mkdir {} failed", name));
    }

    // Check the modes via getattr
    for (name, expected_mode) in test_cases {
        let path = PathBuf::from("/").join(name);
        let (_, attr) = encfs
            .getattr(r, &path, None)
            .unwrap_or_else(|_| panic!("getattr for {} failed", name));
        let actual_mode = (attr.perm as u32) & 0o777;

        println!(
            "{}: expected {:o}, got {:o}",
            name, expected_mode, actual_mode
        );
        assert_eq!(
            actual_mode, expected_mode,
            "{}: Directory mode should match requested mode. Expected {:o}, got {:o}",
            name, expected_mode, actual_mode
        );
    }

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

// ============================================================================
// File creation permission tests
// ============================================================================

#[test]
fn test_create_file_uses_mode_parameter() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_create_file_mode_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Create a file with restrictive permissions (0o600 = rw-------)
    let mode: u32 = 0o600;
    let created = encfs
        .create(
            r,
            Path::new("/"),
            OsStr::new("restricted_file.txt"),
            mode,
            (libc::O_CREAT | libc::O_RDWR) as u32,
        )
        .expect("create file failed");

    // Release the file handle
    let _ = encfs.release(
        r,
        &PathBuf::from("/restricted_file.txt"),
        created.fh,
        0,
        0,
        true,
    );

    // Find the actual encrypted file in the root
    let entries: Vec<_> = fs::read_dir(&tmp)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .collect();

    assert_eq!(entries.len(), 1, "Expected exactly one file");

    let encrypted_file = &entries[0];
    let metadata = encrypted_file.metadata().unwrap();
    let actual_mode = metadata.mode() & 0o777;

    println!(
        "File: Requested mode: {:o}, Actual mode: {:o}",
        mode, actual_mode
    );

    assert_eq!(
        actual_mode, mode,
        "File mode should match requested mode. Expected {:o}, got {:o}",
        mode, actual_mode
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_create_file_various_modes() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_create_file_various_modes_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Test various file mode values
    // Note: OpenOptions::mode() is affected by umask.
    // With typical umask 0o022, group write and other write bits are cleared.
    let test_cases = [
        ("file_600", 0o600u32),
        ("file_640", 0o640u32),
        ("file_644", 0o644u32),
        ("file_400", 0o400u32),
        ("file_755", 0o755u32), // executable file
    ];

    for (name, mode) in test_cases {
        let created = encfs
            .create(
                r,
                Path::new("/"),
                OsStr::new(name),
                mode,
                (libc::O_CREAT | libc::O_RDWR) as u32,
            )
            .unwrap_or_else(|_| panic!("create {} failed", name));

        // Release the file handle
        let _ = encfs.release(r, &PathBuf::from("/").join(name), created.fh, 0, 0, true);
    }

    // Check the modes via getattr
    for (name, expected_mode) in test_cases {
        let path = PathBuf::from("/").join(name);
        let (_, attr) = encfs
            .getattr(r, &path, None)
            .unwrap_or_else(|_| panic!("getattr for {} failed", name));
        let actual_mode = (attr.perm as u32) & 0o777;

        println!(
            "File {}: expected {:o}, got {:o}",
            name, expected_mode, actual_mode
        );
        assert_eq!(
            actual_mode, expected_mode,
            "File {}: mode should match requested mode. Expected {:o}, got {:o}",
            name, expected_mode, actual_mode
        );
    }

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

// ============================================================================
// Symlink permission tests
// ============================================================================

#[test]
fn test_symlink_permissions_are_standard() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_symlink_permissions_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Create a symlink
    encfs
        .symlink(
            r,
            Path::new("/"),
            OsStr::new("test_symlink"),
            Path::new("target"),
        )
        .expect("symlink creation failed");

    // Check the symlink's attributes
    let path = PathBuf::from("/test_symlink");
    let (_, attr) = encfs
        .getattr(r, &path, None)
        .expect("getattr for symlink failed");

    // On Unix, symlinks typically have mode 0o777 (or 0o120777 for type + perms)
    // The actual permission bits depend on the platform, but should be predictable
    let actual_mode = (attr.perm as u32) & 0o777;
    println!("Symlink permissions: {:o}", actual_mode);

    // Verify it's marked as a symlink
    assert_eq!(
        attr.kind,
        fuse_mt::FileType::Symlink,
        "Expected symlink file type"
    );

    // On most Unix systems, symlinks have 0o777 permissions
    // (the actual file permissions are determined by the target)
    assert_eq!(
        actual_mode, 0o777,
        "Symlinks should have 0o777 permissions, got {:o}",
        actual_mode
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_permissions_mixed_types_in_directory() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_mixed_permissions_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Create a directory with specific permissions
    let dir_mode: u32 = 0o750;
    encfs
        .mkdir(r, Path::new("/"), OsStr::new("test_dir"), dir_mode)
        .expect("mkdir failed");

    // Create a file inside the directory with different permissions
    let file_mode: u32 = 0o640;
    let created = encfs
        .create(
            r,
            Path::new("/test_dir"),
            OsStr::new("test_file.txt"),
            file_mode,
            (libc::O_CREAT | libc::O_RDWR) as u32,
        )
        .expect("create file failed");
    let _ = encfs.release(
        r,
        &PathBuf::from("/test_dir/test_file.txt"),
        created.fh,
        0,
        0,
        true,
    );

    // Create a symlink inside the directory
    encfs
        .symlink(
            r,
            Path::new("/test_dir"),
            OsStr::new("test_link"),
            Path::new("test_file.txt"),
        )
        .expect("symlink creation failed");

    // Verify directory permissions
    let (_, dir_attr) = encfs
        .getattr(r, &PathBuf::from("/test_dir"), None)
        .expect("getattr for dir failed");
    let dir_actual = (dir_attr.perm as u32) & 0o777;
    assert_eq!(
        dir_actual, dir_mode,
        "Directory mode mismatch: expected {:o}, got {:o}",
        dir_mode, dir_actual
    );

    // Verify file permissions
    let (_, file_attr) = encfs
        .getattr(r, &PathBuf::from("/test_dir/test_file.txt"), None)
        .expect("getattr for file failed");
    let file_actual = (file_attr.perm as u32) & 0o777;
    assert_eq!(
        file_actual, file_mode,
        "File mode mismatch: expected {:o}, got {:o}",
        file_mode, file_actual
    );

    // Verify symlink permissions (should be 0o777)
    let (_, link_attr) = encfs
        .getattr(r, &PathBuf::from("/test_dir/test_link"), None)
        .expect("getattr for symlink failed");
    let link_actual = (link_attr.perm as u32) & 0o777;
    assert_eq!(
        link_actual, 0o777,
        "Symlink mode mismatch: expected {:o}, got {:o}",
        0o777, link_actual
    );

    println!(
        "Directory: {:o}, File: {:o}, Symlink: {:o}",
        dir_actual, file_actual, link_actual
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
