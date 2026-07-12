/// Tests for: File and directory permission handling
///
/// Verifies that mkdir, create (file), and symlink properly respect the mode
/// parameter when creating files and directories. On Unix systems, these operations
/// should use the mode parameter rather than relying on umask-based defaults.
use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use rfuse3::FileType;
use rfuse3::path::PathFilesystem;
use rfuse3::path::Request;
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
async fn test_mkdir_uses_mode_parameter() {
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
        .mkdir(r, OsStr::new("/"), OsStr::new("restricted_dir"), mode, 0)
        .await
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

#[tokio::test]
async fn test_mkdir_various_modes() {
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
            .mkdir(r, OsStr::new("/"), OsStr::new(name), mode, 0)
            .await
            .unwrap_or_else(|_| panic!("mkdir {} failed", name));
    }

    // Check the modes via getattr
    for (name, expected_mode) in test_cases {
        let path = PathBuf::from("/").join(name);
        let attr = encfs
            .getattr(r, Some(path.as_os_str()), None, 0)
            .await
            .unwrap_or_else(|_| panic!("getattr for {} failed", name))
            .attr;
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

#[tokio::test]
async fn test_create_file_uses_mode_parameter() {
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
            OsStr::new("/"),
            OsStr::new("restricted_file.txt"),
            mode,
            (libc::O_CREAT | libc::O_RDWR) as u32,
        )
        .await
        .expect("create file failed");

    // Release the file handle
    let _ = encfs
        .release(
            r,
            Some(PathBuf::from("/restricted_file.txt").as_os_str()),
            created.fh,
            0,
            0,
            true,
        )
        .await;

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

#[tokio::test]
async fn test_create_file_various_modes() {
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
                OsStr::new("/"),
                OsStr::new(name),
                mode,
                (libc::O_CREAT | libc::O_RDWR) as u32,
            )
            .await
            .unwrap_or_else(|_| panic!("create {} failed", name));

        // Release the file handle
        let _ = encfs
            .release(
                r,
                Some(PathBuf::from("/").join(name).as_os_str()),
                created.fh,
                0,
                0,
                true,
            )
            .await;
    }

    // Check the modes via getattr
    for (name, expected_mode) in test_cases {
        let path = PathBuf::from("/").join(name);
        let attr = encfs
            .getattr(r, Some(path.as_os_str()), None, 0)
            .await
            .unwrap_or_else(|_| panic!("getattr for {} failed", name))
            .attr;
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

#[tokio::test]
async fn test_symlink_permissions_are_standard() {
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
            OsStr::new("/"),
            OsStr::new("test_symlink"),
            Path::new("target").as_os_str(),
        )
        .await
        .expect("symlink creation failed");

    // Check the symlink's attributes
    let path = PathBuf::from("/test_symlink");
    let attr = encfs
        .getattr(r, Some(path.as_os_str()), None, 0)
        .await
        .expect("getattr for symlink failed")
        .attr;

    // On Unix, symlinks typically have mode 0o777 (or 0o120777 for type + perms)
    // The actual permission bits depend on the platform, but should be predictable
    let actual_mode = (attr.perm as u32) & 0o777;
    println!("Symlink permissions: {:o}", actual_mode);

    // Verify it's marked as a symlink
    assert_eq!(attr.kind, FileType::Symlink, "Expected symlink file type");

    // On most Unix systems, symlinks have 0o777 permissions
    // (the actual file permissions are determined by the target)
    #[cfg(not(target_os = "macos"))]
    assert_eq!(
        actual_mode, 0o777,
        "Symlinks should have 0o777 permissions, got {:o}",
        actual_mode
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

#[tokio::test]
async fn test_permissions_mixed_types_in_directory() {
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
        .mkdir(r, OsStr::new("/"), OsStr::new("test_dir"), dir_mode, 0)
        .await
        .expect("mkdir failed");

    // Create a file inside the directory with different permissions
    let file_mode: u32 = 0o640;
    let created = encfs
        .create(
            r,
            OsStr::new("/test_dir"),
            OsStr::new("test_file.txt"),
            file_mode,
            (libc::O_CREAT | libc::O_RDWR) as u32,
        )
        .await
        .expect("create file failed");
    let _ = encfs
        .release(
            r,
            Some(PathBuf::from("/test_dir/test_file.txt").as_os_str()),
            created.fh,
            0,
            0,
            true,
        )
        .await;

    // Create a symlink inside the directory
    encfs
        .symlink(
            r,
            OsStr::new("/test_dir"),
            OsStr::new("test_link"),
            Path::new("test_file.txt").as_os_str(),
        )
        .await
        .expect("symlink creation failed");

    // Verify directory permissions
    let dir_attr = encfs
        .getattr(r, Some(PathBuf::from("/test_dir").as_os_str()), None, 0)
        .await
        .expect("getattr for dir failed")
        .attr;
    let dir_actual = (dir_attr.perm as u32) & 0o777;
    assert_eq!(
        dir_actual, dir_mode,
        "Directory mode mismatch: expected {:o}, got {:o}",
        dir_mode, dir_actual
    );

    // Verify file permissions
    let file_attr = encfs
        .getattr(
            r,
            Some(PathBuf::from("/test_dir/test_file.txt").as_os_str()),
            None,
            0,
        )
        .await
        .expect("getattr for file failed")
        .attr;
    let file_actual = (file_attr.perm as u32) & 0o777;
    assert_eq!(
        file_actual, file_mode,
        "File mode mismatch: expected {:o}, got {:o}",
        file_mode, file_actual
    );

    // Verify symlink permissions (should be 0o777)
    let link_attr = encfs
        .getattr(
            r,
            Some(PathBuf::from("/test_dir/test_link").as_os_str()),
            None,
            0,
        )
        .await
        .expect("getattr for symlink failed")
        .attr;
    let link_actual = (link_attr.perm as u32) & 0o777;
    #[cfg(not(target_os = "macos"))]
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
