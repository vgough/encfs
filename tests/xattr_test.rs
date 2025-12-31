/// Tests for: Extended attribute (xattr) support
///
/// Verifies that xattr operations (set, get, list, remove) work correctly
/// with encryption. All attributes are encrypted and stored with the
/// "user.encfs." prefix on disk.
use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use fuse_mt::{FilesystemMT, RequestInfo, Xattr};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
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
fn test_xattr_set_get() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_xattr_set_get_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Create a file
    let parent = Path::new("/");
    let name = OsStr::new("test.txt");
    let created = encfs
        .create(r, parent, name, 0o644, 0)
        .expect("create failed");
    let _ = encfs.release(r, &PathBuf::from("/test.txt"), created.fh, 0, 0, true);

    let path = PathBuf::from("/test.txt");

    // Test setting and getting various xattr names
    let test_cases = vec![
        ("user.foo", b"value1".to_vec()),
        ("user.bar", b"value2".to_vec()),
        (
            "security.selinux",
            b"system_u:object_r:user_home_t:s0".to_vec(),
        ),
        ("trusted.baz", b"trusted_value".to_vec()),
        ("user.empty", b"".to_vec()),
        ("user.long", vec![0u8; 1000]), // Large value
    ];

    for (attr_name, attr_value) in &test_cases {
        // Set xattr
        encfs
            .setxattr(r, &path, OsStr::new(attr_name), attr_value, 0, 0)
            .unwrap_or_else(|_| panic!("setxattr failed for {}", attr_name));

        // Get xattr
        let result = encfs
            .getxattr(r, &path, OsStr::new(attr_name), 0)
            .unwrap_or_else(|_| panic!("getxattr failed for {}", attr_name));

        match result {
            Xattr::Data(data) => {
                assert_eq!(
                    data, *attr_value,
                    "xattr value mismatch for {}: expected {:?}, got {:?}",
                    attr_name, attr_value, data
                );
            }
            Xattr::Size(_) => {
                panic!("getxattr returned Size instead of Data for {}", attr_name);
            }
        }
    }

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_xattr_list() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_xattr_list_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Create a file
    let parent = Path::new("/");
    let name = OsStr::new("test.txt");
    let created = encfs
        .create(r, parent, name, 0o644, 0)
        .expect("create failed");
    let _ = encfs.release(r, &PathBuf::from("/test.txt"), created.fh, 0, 0, true);

    let path = PathBuf::from("/test.txt");

    // Set multiple xattrs
    let attrs = vec![
        ("user.foo", b"value1".to_vec()),
        ("user.bar", b"value2".to_vec()),
        ("security.selinux", b"value3".to_vec()),
        ("trusted.baz", b"value4".to_vec()),
    ];

    for (attr_name, attr_value) in &attrs {
        encfs
            .setxattr(r, &path, OsStr::new(attr_name), attr_value, 0, 0)
            .unwrap_or_else(|_| panic!("setxattr failed for {}", attr_name));
    }

    // List xattrs
    let result = encfs.listxattr(r, &path, 0).expect("listxattr failed");

    let mut listed_attrs = Vec::new();
    match result {
        Xattr::Data(data) => {
            // Parse null-separated list
            let mut current = Vec::new();
            for &byte in &data {
                if byte == 0 {
                    if !current.is_empty() {
                        listed_attrs.push(String::from_utf8(current.clone()).unwrap());
                        current.clear();
                    }
                } else {
                    current.push(byte);
                }
            }
            if !current.is_empty() {
                listed_attrs.push(String::from_utf8(current).unwrap());
            }
        }
        Xattr::Size(_) => {
            panic!("listxattr returned Size instead of Data");
        }
    }

    // Verify all attributes are listed
    for (attr_name, _) in &attrs {
        assert!(
            listed_attrs.contains(&attr_name.to_string()),
            "Attribute {} should be in list: {:?}",
            attr_name,
            listed_attrs
        );
    }

    assert_eq!(
        listed_attrs.len(),
        attrs.len(),
        "Expected {} attributes, got {}: {:?}",
        attrs.len(),
        listed_attrs.len(),
        listed_attrs
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_xattr_remove() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_xattr_remove_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Create a file
    let parent = Path::new("/");
    let name = OsStr::new("test.txt");
    let created = encfs
        .create(r, parent, name, 0o644, 0)
        .expect("create failed");
    let _ = encfs.release(r, &PathBuf::from("/test.txt"), created.fh, 0, 0, true);

    let path = PathBuf::from("/test.txt");

    // Set an xattr
    let attr_name = "user.foo";
    let attr_value = b"test_value".to_vec();
    encfs
        .setxattr(r, &path, OsStr::new(attr_name), &attr_value, 0, 0)
        .expect("setxattr failed");

    // Verify it exists
    let result = encfs
        .getxattr(r, &path, OsStr::new(attr_name), 0)
        .expect("getxattr failed");
    match result {
        Xattr::Data(data) => assert_eq!(data, attr_value),
        Xattr::Size(_) => panic!("getxattr returned Size instead of Data"),
    }

    // Remove it
    encfs
        .removexattr(r, &path, OsStr::new(attr_name))
        .expect("removexattr failed");

    // Verify it's gone
    let result = encfs.getxattr(r, &path, OsStr::new(attr_name), 0);
    assert!(result.is_err(), "getxattr should fail after removexattr");

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_xattr_on_disk_storage() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_xattr_disk_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Create a file
    let parent = Path::new("/");
    let name = OsStr::new("test.txt");
    let created = encfs
        .create(r, parent, name, 0o644, 0)
        .expect("create failed");
    let _ = encfs.release(r, &PathBuf::from("/test.txt"), created.fh, 0, 0, true);

    let path = PathBuf::from("/test.txt");

    // Set an xattr
    let attr_name = "user.foo";
    let attr_value = b"test_value".to_vec();
    encfs
        .setxattr(r, &path, OsStr::new(attr_name), &attr_value, 0, 0)
        .expect("setxattr failed");

    // Find the encrypted file on disk
    let entries: Vec<_> = fs::read_dir(&tmp)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .collect();

    assert_eq!(entries.len(), 1, "Expected exactly one file");
    let encrypted_file_path = entries[0].path();

    // Check that xattrs on disk start with "user.encfs."
    // Use libc to list xattrs on the encrypted file
    let c_path = std::ffi::CString::new(encrypted_file_path.as_os_str().as_bytes()).unwrap();

    // Get size first
    let size = unsafe { libc::llistxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };

    if size > 0 {
        let size_usize = size as usize;
        let mut buf = vec![0i8; size_usize];
        let ret = unsafe { libc::llistxattr(c_path.as_ptr(), buf.as_mut_ptr(), size_usize) };

        if ret > 0 {
            buf.truncate(ret as usize);
            let list_u8: Vec<u8> = buf.iter().map(|&b| b as u8).collect();
            let list_str = String::from_utf8_lossy(&list_u8);
            let names: Vec<&str> = list_str.split('\0').filter(|s| !s.is_empty()).collect();

            // Verify all xattrs on disk start with "user.encfs."
            for name in names {
                assert!(
                    name.starts_with("user.encfs."),
                    "xattr on disk should start with 'user.encfs.': {}",
                    name
                );
            }
        }
    }

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_xattr_round_trip() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_xattr_round_trip_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let encfs = setup_fs(&tmp);
    let r = req();

    // Create a file
    let parent = Path::new("/");
    let name = OsStr::new("test.txt");
    let created = encfs
        .create(r, parent, name, 0o644, 0)
        .expect("create failed");
    let _ = encfs.release(r, &PathBuf::from("/test.txt"), created.fh, 0, 0, true);

    let path = PathBuf::from("/test.txt");

    // Test various attribute names and values
    let test_cases = vec![
        ("user.simple", b"simple_value".to_vec()),
        (
            "security.complex",
            b"complex_value_with_special_chars_!@#$%^&*()".to_vec(),
        ),
        ("trusted.binary", vec![0u8, 1u8, 2u8, 0xFFu8, 0x00u8]),
        ("user.unicode", "测试值".as_bytes().to_vec()),
        ("user.empty", b"".to_vec()),
    ];

    for (attr_name, attr_value) in &test_cases {
        // Set
        encfs
            .setxattr(r, &path, OsStr::new(attr_name), attr_value, 0, 0)
            .unwrap_or_else(|_| panic!("setxattr failed for {}", attr_name));

        // Get
        let result = encfs
            .getxattr(r, &path, OsStr::new(attr_name), 0)
            .unwrap_or_else(|_| panic!("getxattr failed for {}", attr_name));

        match result {
            Xattr::Data(data) => {
                assert_eq!(
                    data, *attr_value,
                    "Round-trip failed for {}: expected {:?}, got {:?}",
                    attr_name, attr_value, data
                );
            }
            Xattr::Size(_) => {
                panic!("getxattr returned Size instead of Data for {}", attr_name);
            }
        }

        // Remove
        encfs
            .removexattr(r, &path, OsStr::new(attr_name))
            .unwrap_or_else(|_| panic!("removexattr failed for {}", attr_name));

        // Verify it's gone
        assert!(
            encfs.getxattr(r, &path, OsStr::new(attr_name), 0).is_err(),
            "xattr should be removed: {}",
            attr_name
        );
    }

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
