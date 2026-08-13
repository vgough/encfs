/// Tests for: Extended attribute (xattr) support
///
/// Verifies that xattr operations (set, get, list, remove) work correctly
/// with encryption. All attributes are encrypted and stored with the
/// "user.encfs." prefix on disk.
use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::{EncFs, FileState};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use typed_fuse::{Caller, PathFilesystem, PathNodeRef, XattrReply as ReplyXAttr};

mod common;
use common::Node;

/// Generous buffer size passed to getxattr/listxattr so the reply is always
/// `ReplyXAttr::Data` rather than a `Size` probe.
const XATTR_BUF_SIZE: usize = 65536;

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

fn req() -> Caller {
    Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    }
}

fn create_test_file(encfs: &EncFs, root: &Arc<FileState>, caller: &Caller) -> Node<FileState> {
    let (entry, created) = encfs
        .create(
            PathNodeRef::new(Some(Path::new("/")), root),
            OsStr::new("test.txt"),
            0o644,
            0,
            0,
            caller,
        )
        .expect("create failed");
    let node = Node::at(PathBuf::from("/test.txt"), entry.state);
    encfs
        .release(node.as_node(), created.handle, caller)
        .unwrap();
    node
}

#[cfg(target_os = "macos")]
unsafe fn listxattr_nofollow(
    path: *const libc::c_char,
    value: *mut libc::c_char,
    size: usize,
) -> libc::ssize_t {
    unsafe { libc::listxattr(path, value, size, libc::XATTR_NOFOLLOW) }
}

#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
unsafe fn listxattr_nofollow(
    path: *const libc::c_char,
    value: *mut libc::c_char,
    size: usize,
) -> libc::ssize_t {
    unsafe { libc::llistxattr(path, value, size) }
}

/// The attribute names actually present on the backing file, read with the
/// platform's own syscall rather than through the filesystem under test.
#[cfg(not(target_os = "freebsd"))]
fn backing_xattr_names(path: &Path) -> Vec<String> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let size = unsafe { listxattr_nofollow(c_path.as_ptr(), std::ptr::null_mut(), 0) };
    if size <= 0 {
        return Vec::new();
    }
    let mut buf = vec![0 as libc::c_char; size as usize];
    let ret = unsafe { listxattr_nofollow(c_path.as_ptr(), buf.as_mut_ptr(), size as usize) };
    if ret <= 0 {
        return Vec::new();
    }
    buf.truncate(ret as usize);
    let bytes: Vec<u8> = buf.iter().map(|&b| b as u8).collect();
    String::from_utf8_lossy(&bytes)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// FreeBSD has no `llistxattr`. `extattr_list_link(2)` lists one namespace at
/// a time and returns "a single byte containing the length of the attribute
/// name, followed by the attribute name", with no NUL terminator.
#[cfg(target_os = "freebsd")]
fn backing_xattr_names(path: &Path) -> Vec<String> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let namespace = libc::EXTATTR_NAMESPACE_USER;
    let size =
        unsafe { libc::extattr_list_link(c_path.as_ptr(), namespace, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return Vec::new();
    }
    let mut raw = vec![0u8; size as usize];
    let ret = unsafe {
        libc::extattr_list_link(
            c_path.as_ptr(),
            namespace,
            raw.as_mut_ptr() as *mut libc::c_void,
            raw.len(),
        )
    };
    if ret <= 0 {
        return Vec::new();
    }
    raw.truncate(ret as usize);
    let mut names = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let len = raw[i] as usize;
        i += 1;
        if i + len > raw.len() {
            break;
        }
        names.push(String::from_utf8_lossy(&raw[i..i + len]).to_string());
        i += len;
    }
    names
}

/// What an encfs-stored attribute name looks like on the backing file. On
/// FreeBSD the namespace is a syscall argument rather than part of the name,
/// so the "user." half is not stored there.
#[cfg(target_os = "freebsd")]
const ON_DISK_PREFIX: &str = "encfs.";
#[cfg(not(target_os = "freebsd"))]
const ON_DISK_PREFIX: &str = "user.encfs.";

#[test]
fn test_xattr_set_get() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_xattr_set_get_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let mut encfs = setup_fs(&tmp);
    let root = encfs.root_state();
    let r = req();

    let file = create_test_file(&encfs, &root, &r);

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
            .setxattr(file.as_node(), OsStr::new(attr_name), attr_value, 0, &r)
            .unwrap_or_else(|e| panic!("setxattr failed for {}: {:?}", attr_name, e));

        // Get xattr
        let result = encfs
            .getxattr(file.as_node(), OsStr::new(attr_name), XATTR_BUF_SIZE, &r)
            .unwrap_or_else(|_| panic!("getxattr failed for {}", attr_name));

        match result {
            ReplyXAttr::Data(data) => {
                assert_eq!(
                    data, *attr_value,
                    "xattr value mismatch for {}: expected {:?}, got {:?}",
                    attr_name, attr_value, data
                );
            }
            ReplyXAttr::Size(_) => {
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

    let mut encfs = setup_fs(&tmp);
    let root = encfs.root_state();
    let r = req();

    let file = create_test_file(&encfs, &root, &r);

    // Set multiple xattrs
    let attrs = vec![
        ("user.foo", b"value1".to_vec()),
        ("user.bar", b"value2".to_vec()),
        ("security.selinux", b"value3".to_vec()),
        ("trusted.baz", b"value4".to_vec()),
    ];

    for (attr_name, attr_value) in &attrs {
        encfs
            .setxattr(file.as_node(), OsStr::new(attr_name), attr_value, 0, &r)
            .unwrap_or_else(|e| panic!("setxattr failed for {}: {:?}", attr_name, e));
    }

    // List xattrs
    let result = encfs
        .listxattr(file.as_node(), XATTR_BUF_SIZE, &r)
        .expect("listxattr failed");

    let mut listed_attrs = Vec::new();
    match result {
        ReplyXAttr::Data(data) => {
            // Parse null-separated list
            let mut current = Vec::new();
            for &byte in data.iter() {
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
        ReplyXAttr::Size(_) => {
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

    let mut encfs = setup_fs(&tmp);
    let root = encfs.root_state();
    let r = req();

    let file = create_test_file(&encfs, &root, &r);

    // Set an xattr
    let attr_name = "user.foo";
    let attr_value = b"test_value".to_vec();
    encfs
        .setxattr(file.as_node(), OsStr::new(attr_name), &attr_value, 0, &r)
        .expect("setxattr failed");

    // Verify it exists
    let result = encfs
        .getxattr(file.as_node(), OsStr::new(attr_name), XATTR_BUF_SIZE, &r)
        .expect("getxattr failed");
    match result {
        ReplyXAttr::Data(data) => assert_eq!(data, attr_value),
        ReplyXAttr::Size(_) => panic!("getxattr returned Size instead of Data"),
    }

    // Remove it
    encfs
        .removexattr(file.as_node(), OsStr::new(attr_name), &r)
        .expect("removexattr failed");

    // Verify it's gone
    let result = encfs.getxattr(file.as_node(), OsStr::new(attr_name), XATTR_BUF_SIZE, &r);
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

    let mut encfs = setup_fs(&tmp);
    let root = encfs.root_state();
    let r = req();

    let file = create_test_file(&encfs, &root, &r);

    // Set an xattr
    let attr_name = "user.foo";
    let attr_value = b"test_value".to_vec();
    encfs
        .setxattr(file.as_node(), OsStr::new(attr_name), &attr_value, 0, &r)
        .expect("setxattr failed");

    // Find the encrypted file on disk
    let entries: Vec<_> = fs::read_dir(&tmp)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
        .collect();

    assert_eq!(entries.len(), 1, "Expected exactly one file");
    let encrypted_file_path = entries[0].path();

    // Check that the names stored on disk carry encfs's prefix. Assert at
    // least one such name exists so a failing or empty listing can't pass
    // vacuously.
    let names = backing_xattr_names(&encrypted_file_path);
    assert!(
        names.iter().any(|name| name.starts_with(ON_DISK_PREFIX)),
        "expected at least one encfs xattr on disk with prefix '{}', got {:?}",
        ON_DISK_PREFIX,
        names
    );
    for name in names {
        // Ignore macOS system xattrs
        if cfg!(target_os = "macos") && name.starts_with("com.apple.") {
            continue;
        }
        assert!(
            name.starts_with(ON_DISK_PREFIX),
            "xattr on disk should start with '{}': {}",
            ON_DISK_PREFIX,
            name
        );
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

    let mut encfs = setup_fs(&tmp);
    let root = encfs.root_state();
    let r = req();

    let file = create_test_file(&encfs, &root, &r);

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
            .setxattr(file.as_node(), OsStr::new(attr_name), attr_value, 0, &r)
            .unwrap_or_else(|e| panic!("setxattr failed for {}: {:?}", attr_name, e));

        // Get
        let result = encfs
            .getxattr(file.as_node(), OsStr::new(attr_name), XATTR_BUF_SIZE, &r)
            .unwrap_or_else(|_| panic!("getxattr failed for {}", attr_name));

        match result {
            ReplyXAttr::Data(data) => {
                assert_eq!(
                    data, *attr_value,
                    "Round-trip failed for {}: expected {:?}, got {:?}",
                    attr_name, attr_value, data
                );
            }
            ReplyXAttr::Size(_) => {
                panic!("getxattr returned Size instead of Data for {}", attr_name);
            }
        }

        // Remove
        encfs
            .removexattr(file.as_node(), OsStr::new(attr_name), &r)
            .unwrap_or_else(|_| panic!("removexattr failed for {}", attr_name));

        // Verify it's gone
        assert!(
            encfs
                .getxattr(file.as_node(), OsStr::new(attr_name), XATTR_BUF_SIZE, &r)
                .is_err(),
            "xattr should be removed: {}",
            attr_name
        );
    }

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
