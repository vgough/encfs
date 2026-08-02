use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use std::ffi::OsStr;
use std::path::Path;
use tempfile::TempDir;
use typed_fuse::{Caller, Errno, PathFilesystem, PathNodeRef};

mod common;
use common::Node;

fn caller() -> Caller {
    Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    }
}

fn make_fs(root: &Path) -> EncFs {
    let iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };
    let mut cipher = SslCipher::new(&iface, 192).unwrap();
    cipher.set_key(&[1u8; 24], &[2u8; 16]);
    EncFs::new(
        root.to_path_buf(),
        Box::new(cipher),
        encfs::config::EncfsConfig::test_default(),
    )
}

#[test]
fn flock_is_forwarded_to_each_backing_file_description() {
    let tmp = TempDir::new().unwrap();
    let mut fs = make_fs(tmp.path());
    let root = fs.root_state();
    let caller = caller();
    let parent = Path::new("");
    let name = OsStr::new("locked");
    let path = parent.join(name);

    let (entry, created) = fs
        .create(
            PathNodeRef::new(Some(parent), &root),
            name,
            0o644,
            0,
            libc::O_RDWR,
            &caller,
        )
        .unwrap();
    let node = Node::at(&path, entry.state);
    fs.release(node.as_node(), created.handle, &caller).unwrap();

    let first = fs
        .open(node.as_node(), libc::O_RDWR, &caller)
        .unwrap()
        .handle;
    let second = fs
        .open(node.as_node(), libc::O_RDWR, &caller)
        .unwrap()
        .handle;

    fs.flock(
        node.as_node(),
        &first,
        libc::LOCK_EX | libc::LOCK_NB,
        &caller,
    )
    .unwrap();
    let error = fs
        .flock(
            node.as_node(),
            &second,
            libc::LOCK_EX | libc::LOCK_NB,
            &caller,
        )
        .unwrap_err();
    assert!(
        error == Errno::from_raw(libc::EAGAIN) || error == Errno::from_raw(libc::EWOULDBLOCK),
        "second open unexpectedly acquired the lock: {error}"
    );

    fs.flock(node.as_node(), &first, libc::LOCK_UN, &caller)
        .unwrap();
    fs.flock(
        node.as_node(),
        &second,
        libc::LOCK_EX | libc::LOCK_NB,
        &caller,
    )
    .unwrap();
    fs.flock(node.as_node(), &second, libc::LOCK_UN, &caller)
        .unwrap();

    fs.release(node.as_node(), first, &caller).unwrap();
    fs.release(node.as_node(), second, &caller).unwrap();
}
