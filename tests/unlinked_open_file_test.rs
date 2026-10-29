//! Attribute calls on an open file whose last name has been unlinked, driven
//! through typed-fuse's node runtime as the kernel would send them: with no
//! file handle, so the runtime has to lend one of the file's open handles.

use encfs::config::{EncfsConfig, Interface};
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use std::ffi::OsStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use typed_fuse::{Caller, Errno, PathNodeFs, SetAttr, TimeOrNow};
use typed_fuse_core::Runtime;

fn runtime(root: &std::path::Path) -> Runtime<PathNodeFs<EncFs>> {
    let iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };
    let mut cipher = SslCipher::new(&iface, 192).unwrap();
    cipher.set_key(&[1u8; 24], &[2u8; 16]);
    let fs = EncFs::new(
        root.to_path_buf(),
        Box::new(cipher),
        EncfsConfig::test_default(),
    );
    Runtime::new(PathNodeFs::new(fs))
}

fn caller() -> Caller {
    Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    }
}

#[test]
fn unlinked_open_file_takes_fchmod_futimens_and_fstat() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime(dir.path());
    let caller = caller();

    let (entry, open) = runtime
        .create(1, OsStr::new("file"), 0o600, 0, libc::O_RDWR, &caller)
        .unwrap();
    runtime
        .write(entry.ino, open.fh, b"contents", 0, &caller)
        .unwrap();
    runtime.unlink(1, OsStr::new("file"), &caller).unwrap();

    let mtime = UNIX_EPOCH + Duration::from_secs(1_000_000);
    let set = SetAttr {
        mode: Some(0o640),
        mtime: Some(TimeOrNow::SpecificTime(mtime)),
        ..SetAttr::default()
    };
    let attr = runtime.setattr(entry.ino, None, &set, &caller).unwrap();
    assert_eq!(attr.perm, 0o640);
    assert_eq!(attr.mtime, mtime);

    let attr = runtime.getattr(entry.ino, None, &caller).unwrap();
    assert_eq!(attr.perm, 0o640);
    assert_eq!(attr.mtime, mtime);
    assert_eq!(attr.size, 8);

    runtime.release(entry.ino, open.fh, &caller).unwrap();
}

#[test]
fn unlinked_open_file_truncates_only_through_a_writable_handle() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime(dir.path());
    let caller = caller();

    let (entry, writer) = runtime
        .create(1, OsStr::new("file"), 0o600, 0, libc::O_RDWR, &caller)
        .unwrap();
    runtime
        .write(entry.ino, writer.fh, b"contents", 0, &caller)
        .unwrap();
    // The most recent open is the one the runtime lends.
    let reader = runtime.open(entry.ino, libc::O_RDONLY, &caller).unwrap();
    runtime.unlink(1, OsStr::new("file"), &caller).unwrap();

    let truncate = SetAttr {
        size: Some(3),
        ..SetAttr::default()
    };
    assert_eq!(
        runtime.setattr(entry.ino, None, &truncate, &caller).err(),
        Some(Errno::from(libc::ESTALE)),
        "a read-only handle must not be used to truncate",
    );
    assert_eq!(runtime.getattr(entry.ino, None, &caller).unwrap().size, 8);

    let attr = runtime
        .setattr(entry.ino, Some(writer.fh), &truncate, &caller)
        .unwrap();
    assert_eq!(attr.size, 3);

    runtime.release(entry.ino, reader.fh, &caller).unwrap();
    // With the reader gone, the writer is the handle lent.
    let truncate = SetAttr {
        size: Some(1),
        atime: Some(TimeOrNow::SpecificTime(SystemTime::now())),
        ..SetAttr::default()
    };
    let attr = runtime
        .setattr(entry.ino, None, &truncate, &caller)
        .unwrap();
    assert_eq!(attr.size, 1);
    runtime.release(entry.ino, writer.fh, &caller).unwrap();
}
