//! Concurrency regression tests for the per-backing-inode file state.
//!
//! Every operation on an encrypted file is a multi-syscall sequence: a partial
//! block write is read-decrypt-modify-encrypt-write, a truncate is
//! read/set_len/re-encrypt, and a truncating open resets the file *and* its IV.
//! fuse3 runs read/write/setattr concurrently, so `EncFs` has to serialize
//! these per backing inode. These tests fail (lost updates, or EIO from a
//! failed block MAC) if that serialization is missing or is taken too late.

use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use fuse3::{Caller, PathFilesystem};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

/// One block of `test_default` holds 1024 - 8 MAC bytes of plaintext.
const BLOCK_DATA: usize = 1016;

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

/// A mounted-less `EncFs` over a fresh backing directory, plus the root-relative
/// parent path FUSE would hand us.
fn fixture() -> (TempDir, Arc<EncFs>, PathBuf) {
    let tmp = TempDir::new().unwrap();
    let fs = Arc::new(make_fs(tmp.path()));
    (tmp, fs, PathBuf::from(""))
}

#[test]
fn concurrent_partial_block_writes_same_file() {
    // Two handles on the same inode write disjoint halves of the SAME block.
    // Without serialization the two read-modify-write cycles interleave and one
    // writer's bytes are lost (or the block MAC breaks).
    let (_tmp, fs, parent) = fixture();
    let req = caller();
    let name = OsStr::new("racefile");
    let path = parent.join(name);

    let (_, created) = fs.create(&parent, name, 0o644, 0, 0, &req).unwrap();
    let h0 = created.handle;
    fs.write(Some(&path), &h0, &vec![0u8; BLOCK_DATA], 0, &req)
        .unwrap();
    fs.release(Some(&path), h0, &req).unwrap();

    let ha = fs.open(&path, libc::O_RDWR, &req).unwrap().handle;
    let hb = fs.open(&path, libc::O_RDWR, &req).unwrap().handle;

    let half = BLOCK_DATA / 2;
    let fsa = Arc::clone(&fs);
    let pa = path.clone();
    let ta = std::thread::spawn(move || {
        let data = vec![0xAAu8; half];
        for _ in 0..20000 {
            fsa.write(Some(&pa), &ha, &data, 0, &req).unwrap();
        }
        ha
    });
    let fsb = Arc::clone(&fs);
    let pb = path.clone();
    let tb = std::thread::spawn(move || {
        let data = vec![0xBBu8; BLOCK_DATA - half];
        for _ in 0..20000 {
            fsb.write(Some(&pb), &hb, &data, half as u64, &req).unwrap();
        }
        hb
    });
    let ha = ta.join().unwrap();
    let hb = tb.join().unwrap();

    // Read back through a fresh handle: both halves intact, MAC verifying.
    let hr = fs.open(&path, libc::O_RDONLY, &req).unwrap().handle;
    let buf = fs.read(None, &hr, 0, BLOCK_DATA, &req).unwrap();
    assert_eq!(buf.len(), BLOCK_DATA);
    assert!(
        buf[..half].iter().all(|&b| b == 0xAA),
        "first half corrupted: {:?}",
        &buf[..16]
    );
    assert!(
        buf[half..].iter().all(|&b| b == 0xBB),
        "second half corrupted: {:?}",
        &buf[half..half + 16]
    );

    fs.release(Some(&path), ha, &req).unwrap();
    fs.release(Some(&path), hb, &req).unwrap();
    fs.release(Some(&path), hr, &req).unwrap();
}

#[test]
fn concurrent_write_and_truncate_same_file() {
    // A writer and a truncater on two handles to the same inode. Every
    // operation must succeed: a truncate that lands inside a write's
    // read-modify-write leaves a block whose MAC no longer matches, which
    // surfaces as EIO here or on the final read-back.
    let (_tmp, fs, parent) = fixture();
    let req = caller();
    let name = OsStr::new("truncrace");
    let path = parent.join(name);

    let (_, created) = fs.create(&parent, name, 0o644, 0, 0, &req).unwrap();
    let hw = created.handle;
    fs.write(Some(&path), &hw, &vec![7u8; 2000], 0, &req)
        .unwrap();

    let ht = fs.open(&path, libc::O_RDWR, &req).unwrap().handle;

    let fsw = Arc::clone(&fs);
    let pw = path.clone();
    let tw = std::thread::spawn(move || {
        let mut errors = Vec::new();
        for i in 0..200u64 {
            let data = vec![(i % 251) as u8; 512];
            if let Err(e) = fsw.write(Some(&pw), &hw, &data, (i % 3) * 512, &req) {
                errors.push(("write", i, e));
            }
        }
        (hw, errors)
    });
    let fst = Arc::clone(&fs);
    let pt = path.clone();
    let tt = std::thread::spawn(move || {
        let mut sa = fuse3::SetAttr::default();
        let mut errors = Vec::new();
        for i in 0..200u64 {
            sa.size = Some(1024 + (i % 4) * 256);
            if let Err(e) = fst.setattr(Some(&pt), Some(&ht), &sa, &req) {
                errors.push(("truncate", i, e));
            }
        }
        (ht, errors)
    });
    let (hw, write_errors) = tw.join().unwrap();
    let (ht, truncate_errors) = tt.join().unwrap();
    assert!(write_errors.is_empty(), "writes failed: {:?}", write_errors);
    assert!(
        truncate_errors.is_empty(),
        "truncates failed: {:?}",
        truncate_errors
    );

    // Every byte of the surviving file must still decrypt.
    let size = fs.getattr(Some(&path), None, &req).unwrap().size;
    let hr = fs.open(&path, libc::O_RDONLY, &req).unwrap().handle;
    let mut off = 0u64;
    while off < size {
        let n = std::cmp::min(512, size - off) as usize;
        let chunk = fs
            .read(None, &hr, off, n, &req)
            .unwrap_or_else(|e| panic!("read at {} failed: {:?}", off, e));
        assert_eq!(chunk.len(), n, "short read at {}", off);
        off += n as u64;
    }

    fs.release(Some(&path), hw, &req).unwrap();
    fs.release(Some(&path), ht, &req).unwrap();
    fs.release(Some(&path), hr, &req).unwrap();
}

#[test]
fn truncating_open_updates_iv_for_existing_handles() {
    // O_TRUNC installs a header carrying a freshly generated file IV. A handle
    // opened *before* that must switch to the new IV, otherwise it encrypts
    // blocks under an IV the header no longer names and nothing can decrypt
    // them again. No threads here: this is deterministic.
    let (_tmp, fs, parent) = fixture();
    let req = caller();
    let name = OsStr::new("trunciv");
    let path = parent.join(name);

    let (_, created) = fs.create(&parent, name, 0o644, 0, 0, &req).unwrap();
    let old = created.handle;
    fs.write(Some(&path), &old, &vec![0x11u8; BLOCK_DATA], 0, &req)
        .unwrap();

    // Someone else truncates the file out from under `old`.
    let fresh = fs
        .open(&path, libc::O_RDWR | libc::O_TRUNC, &req)
        .unwrap()
        .handle;

    // The pre-existing handle writes again; this must use the new IV.
    fs.write(Some(&path), &old, &vec![0x22u8; BLOCK_DATA], 0, &req)
        .unwrap();

    for (label, handle) in [("truncating handle", &fresh), ("stale handle", &old)] {
        let buf = fs
            .read(None, handle, 0, BLOCK_DATA, &req)
            .unwrap_or_else(|e| panic!("read via {} failed: {:?}", label, e));
        assert_eq!(buf.len(), BLOCK_DATA, "short read via {}", label);
        assert!(
            buf.iter().all(|&b| b == 0x22),
            "wrong plaintext via {}: {:?}",
            label,
            &buf[..16]
        );
    }

    // And through a handle that reads the header from scratch.
    let reader = fs.open(&path, libc::O_RDONLY, &req).unwrap().handle;
    let buf = fs.read(None, &reader, 0, BLOCK_DATA, &req).unwrap();
    assert!(buf.iter().all(|&b| b == 0x22), "wrong plaintext on reopen");

    fs.release(Some(&path), old, &req).unwrap();
    fs.release(Some(&path), fresh, &req).unwrap();
    fs.release(Some(&path), reader, &req).unwrap();
}

#[test]
fn recreating_file_updates_iv_for_existing_handles() {
    // Same as above for the `create` path, which is what
    // open(O_CREAT|O_WRONLY|O_TRUNC) takes for a compiler writing over its
    // previous output.
    let (_tmp, fs, parent) = fixture();
    let req = caller();
    let name = OsStr::new("createiv");
    let path = parent.join(name);

    let (_, created) = fs.create(&parent, name, 0o644, 0, 0, &req).unwrap();
    let old = created.handle;
    fs.write(Some(&path), &old, &vec![0x33u8; BLOCK_DATA], 0, &req)
        .unwrap();

    let (_, recreated) = fs.create(&parent, name, 0o644, 0, 0, &req).unwrap();
    let fresh = recreated.handle;

    fs.write(Some(&path), &old, &vec![0x44u8; BLOCK_DATA], 0, &req)
        .unwrap();

    let buf = fs
        .read(None, &fresh, 0, BLOCK_DATA, &req)
        .unwrap_or_else(|e| panic!("read after re-create failed: {:?}", e));
    assert!(
        buf.iter().all(|&b| b == 0x44),
        "wrong plaintext after re-create: {:?}",
        &buf[..16]
    );

    fs.release(Some(&path), old, &req).unwrap();
    fs.release(Some(&path), fresh, &req).unwrap();
}

#[test]
fn concurrent_write_and_truncating_open() {
    // The racy form of the two tests above: one thread writes through a
    // long-lived handle while another repeatedly reopens the same path with
    // O_TRUNC. If the truncate and header rewrite happen outside the per-file
    // lock, a write lands under the previous IV and the block stops decrypting.
    let (_tmp, fs, parent) = fixture();
    let req = caller();
    let name = OsStr::new("trunopen");
    let path = parent.join(name);

    let (_, created) = fs.create(&parent, name, 0o644, 0, 0, &req).unwrap();
    let hw = created.handle;

    let fsw = Arc::clone(&fs);
    let pw = path.clone();
    let tw = std::thread::spawn(move || {
        let data = vec![0x5Au8; BLOCK_DATA];
        let mut errors = Vec::new();
        for i in 0..2000u64 {
            if let Err(e) = fsw.write(Some(&pw), &hw, &data, 0, &req) {
                errors.push(("write", i, e));
            }
        }
        (hw, errors)
    });
    let fso = Arc::clone(&fs);
    let po = path.clone();
    let to = std::thread::spawn(move || {
        let mut errors = Vec::new();
        for i in 0..2000u64 {
            match fso.open(&po, libc::O_RDWR | libc::O_TRUNC, &req) {
                Ok(opened) => {
                    if let Err(e) = fso.release(Some(&po), opened.handle, &req) {
                        errors.push(("release", i, e));
                    }
                }
                Err(e) => errors.push(("open", i, e)),
            }
        }
        errors
    });
    let (hw, write_errors) = tw.join().unwrap();
    let open_errors = to.join().unwrap();
    assert!(write_errors.is_empty(), "writes failed: {:?}", write_errors);
    assert!(open_errors.is_empty(), "opens failed: {:?}", open_errors);

    // Whatever survived must decrypt: either an empty file, or a block written
    // under the IV currently named by the header.
    let size = fs.getattr(Some(&path), None, &req).unwrap().size;
    let hr = fs.open(&path, libc::O_RDONLY, &req).unwrap().handle;
    if size > 0 {
        let buf = fs
            .read(None, &hr, 0, size as usize, &req)
            .unwrap_or_else(|e| panic!("read of {} bytes failed: {:?}", size, e));
        assert!(
            buf.iter().all(|&b| b == 0x5A),
            "wrong plaintext survived: {:?}",
            &buf[..std::cmp::min(16, buf.len())]
        );
    }

    fs.release(Some(&path), hw, &req).unwrap();
    fs.release(Some(&path), hr, &req).unwrap();
}
