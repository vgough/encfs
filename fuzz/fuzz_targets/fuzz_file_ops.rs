#![no_main]

//! Differential fuzz testing of EncFS file operations.
//!
//! Generates random sequences of writes, reads, and truncates (both shrinking
//! and expanding). Each operation is applied to both an EncFS-encrypted file
//! (via the `EncFs` FUSE-layer API) and a plain in-memory reference buffer.
//! After every mutating operation, and on every Read, the decrypted EncFS
//! content is compared against the reference to detect divergence immediately.

use arbitrary::Arbitrary;
use encfs::config::Interface;
use encfs::crypto::file::FileDecoder;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use fuse_mt::{FilesystemMT, RequestInfo};
use libfuzzer_sys::fuzz_target;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of operations executed per fuzz input (keeps runs fast).
const MAX_OPS: usize = 32;

/// Maximum bytes written in a single write (about 4 blocks worth of data).
const MAX_WRITE_SIZE: usize = 4096;

/// Maximum logical file size. u16 keeps the address space manageable while
/// still exercising multi-block boundaries.
const MAX_FILE_SIZE: usize = 65535;

/// Block layout constants matching `EncfsConfig::test_default()`.
const BLOCK_SIZE: u64 = 1024;
const BLOCK_MAC_BYTES: u64 = 8;
const HEADER_SIZE: u64 = 8; // unique_iv = true → 8-byte file IV header

// ---------------------------------------------------------------------------
// Operation model
// ---------------------------------------------------------------------------

#[derive(Debug, Arbitrary)]
enum Op {
    /// Write `data` at byte `offset`.
    Write { offset: u16, data: Vec<u8> },
    /// Read `len` bytes starting at byte `offset` and compare to reference.
    Read { offset: u16, len: u16 },
    /// Shrink the file to `size` bytes (skipped when size >= current length).
    TruncateShrink { size: u16 },
    /// Expand the file to `size` bytes (skipped when size <= current length).
    TruncateExpand { size: u16 },
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    ops: Vec<Op>,
}

// ---------------------------------------------------------------------------
// Temp directory that removes itself on drop
// ---------------------------------------------------------------------------

static ITER_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = ITER_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("encfs_fuzz_{}", n));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

fn make_request() -> RequestInfo {
    RequestInfo {
        unique: 1,
        pid: 1,
        uid: 0,
        gid: 0,
    }
}

/// Create an SslCipher with a fixed, deterministic key so that fuzz inputs
/// are self-contained and reproducible from the raw bytes alone.
fn make_cipher() -> SslCipher {
    let iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };
    let mut cipher = SslCipher::new(&iface, 192).expect("SslCipher::new");
    cipher.set_key(&[1u8; 24], &[2u8; 16]);
    cipher
}

fn make_encfs(root: PathBuf) -> EncFs {
    let mut config = encfs::config::EncfsConfig::test_default();
    // allow_holes must be true so that the zero-filled regions introduced by
    // a truncate-expand can be read back without MAC verification errors.
    config.allow_holes = true;
    EncFs::new(root, make_cipher(), config)
}

// ---------------------------------------------------------------------------
// Reference-buffer helpers
// ---------------------------------------------------------------------------

/// Apply a write to the plain reference buffer, extending with zeros as needed.
fn ref_write(buf: &mut Vec<u8>, offset: usize, data: &[u8]) {
    let end = offset + data.len();
    if end > buf.len() {
        buf.resize(end, 0);
    }
    buf[offset..end].copy_from_slice(data);
}

/// Slice the reference buffer at `[offset, offset+len)`, clamped at EOF.
fn ref_slice(buf: &[u8], offset: usize, len: usize) -> &[u8] {
    if offset >= buf.len() {
        return &[];
    }
    let end = (offset + len).min(buf.len());
    &buf[offset..end]
}

// ---------------------------------------------------------------------------
// Encrypted-file read helper (uses FileDecoder, not fs.read callback)
// ---------------------------------------------------------------------------

/// Decrypt the full logical content of the physical file and return it.
///
/// Opens the file fresh on every call so that the latest on-disk state is
/// always reflected (EncFs writes go directly to disk via pwrite64).
fn read_encfs_full(
    physical_path: &Path,
    verify_cipher: &SslCipher,
    file_iv: u64,
    expected_len: usize,
) -> Vec<u8> {
    if expected_len == 0 {
        return Vec::new();
    }
    let file = fs::File::open(physical_path).expect("open physical encrypted file");
    let decoder = FileDecoder::new(
        verify_cipher,
        &file,
        file_iv,
        HEADER_SIZE,
        BLOCK_SIZE,
        BLOCK_MAC_BYTES,
        false, // ignore_mac_mismatch: strict mode
        true,  // allow_holes: needed for truncate-expand zero regions
    );
    let mut buf = vec![0u8; expected_len];
    let n = decoder.read_at(&mut buf, 0).expect("FileDecoder::read_at");
    buf.truncate(n);
    buf
}

/// After every mutating operation, assert full content equality.
fn verify_full(
    physical_path: &Path,
    verify_cipher: &SslCipher,
    file_iv: u64,
    reference: &[u8],
    op_label: &str,
) {
    let encfs_data = read_encfs_full(physical_path, verify_cipher, file_iv, reference.len());
    assert_eq!(
        encfs_data.len(),
        reference.len(),
        "{}: size mismatch — encfs={} reference={}",
        op_label,
        encfs_data.len(),
        reference.len(),
    );
    assert_eq!(
        encfs_data,
        reference,
        "{}: content mismatch (first bytes) encfs={:?} reference={:?}",
        op_label,
        &encfs_data[..encfs_data.len().min(64)],
        &reference[..reference.len().min(64)],
    );
}

// ---------------------------------------------------------------------------
// Fuzz entry point
// ---------------------------------------------------------------------------

fuzz_target!(|input: FuzzInput| {
    let tmp = TempDir::new();
    let fs = make_encfs(tmp.0.clone());

    // Second cipher instance with identical key — used only for verification
    // reads so as not to share state with the EncFs cipher.
    let verify_cipher = make_cipher();

    let req = make_request();

    // Create the single test file for this iteration.
    let filename = "fuzz_test.bin";
    let parent = PathBuf::from("");
    let path = parent.join(filename);

    let create_res = fs
        .create(req, &parent, OsStr::new(filename), 0o644, 0)
        .unwrap_or_else(|e| panic!("create failed: errno={}", e));
    let fh = create_res.fh;

    // The encrypted filename on disk is opaque; find it by scanning the dir.
    // Only one file exists at this point.
    let physical_path = fs::read_dir(&tmp.0)
        .expect("read_dir")
        .map(|e| e.expect("dir entry").path())
        .find(|p| p.is_file())
        .expect("no encrypted file found after create");

    // Decode the file's IV from its header once — it is fixed after create.
    let phys_file = fs::File::open(&physical_path).expect("open for header read");
    let mut header_bytes = [0u8; 8];
    phys_file
        .read_at(&mut header_bytes, 0)
        .expect("read file header");
    // external_iv = 0 because external_iv_chaining is false in test_default().
    let file_iv = verify_cipher
        .decrypt_header(&mut header_bytes, 0)
        .expect("decrypt file IV from header");
    drop(phys_file);

    // Plain reference buffer — mirrors the expected decrypted file content.
    let mut reference: Vec<u8> = Vec::new();

    let ops: &[Op] = if input.ops.len() > MAX_OPS {
        &input.ops[..MAX_OPS]
    } else {
        &input.ops[..]
    };

    for op in ops {
        match op {
            Op::Write { offset, data } => {
                let offset = *offset as usize;
                if offset > MAX_FILE_SIZE {
                    continue;
                }
                let max_data = MAX_WRITE_SIZE.min(MAX_FILE_SIZE - offset);
                let data: Vec<u8> = data.iter().copied().take(max_data).collect();
                if data.is_empty() {
                    continue;
                }

                let written = fs
                    .write(req, &path, fh, offset as u64, data.clone(), 0)
                    .unwrap_or_else(|e| panic!("write at offset={} failed: errno={}", offset, e));
                assert_eq!(
                    written as usize,
                    data.len(),
                    "short write: expected {} got {}",
                    data.len(),
                    written,
                );

                ref_write(&mut reference, offset, &data);
                verify_full(
                    &physical_path,
                    &verify_cipher,
                    file_iv,
                    &reference,
                    &format!("Write(offset={}, len={})", offset, data.len()),
                );
            }

            Op::Read { offset, len } => {
                let offset = *offset as usize;
                let len = *len as usize;
                if len == 0 {
                    continue;
                }

                // Re-read the full file from EncFS and compare the requested
                // slice against the reference.  This is equivalent to issuing
                // a ranged read but avoids the fuse_mt callback-result type.
                let encfs_all =
                    read_encfs_full(&physical_path, &verify_cipher, file_iv, reference.len());
                let encfs_slice = if offset < encfs_all.len() {
                    let end = (offset + len).min(encfs_all.len());
                    &encfs_all[offset..end]
                } else {
                    &[]
                };
                let expected = ref_slice(&reference, offset, len);
                assert_eq!(
                    encfs_slice,
                    expected,
                    "Read mismatch at offset={} len={}: encfs={:?} reference={:?}",
                    offset,
                    len,
                    &encfs_slice[..encfs_slice.len().min(32)],
                    &expected[..expected.len().min(32)],
                );
            }

            Op::TruncateShrink { size } => {
                let size = *size as usize;
                if size >= reference.len() {
                    continue;
                }

                fs.truncate(req, &path, Some(fh), size as u64)
                    .unwrap_or_else(|e| {
                        panic!("truncate shrink to {} failed: errno={}", size, e)
                    });

                reference.truncate(size);
                verify_full(
                    &physical_path,
                    &verify_cipher,
                    file_iv,
                    &reference,
                    &format!("TruncateShrink(size={})", size),
                );
            }

            Op::TruncateExpand { size } => {
                let size = *size as usize;
                if size <= reference.len() || size > MAX_FILE_SIZE {
                    continue;
                }

                fs.truncate(req, &path, Some(fh), size as u64)
                    .unwrap_or_else(|e| {
                        panic!("truncate expand to {} failed: errno={}", size, e)
                    });

                reference.resize(size, 0);
                verify_full(
                    &physical_path,
                    &verify_cipher,
                    file_iv,
                    &reference,
                    &format!("TruncateExpand(size={})", size),
                );
            }
        }
    }

    let _ = fs.release(req, &path, fh, 0, 0, true);
});
