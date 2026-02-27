use crate::config::EncfsConfig;
use crate::crypto::block::BlockLayout;
use crate::crypto::ssl::SslCipher;
use fuse_mt::{
    CallbackResult, DirectoryEntry, FileAttr, FileType, FilesystemMT, RequestInfo, ResultCreate,
    ResultEmpty, ResultEntry, ResultOpen, ResultReaddir, ResultSlice, ResultStatfs, ResultWrite,
    ResultXattr, Statfs,
};
use libc;
use log::{debug, warn};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

struct ReverseFileHandle {
    file: File,
    file_iv: u64,
}

/// A reverse-direction FUSE filesystem.
///
/// Where `EncFs` stores encrypted files on disk and presents a plaintext FUSE view,
/// `ReverseFs` reads plaintext files on disk and presents an encrypted virtual filesystem
/// to FUSE callers. This enables plaintext directories to be backed up in encrypted form
/// without duplicating storage.
pub struct ReverseFs {
    pub source: PathBuf,
    pub cipher: SslCipher,
    pub config: EncfsConfig,
    handles: Mutex<HashMap<u64, Arc<ReverseFileHandle>>>,
    next_fh: AtomicU64,
    config_bytes: Vec<u8>,
    config_mtime: SystemTime,
    config_uid: u32,
    config_gid: u32,
}

impl ReverseFs {
    pub fn new(
        source: PathBuf,
        cipher: SslCipher,
        config: EncfsConfig,
        config_bytes: Vec<u8>,
        config_metadata: std::fs::Metadata,
    ) -> Self {
        let config_mtime =
            system_time_from_metadata_secs(config_metadata.mtime(), config_metadata.mtime_nsec());
        let config_uid = config_metadata.uid();
        let config_gid = config_metadata.gid();
        Self {
            source,
            cipher,
            config,
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            config_bytes,
            config_mtime,
            config_uid,
            config_gid,
        }
    }

    fn handles_guard(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<ReverseFileHandle>>> {
        self.handles.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Decrypt an incoming encrypted FUSE path to the corresponding plaintext source path.
    ///
    /// FUSE requests arrive with encrypted paths (callers see the virtual encrypted FS).
    /// We must decrypt each path component to find the plaintext source file.
    /// Returns (absolute_source_path, dir_iv) where dir_iv is the IV after processing
    /// the last path component — pass this to encrypt_filename in readdir for the
    /// correct per-directory IV.
    fn resolve_source_path(&self, fuse_path: &Path) -> Result<(PathBuf, u64), libc::c_int> {
        let mut source_path = self.source.clone();
        let mut iv = 0u64;
        for component in fuse_path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => {
                    let name_str = name.to_str().ok_or(libc::EILSEQ)?;
                    let (plain_bytes, new_iv) = self
                        .cipher
                        .decrypt_filename(name_str, iv)
                        .map_err(|_| libc::ENOENT)?;
                    source_path.push(OsStr::from_bytes(&plain_bytes));
                    if self.config.chained_name_iv {
                        iv = new_iv;
                    }
                }
                _ => return Err(libc::EINVAL),
            }
        }
        Ok((source_path, iv))
    }

    /// Compute the ciphertext size for a given plaintext file size (FUSE-03).
    ///
    /// header_size = 0 because unique_iv = false (enforced in Phase 1 by CONF-01).
    fn ciphertext_size_for_plaintext(&self, plaintext_size: u64) -> Result<u64, libc::c_int> {
        let layout = BlockLayout::new(
            self.config.block_mode(),
            self.config.block_size as u64,
            self.config.block_mac_bytes as u64,
        )
        .map_err(|_| libc::EINVAL)?;
        Ok(layout.physical_size_from_logical(plaintext_size, 0))
    }

    fn read_encrypted(
        &self,
        file: &File,
        file_iv: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, libc::c_int> {
        use crate::crypto::block::{BlockCodec, BlockLayout};

        let layout = BlockLayout::new(
            self.config.block_mode(),
            self.config.block_size as u64,
            self.config.block_mac_bytes as u64,
        )
        .map_err(|_| libc::EINVAL)?;

        let codec = BlockCodec::new(
            &self.cipher,
            layout,
            false, // ignore_legacy_mac_mismatch unused for encrypt
            self.config.allow_holes,
        );

        let data_block_size = layout.data_size_per_block();
        // CIPHERTEXT offset arithmetic: ciphertext block N is at [N*block_size, (N+1)*block_size)
        // Corresponding plaintext is at [N*data_block_size, (N+1)*data_block_size)
        // header_size = 0 because unique_iv = false (CONF-01 enforces this)
        let start_block = offset / layout.block_size();
        let end_block = (offset + size as u64 - 1) / layout.block_size();

        let mut out = Vec::with_capacity(size as usize);

        for block_num in start_block..=end_block {
            let pt_offset = block_num * data_block_size; // header_size = 0
            let mut plain_buf = vec![0u8; data_block_size as usize];
            let n = file
                .read_at(&mut plain_buf, pt_offset)
                .map_err(|_| libc::EIO)?;
            if n == 0 {
                break;
            }
            plain_buf.truncate(n);

            let cipher_block = codec
                .encrypt_block(block_num, file_iv, &plain_buf)
                .map_err(|_| libc::EIO)?;

            // Slice out only the bytes the caller requested (first/last blocks may be partial)
            let block_start_in_ct = block_num * layout.block_size();
            let lo = if block_start_in_ct < offset {
                (offset - block_start_in_ct) as usize
            } else {
                0
            };
            let hi = std::cmp::min(
                cipher_block.len(),
                (offset + size as u64 - block_start_in_ct) as usize,
            );
            if lo < hi {
                out.extend_from_slice(&cipher_block[lo..hi]);
            }
        }
        Ok(out)
    }
}

/// Map std::fs::Metadata file type to FUSE FileType.
fn metadata_to_filetype(metadata: &std::fs::Metadata) -> FileType {
    let ft = metadata.file_type();
    if ft.is_dir() {
        FileType::Directory
    } else if ft.is_symlink() {
        FileType::Symlink
    } else if ft.is_block_device() {
        FileType::BlockDevice
    } else if ft.is_char_device() {
        FileType::CharDevice
    } else if ft.is_fifo() {
        FileType::NamedPipe
    } else if ft.is_socket() {
        FileType::Socket
    } else {
        FileType::RegularFile
    }
}

/// Convert metadata timestamps (seconds + nanoseconds since epoch) to SystemTime.
fn system_time_from_metadata_secs(secs: i64, nanos: i64) -> SystemTime {
    if secs >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(secs as u64, nanos as u32)
    } else {
        SystemTime::UNIX_EPOCH
            .checked_sub(Duration::new((-secs) as u64, 0))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

impl FilesystemMT for ReverseFs {
    fn init(&self, _req: RequestInfo) -> ResultEmpty {
        debug!("ReverseFs::init");
        Ok(())
    }

    fn destroy(&self) {
        debug!("ReverseFs::destroy");
    }

    fn statfs(&self, _req: RequestInfo, path: &Path) -> ResultStatfs {
        debug!("ReverseFs::statfs {:?}", path);
        let c_path =
            std::ffi::CString::new(self.source.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let res = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if res != 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }
        Ok(Statfs {
            blocks: stat.f_blocks,
            bfree: stat.f_bfree,
            bavail: stat.f_bavail,
            files: stat.f_files,
            ffree: stat.f_ffree,
            bsize: stat.f_bsize as u32,
            namelen: stat.f_namemax as u32,
            frsize: stat.f_frsize as u32,
        })
    }

    fn getattr(&self, _req: RequestInfo, path: &Path, _fh: Option<u64>) -> ResultEntry {
        debug!("ReverseFs::getattr {:?}", path);

        // Virtual config file at root
        if path == Path::new("/.encfs7") {
            let size = self.config_bytes.len() as u64;
            return Ok((
                Duration::from_secs(1),
                FileAttr {
                    size,
                    blocks: size.div_ceil(512),
                    atime: self.config_mtime,
                    mtime: self.config_mtime,
                    ctime: self.config_mtime,
                    crtime: SystemTime::UNIX_EPOCH,
                    kind: FileType::RegularFile,
                    perm: 0o444,
                    nlink: 1,
                    uid: self.config_uid,
                    gid: self.config_gid,
                    rdev: 0,
                    flags: 0,
                },
            ));
        }

        let (source_path, _) = self.resolve_source_path(path)?;
        let metadata = std::fs::symlink_metadata(&source_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let mut reported_size = metadata.len();
        if metadata.is_file() {
            reported_size = self.ciphertext_size_for_plaintext(reported_size)?;
        }

        let atime = system_time_from_metadata_secs(metadata.atime(), metadata.atime_nsec());
        let mtime = system_time_from_metadata_secs(metadata.mtime(), metadata.mtime_nsec());
        let ctime = system_time_from_metadata_secs(metadata.ctime(), metadata.ctime_nsec());

        Ok((
            Duration::from_secs(1),
            FileAttr {
                size: reported_size,
                blocks: metadata.blocks(),
                atime,
                mtime,
                ctime,
                crtime: SystemTime::UNIX_EPOCH,
                kind: metadata_to_filetype(&metadata),
                perm: metadata.mode() as u16,
                nlink: metadata.nlink() as u32,
                uid: metadata.uid(),
                gid: metadata.gid(),
                rdev: metadata.rdev() as u32,
                flags: 0,
            },
        ))
    }

    fn opendir(&self, _req: RequestInfo, path: &Path, _flags: u32) -> ResultOpen {
        debug!("ReverseFs::opendir {:?}", path);
        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        Ok((fh, 0))
    }

    fn releasedir(&self, _req: RequestInfo, _path: &Path, _fh: u64, _flags: u32) -> ResultEmpty {
        Ok(())
    }

    fn readdir(&self, _req: RequestInfo, path: &Path, _fh: u64) -> ResultReaddir {
        debug!("ReverseFs::readdir {:?}", path);
        let (source_dir, dir_iv) = self.resolve_source_path(path)?;

        let read_dir =
            std::fs::read_dir(&source_dir).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let mut result = vec![
            DirectoryEntry {
                name: OsStr::new(".").to_os_string(),
                kind: FileType::Directory,
            },
            DirectoryEntry {
                name: OsStr::new("..").to_os_string(),
                kind: FileType::Directory,
            },
        ];

        for entry in read_dir {
            let entry = entry.map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            let file_name = entry.file_name();
            let name_bytes = file_name.as_bytes();

            // Skip dot-files: config files (.encfs6.xml, .encfs7) and hidden files
            if name_bytes.starts_with(b".") {
                continue;
            }

            match self.cipher.encrypt_filename(name_bytes, dir_iv) {
                Ok((encrypted_name, _)) => {
                    let metadata = entry
                        .metadata()
                        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                    result.push(DirectoryEntry {
                        name: OsStr::new(&encrypted_name).to_os_string(),
                        kind: metadata_to_filetype(&metadata),
                    });
                }
                Err(e) => {
                    warn!(
                        "ReverseFs::readdir: failed to encrypt {:?}: {}",
                        file_name, e
                    );
                }
            }
        }

        if path == Path::new("/") {
            result.push(DirectoryEntry {
                name: OsStr::new(".encfs7").to_os_string(),
                kind: FileType::RegularFile,
            });
        }

        Ok(result)
    }

    fn open(&self, _req: RequestInfo, path: &Path, flags: u32) -> ResultOpen {
        debug!("ReverseFs::open {:?}", path);

        // Special case: virtual .encfs7 config file at the FUSE root (CRPT-05).
        // This file is backed by in-memory config bytes, not a real source file, so
        // we must not run it through encrypted path resolution.
        if path == Path::new("/.encfs7") {
            // Enforce read-only semantics for the virtual config file.
            let write_flags = libc::O_WRONLY as u32
                | libc::O_RDWR as u32
                | libc::O_TRUNC as u32
                | libc::O_CREAT as u32;
            if flags & write_flags != 0 {
                return Err(libc::EROFS);
            }
            // We don't need a real file handle here because read() for .encfs7 ignores fh
            // and serves data directly from self.config_bytes.
            return Ok((0, flags));
        }

        let (source_path, dir_iv) = self.resolve_source_path(path)?;
        let file_iv = if self.config.external_iv_chaining {
            dir_iv
        } else {
            0u64
        };
        let file = File::open(&source_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        self.handles_guard()
            .insert(fh, Arc::new(ReverseFileHandle { file, file_iv }));
        Ok((fh, flags))
    }

    fn release(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> ResultEmpty {
        self.handles_guard().remove(&fh);
        Ok(())
    }

    fn read(
        &self,
        _req: RequestInfo,
        path: &Path,
        fh: u64,
        offset: u64,
        size: u32,
        callback: impl FnOnce(ResultSlice<'_>) -> CallbackResult,
    ) -> CallbackResult {
        // Special case: virtual .encfs7 config file (CRPT-05)
        if path == Path::new("/.encfs7") {
            let data = &self.config_bytes;
            let start = offset as usize;
            if start >= data.len() {
                return callback(Ok(&[]));
            }
            let end = std::cmp::min(data.len(), start + size as usize);
            return callback(Ok(&data[start..end]));
        }

        // CRITICAL: release the handles lock before calling callback to avoid deadlock
        let handle = {
            let handles = self.handles_guard();
            match handles.get(&fh).cloned() {
                Some(h) => h,
                None => return callback(Err(libc::EBADF)),
            }
        }; // lock dropped here

        let plaintext_size = match handle.file.metadata() {
            Ok(m) => m.len(),
            Err(_) => return callback(Err(libc::EIO)),
        };
        let ciphertext_size = match self.ciphertext_size_for_plaintext(plaintext_size) {
            Ok(s) => s,
            Err(e) => return callback(Err(e)),
        };
        if offset >= ciphertext_size {
            return callback(Ok(&[]));
        }

        // Do encryption work without holding the handles lock
        let actual_size = std::cmp::min(size as u64, ciphertext_size - offset) as u32;
        match self.read_encrypted(&handle.file, handle.file_iv, offset, actual_size) {
            Ok(data) => callback(Ok(&data)),
            Err(e) => callback(Err(e)),
        }
    }

    fn readlink(&self, _req: RequestInfo, path: &Path) -> Result<Vec<u8>, libc::c_int> {
        debug!("ReverseFs::readlink {:?}", path);
        let (source_path, dir_iv) = self.resolve_source_path(path)?;
        let target =
            std::fs::read_link(&source_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let plain_bytes = target.as_os_str().as_bytes();
        // Encrypt the symlink target using the directory IV of the symlink's location (CRPT-04)
        // This matches what forward encfs does in fs.rs::symlink() — same IV, same call
        let (enc_target, _) = self
            .cipher
            .encrypt_filename(plain_bytes, dir_iv)
            .map_err(|_| libc::EIO)?;
        Ok(enc_target.into_bytes())
    }

    fn flush(&self, _req: RequestInfo, _path: &Path, _fh: u64, _lock_owner: u64) -> ResultEmpty {
        Ok(())
    }

    fn fsync(&self, _req: RequestInfo, _path: &Path, _fh: u64, _datasync: bool) -> ResultEmpty {
        Ok(())
    }

    fn fsyncdir(&self, _req: RequestInfo, _path: &Path, _fh: u64, _datasync: bool) -> ResultEmpty {
        Ok(())
    }

    fn getxattr(&self, _req: RequestInfo, _path: &Path, _name: &OsStr, _size: u32) -> ResultXattr {
        Err(libc::ENODATA)
    }

    fn listxattr(&self, _req: RequestInfo, _path: &Path, _size: u32) -> ResultXattr {
        Err(libc::ENOSYS)
    }

    // All mutating operations return EROFS (FUSE-01)

    fn write(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: u64,
        _offset: u64,
        _data: Vec<u8>,
        _flags: u32,
    ) -> ResultWrite {
        Err(libc::EROFS)
    }

    fn create(
        &self,
        _req: RequestInfo,
        _parent: &Path,
        _name: &OsStr,
        _mode: u32,
        _flags: u32,
    ) -> ResultCreate {
        Err(libc::EROFS)
    }

    fn mkdir(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr, _mode: u32) -> ResultEntry {
        Err(libc::EROFS)
    }

    fn unlink(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn rmdir(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn rename(
        &self,
        _req: RequestInfo,
        _parent: &Path,
        _name: &OsStr,
        _newparent: &Path,
        _newname: &OsStr,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn truncate(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: Option<u64>,
        _size: u64,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn symlink(
        &self,
        _req: RequestInfo,
        _parent: &Path,
        _name: &OsStr,
        _target: &Path,
    ) -> ResultEntry {
        Err(libc::EROFS)
    }

    fn link(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _newparent: &Path,
        _newname: &OsStr,
    ) -> ResultEntry {
        Err(libc::EROFS)
    }

    fn mknod(
        &self,
        _req: RequestInfo,
        _parent: &Path,
        _name: &OsStr,
        _mode: u32,
        _rdev: u32,
    ) -> ResultEntry {
        Err(libc::EROFS)
    }

    fn chmod(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _mode: u32) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn chown(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: Option<u64>,
        _uid: Option<u32>,
        _gid: Option<u32>,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn utimens(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: Option<u64>,
        _atime: Option<SystemTime>,
        _mtime: Option<SystemTime>,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn setxattr(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _name: &OsStr,
        _value: &[u8],
        _flags: u32,
        _position: u32,
    ) -> ResultEmpty {
        Err(libc::EROFS)
    }

    fn removexattr(&self, _req: RequestInfo, _path: &Path, _name: &OsStr) -> ResultEmpty {
        Err(libc::EROFS)
    }
}
