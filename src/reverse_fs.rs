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
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

struct ReverseFileHandle {
    file: File,
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
}

impl ReverseFs {
    pub fn new(source: PathBuf, cipher: SslCipher, config: EncfsConfig) -> Self {
        Self {
            source,
            cipher,
            config,
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
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

        Ok(result)
    }

    fn open(&self, _req: RequestInfo, path: &Path, flags: u32) -> ResultOpen {
        debug!("ReverseFs::open {:?}", path);
        let (source_path, _) = self.resolve_source_path(path)?;
        let file = File::open(&source_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        self.handles_guard()
            .insert(fh, Arc::new(ReverseFileHandle { file }));
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
        _path: &Path,
        fh: u64,
        offset: u64,
        size: u32,
        callback: impl FnOnce(ResultSlice<'_>) -> CallbackResult,
    ) -> CallbackResult {
        let handle = {
            let handles = self.handles_guard();
            match handles.get(&fh).cloned() {
                Some(h) => h,
                None => return callback(Err(libc::EBADF)),
            }
        };
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
        let available = (ciphertext_size - offset).min(size as u64) as usize;
        let zeros = vec![0u8; available];
        callback(Ok(&zeros))
    }

    fn readlink(&self, _req: RequestInfo, path: &Path) -> Result<Vec<u8>, libc::c_int> {
        debug!("ReverseFs::readlink {:?}", path);
        let (source_path, _) = self.resolve_source_path(path)?;
        let target =
            std::fs::read_link(&source_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        Ok(target.as_os_str().as_bytes().to_vec())
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
