use crate::attr::{file_attr_from_metadata, file_type_from_metadata, synthetic_file_attr};
use crate::config::EncfsConfig;
use crate::crypto::block::BlockLayout;
use crate::crypto::cipher::Cipher;
use bytes::Bytes;
use futures_util::stream::{self, Stream};
use libc;
use log::{debug, warn};
use rfuse3::path::Request;
use rfuse3::path::reply::{
    DirectoryEntry, DirectoryEntryPlus, FileAttr, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEntry, ReplyInit, ReplyLock, ReplyOpen, ReplyStatFs, ReplyXAttr,
};
use rfuse3::{Errno, FileType, Result as FuseResult, SetAttr};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const ATTR_TTL: Duration = Duration::from_secs(1);
const CONFIG_FILE_NAME: &str = ".encfs7";

enum ReverseHandle {
    /// Virtual config file served from in-memory bytes.
    Config,
    /// A real plaintext source file being encrypted on the fly.
    File { file: File, file_iv: u64 },
}

/// A reverse-direction FUSE filesystem.
///
/// Where `EncFs` stores encrypted files on disk and presents a plaintext FUSE view,
/// `ReverseFs` reads plaintext files on disk and presents an encrypted virtual filesystem
/// to FUSE callers. This enables plaintext directories to be backed up in encrypted form
/// without duplicating storage.
pub struct ReverseFs {
    pub source: PathBuf,
    pub cipher: Box<dyn Cipher>,
    pub config: EncfsConfig,
    handles: Mutex<HashMap<u64, Arc<ReverseHandle>>>,
    next_fh: AtomicU64,
    config_bytes: Vec<u8>,
    config_mtime: SystemTime,
    config_uid: u32,
    config_gid: u32,
}

impl ReverseFs {
    pub fn new(
        source: PathBuf,
        cipher: Box<dyn Cipher>,
        config: EncfsConfig,
        config_bytes: Vec<u8>,
        config_metadata: std::fs::Metadata,
    ) -> Self {
        let config_mtime = crate::attr::system_time_from_secs(
            config_metadata.mtime(),
            config_metadata.mtime_nsec(),
        );
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

    // Guards are always dropped before any .await (the op bodies below contain
    // no awaits), so a std::sync::Mutex is safe here.
    fn handles_guard(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<ReverseHandle>>> {
        self.handles.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn is_config_path(path: &Path) -> bool {
        path == Path::new("/").join(CONFIG_FILE_NAME)
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
            self.cipher.as_ref(),
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

    fn config_file_attr(&self) -> FileAttr {
        synthetic_file_attr(
            self.config_bytes.len() as u64,
            self.config_mtime,
            0o444,
            self.config_uid,
            self.config_gid,
        )
    }

    /// Build the FUSE attributes for an encrypted FUSE path (including the
    /// virtual config file), reporting ciphertext sizes for regular files.
    fn attr_for_fuse_path(&self, path: &Path) -> Result<FileAttr, Errno> {
        if Self::is_config_path(path) {
            return Ok(self.config_file_attr());
        }

        let (source_path, _) = self.resolve_source_path(path)?;
        let metadata = std::fs::symlink_metadata(&source_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let mut reported_size = metadata.len();
        if metadata.is_file() {
            reported_size = self.ciphertext_size_for_plaintext(reported_size)?;
        }

        Ok(file_attr_from_metadata(&metadata, reported_size))
    }

    /// List encrypted directory entries for a FUSE path (including `.` / `..`
    /// and the virtual root config file).
    fn readdir_entries(
        &self,
        path: &Path,
    ) -> Result<Vec<(std::ffi::OsString, FileType)>, libc::c_int> {
        let (source_dir, dir_iv) = self.resolve_source_path(path)?;

        let read_dir =
            std::fs::read_dir(&source_dir).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let mut result = vec![
            (OsStr::new(".").to_os_string(), FileType::Directory),
            (OsStr::new("..").to_os_string(), FileType::Directory),
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
                    result.push((
                        OsStr::new(&encrypted_name).to_os_string(),
                        file_type_from_metadata(&metadata),
                    ));
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
            result.push((
                OsStr::new(CONFIG_FILE_NAME).to_os_string(),
                FileType::RegularFile,
            ));
        }

        Ok(result)
    }
}

impl rfuse3::path::PathFilesystem for ReverseFs {
    async fn init(&self, _req: Request) -> FuseResult<ReplyInit> {
        debug!("ReverseFs::init");
        Ok(ReplyInit::default())
    }

    async fn destroy(&self, _req: Request) {
        debug!("ReverseFs::destroy");
    }

    async fn lookup(&self, _req: Request, parent: &OsStr, name: &OsStr) -> FuseResult<ReplyEntry> {
        let path = Path::new(parent).join(name);
        debug!("ReverseFs::lookup {:?}", path);
        let attr = self.attr_for_fuse_path(&path)?;
        Ok(ReplyEntry {
            ttl: ATTR_TTL,
            attr,
        })
    }

    async fn getattr(
        &self,
        _req: Request,
        path: Option<&OsStr>,
        fh: Option<u64>,
        _flags: u32,
    ) -> FuseResult<ReplyAttr> {
        debug!("ReverseFs::getattr {:?} fh={:?}", path, fh);

        if let Some(path) = path {
            let attr = self.attr_for_fuse_path(Path::new(path))?;
            return Ok(ReplyAttr {
                ttl: ATTR_TTL,
                attr,
            });
        }

        // Path unknown (possibly deleted): fall back to an open handle.
        let handle = fh
            .and_then(|fh| self.handles_guard().get(&fh).cloned())
            .ok_or_else(|| Errno::from(libc::ESTALE))?;
        let attr = match handle.as_ref() {
            ReverseHandle::Config => self.config_file_attr(),
            ReverseHandle::File { file, .. } => {
                let metadata = file
                    .metadata()
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                let size = self.ciphertext_size_for_plaintext(metadata.len())?;
                file_attr_from_metadata(&metadata, size)
            }
        };
        Ok(ReplyAttr {
            ttl: ATTR_TTL,
            attr,
        })
    }

    async fn statfs(&self, _req: Request, path: &OsStr) -> FuseResult<ReplyStatFs> {
        debug!("ReverseFs::statfs {:?}", path);
        let c_path =
            std::ffi::CString::new(self.source.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let res = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if res != 0 {
            return Err(Errno::from(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            ));
        }
        Ok(ReplyStatFs {
            blocks: stat.f_blocks as u64,
            bfree: stat.f_bfree as u64,
            bavail: stat.f_bavail as u64,
            files: stat.f_files as u64,
            ffree: stat.f_ffree as u64,
            bsize: stat.f_bsize as u32,
            namelen: stat.f_namemax as u32,
            frsize: stat.f_frsize as u32,
        })
    }

    async fn opendir(&self, _req: Request, path: &OsStr, _flags: u32) -> FuseResult<ReplyOpen> {
        debug!("ReverseFs::opendir {:?}", path);
        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        Ok(ReplyOpen { fh, flags: 0 })
    }

    async fn releasedir(
        &self,
        _req: Request,
        _path: &OsStr,
        _fh: u64,
        _flags: u32,
    ) -> FuseResult<()> {
        Ok(())
    }

    async fn readdir<'a>(
        &'a self,
        _req: Request,
        path: &'a OsStr,
        _fh: u64,
        offset: i64,
    ) -> FuseResult<ReplyDirectory<impl Stream<Item = FuseResult<DirectoryEntry>> + Send + 'a>>
    {
        let path = Path::new(path);
        debug!("ReverseFs::readdir {:?} offset={}", path, offset);
        let result = self.readdir_entries(path)?;

        // The kernel may issue multiple READDIR calls, resuming at `offset`;
        // each entry's offset field is the offset of the *next* entry.
        let entries = result
            .into_iter()
            .enumerate()
            .skip(offset.max(0) as usize)
            .map(|(i, (name, kind))| {
                Ok(DirectoryEntry {
                    kind,
                    name,
                    offset: i as i64 + 1,
                })
            });

        Ok(ReplyDirectory {
            entries: stream::iter(entries),
        })
    }

    async fn readdirplus<'a>(
        &'a self,
        _req: Request,
        path: &'a OsStr,
        _fh: u64,
        offset: u64,
        _lock_owner: u64,
    ) -> FuseResult<
        ReplyDirectoryPlus<impl Stream<Item = FuseResult<DirectoryEntryPlus>> + Send + 'a>,
    > {
        let dir = Path::new(path);
        debug!("ReverseFs::readdirplus {:?} offset={}", dir, offset);
        let result = self.readdir_entries(dir)?;

        let entries =
            result
                .into_iter()
                .enumerate()
                .skip(offset as usize)
                .map(|(i, (name, kind))| {
                    let entry_path = if name.as_os_str() == "." {
                        dir.to_path_buf()
                    } else if name.as_os_str() == ".." {
                        dir.parent()
                            .filter(|p| !p.as_os_str().is_empty())
                            .unwrap_or(dir)
                            .to_path_buf()
                    } else {
                        dir.join(&name)
                    };
                    let attr = self.attr_for_fuse_path(&entry_path)?;
                    Ok(DirectoryEntryPlus {
                        kind,
                        name,
                        offset: i as i64 + 1,
                        attr,
                        entry_ttl: ATTR_TTL,
                        attr_ttl: ATTR_TTL,
                    })
                });

        Ok(ReplyDirectoryPlus {
            entries: stream::iter(entries),
        })
    }

    async fn open(&self, _req: Request, path: &OsStr, flags: u32) -> FuseResult<ReplyOpen> {
        let path = Path::new(path);
        debug!("ReverseFs::open {:?}", path);

        // Special case: virtual .encfs7 config file at the FUSE root (CRPT-05).
        // This file is backed by in-memory config bytes, not a real source file, so
        // we must not run it through encrypted path resolution.
        if Self::is_config_path(path) {
            // Enforce read-only semantics for the virtual config file.
            let write_flags = libc::O_WRONLY as u32
                | libc::O_RDWR as u32
                | libc::O_TRUNC as u32
                | libc::O_CREAT as u32;
            if flags & write_flags != 0 {
                return Err(Errno::from(libc::EROFS));
            }
            let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
            self.handles_guard()
                .insert(fh, Arc::new(ReverseHandle::Config));
            return Ok(ReplyOpen { fh, flags });
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
            .insert(fh, Arc::new(ReverseHandle::File { file, file_iv }));
        Ok(ReplyOpen { fh, flags })
    }

    async fn release(
        &self,
        _req: Request,
        _path: Option<&OsStr>,
        fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> FuseResult<()> {
        self.handles_guard().remove(&fh);
        Ok(())
    }

    async fn read(
        &self,
        _req: Request,
        _path: Option<&OsStr>,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> FuseResult<ReplyData> {
        let handle = {
            let handles = self.handles_guard();
            handles
                .get(&fh)
                .cloned()
                .ok_or_else(|| Errno::from(libc::EBADF))?
        };

        match handle.as_ref() {
            // Virtual .encfs7 config file (CRPT-05), served from memory.
            ReverseHandle::Config => {
                let data = &self.config_bytes;
                let start = offset as usize;
                if start >= data.len() {
                    return Ok(ReplyData { data: Bytes::new() });
                }
                let end = std::cmp::min(data.len(), start + size as usize);
                Ok(ReplyData {
                    data: Bytes::copy_from_slice(&data[start..end]),
                })
            }
            ReverseHandle::File { file, file_iv } => {
                let plaintext_size = file
                    .metadata()
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?
                    .len();
                let ciphertext_size = self.ciphertext_size_for_plaintext(plaintext_size)?;
                if offset >= ciphertext_size {
                    return Ok(ReplyData { data: Bytes::new() });
                }

                let actual_size = std::cmp::min(size as u64, ciphertext_size - offset) as u32;
                let data = self.read_encrypted(file, *file_iv, offset, actual_size)?;
                Ok(ReplyData {
                    data: Bytes::from(data),
                })
            }
        }
    }

    async fn getlk(
        &self,
        _req: Request,
        _path: Option<&OsStr>,
        fh: u64,
        _lock_owner: u64,
        start: u64,
        end: u64,
        r#type: u32,
        pid: u32,
    ) -> FuseResult<ReplyLock> {
        let handle = self.handles_guard().get(&fh).cloned().ok_or(libc::ESTALE)?;
        let ReverseHandle::File { file, .. } = handle.as_ref() else {
            return Err(Errno::from(libc::ENOSYS));
        };
        Ok(crate::file_lock::getlk(
            file.as_raw_fd(),
            start,
            end,
            r#type,
            pid,
        )?)
    }

    async fn setlk(
        &self,
        _req: Request,
        _path: Option<&OsStr>,
        fh: u64,
        _lock_owner: u64,
        start: u64,
        end: u64,
        r#type: u32,
        pid: u32,
        block: bool,
    ) -> FuseResult<()> {
        let handle = self.handles_guard().get(&fh).cloned().ok_or(libc::ESTALE)?;
        let ReverseHandle::File { file, .. } = handle.as_ref() else {
            return Err(Errno::from(libc::ENOSYS));
        };
        crate::file_lock::setlk(file.as_raw_fd(), start, end, r#type, pid, block)?;
        Ok(())
    }

    async fn readlink(&self, _req: Request, path: &OsStr) -> FuseResult<ReplyData> {
        let path = Path::new(path);
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
        Ok(ReplyData {
            data: Bytes::from(enc_target.into_bytes()),
        })
    }

    async fn flush(
        &self,
        _req: Request,
        _path: Option<&OsStr>,
        _fh: u64,
        _lock_owner: u64,
    ) -> FuseResult<()> {
        Ok(())
    }

    async fn fsync(
        &self,
        _req: Request,
        _path: Option<&OsStr>,
        _fh: u64,
        _datasync: bool,
    ) -> FuseResult<()> {
        Ok(())
    }

    async fn fsyncdir(
        &self,
        _req: Request,
        _path: &OsStr,
        _fh: u64,
        _datasync: bool,
    ) -> FuseResult<()> {
        Ok(())
    }

    async fn getxattr(
        &self,
        _req: Request,
        _path: &OsStr,
        _name: &OsStr,
        _size: u32,
    ) -> FuseResult<ReplyXAttr> {
        Err(Errno::from(libc::ENODATA))
    }

    async fn listxattr(&self, _req: Request, _path: &OsStr, _size: u32) -> FuseResult<ReplyXAttr> {
        Err(Errno::from(libc::ENOSYS))
    }

    // All mutating operations return EROFS (FUSE-01)

    async fn setattr(
        &self,
        _req: Request,
        _path: Option<&OsStr>,
        _fh: Option<u64>,
        _set_attr: SetAttr,
    ) -> FuseResult<ReplyAttr> {
        Err(Errno::from(libc::EROFS))
    }

    async fn write(
        &self,
        _req: Request,
        _path: Option<&OsStr>,
        _fh: u64,
        _offset: u64,
        _data: &[u8],
        _write_flags: u32,
        _flags: u32,
    ) -> FuseResult<rfuse3::path::reply::ReplyWrite> {
        Err(Errno::from(libc::EROFS))
    }

    async fn create(
        &self,
        _req: Request,
        _parent: &OsStr,
        _name: &OsStr,
        _mode: u32,
        _flags: u32,
    ) -> FuseResult<rfuse3::path::reply::ReplyCreated> {
        Err(Errno::from(libc::EROFS))
    }

    async fn mkdir(
        &self,
        _req: Request,
        _parent: &OsStr,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
    ) -> FuseResult<ReplyEntry> {
        Err(Errno::from(libc::EROFS))
    }

    async fn unlink(&self, _req: Request, _parent: &OsStr, _name: &OsStr) -> FuseResult<()> {
        Err(Errno::from(libc::EROFS))
    }

    async fn rmdir(&self, _req: Request, _parent: &OsStr, _name: &OsStr) -> FuseResult<()> {
        Err(Errno::from(libc::EROFS))
    }

    async fn rename(
        &self,
        _req: Request,
        _origin_parent: &OsStr,
        _origin_name: &OsStr,
        _parent: &OsStr,
        _name: &OsStr,
    ) -> FuseResult<()> {
        Err(Errno::from(libc::EROFS))
    }

    async fn symlink(
        &self,
        _req: Request,
        _parent: &OsStr,
        _name: &OsStr,
        _link_path: &OsStr,
    ) -> FuseResult<ReplyEntry> {
        Err(Errno::from(libc::EROFS))
    }

    async fn link(
        &self,
        _req: Request,
        _path: &OsStr,
        _new_parent: &OsStr,
        _new_name: &OsStr,
    ) -> FuseResult<ReplyEntry> {
        Err(Errno::from(libc::EROFS))
    }

    async fn mknod(
        &self,
        _req: Request,
        _parent: &OsStr,
        _name: &OsStr,
        _mode: u32,
        _rdev: u32,
    ) -> FuseResult<ReplyEntry> {
        Err(Errno::from(libc::EROFS))
    }

    async fn setxattr(
        &self,
        _req: Request,
        _path: &OsStr,
        _name: &OsStr,
        _value: &[u8],
        _flags: u32,
        _position: u32,
    ) -> FuseResult<()> {
        Err(Errno::from(libc::EROFS))
    }

    async fn removexattr(&self, _req: Request, _path: &OsStr, _name: &OsStr) -> FuseResult<()> {
        Err(Errno::from(libc::EROFS))
    }
}
