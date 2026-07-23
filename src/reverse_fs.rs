use crate::attr::{file_attr_from_metadata, file_type_from_metadata, synthetic_file_attr};
use crate::config::EncfsConfig;
use crate::crypto::block::BlockLayout;
use crate::crypto::cipher::Cipher;
use fuse3::{
    Caller as Request, Errno, FileKind as FileType, FileLock, NodeAttr as FileAttr, Opened,
    PathDirSink, PathFilesystem, PathPlusDirSink, SetAttr, StatFs as ReplyStatFs, XattrReply,
};
use libc;
use log::{debug, warn};
use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

const CONFIG_FILE_NAME: &str = ".encfs7";

pub enum ReverseHandle {
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
            config_bytes,
            config_mtime,
            config_uid,
            config_gid,
        }
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

impl PathFilesystem for ReverseFs {
    type Handle = ReverseHandle;
    type DirHandle = ();

    const SUPPORTS_POSIX_LOCKS: bool = true;
    const SUPPORTS_READDIRPLUS: bool = true;

    fn init(&self, _conn: &mut fuse3::ConnInfo) {
        debug!("ReverseFs::init");
    }

    fn destroy(&self) {
        debug!("ReverseFs::destroy");
    }

    fn lookup(
        &self,
        parent: &Path,
        name: &OsStr,
        _caller: &Request,
    ) -> Result<Option<FileAttr>, Errno> {
        let path = parent.join(name);
        match self.attr_for_fuse_path(&path) {
            Ok(attr) => Ok(Some(attr)),
            Err(error) if error == Errno::ENOENT => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn getattr(
        &self,
        path: Option<&Path>,
        handle: Option<&ReverseHandle>,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        if let Some(path) = path {
            return self.attr_for_fuse_path(path);
        }
        match handle.ok_or_else(|| Errno::from(libc::ESTALE))? {
            ReverseHandle::Config => Ok(self.config_file_attr()),
            ReverseHandle::File { file, .. } => {
                let metadata = file
                    .metadata()
                    .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
                let size = self.ciphertext_size_for_plaintext(metadata.len())?;
                Ok(file_attr_from_metadata(&metadata, size))
            }
        }
    }

    fn statfs(&self, path: &Path, _caller: &Request) -> Result<ReplyStatFs, Errno> {
        debug!("ReverseFs::statfs {:?}", path);
        let c_path =
            std::ffi::CString::new(self.source.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
                .into());
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

    fn opendir(&self, path: &Path, _flags: i32, _caller: &Request) -> Result<Opened<()>, Errno> {
        self.resolve_source_path(path)?;
        Ok(Opened::new(()))
    }

    fn readdir(
        &self,
        path: &Path,
        _handle: &(),
        offset: u64,
        sink: &mut dyn PathDirSink,
        _caller: &Request,
    ) -> Result<(), Errno> {
        for (index, (name, kind)) in self
            .readdir_entries(path)?
            .into_iter()
            .enumerate()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        {
            if !sink.add(&name, kind, index as u64 + 1) {
                break;
            }
        }
        Ok(())
    }

    fn readdirplus(
        &self,
        path: &Path,
        _handle: &(),
        offset: u64,
        sink: &mut dyn PathPlusDirSink,
        _caller: &Request,
    ) -> Result<(), Errno> {
        for (index, (name, _kind)) in self
            .readdir_entries(path)?
            .into_iter()
            .enumerate()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        {
            let entry_path = if name == OsStr::new(".") {
                path.to_path_buf()
            } else if name == OsStr::new("..") {
                path.parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or(path)
                    .to_path_buf()
            } else {
                path.join(&name)
            };
            let attr = self.attr_for_fuse_path(&entry_path)?;
            if !sink.add(&name, attr, index as u64 + 1) {
                break;
            }
        }
        Ok(())
    }

    fn open(
        &self,
        path: &Path,
        flags: i32,
        _caller: &Request,
    ) -> Result<Opened<ReverseHandle>, Errno> {
        let write_flags = libc::O_WRONLY | libc::O_RDWR | libc::O_TRUNC | libc::O_CREAT;
        if flags & write_flags != 0 {
            return Err(Errno::EROFS);
        }
        if Self::is_config_path(path) {
            return Ok(Opened::new(ReverseHandle::Config));
        }
        let (source_path, dir_iv) = self.resolve_source_path(path)?;
        let file_iv = if self.config.external_iv_chaining {
            dir_iv
        } else {
            0
        };
        let file =
            File::open(source_path).map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
        Ok(Opened::new(ReverseHandle::File { file, file_iv }))
    }

    fn read<'a>(
        &'a self,
        _path: Option<&Path>,
        handle: &'a ReverseHandle,
        offset: u64,
        size: usize,
        _caller: &Request,
    ) -> Result<Cow<'a, [u8]>, Errno> {
        let size = u32::try_from(size).unwrap_or(u32::MAX);
        match handle {
            ReverseHandle::Config => {
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                if start >= self.config_bytes.len() {
                    return Ok(Cow::Borrowed(&[]));
                }
                let end = self
                    .config_bytes
                    .len()
                    .min(start.saturating_add(size as usize));
                Ok(Cow::Borrowed(&self.config_bytes[start..end]))
            }
            ReverseHandle::File { file, file_iv } => {
                let plaintext_size = file
                    .metadata()
                    .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?
                    .len();
                let ciphertext_size = self.ciphertext_size_for_plaintext(plaintext_size)?;
                if offset >= ciphertext_size {
                    return Ok(Cow::Borrowed(&[]));
                }
                let actual_size = (size as u64).min(ciphertext_size - offset) as u32;
                Ok(Cow::Owned(self.read_encrypted(
                    file,
                    *file_iv,
                    offset,
                    actual_size,
                )?))
            }
        }
    }

    fn readlink(&self, path: &Path, _caller: &Request) -> Result<PathBuf, Errno> {
        let (source_path, dir_iv) = self.resolve_source_path(path)?;
        let target = std::fs::read_link(source_path)
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
        let (encrypted, _) = self
            .cipher
            .encrypt_filename(target.as_os_str().as_bytes(), dir_iv)
            .map_err(|_| libc::EIO)?;
        Ok(PathBuf::from(encrypted))
    }

    fn getlk(
        &self,
        _path: Option<&Path>,
        handle: &ReverseHandle,
        _owner: u64,
        lock: FileLock,
        _caller: &Request,
    ) -> Result<FileLock, Errno> {
        let ReverseHandle::File { file, .. } = handle else {
            return Err(Errno::ENOSYS);
        };
        Ok(crate::file_lock::getlk(file.as_raw_fd(), lock)?)
    }

    fn setlk(
        &self,
        _path: Option<&Path>,
        handle: &ReverseHandle,
        _owner: u64,
        lock: FileLock,
        sleep: bool,
        _caller: &Request,
    ) -> Result<(), Errno> {
        let ReverseHandle::File { file, .. } = handle else {
            return Err(Errno::ENOSYS);
        };
        Ok(crate::file_lock::setlk(file.as_raw_fd(), lock, sleep)?)
    }

    fn setattr(
        &self,
        _path: Option<&Path>,
        _handle: Option<&ReverseHandle>,
        _set: &SetAttr,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Err(Errno::EROFS)
    }

    fn write(
        &self,
        _path: Option<&Path>,
        _handle: &ReverseHandle,
        _data: &[u8],
        _offset: u64,
        _caller: &Request,
    ) -> Result<usize, Errno> {
        Err(Errno::EROFS)
    }

    fn create(
        &self,
        _parent: &Path,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        _caller: &Request,
    ) -> Result<(FileAttr, Opened<ReverseHandle>), Errno> {
        Err(Errno::EROFS)
    }

    fn mkdir(
        &self,
        _parent: &Path,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Err(Errno::EROFS)
    }
    fn mknod(
        &self,
        _parent: &Path,
        _name: &OsStr,
        _mode: u32,
        _rdev: u32,
        _umask: u32,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Err(Errno::EROFS)
    }
    fn symlink(
        &self,
        _parent: &Path,
        _name: &OsStr,
        _target: &Path,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Err(Errno::EROFS)
    }
    fn link(
        &self,
        _path: &Path,
        _new_parent: &Path,
        _new_name: &OsStr,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Err(Errno::EROFS)
    }
    fn unlink(&self, _parent: &Path, _name: &OsStr, _caller: &Request) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }
    fn rmdir(&self, _parent: &Path, _name: &OsStr, _caller: &Request) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }
    fn rename(
        &self,
        _parent: &Path,
        _name: &OsStr,
        _new_parent: &Path,
        _new_name: &OsStr,
        _caller: &Request,
    ) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }
    fn setxattr(
        &self,
        _path: &Path,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _caller: &Request,
    ) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }
    fn removexattr(&self, _path: &Path, _name: &OsStr, _caller: &Request) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }
    fn getxattr(
        &self,
        _path: &Path,
        _name: &OsStr,
        _size: usize,
        _caller: &Request,
    ) -> Result<XattrReply, Errno> {
        Err(Errno::ENODATA)
    }
    fn listxattr(
        &self,
        _path: &Path,
        _size: usize,
        _caller: &Request,
    ) -> Result<XattrReply, Errno> {
        Err(Errno::ENOSYS)
    }
}
