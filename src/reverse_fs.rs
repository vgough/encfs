use crate::config::EncfsConfig;
use crate::crypto::block::{BlockCodec, BlockLayout};
use crate::crypto::cipher::Cipher;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use libc;
use log::{debug, warn};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;
use typed_fuse::passthrough::{
    self, c_path, file_attr_from_metadata, file_type_from_metadata, statfs_path,
    synthetic_file_attr, system_time_from_secs,
};
use typed_fuse::{
    Caller as Request, DirBuffer, Errno, FileKind as FileType, NodeAttr as FileAttr, Opened,
    PathDirSink, PathFilesystem, PathPlusDirSink, SetAttr, StatFs as ReplyStatFs, TimeOrNow,
    XattrReply,
};

const CONFIG_FILE_NAME: &str = ".encfs7";

type FileKey = (u64, u64);

/// Policy used when constructing a reverse filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReverseFsOptions {
    /// Permit mutations through the encrypted view.  The default preserves the
    /// traditional reverse-mount read-only behaviour.
    pub writable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceFingerprint {
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl SourceFingerprint {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            size: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

/// A complete virtual ciphertext image.  It is deliberately an unnamed temp
/// file: staged data is ciphertext, disappears on unmount, and never creates
/// a visible entry in the plaintext source tree.
struct StagedCiphertext {
    file: File,
    size: u64,
    file_iv: u64,
    source: SourceFingerprint,
}

#[derive(Default)]
#[doc(hidden)]
pub struct ReverseFileState {
    staged: Option<StagedCiphertext>,
}

#[derive(Default)]
struct ReverseFileStates {
    entries: Mutex<HashMap<FileKey, Weak<Mutex<ReverseFileState>>>>,
}

impl ReverseFileStates {
    fn get(&self, file: &File) -> Result<Arc<Mutex<ReverseFileState>>, libc::c_int> {
        let metadata = file
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let key = (metadata.dev(), metadata.ino());
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(state) = entries.get(&key).and_then(Weak::upgrade) {
            return Ok(state);
        }
        entries.retain(|_, value| value.strong_count() > 0);
        let state = Arc::new(Mutex::new(ReverseFileState::default()));
        entries.insert(key, Arc::downgrade(&state));
        Ok(state)
    }
}

pub enum ReverseHandle {
    /// Virtual config file served from in-memory bytes.
    Config,
    /// A real plaintext source file being encrypted on the fly.
    File {
        file: File,
        file_iv: u64,
        state: Arc<Mutex<ReverseFileState>>,
        writable: bool,
    },
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
    writable: bool,
    file_states: ReverseFileStates,
}

impl ReverseFs {
    pub fn new(
        source: PathBuf,
        cipher: Box<dyn Cipher>,
        config: EncfsConfig,
        config_bytes: Vec<u8>,
        config_metadata: std::fs::Metadata,
        options: ReverseFsOptions,
    ) -> Self {
        let config_mtime =
            system_time_from_secs(config_metadata.mtime(), config_metadata.mtime_nsec());
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
            writable: options.writable,
            file_states: ReverseFileStates::default(),
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

    /// Compute the ciphertext size for a given plaintext file size.
    ///
    /// header_size = 0 because unique_iv = false.
    fn ciphertext_size_for_plaintext(&self, plaintext_size: u64) -> Result<u64, libc::c_int> {
        let layout = BlockLayout::new(
            self.config.block_mode(),
            self.config.block_size as u64,
            self.config.block_mac_bytes as u64,
        )
        .map_err(|_| libc::EINVAL)?;
        Ok(layout.physical_size_from_logical(plaintext_size, 0))
    }

    fn ensure_writable(&self) -> Result<(), libc::c_int> {
        if self.writable {
            Ok(())
        } else {
            Err(libc::EROFS)
        }
    }

    fn file_iv_for_path(&self, path: &Path) -> Result<u64, libc::c_int> {
        let (_, path_iv) = self.resolve_source_path(path)?;
        Ok(if self.config.external_iv_chaining {
            path_iv
        } else {
            0
        })
    }

    fn read_exact_at(file: &File, mut data: &mut [u8], mut offset: u64) -> io::Result<()> {
        while !data.is_empty() {
            let count = file.read_at(data, offset)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short staged read",
                ));
            }
            offset += count as u64;
            data = &mut data[count..];
        }
        Ok(())
    }

    fn write_all_at(file: &File, mut data: &[u8], mut offset: u64) -> io::Result<()> {
        while !data.is_empty() {
            let count = file.write_at(data, offset)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short staged write",
                ));
            }
            offset += count as u64;
            data = &data[count..];
        }
        Ok(())
    }

    fn materialize_ciphertext(&self, source: &File, file_iv: u64) -> Result<File, libc::c_int> {
        let source_size = source
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?
            .len();
        let ciphertext_size = self.ciphertext_size_for_plaintext(source_size)?;
        let staged = tempfile::tempfile().map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let mut offset = 0;
        while offset < ciphertext_size {
            let count = (ciphertext_size - offset).min(1024 * 1024) as u32;
            let data = self.read_encrypted(source, file_iv, offset, count)?;
            if data.is_empty() {
                return Err(libc::EIO);
            }
            Self::write_all_at(&staged, &data, offset)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            offset += data.len() as u64;
        }
        staged
            .set_len(ciphertext_size)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        Ok(staged)
    }

    fn begin_staging(
        &self,
        source: &File,
        file_iv: u64,
        state: &Arc<Mutex<ReverseFileState>>,
    ) -> Result<(), libc::c_int> {
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(staged) = &state.staged {
            return if staged.file_iv == file_iv {
                Ok(())
            } else {
                // One inode can have multiple encrypted representations when
                // external IV chaining and hard links are involved.  Do not
                // let two uncommitted representations overwrite each other.
                Err(libc::EBUSY)
            };
        }
        let metadata = source
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let staged_file = self.materialize_ciphertext(source, file_iv)?;
        let size = staged_file
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?
            .len();
        state.staged = Some(StagedCiphertext {
            file: staged_file,
            size,
            file_iv,
            source: SourceFingerprint::from_metadata(&metadata),
        });
        Ok(())
    }

    fn staged_size(&self, state: &Arc<Mutex<ReverseFileState>>, file_iv: u64) -> Option<u64> {
        let state = state.lock().unwrap_or_else(|p| p.into_inner());
        state
            .staged
            .as_ref()
            .filter(|staged| staged.file_iv == file_iv)
            .map(|staged| staged.size)
    }

    fn read_staged(
        &self,
        state: &Arc<Mutex<ReverseFileState>>,
        file_iv: u64,
        offset: u64,
        size: usize,
    ) -> Result<Option<Vec<u8>>, libc::c_int> {
        let state = state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(staged) = state
            .staged
            .as_ref()
            .filter(|staged| staged.file_iv == file_iv)
        else {
            return Ok(None);
        };
        if offset >= staged.size {
            return Ok(Some(Vec::new()));
        }
        let count = (staged.size - offset).min(size as u64) as usize;
        let mut out = vec![0; count];
        Self::read_exact_at(&staged.file, &mut out, offset)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        Ok(Some(out))
    }

    fn write_staged(
        &self,
        source: &File,
        state: &Arc<Mutex<ReverseFileState>>,
        file_iv: u64,
        data: &[u8],
        offset: u64,
    ) -> Result<(), libc::c_int> {
        self.begin_staging(source, file_iv, state)?;
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        let staged = state.staged.as_mut().ok_or(libc::EIO)?;
        Self::write_all_at(&staged.file, data, offset)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        staged.size = staged.size.max(offset.saturating_add(data.len() as u64));
        staged
            .file
            .set_len(staged.size)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        Ok(())
    }

    fn truncate_staged(
        &self,
        source: &File,
        state: &Arc<Mutex<ReverseFileState>>,
        file_iv: u64,
        size: u64,
    ) -> Result<(), libc::c_int> {
        self.begin_staging(source, file_iv, state)?;
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        let staged = state.staged.as_mut().ok_or(libc::EIO)?;
        staged
            .file
            .set_len(size)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        staged.size = size;
        Ok(())
    }

    fn refresh_staged_fingerprint(
        &self,
        source: &File,
        state: &Arc<Mutex<ReverseFileState>>,
        file_iv: u64,
    ) -> Result<(), libc::c_int> {
        let fingerprint = SourceFingerprint::from_metadata(
            &source
                .metadata()
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?,
        );
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(staged) = state
            .staged
            .as_mut()
            .filter(|staged| staged.file_iv == file_iv)
        {
            staged.source = fingerprint;
        }
        Ok(())
    }

    /// Validate the staged encrypted image before making any source mutation,
    /// then decode it a second time into the existing plaintext inode.
    fn commit_staged(
        &self,
        source: &File,
        state: &Arc<Mutex<ReverseFileState>>,
        file_iv: u64,
    ) -> Result<(), libc::c_int> {
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(staged) = state
            .staged
            .as_mut()
            .filter(|staged| staged.file_iv == file_iv)
        else {
            return Ok(());
        };

        let source_meta = source
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        if SourceFingerprint::from_metadata(&source_meta) != staged.source {
            return Err(libc::ESTALE);
        }

        let layout = BlockLayout::new(
            self.config.block_mode(),
            self.config.block_size as u64,
            self.config.block_mac_bytes as u64,
        )
        .map_err(|_| libc::EINVAL)?;
        let logical_size = layout.logical_size_from_physical(staged.size, 0);
        if layout.physical_size_from_logical(logical_size, 0) != staged.size {
            return Err(libc::EINVAL);
        }
        let codec = BlockCodec::new(self.cipher.as_ref(), layout, false, self.config.allow_holes);

        // First pass: authentication / structural validation only.
        let mut physical_offset = 0;
        let mut block_num = 0;
        while physical_offset < staged.size {
            let size = (staged.size - physical_offset).min(layout.block_size()) as usize;
            let mut encrypted = vec![0; size];
            Self::read_exact_at(&staged.file, &mut encrypted, physical_offset)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            codec
                .decrypt_block(block_num, file_iv, &mut encrypted)
                .map_err(|_| libc::EBADMSG)?;
            physical_offset += size as u64;
            block_num += 1;
        }

        source
            .set_len(logical_size)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        physical_offset = 0;
        block_num = 0;
        let mut plaintext_offset = 0;
        while physical_offset < staged.size {
            let size = (staged.size - physical_offset).min(layout.block_size()) as usize;
            let mut encrypted = vec![0; size];
            Self::read_exact_at(&staged.file, &mut encrypted, physical_offset)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            let plaintext = codec
                .decrypt_block(block_num, file_iv, &mut encrypted)
                .map_err(|_| libc::EIO)?;
            Self::write_all_at(source, &plaintext, plaintext_offset)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            physical_offset += size as u64;
            plaintext_offset += plaintext.len() as u64;
            block_num += 1;
        }
        source
            .sync_data()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        state.staged = None;
        Ok(())
    }

    fn commit_path(&self, path: &Path) -> Result<(), libc::c_int> {
        if Self::is_config_path(path) {
            return Ok(());
        }
        let (source_path, _) = self.resolve_source_path(path)?;
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        if !metadata.is_file() {
            return Ok(());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(source_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let state = self.file_states.get(&file)?;
        self.commit_staged(&file, &state, self.file_iv_for_path(path)?)
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
            let file =
                File::open(&source_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            let file_iv = self.file_iv_for_path(path)?;
            let state = self.file_states.get(&file)?;
            reported_size = self
                .staged_size(&state, file_iv)
                .unwrap_or(self.ciphertext_size_for_plaintext(reported_size)?);
        }

        Ok(file_attr_from_metadata(&metadata, reported_size))
    }

    /// Snapshot encrypted directory entries (with attributes) for a FUSE
    /// path, including `.` / `..` and the virtual root config file.
    ///
    /// The source tree's directory nesting mirrors the FUSE path nesting
    /// (reverse mode presents an encrypted view of the same tree shape), so
    /// `..`'s attributes come from `source_dir`'s real OS parent rather than
    /// re-decrypting the FUSE path.
    fn build_dir_buffer(&self, path: &Path) -> Result<DirBuffer, libc::c_int> {
        let (source_dir, dir_iv) = self.resolve_source_path(path)?;

        let read_dir =
            std::fs::read_dir(&source_dir).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let self_meta = std::fs::symlink_metadata(&source_dir)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let self_attr = file_attr_from_metadata(&self_meta, self_meta.len());

        let parent_attr = if source_dir == self.source {
            self_attr
        } else {
            let parent_dir = source_dir.parent().unwrap_or(&source_dir);
            let parent_meta = std::fs::symlink_metadata(parent_dir)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            file_attr_from_metadata(&parent_meta, parent_meta.len())
        };

        let mut result = DirBuffer::new();
        result.push_dots(self_attr, parent_attr);

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
                    let mut size = metadata.len();
                    if metadata.is_file() {
                        let entry_file = File::open(entry.path())
                            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                        let entry_iv = if self.config.external_iv_chaining {
                            let (_, entry_iv) =
                                self.resolve_source_path(&path.join(&encrypted_name))?;
                            entry_iv
                        } else {
                            0
                        };
                        let state = self.file_states.get(&entry_file)?;
                        size = self
                            .staged_size(&state, entry_iv)
                            .unwrap_or(self.ciphertext_size_for_plaintext(size)?);
                    }
                    result.push(
                        encrypted_name,
                        file_type_from_metadata(&metadata),
                        file_attr_from_metadata(&metadata, size),
                    );
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
            result.push(
                CONFIG_FILE_NAME,
                FileType::RegularFile,
                self.config_file_attr(),
            );
        }

        Ok(result)
    }

    fn decrypt_xattr_name(&self, name: &OsStr, path_iv: u64) -> Result<Vec<u8>, libc::c_int> {
        let name = name.to_str().ok_or(libc::EILSEQ)?;
        let encoded = name.strip_prefix("user.encfs.").ok_or(libc::ENODATA)?;
        let encrypted = STANDARD_NO_PAD.decode(encoded).map_err(|_| libc::ENODATA)?;
        self.cipher
            .decrypt_xattr_name(&encrypted, path_iv)
            .map_err(|_| libc::ENODATA)
    }

    fn encrypted_xattr_name(&self, name: &[u8], path_iv: u64) -> Result<String, libc::c_int> {
        let encrypted = self
            .cipher
            .encrypt_xattr_name(name, path_iv)
            .map_err(|_| libc::EIO)?;
        Ok(format!("user.encfs.{}", STANDARD_NO_PAD.encode(encrypted)))
    }
}

impl PathFilesystem for ReverseFs {
    type Handle = ReverseHandle;
    type DirHandle = DirBuffer;

    // Left to the kernel, as in the forward filesystem: a passthrough would
    // apply every client's lock in this one process (where POSIX locks cannot
    // conflict with each other), and here it would place those locks on the
    // plaintext source files rather than the ciphertext view being read.
    const SUPPORTS_POSIX_LOCKS: bool = false;
    const SUPPORTS_READDIRPLUS: bool = true;

    fn init(&self, _conn: &mut typed_fuse::ConnInfo) {
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
            ReverseHandle::File {
                file,
                file_iv,
                state,
                ..
            } => {
                let metadata = file
                    .metadata()
                    .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
                let size = self
                    .staged_size(state, *file_iv)
                    .unwrap_or(self.ciphertext_size_for_plaintext(metadata.len())?);
                Ok(file_attr_from_metadata(&metadata, size))
            }
        }
    }

    fn statfs(&self, path: &Path, _caller: &Request) -> Result<ReplyStatFs, Errno> {
        debug!("ReverseFs::statfs {:?}", path);
        statfs_path(&self.source)
    }

    fn opendir(
        &self,
        path: &Path,
        _flags: i32,
        _caller: &Request,
    ) -> Result<Opened<DirBuffer>, Errno> {
        Ok(Opened::new(self.build_dir_buffer(path)?))
    }

    fn readdir(
        &self,
        _path: &Path,
        handle: &DirBuffer,
        offset: u64,
        sink: &mut dyn PathDirSink,
        _caller: &Request,
    ) -> Result<(), Errno> {
        handle.fill(offset, sink);
        Ok(())
    }

    fn readdirplus(
        &self,
        _path: &Path,
        handle: &DirBuffer,
        offset: u64,
        sink: &mut dyn PathPlusDirSink,
        _caller: &Request,
    ) -> Result<(), Errno> {
        handle.fill_plus(offset, sink);
        Ok(())
    }

    fn open(
        &self,
        path: &Path,
        flags: i32,
        _caller: &Request,
    ) -> Result<Opened<ReverseHandle>, Errno> {
        let write_flags = libc::O_WRONLY | libc::O_RDWR | libc::O_TRUNC | libc::O_CREAT;
        if flags & write_flags != 0 && !self.writable {
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
        let mut options = OpenOptions::new();
        options.read(true);
        if flags & write_flags != 0 {
            options.write(true);
        }
        let file = options
            .open(source_path)
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
        let state = self.file_states.get(&file)?;
        if flags & libc::O_TRUNC != 0 {
            self.truncate_staged(&file, &state, file_iv, 0)?;
        }
        Ok(Opened::new(ReverseHandle::File {
            file,
            file_iv,
            state,
            writable: flags & write_flags != 0,
        }))
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
            ReverseHandle::File {
                file,
                file_iv,
                state,
                ..
            } => {
                if let Some(data) = self.read_staged(state, *file_iv, offset, size as usize)? {
                    return Ok(Cow::Owned(data));
                }
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

    #[allow(clippy::type_complexity)]
    fn setattr(
        &self,
        path: Option<&Path>,
        handle: Option<&ReverseHandle>,
        set: &SetAttr,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        self.ensure_writable()?;
        let (file, file_iv, state, source_path): (
            Option<&File>,
            Option<u64>,
            Option<&Arc<Mutex<ReverseFileState>>>,
            Option<PathBuf>,
        ) = match handle {
            Some(ReverseHandle::File {
                file,
                file_iv,
                state,
                ..
            }) => (Some(file), Some(*file_iv), Some(state), None),
            Some(ReverseHandle::Config) => return Err(Errno::EROFS),
            None => {
                let path = path.ok_or(libc::ESTALE)?;
                if Self::is_config_path(path) {
                    return Err(Errno::EROFS);
                }
                let (source, iv) = self.resolve_source_path(path)?;
                (
                    None,
                    Some(if self.config.external_iv_chaining {
                        iv
                    } else {
                        0
                    }),
                    None,
                    Some(source),
                )
            }
        };

        if let Some(size) = set.size {
            if let (Some(file), Some(iv), Some(state)) = (file, file_iv, state) {
                self.truncate_staged(file, state, iv, size)?;
            } else if let Some(source_path) = source_path.as_ref() {
                let opened = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(source_path)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                let state = self.file_states.get(&opened)?;
                self.truncate_staged(&opened, &state, file_iv.ok_or(libc::EIO)?, size)?;
            }
        }

        let target = if let Some(source) = source_path.as_ref() {
            source.clone()
        } else if let Some(path) = path {
            self.resolve_source_path(path)?.0
        } else {
            return Err(Errno::from(libc::ESTALE));
        };
        if let Some(mode) = set.mode {
            let mut permissions = fs::symlink_metadata(&target)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?
                .permissions();
            permissions.set_mode(mode);
            fs::set_permissions(&target, permissions)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        }
        if set.uid.is_some() || set.gid.is_some() {
            use std::ffi::CString;
            let path = CString::new(target.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
            let uid = set.uid.unwrap_or(u32::MAX) as libc::uid_t;
            let gid = set.gid.unwrap_or(u32::MAX) as libc::gid_t;
            if unsafe { libc::lchown(path.as_ptr(), uid, gid) } != 0 {
                return Err(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
                    .into());
            }
        }
        if set.atime.is_some() || set.mtime.is_some() {
            let resolve = |value: Option<TimeOrNow>| {
                value.map(|value| match value {
                    TimeOrNow::SpecificTime(value) => value,
                    TimeOrNow::Now => SystemTime::now(),
                })
            };
            passthrough::utimens_path(&target, resolve(set.atime), resolve(set.mtime))
                .map_err(|e| e.raw())?;
        }
        if let (Some(file), Some(iv), Some(state)) = (file, file_iv, state) {
            self.refresh_staged_fingerprint(file, state, iv)?;
        } else if let Some(source_path) = source_path.as_ref() {
            let opened = OpenOptions::new()
                .read(true)
                .write(true)
                .open(source_path)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            let state = self.file_states.get(&opened)?;
            self.refresh_staged_fingerprint(&opened, &state, file_iv.ok_or(libc::EIO)?)?;
        }
        self.attr_for_fuse_path(path.ok_or(libc::ESTALE)?)
    }

    fn write(
        &self,
        _path: Option<&Path>,
        handle: &ReverseHandle,
        data: &[u8],
        offset: u64,
        _caller: &Request,
    ) -> Result<usize, Errno> {
        self.ensure_writable()?;
        let ReverseHandle::File {
            file,
            file_iv,
            state,
            writable,
        } = handle
        else {
            return Err(Errno::EROFS);
        };
        if !writable {
            return Err(Errno::EBADF);
        }
        self.write_staged(file, state, *file_iv, data, offset)?;
        Ok(data.len())
    }

    fn flush(
        &self,
        _path: Option<&Path>,
        handle: &ReverseHandle,
        _caller: &Request,
    ) -> Result<(), Errno> {
        if let ReverseHandle::File {
            file,
            file_iv,
            state,
            writable: true,
        } = handle
        {
            self.commit_staged(file, state, *file_iv)?;
        }
        Ok(())
    }

    fn release(
        &self,
        _path: Option<&Path>,
        handle: ReverseHandle,
        _caller: &Request,
    ) -> Result<(), Errno> {
        if let ReverseHandle::File {
            file,
            file_iv,
            state,
            writable: true,
        } = handle
        {
            self.commit_staged(&file, &state, file_iv)?;
        }
        Ok(())
    }

    fn fsync(
        &self,
        _path: Option<&Path>,
        handle: &ReverseHandle,
        datasync: bool,
        _caller: &Request,
    ) -> Result<(), Errno> {
        match handle {
            ReverseHandle::Config => Ok(()),
            ReverseHandle::File {
                file,
                file_iv,
                state,
                writable: true,
            } => {
                self.commit_staged(file, state, *file_iv)?;
                if datasync {
                    file.sync_data()
                        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                } else {
                    file.sync_all()
                        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                }
                Ok(())
            }
            ReverseHandle::File { file, .. } => {
                if datasync {
                    file.sync_data()
                        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                } else {
                    file.sync_all()
                        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                }
                Ok(())
            }
        }
    }

    fn create(
        &self,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        _caller: &Request,
    ) -> Result<(FileAttr, Opened<ReverseHandle>), Errno> {
        self.ensure_writable()?;
        let path = parent.join(name);
        if Self::is_config_path(&path) {
            return Err(Errno::EROFS);
        }
        let (source_path, dir_iv) = self.resolve_source_path(&path)?;
        let file_iv = if self.config.external_iv_chaining {
            dir_iv
        } else {
            0
        };
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).mode(mode);
        if flags & libc::O_EXCL != 0 {
            options.create_new(true);
        }
        let file = options
            .open(source_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let state = self.file_states.get(&file)?;
        self.truncate_staged(&file, &state, file_iv, 0)?;
        let metadata = file
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        Ok((
            file_attr_from_metadata(&metadata, 0),
            Opened::new(ReverseHandle::File {
                file,
                file_iv,
                state,
                writable: true,
            }),
        ))
    }

    fn mkdir(
        &self,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        self.ensure_writable()?;
        let path = parent.join(name);
        if Self::is_config_path(&path) {
            return Err(Errno::EROFS);
        }
        let (source, _) = self.resolve_source_path(&path)?;
        fs::DirBuilder::new()
            .mode(mode)
            .create(&source)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        self.attr_for_fuse_path(&path)
    }
    fn mknod(
        &self,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        _rdev: u32,
        _umask: u32,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        self.ensure_writable()?;
        let path = parent.join(name);
        if Self::is_config_path(&path) {
            return Err(Errno::EROFS);
        }
        let (source, _) = self.resolve_source_path(&path)?;
        if mode & libc::S_IFMT as u32 != libc::S_IFREG as u32 {
            return Err(Errno::ENOSYS);
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(source)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        self.attr_for_fuse_path(&path)
    }
    fn symlink(
        &self,
        parent: &Path,
        name: &OsStr,
        target: &Path,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        self.ensure_writable()?;
        let path = parent.join(name);
        if Self::is_config_path(&path) {
            return Err(Errno::EROFS);
        }
        let (source, iv) = self.resolve_source_path(&path)?;
        let target = target.as_os_str().to_str().ok_or(libc::EILSEQ)?;
        let (plain_target, _) = self
            .cipher
            .decrypt_filename(target, iv)
            .map_err(|_| libc::EINVAL)?;
        std::os::unix::fs::symlink(OsString::from_vec(plain_target), source)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        self.attr_for_fuse_path(&path)
    }
    fn link(
        &self,
        path: &Path,
        new_parent: &Path,
        new_name: &OsStr,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        self.ensure_writable()?;
        if self.config.external_iv_chaining {
            return Err(Errno::EPERM);
        }
        let dest = new_parent.join(new_name);
        if Self::is_config_path(path) || Self::is_config_path(&dest) {
            return Err(Errno::EROFS);
        }
        self.commit_path(path)?;
        let (source, _) = self.resolve_source_path(path)?;
        let (destination, _) = self.resolve_source_path(&dest)?;
        fs::hard_link(source, destination).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        self.attr_for_fuse_path(&dest)
    }
    fn unlink(&self, parent: &Path, name: &OsStr, _caller: &Request) -> Result<(), Errno> {
        self.ensure_writable()?;
        let path = parent.join(name);
        if Self::is_config_path(&path) {
            return Err(Errno::EROFS);
        }
        self.commit_path(&path)?;
        let (source, _) = self.resolve_source_path(&path)?;
        fs::remove_file(source).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO).into())
    }
    fn rmdir(&self, parent: &Path, name: &OsStr, _caller: &Request) -> Result<(), Errno> {
        self.ensure_writable()?;
        let path = parent.join(name);
        if Self::is_config_path(&path) {
            return Err(Errno::EROFS);
        }
        let (source, _) = self.resolve_source_path(&path)?;
        fs::remove_dir(source).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO).into())
    }
    fn rename(
        &self,
        parent: &Path,
        name: &OsStr,
        new_parent: &Path,
        new_name: &OsStr,
        _caller: &Request,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        let source = parent.join(name);
        let destination = new_parent.join(new_name);
        if Self::is_config_path(&source) || Self::is_config_path(&destination) {
            return Err(Errno::EROFS);
        }
        self.commit_path(&source)?;
        let (source_path, _) = self.resolve_source_path(&source)?;
        let (destination_path, _) = self.resolve_source_path(&destination)?;
        fs::rename(source_path, destination_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO).into())
    }
    fn setxattr(
        &self,
        path: &Path,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        _caller: &Request,
    ) -> Result<(), Errno> {
        self.ensure_writable()?;
        if Self::is_config_path(path) {
            return Err(Errno::EROFS);
        }
        let (source, path_iv) = self.resolve_source_path(path)?;
        let plain_name = self.decrypt_xattr_name(name, path_iv)?;
        let plain_value = self
            .cipher
            .decrypt_xattr_value(value, path_iv)
            .map_err(|_| libc::EINVAL)?;
        let c_path = c_path(&source).map_err(|e| e.raw())?;
        let c_name = std::ffi::CString::new(plain_name).map_err(|_| libc::EINVAL)?;
        passthrough::setxattr_nofollow(&c_path, &c_name, &plain_value, flags)
            .map_err(|e| e.raw())?;
        Ok(())
    }
    fn removexattr(&self, path: &Path, name: &OsStr, _caller: &Request) -> Result<(), Errno> {
        self.ensure_writable()?;
        if Self::is_config_path(path) {
            return Err(Errno::EROFS);
        }
        let (source, path_iv) = self.resolve_source_path(path)?;
        let plain_name = self.decrypt_xattr_name(name, path_iv)?;
        let c_path = c_path(&source).map_err(|e| e.raw())?;
        let c_name = std::ffi::CString::new(plain_name).map_err(|_| libc::EINVAL)?;
        passthrough::removexattr_nofollow(&c_path, &c_name).map_err(|e| e.raw())?;
        Ok(())
    }
    fn getxattr(
        &self,
        path: &Path,
        name: &OsStr,
        size: usize,
        _caller: &Request,
    ) -> Result<XattrReply, Errno> {
        if Self::is_config_path(path) {
            return Err(Errno::ENODATA);
        }
        let (source, path_iv) = self.resolve_source_path(path)?;
        let plain_name = self.decrypt_xattr_name(name, path_iv)?;
        let c_path = c_path(&source).map_err(|e| e.raw())?;
        let c_name = std::ffi::CString::new(plain_name).map_err(|_| libc::EINVAL)?;
        let plain_value =
            passthrough::getxattr_value_nofollow(&c_path, &c_name).map_err(|e| e.raw())?;
        let encrypted = self
            .cipher
            .encrypt_xattr_value(&plain_value, path_iv)
            .map_err(|_| libc::EIO)?;
        XattrReply::sized(encrypted, size)
    }
    fn listxattr(&self, path: &Path, size: usize, _caller: &Request) -> Result<XattrReply, Errno> {
        if Self::is_config_path(path) {
            return XattrReply::sized(Vec::new(), size);
        }
        let (source, path_iv) = self.resolve_source_path(path)?;
        let c_path = c_path(&source).map_err(|e| e.raw())?;
        let mut output = Vec::new();
        for name in passthrough::listxattr_names_nofollow(&c_path).map_err(|e| e.raw())? {
            if std::str::from_utf8(&name).is_err() || name.starts_with(b"com.apple.") {
                continue;
            }
            let encrypted = self.encrypted_xattr_name(&name, path_iv)?;
            output.extend_from_slice(encrypted.as_bytes());
            output.push(0);
        }
        XattrReply::sized(output, size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EncfsConfig;

    fn reverse_fs(root: &Path) -> ReverseFs {
        let config_path = root.join(".encfs7");
        let mut config = EncfsConfig::standard_v7();
        config.unique_iv = false;
        config.argon2_memory_cost = Some(8);
        config.argon2_time_cost = Some(1);
        config.argon2_parallelism = Some(1);
        config.set_v7_key("test-password", &[0; 48]).unwrap();
        config.save(&config_path).unwrap();
        let bytes = fs::read(&config_path).unwrap();
        let metadata = fs::metadata(&config_path).unwrap();
        let cipher = config.get_cipher("test-password").unwrap();
        ReverseFs::new(
            root.to_path_buf(),
            cipher,
            config,
            bytes,
            metadata,
            ReverseFsOptions { writable: true },
        )
    }

    fn encrypted_image(reverse: &ReverseFs, root: &Path, contents: &[u8]) -> File {
        let candidate = root.join("candidate");
        fs::write(&candidate, contents).unwrap();
        let file = File::open(candidate).unwrap();
        reverse.materialize_ciphertext(&file, 0).unwrap()
    }

    #[test]
    fn staged_aead_write_commits_only_after_validation() {
        let dir = tempfile::tempdir().unwrap();
        let reverse = reverse_fs(dir.path());
        let source_path = dir.path().join("source");
        fs::write(&source_path, b"old plaintext").unwrap();
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source_path)
            .unwrap();
        let state = reverse.file_states.get(&source).unwrap();
        let replacement = encrypted_image(&reverse, dir.path(), b"new authenticated plaintext");
        let size = replacement.metadata().unwrap().len();
        let mut bytes = vec![0; size as usize];
        ReverseFs::read_exact_at(&replacement, &mut bytes, 0).unwrap();

        reverse.write_staged(&source, &state, 0, &bytes, 0).unwrap();
        assert_eq!(fs::read(&source_path).unwrap(), b"old plaintext");
        reverse.commit_staged(&source, &state, 0).unwrap();
        assert_eq!(
            fs::read(&source_path).unwrap(),
            b"new authenticated plaintext"
        );
    }

    #[test]
    fn invalid_staged_aead_write_preserves_source() {
        let dir = tempfile::tempdir().unwrap();
        let reverse = reverse_fs(dir.path());
        let source_path = dir.path().join("source");
        fs::write(&source_path, b"unchanged").unwrap();
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source_path)
            .unwrap();
        let state = reverse.file_states.get(&source).unwrap();

        reverse.begin_staging(&source, 0, &state).unwrap();
        let original = reverse.read_staged(&state, 0, 0, 1).unwrap().unwrap()[0];
        reverse
            .write_staged(&source, &state, 0, &[original ^ 0xff], 0)
            .unwrap();
        assert_eq!(
            reverse.commit_staged(&source, &state, 0),
            Err(libc::EBADMSG)
        );
        assert_eq!(fs::read(&source_path).unwrap(), b"unchanged");
    }

    #[test]
    fn staged_write_detects_direct_source_change() {
        let dir = tempfile::tempdir().unwrap();
        let reverse = reverse_fs(dir.path());
        let source_path = dir.path().join("source");
        fs::write(&source_path, b"before").unwrap();
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source_path)
            .unwrap();
        let state = reverse.file_states.get(&source).unwrap();
        reverse.write_staged(&source, &state, 0, &[0], 0).unwrap();
        fs::write(&source_path, b"external change").unwrap();

        assert_eq!(reverse.commit_staged(&source, &state, 0), Err(libc::ESTALE));
        assert_eq!(fs::read(&source_path).unwrap(), b"external change");
    }
}
