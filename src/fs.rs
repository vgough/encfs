use crate::crypto::block::BlockLayout;
use crate::crypto::cipher::Cipher;
use crate::crypto::file::{FileDecoder, FileEncoder};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use typed_fuse::passthrough::{
    self, access_check, c_path, file_attr_from_metadata, file_type_from_metadata, is_apple_xattr,
    set_ownership_fd, set_ownership_path, statfs_path, symlink as passthrough_symlink,
    utimens_permission_check,
};
use typed_fuse::{
    Caller as Request, DirBuffer, Errno, NodeAttr as FileAttr, Opened, PathDirSink, PathFilesystem,
    PathPlusDirSink, SetAttr, StatFs as ReplyStatFs, TimeOrNow, XattrReply as ReplyXAttr,
};
use libc;
use log::{debug, error, warn};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak};
use std::time::SystemTime;

/// Errors from internal helpers are raw errno values; trait methods convert
/// them to typed FUSE errors via `?`.
type OpResult = Result<(), libc::c_int>;

/// Key identifying a backing file.
///
/// Two `FileHandle`s referring to the same on-disk file (same device + inode)
/// share one [`FileState`], even when opened through different plaintext paths.
type FileKey = (u64, u64); // (st_dev, st_ino)

/// Mutable per-file state, guarded by [`FileState::meta`].
#[derive(Debug, Default, Clone, Copy)]
struct FileMeta {
    /// IV read from (or written to) the file header, shared by every handle on
    /// the inode. `None` for headerless configurations (`header_size == 0`),
    /// where the IV is derived from the path instead and lives on the handle;
    /// see [`FileHandle::headerless_iv`].
    header_iv: Option<u64>,
}

/// State shared by every handle on one backing inode.
///
/// The lock serializes two things that are not atomic at the syscall level:
///
/// * A partial-block write in [`crate::crypto::file::FileEncoder`] is a
///   read-decrypt-modify-encrypt-write sequence spanning two syscalls, and a
///   truncate is a read/set_len/re-encrypt sequence. Without serialization two
///   writers to the same block lose each other's updates, and a truncate
///   racing a write resurrects stale data or breaks a block's MAC.
/// * The per-file IV. Opening with `O_TRUNC` (and `create`) resets the file and
///   installs a header carrying a *newly generated* IV. Since the IV lives here
///   rather than on each handle, handles opened earlier pick up the new one at
///   the same instant the contents are reset; otherwise they would keep
///   encrypting blocks under an IV the header no longer names, and nothing
///   could ever decrypt them again.
#[derive(Debug)]
struct FileState {
    key: FileKey,
    meta: RwLock<FileMeta>,
}

impl FileState {
    fn new(key: FileKey) -> Self {
        Self {
            key,
            meta: RwLock::new(FileMeta::default()),
        }
    }

    /// Shared access, for operations that only read the file.
    ///
    /// Lock poisoning is recovered from rather than propagated: a writer that
    /// panicked mid-RMW may have left the *file* inconsistent, but that is not
    /// improved by failing every later operation on the mount, and [`FileMeta`]
    /// itself is plain `Copy` data that cannot be torn.
    fn read(&self) -> RwLockReadGuard<'_, FileMeta> {
        self.meta.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Exclusive access, required for any read-modify-write, truncate, or
    /// header rewrite. See [`FileState::read`] on poisoning.
    fn write(&self) -> RwLockWriteGuard<'_, FileMeta> {
        self.meta.write().unwrap_or_else(|p| p.into_inner())
    }
}

/// Smallest table size worth sweeping for dead entries.
const FILE_STATE_SWEEP_FLOOR: usize = 64;

/// Table of live [`FileState`]s, keyed by backing device + inode.
///
/// Entries are weak, so the state disappears once the last handle (or transient
/// operation) drops its `Arc`; dead entries are swept out on insert. A
/// long-lived mount therefore does not accumulate one entry per file it has
/// ever touched.
#[derive(Default)]
struct FileStates {
    table: Mutex<FileStateTable>,
}

#[derive(Default)]
struct FileStateTable {
    entries: HashMap<FileKey, Weak<FileState>>,
    /// Sweep once `entries` grows past this, then reset it to twice the
    /// surviving size. Sweeping is thus amortized O(1) per insert and the table
    /// stays within twice the live set (plus [`FILE_STATE_SWEEP_FLOOR`]).
    sweep_at: usize,
}

impl FileStates {
    /// Returns the shared state for `file`, creating it if this is the first
    /// live reference to that inode.
    ///
    /// Failing to stat an already-open fd is reported rather than papered over:
    /// a fallback key would silently stop two handles on the same inode from
    /// serializing, which is exactly the bug this table exists to prevent.
    fn get(&self, file: &File) -> Result<Arc<FileState>, libc::c_int> {
        let metadata = file.metadata().map_err(|e| {
            error!("stat of open backing file failed: {}", e);
            e.raw_os_error().unwrap_or(libc::EIO)
        })?;
        Ok(self.get_by_key((metadata.dev(), metadata.ino())))
    }

    fn get_by_key(&self, key: FileKey) -> Arc<FileState> {
        let mut table = self.table.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = table.entries.get(&key).and_then(Weak::upgrade) {
            return existing;
        }

        if table.entries.len() >= table.sweep_at.max(FILE_STATE_SWEEP_FLOOR) {
            table.entries.retain(|_, state| state.strong_count() > 0);
            table.sweep_at = table.entries.len().saturating_mul(2);
        }

        let state = Arc::new(FileState::new(key));
        table.entries.insert(key, Arc::downgrade(&state));
        state
    }
}

/// Takes the write lock on both ends of a copy.
///
/// Locks in ascending key order, so a copy running the other way over the same
/// pair (a rename back) cannot deadlock against this one. When both names
/// resolve to the same inode there is only one lock to take and the returned
/// source guard is `None` — the destination guard covers both.
fn lock_source_and_dest<'a>(
    src: &'a FileState,
    dest: &'a FileState,
) -> (
    Option<RwLockWriteGuard<'a, FileMeta>>,
    RwLockWriteGuard<'a, FileMeta>,
) {
    match src.key.cmp(&dest.key) {
        std::cmp::Ordering::Equal => (None, dest.write()),
        std::cmp::Ordering::Less => {
            let src_guard = src.write();
            let dest_guard = dest.write();
            (Some(src_guard), dest_guard)
        }
        std::cmp::Ordering::Greater => {
            let dest_guard = dest.write();
            let src_guard = src.write();
            (Some(src_guard), dest_guard)
        }
    }
}

pub struct FileHandle {
    file: File,
    /// IV for headerless configurations, derived from the path at open time.
    /// Truncation cannot change it, so unlike the header IV it is safe to cache
    /// per handle. Zero (and unused) when the config stores a per-file header.
    headerless_iv: u64,
    /// Shared state for the backing inode; guards every RMW on this file.
    state: Arc<FileState>,
}

impl FileHandle {
    /// The IV this file's blocks are encrypted under, as of `meta`.
    fn file_iv(&self, meta: &FileMeta) -> u64 {
        meta.header_iv.unwrap_or(self.headerless_iv)
    }
}

struct PathInfo<'a> {
    logical: &'a Path,
    physical: &'a Path,
    iv: u64,
}

/// The main FUSE filesystem implementation.
///
/// Handles mapping of FUSE operations to the underlying encrypted directory.
/// Stores file handles and the cipher instance.
pub struct EncFs {
    pub root: PathBuf,
    pub cipher: Box<dyn Cipher>,
    pub config: crate::config::EncfsConfig,
    /// Reject all mutating operations with EROFS. Enforced at the filesystem
    /// layer as well as at mount level as defense in depth.
    read_only: bool,
    /// Per-backing-inode state serializing read-modify-write I/O.
    file_states: FileStates,
}

impl EncFs {
    pub fn new(root: PathBuf, cipher: Box<dyn Cipher>, config: crate::config::EncfsConfig) -> Self {
        Self {
            root,
            cipher,
            config,
            read_only: false,
            file_states: FileStates::default(),
        }
    }

    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    fn ensure_writable(&self) -> OpResult {
        if self.read_only {
            Err(libc::EROFS)
        } else {
            Ok(())
        }
    }

    /// Encrypts a plaintext path (from FUSE request) to an encrypted path (on disk).
    ///
    /// This walks the path component by component, encrypting each filename.
    /// If IV chaining is enabled (standard), the IV of a directory is derived from
    /// its parent's IV and its encrypted filename.
    /// Returns the full encrypted path and the IV of the final directory.
    fn encrypt_path(&self, path: &Path) -> Result<(PathBuf, u64), libc::c_int> {
        let mut encrypted_path = PathBuf::new();
        let mut iv = 0u64;
        for component in path.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::CurDir => {}
                std::path::Component::Normal(name) => {
                    let name_bytes = name.as_bytes();
                    let (encrypted_name, new_iv) =
                        self.cipher.encrypt_filename(name_bytes, iv).map_err(|e| {
                            error!("Encrypt filename failed: {}", e);
                            libc::EIO
                        })?;
                    encrypted_path.push(encrypted_name);
                    if self.config.chained_name_iv {
                        iv = new_iv;
                    }
                }
                _ => return Err(libc::EINVAL),
            }
        }
        Ok((self.root.join(encrypted_path), iv))
    }

    /// Decrypts a full path from the encrypted root.
    /// Used primarily for testing/verification and potential future features
    /// (e.g. reverse mode or tools), as the FUSE filesystem mostly maps
    /// plaintext requests to encrypted paths via `encrypt_path`.
    pub fn decrypt_path(&self, encrypted_path: &Path) -> Result<(PathBuf, u64), libc::c_int> {
        let mut decrypted_path = PathBuf::new();
        let mut iv = 0u64;
        for component in encrypted_path.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => {
                    let name_str = name.to_str().ok_or(libc::EILSEQ)?;
                    let (decrypted_name_bytes, new_iv) =
                        self.cipher.decrypt_filename(name_str, iv).map_err(|e| {
                            error!("Failed to decrypt filename {}: {}", name_str, e);
                            libc::EIO
                        })?;
                    decrypted_path.push(OsStr::from_bytes(&decrypted_name_bytes));
                    if self.config.chained_name_iv {
                        iv = new_iv;
                    }
                }
                _ => return Err(libc::EINVAL),
            }
        }
        Ok((decrypted_path, iv))
    }

    fn rename_internal(
        &self,
        parent: &Path,
        name: &OsStr,
        newparent: &Path,
        newname: &OsStr,
    ) -> OpResult {
        debug!(
            "rename: {:?}/{:?} -> {:?}/{:?}",
            parent, name, newparent, newname
        );
        self.ensure_writable()?;
        let source = parent.join(name);
        let dest = newparent.join(newname);

        let (real_source, _) = self.encrypt_path(&source)?;
        let (real_dest, _) = self.encrypt_path(&dest)?;

        let meta = fs::symlink_metadata(&real_source)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        if (meta.is_dir() && (self.config.chained_name_iv || self.config.external_iv_chaining))
            || (meta.is_file() && self.config.external_iv_chaining)
        {
            let (_, source_iv) = self.encrypt_path(&source)?;
            let (_, dest_iv) = self.encrypt_path(&dest)?;

            if let Err(e) = self.copy_recursive(
                PathInfo {
                    logical: &source,
                    physical: &real_source,
                    iv: source_iv,
                },
                PathInfo {
                    logical: &dest,
                    physical: &real_dest,
                    iv: dest_iv,
                },
                &meta,
            ) {
                // Best-effort cleanup on failure
                if meta.is_dir() {
                    let _ = fs::remove_dir_all(real_dest);
                } else {
                    let _ = fs::remove_file(real_dest);
                }
                return Err(e);
            }

            if meta.is_dir() {
                return fs::remove_dir_all(real_source)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO));
            } else {
                return fs::remove_file(real_source)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO));
            }
        }

        // Symlink targets are encrypted using a path-derived IV (see `symlink`/`readlink`).
        // If the symlink name changes while `chained_name_iv` is enabled, the IV used to
        // decrypt/encrypt the symlink target changes. A plain `rename` would therefore
        // break `readlink`. Rewrite the symlink target under the destination IV.
        if meta.is_symlink() {
            if self.config.external_iv_chaining {
                warn!("Renaming symlinks with external IV chaining is not supported");
                return Err(libc::ENOSYS);
            }

            if self.config.chained_name_iv {
                let (_, source_iv) = self.encrypt_path(&source)?;
                let (_, dest_iv) = self.encrypt_path(&dest)?;

                let target = fs::read_link(&real_source)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                let target_str = target.to_str().ok_or(libc::EILSEQ)?;

                let (plain_target, _) = self
                    .cipher
                    .decrypt_filename(target_str, source_iv)
                    .map_err(|e| {
                        error!("Failed to decrypt symlink target during rename: {}", e);
                        libc::EIO
                    })?;

                let (enc_target, _) = self
                    .cipher
                    .encrypt_filename(&plain_target, dest_iv)
                    .map_err(|e| {
                        error!("Failed to encrypt symlink target during rename: {}", e);
                        libc::EIO
                    })?;

                // Best-effort remove existing destination (rename(2) would replace).
                match fs::remove_file(&real_dest) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.raw_os_error().unwrap_or(libc::EIO)),
                }

                passthrough_symlink(OsStr::new(&enc_target), &real_dest).map_err(|e| e.raw())?;

                // Remove source symlink.
                fs::remove_file(&real_source).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

                return Ok(());
            }
        }

        fs::rename(real_source, real_dest).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
    }

    fn copy_recursive(
        &self,
        source: PathInfo,
        dest: PathInfo,
        meta: &std::fs::Metadata,
    ) -> OpResult {
        if meta.is_dir() {
            // Create dest dir
            if let Err(e) = fs::create_dir(dest.physical) {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    // Check empty
                    let mut iter = fs::read_dir(dest.physical)
                        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                    if iter.next().is_some() {
                        return Err(libc::ENOTEMPTY);
                    }
                } else {
                    return Err(e.raw_os_error().unwrap_or(libc::EIO));
                }
            }

            // Iterate children
            // source_iv is the IV of the directory 'source', used for decrypting children
            let entries =
                fs::read_dir(source.physical).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            for entry in entries {
                let entry = entry.map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                let fname = entry.file_name();
                let fname_bytes = fname.as_bytes();

                if fname_bytes == b"." || fname_bytes == b".." || fname_bytes.starts_with(b".") {
                    continue;
                }

                // fname is the ENCRYPTED filename (string usually, but treating as str for legacy reasons mostly)
                // Encrypted filenames ARE strings (base64 subset), so to_str() is generally safe for THEM.
                let fname_utf8 = match fname.to_str() {
                    Some(s) => s,
                    None => {
                        error!("Skipping invalid filename in recursive copy: {:?}", fname);
                        continue;
                    }
                };

                let (plain_name_bytes, _) =
                    match self.cipher.decrypt_filename(fname_utf8, source.iv) {
                        Ok(res) => res,
                        Err(e) => {
                            warn!("Skipping undecryptable child {:?}: {}", fname, e);
                            continue;
                        }
                    };

                let child_name = OsStr::from_bytes(&plain_name_bytes);
                let child_source = source.logical.join(child_name);
                let child_dest = dest.logical.join(child_name);

                let (child_real_source, child_source_iv) = self.encrypt_path(&child_source)?;
                let (child_real_dest, child_dest_iv) = self.encrypt_path(&child_dest)?;

                let child_meta = fs::symlink_metadata(&child_real_source)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

                self.copy_recursive(
                    PathInfo {
                        logical: &child_source,
                        physical: &child_real_source,
                        iv: child_source_iv,
                    },
                    PathInfo {
                        logical: &child_dest,
                        physical: &child_real_dest,
                        iv: child_dest_iv,
                    },
                    &child_meta,
                )?;
            }
        } else if self.config.external_iv_chaining && meta.is_file() {
            self.copy_file_with_header_rewrite(source.physical, dest.physical, source.iv, dest.iv)?;
        } else if meta.is_symlink() {
            // Handle symlinks during recursive directory copies.
            // When chained_name_iv is enabled, symlink targets are encrypted using
            // the path IV of the symlink. If the symlink's path changes (due to parent
            // directory rename), we need to re-encrypt the target with the new IV.
            if self.config.external_iv_chaining {
                // External IV chaining for symlinks is not supported
                return Err(libc::ENOSYS);
            }

            if self.config.chained_name_iv {
                // Re-encrypt symlink target with the new path IV
                let target = fs::read_link(source.physical)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                let target_str = target.to_str().ok_or(libc::EILSEQ)?;

                let (plain_target, _) = self
                    .cipher
                    .decrypt_filename(target_str, source.iv)
                    .map_err(|e| {
                        error!(
                            "Failed to decrypt symlink target during recursive copy: {}",
                            e
                        );
                        libc::EIO
                    })?;

                let (enc_target, _) = self
                    .cipher
                    .encrypt_filename(&plain_target, dest.iv)
                    .map_err(|e| {
                        error!(
                            "Failed to encrypt symlink target during recursive copy: {}",
                            e
                        );
                        libc::EIO
                    })?;

                // Remove existing destination if present
                match fs::remove_file(dest.physical) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.raw_os_error().unwrap_or(libc::EIO)),
                }

                passthrough_symlink(OsStr::new(&enc_target), dest.physical).map_err(|e| e.raw())?;
            } else {
                // No IV chaining - just copy the symlink as-is
                let target = fs::read_link(source.physical)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                passthrough_symlink(target.as_os_str(), dest.physical).map_err(|e| e.raw())?;
            }
        } else {
            // Standard copy for regular files without external IV chaining
            fs::copy(source.physical, dest.physical)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            // Best effort metadata copy
            let _ = fs::set_permissions(dest.physical, meta.permissions());
        }
        Ok(())
    }

    fn copy_file_with_header_rewrite(
        &self,
        real_src: &Path,
        real_dest: &Path,
        src_iv: u64,
        dst_iv: u64,
    ) -> OpResult {
        // 1. Open both ends. The destination is opened without O_TRUNC so that,
        //    as in `open_impl`, it is reset under the lock rather than by
        //    open(2) — otherwise the reset lands on top of an in-flight
        //    read-modify-write by whoever already has it open.
        let mut src_f = File::open(real_src).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let mut dst_f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(real_dest)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        // Serialize against concurrent writes at both ends: a write landing
        // mid-copy on the source would produce a torn destination block, and a
        // write to the destination would be silently overwritten by the body
        // copy.
        let src_state = self.file_states.get(&src_f)?;
        let dst_state = self.file_states.get(&dst_f)?;
        let (_src_guard, mut dst_meta) = lock_source_and_dest(&src_state, &dst_state);

        let metadata = src_f.metadata().ok();

        let header_size = self.config.header_size();
        let mut header = vec![0u8; header_size as usize];
        if header_size > 0 {
            // 2. Read and decrypt the source header. Done before touching the
            //    destination so a source we can't decrypt leaves it intact.
            src_f
                .read_exact(&mut header)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            let file_iv = self
                .cipher
                .decrypt_header(&mut header, src_iv)
                .map_err(|_| libc::EIO)?;

            // 3. Re-encrypt the header under the destination's path IV. The
            //    file IV itself carries over, so anyone holding the destination
            //    open switches to the copied file's IV here.
            let new_header = self
                .cipher
                .encrypt_header_with_iv(file_iv, dst_iv)
                .map_err(|_| libc::EIO)?;

            // 4. Reset the destination, now that it is locked, and refill it.
            dst_f
                .set_len(0)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            dst_meta.header_iv = Some(file_iv);

            dst_f
                .write_all(&new_header)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            let mut reader = BufReader::new(src_f);
            let mut writer = BufWriter::new(dst_f);

            std::io::copy(&mut reader, &mut writer)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            writer
                .flush()
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        } else {
            // No header to rewrite: the IV is path-derived, so handles already
            // open on the destination keep using their own.
            dst_f
                .set_len(0)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            dst_meta.header_iv = None;

            let mut reader = BufReader::new(src_f);
            let mut writer = BufWriter::new(dst_f);

            std::io::copy(&mut reader, &mut writer)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            writer
                .flush()
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        }

        // 8. Copy permissions
        if let Some(meta) = metadata {
            let _ = fs::set_permissions(real_dest, meta.permissions());
        }

        Ok(())
    }
}

fn headerless_file_iv(header_size: u64, external_iv: u64) -> u64 {
    if header_size == 0 { external_iv } else { 0 }
}

impl EncFs {
    /// Generates a fresh per-file IV and writes its header at offset 0.
    ///
    /// Callers must hold the file's write lock: this replaces the IV every
    /// existing handle on the inode encrypts under.
    fn write_file_header(&self, file: &File, external_iv: u64) -> Result<u64, libc::c_int> {
        let (header, file_iv) = self.cipher.encrypt_header(external_iv).map_err(|e| {
            error!("Failed to generate header: {}", e);
            libc::EIO
        })?;
        file.write_all_at(&header, 0)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        Ok(file_iv)
    }

    /// Reads and decrypts the per-file header, returning `None` when the file
    /// is too short to hold one (e.g. freshly created via `mknod`).
    fn read_file_header(
        &self,
        file: &File,
        path: &Path,
        external_iv: u64,
    ) -> Result<Option<u64>, libc::c_int> {
        let header_size = self.config.header_size() as usize;
        let mut header = vec![0u8; header_size];
        let bytes_read = file
            .read_at(&mut header, 0)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        if bytes_read != header_size {
            return Ok(None);
        }
        match self.cipher.decrypt_header(&mut header, external_iv) {
            Ok(file_iv) => Ok(Some(file_iv)),
            Err(_) => {
                warn!("Failed to decrypt file header for {:?}", path);
                Err(libc::EIO)
            }
        }
    }

    fn physical_size_for_logical(&self, logical_size: u64, header_size: u64) -> u64 {
        FileEncoder::<File>::calculate_physical_size_with_mode(
            logical_size,
            header_size,
            self.config.block_size as u64,
            self.config.block_mac_bytes as u64,
            self.config.block_mode(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn truncate_expand(
        &self,
        file_ref: &File,
        _guard: &RwLockWriteGuard<'_, FileMeta>,
        file_iv: u64,
        header_size: u64,
        current_logical_size: u64,
        new_logical_size: u64,
        block_layout: BlockLayout,
    ) -> OpResult {
        if new_logical_size <= current_logical_size {
            return Ok(());
        }

        let encoder = FileEncoder::new_from_config(
            self.cipher.as_ref(),
            file_ref,
            file_iv,
            &self.config.file_codec_params(),
        );

        let data_block_size = block_layout.data_size_per_block();
        let mut filled_until = current_logical_size;
        let tail_in_block = current_logical_size % data_block_size;
        if tail_in_block > 0 {
            let to_block_end = data_block_size - tail_in_block;
            let top_up = std::cmp::min(to_block_end, new_logical_size - current_logical_size);
            if top_up > 0 {
                let zeros = vec![0u8; top_up as usize];
                encoder
                    .write_at(&zeros, current_logical_size)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                filled_until += top_up;
            }
        }

        if filled_until >= new_logical_size {
            return Ok(());
        }

        if self.config.allow_holes {
            let physical_size = self.physical_size_for_logical(new_logical_size, header_size);
            file_ref
                .set_len(physical_size)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            return Ok(());
        }

        // Holes are not allowed, so write a bunch of zeros.
        const CHUNK_SIZE: usize = 128 * 1024;
        let mut remaining = new_logical_size - filled_until;
        let mut offset = filled_until;
        let zeros = vec![0u8; CHUNK_SIZE];

        while remaining > 0 {
            let write_len = std::cmp::min(remaining, CHUNK_SIZE as u64);
            encoder
                .write_at(&zeros[..write_len as usize], offset)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            remaining -= write_len;
            offset += write_len;
        }

        Ok(())
    }

    fn truncate_shrink(
        &self,
        file_ref: &File,
        _guard: &RwLockWriteGuard<'_, FileMeta>,
        file_iv: u64,
        header_size: u64,
        new_logical_size: u64,
        block_layout: BlockLayout,
    ) -> OpResult {
        let physical_size = self.physical_size_for_logical(new_logical_size, header_size);
        let data_block_size = block_layout.data_size_per_block();
        let offset_in_block = new_logical_size % data_block_size;

        if offset_in_block == 0 {
            file_ref
                .set_len(physical_size)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            return Ok(());
        }

        let block_start = new_logical_size - offset_in_block;
        let decoder = FileDecoder::new_from_config(
            self.cipher.as_ref(),
            file_ref,
            file_iv,
            &self.config.file_codec_params(),
            false,
        );

        let mut buf = vec![0u8; data_block_size as usize];
        let bytes_read = decoder
            .read_at(&mut buf, block_start)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        if (bytes_read as u64) < offset_in_block {
            return Err(libc::EIO);
        }
        buf.truncate(offset_in_block as usize);

        // Shrink first so re-encryption writes exactly the target last block.
        file_ref
            .set_len(physical_size)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let encoder = FileEncoder::new_from_config(
            self.cipher.as_ref(),
            file_ref,
            file_iv,
            &self.config.file_codec_params(),
        );
        encoder
            .write_at(&buf, block_start)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        Ok(())
    }
}

/// Errno-based operation bodies shared by the `PathFilesystem` impl below.
impl EncFs {
    fn statfs_impl(&self, path: &Path) -> Result<ReplyStatFs, libc::c_int> {
        debug!("statfs: {:?}", path);
        // Check underlying filesystem of the root
        let mut stat = statfs_path(&self.root).map_err(|e| e.raw())?;
        stat.namelen = self.cipher.max_plaintext_name_len(stat.namelen);
        Ok(stat)
    }

    fn do_chmod(&self, path: Option<&Path>, handle: Option<&FileHandle>, mode: u32) -> OpResult {
        debug!("chmod: {:?} mode={:o}", path, mode);
        self.ensure_writable()?;

        if let Some(path) = path {
            let (real_path, _) = self.encrypt_path(path)?;
            return passthrough::chmod_path(&real_path, mode).map_err(|e| e.raw());
        }

        // Path unknown (possibly deleted): fall back to the open handle.
        let handle = handle.ok_or(libc::ESTALE)?;
        passthrough::chmod_fd(handle.file.as_raw_fd(), mode).map_err(|e| e.raw())
    }

    fn do_chown(
        &self,
        path: Option<&Path>,
        handle: Option<&FileHandle>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> OpResult {
        debug!("chown: {:?} uid={:?} gid={:?}", path, uid, gid);
        self.ensure_writable()?;

        let path = match path {
            Some(path) => path,
            None => {
                let handle = handle.ok_or(libc::ESTALE)?;
                return passthrough::chown_fd(handle.file.as_raw_fd(), uid, gid)
                    .map_err(|e| e.raw());
            }
        };

        let (real_path, _) = self.encrypt_path(path)?;
        passthrough::chown_path(&real_path, uid, gid).map_err(|e| e.raw())
    }

    /// Check if the requesting process has the requested access to the path.
    ///
    /// Only the primary gid is considered (no supplementary groups).
    fn access_impl(&self, req: Request, path: &Path, mask: u32) -> OpResult {
        debug!(
            "access: {:?} mask={:#o} uid={} gid={}",
            path, mask, req.uid, req.gid
        );

        let (real_path, _) = self.encrypt_path(path)?;
        let metadata =
            fs::symlink_metadata(&real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        access_check(&req, metadata.uid(), metadata.gid(), metadata.mode(), mask)
            .map_err(|e| e.raw())
    }

    fn do_truncate(&self, path: Option<&Path>, handle: Option<&FileHandle>, size: u64) -> OpResult {
        debug!("truncate: {:?} size={}", path, size);
        self.ensure_writable()?;

        let owned_file: Option<File> = if handle.is_none() {
            let path = path.ok_or(libc::ESTALE)?;
            let (real_path, _) = self.encrypt_path(path)?;
            Some(
                fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(real_path)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?,
            )
        } else {
            None
        };

        let file_ref: &File = match (handle, &owned_file) {
            (Some(h), _) => &h.file,
            (None, Some(f)) => f,
            (None, None) => return Err(libc::EIO),
        };

        // Hold the per-file write lock across the whole read-length / RMW /
        // set_len sequence so a concurrent write can't interleave and lose
        // data or resurrect truncated blocks.
        let state = match handle {
            Some(h) => h.state.clone(),
            None => self.file_states.get(file_ref)?,
        };
        let mut guard = state.write();

        let header_size = self.config.header_size();
        let metadata = file_ref
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let block_layout = BlockLayout::new(
            self.config.block_mode(),
            self.config.block_size as u64,
            self.config.block_mac_bytes as u64,
        )
        .map_err(|_| libc::EINVAL)?;
        let current_logical_size = FileDecoder::<File>::calculate_logical_size_with_mode(
            metadata.len(),
            header_size,
            self.config.block_size as u64,
            self.config.block_mac_bytes as u64,
            self.config.block_mode(),
        );
        if size == current_logical_size {
            return Ok(());
        }

        // Truncation keeps the existing header, so the IV does not change here;
        // it only has to be *known*. With a handle it is already in the shared
        // state. The remaining branches only run without one, where `path` was
        // already required to open the file above.
        let file_iv = if let Some(h) = handle {
            h.file_iv(&guard)
        } else if let Some(file_iv) = guard.header_iv {
            file_iv
        } else if header_size > 0 {
            let path = path.ok_or(libc::ESTALE)?;
            let (_, path_iv) = self.encrypt_path(path)?;
            let external_iv = if self.config.external_iv_chaining {
                path_iv
            } else {
                0
            };
            // Cache it for handles opened later, as `open_impl` would have.
            let file_iv = self
                .read_file_header(file_ref, path, external_iv)?
                .ok_or(libc::EIO)?;
            guard.header_iv = Some(file_iv);
            file_iv
        } else if self.config.external_iv_chaining {
            let (_, path_iv) = self.encrypt_path(path.ok_or(libc::ESTALE)?)?;
            path_iv
        } else {
            0
        };

        if size > current_logical_size {
            self.truncate_expand(
                file_ref,
                &guard,
                file_iv,
                header_size,
                current_logical_size,
                size,
                block_layout,
            )?;
        } else {
            self.truncate_shrink(file_ref, &guard, file_iv, header_size, size, block_layout)?;
        }

        Ok(())
    }

    fn do_utimens(
        &self,
        req: Request,
        path: Option<&Path>,
        handle: Option<&FileHandle>,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> OpResult {
        debug!("utimens: {:?} atime={:?} mtime={:?}", path, atime, mtime);
        self.ensure_writable()?;

        // Get file metadata for permission check (owner/group/mode).
        let metadata = if let Some(handle) = handle {
            handle.file.metadata().ok()
        } else {
            let path = path.ok_or(libc::ESTALE)?;
            let (real_path, _) = self.encrypt_path(path)?;
            fs::symlink_metadata(real_path).ok()
        };

        let setting_times = atime.is_some() || mtime.is_some();
        if setting_times && req.uid != 0 {
            let meta = metadata.as_ref().ok_or(libc::EACCES)?;
            utimens_permission_check(&req, meta.uid(), meta.gid(), meta.mode(), atime, mtime)
                .map_err(|e| e.raw())?
        } else if let Some(ref meta) = metadata {
            utimens_permission_check(&req, meta.uid(), meta.gid(), meta.mode(), atime, mtime)
                .map_err(|e| e.raw())?;
        }
        // If metadata failed and we're root or not setting times, proceed and let utimensat/futimens return the error.

        if let Some(handle) = handle {
            use std::os::fd::AsRawFd;
            return passthrough::utimens_fd(handle.file.as_raw_fd(), atime, mtime)
                .map_err(|e| e.raw());
        }

        let (real_path, _) = self.encrypt_path(path.ok_or(libc::ESTALE)?)?;
        passthrough::utimens_path(&real_path, atime, mtime).map_err(|e| e.raw())
    }

    fn readlink_impl(&self, path: &Path) -> Result<Vec<u8>, libc::c_int> {
        debug!("readlink: {:?}", path);
        let (real_path, path_iv) = self.encrypt_path(path)?;

        let target = fs::read_link(real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        // target on disk is encrypted (base64). So it should be valid string.
        let target_str = target.to_str().ok_or(libc::EILSEQ)?;

        let (plain_target_bytes, _) = self
            .cipher
            .decrypt_filename(target_str, path_iv) // Decrypt takes base64 string
            .map_err(|e| {
                error!("Failed to decrypt symlink target: {}", e);
                libc::EIO
            })?;

        Ok(plain_target_bytes)
    }

    fn link_impl(
        &self,
        path: &Path,
        newparent: &Path,
        newname: &OsStr,
    ) -> Result<FileAttr, libc::c_int> {
        debug!("link: {:?} -> {:?}/{:?}", path, newparent, newname);
        self.ensure_writable()?;

        if self.config.external_iv_chaining {
            return Err(libc::EPERM);
        }

        let new_path = newparent.join(newname);
        let (real_path, _) = self.encrypt_path(path)?;
        let (real_new_path, _) = self.encrypt_path(&new_path)?;

        if let Err(e) = std::fs::hard_link(&real_path, &real_new_path) {
            return Err(e.raw_os_error().unwrap_or(libc::EIO));
        }

        self.attr_for_path(Some(&new_path), None)
    }

    fn symlink_impl(
        &self,
        parent: &Path,
        name: &std::ffi::OsStr,
        target: &std::path::Path,
    ) -> Result<FileAttr, libc::c_int> {
        debug!("symlink: {:?}/{:?} -> {:?}", parent, name, target);
        self.ensure_writable()?;

        let path = parent.join(name);
        let (real_path, path_iv) = self.encrypt_path(&path)?;

        let target_bytes = target.as_os_str().as_bytes();
        let (enc_target, _) = self
            .cipher
            .encrypt_filename(target_bytes, path_iv)
            .map_err(|e| {
                error!("Failed to encrypt symlink target: {}", e);
                libc::EIO
            })?;

        passthrough_symlink(OsStr::new(&enc_target), &real_path).map_err(|e| e.raw())?;

        // Return the attributes of the entry we just created.
        self.attr_for_path(Some(&path), None)
    }

    fn attr_for_path(
        &self,
        path: Option<&Path>,
        handle: Option<&FileHandle>,
    ) -> Result<FileAttr, libc::c_int> {
        debug!("getattr: {:?} handle={}", path, handle.is_some());

        let metadata = if let Some(handle) = handle {
            handle.file.metadata().ok()
        } else {
            None
        };

        let metadata = if let Some(m) = metadata {
            m
        } else {
            let path = path.ok_or(libc::ESTALE)?;
            let (real_path, _) = self.encrypt_path(path)?;
            debug!("real_path: {:?}", real_path);
            fs::symlink_metadata(&real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?
        };

        Ok(self.attr_from_metadata(&metadata))
    }

    fn attr_from_metadata(&self, metadata: &fs::Metadata) -> FileAttr {
        let mut size = metadata.len();
        // Adjust size for header and MAC
        let header_size = self.config.header_size();
        if metadata.is_file() {
            size = FileDecoder::<std::fs::File>::calculate_logical_size_with_mode(
                metadata.len(),
                header_size,
                self.config.block_size as u64,
                self.config.block_mac_bytes as u64,
                self.config.block_mode(),
            );
        }

        file_attr_from_metadata(metadata, size)
    }

    fn directory_snapshot(&self, path: &Path) -> Result<DirBuffer, libc::c_int> {
        let (real_path, dir_iv) = self.encrypt_path(path)?;

        let entries =
            fs::read_dir(&real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let directory_metadata =
            fs::symlink_metadata(&real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let parent = path.parent().unwrap_or(path);
        let parent_attr = self.attr_for_path(Some(parent), None)?;

        let mut result = DirBuffer::new();
        result.push_dots(self.attr_from_metadata(&directory_metadata), parent_attr);

        for entry in entries {
            let entry = entry.map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            let file_name = entry.file_name();
            let Some(name_str) = file_name.to_str() else {
                warn!(
                    "Skipping non-UTF-8 backing filename {:?} while opening {:?}",
                    file_name, path
                );
                continue;
            };

            // Skip filenames starting with ".", since it isn't a valid encrypted filename.
            // Allows skipping over config files.
            if name_str.starts_with('.') {
                continue;
            }

            match self.cipher.decrypt_filename(name_str, dir_iv) {
                Ok((decrypted_name, _)) => {
                    let metadata = fs::symlink_metadata(entry.path())
                        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                    result.push(
                        OsStr::from_bytes(&decrypted_name),
                        file_type_from_metadata(&metadata),
                        self.attr_from_metadata(&metadata),
                    );
                }
                Err(e) => {
                    warn!("Failed to decrypt filename {}: {}", name_str, e);
                }
            }
        }

        Ok(result)
    }

    fn open_impl(&self, path: &Path, flags: u32) -> Result<FileHandle, libc::c_int> {
        debug!("open: {:?}", path);
        let (real_path, path_iv) = self.encrypt_path(path)?;

        // Respect requested open flags. In particular, writes must open the backing file with
        // write permissions; otherwise later `write`/`truncate` operations will fail with EBADF.
        let want_write = (flags as i32 & libc::O_WRONLY) != 0 || (flags as i32 & libc::O_RDWR) != 0;
        let want_trunc = (flags as i32 & libc::O_TRUNC) != 0;

        if want_write || want_trunc {
            self.ensure_writable()?;
        }

        let mut opts = fs::OpenOptions::new();
        opts.read(true);
        if want_write {
            opts.write(true);
        }
        // O_TRUNC is deliberately *not* passed to open(2). Truncating as a side
        // effect of open would reset the file and its IV before we hold the
        // per-file lock, on top of another handle's in-flight
        // read-modify-write. The reset happens below instead, under the lock.
        let file = opts
            .open(&real_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let header_size = self.config.header_size();
        let external_iv = if self.config.external_iv_chaining {
            path_iv
        } else {
            0
        };
        let headerless_iv = headerless_file_iv(header_size, external_iv);

        let state = self.file_states.get(&file)?;
        // Exclusive for the whole open: this path may reset the file and install
        // a new header, and even a read-only open must not observe a header
        // that a concurrent truncate is midway through replacing.
        let mut meta = state.write();

        if want_trunc && want_write {
            file.set_len(0)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            meta.header_iv = if header_size > 0 {
                Some(self.write_file_header(&file, external_iv)?)
            } else {
                None
            };
        } else if header_size > 0 {
            let physical_size = file
                .metadata()
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?
                .len();

            meta.header_iv = if physical_size < header_size {
                // Empty or undersized backing file (e.g. from mknod). Write a
                // header so subsequent writes use the correct physical offset
                // and file format.
                if !want_write {
                    // Opening for read but the file is too small to hold a header.
                    return Err(libc::EIO);
                }
                Some(self.write_file_header(&file, external_iv)?)
            } else {
                // A short read here leaves the IV at zero, matching the
                // pre-header-cache behaviour for partially written files.
                Some(
                    self.read_file_header(&file, path, external_iv)?
                        .unwrap_or(0),
                )
            };
        } else {
            meta.header_iv = None;
        }
        drop(meta);

        Ok(FileHandle {
            file,
            headerless_iv,
            state,
        })
    }

    fn read_impl(
        &self,
        handle: &FileHandle,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, libc::c_int> {
        debug!("read: offset={} size={}", offset, size);
        // Shared: concurrent reads are fine, but a read must not observe a
        // block halfway through someone else's read-modify-write.
        let meta = handle.state.read();

        let decoder = FileDecoder::new_from_config(
            self.cipher.as_ref(),
            &handle.file,
            handle.file_iv(&meta),
            &self.config.file_codec_params(),
            false,
        );

        const MAX_READ_SIZE: u32 = 1024 * 1024;
        let size = std::cmp::min(size, MAX_READ_SIZE);
        let mut result_data = vec![0u8; size as usize];

        match decoder.read_at(&mut result_data, offset) {
            Ok(bytes_read) => {
                result_data.truncate(bytes_read);
                Ok(result_data)
            }
            Err(e) => {
                error!("Read failed: {}", e);
                Err(e.raw_os_error().unwrap_or(libc::EIO))
            }
        }
    }

    fn write_impl(
        &self,
        handle: &FileHandle,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, libc::c_int> {
        debug!("write: offset={} size={}", offset, data.len());
        self.ensure_writable()?;
        // Exclusive across the whole read-decrypt-modify-encrypt-write cycle.
        let meta = handle.state.write();

        let encoder = FileEncoder::new_from_config(
            self.cipher.as_ref(),
            &handle.file,
            handle.file_iv(&meta),
            &self.config.file_codec_params(),
        );

        match encoder.write_at(data, offset) {
            Ok(written) => Ok(written as u32),
            Err(e) => {
                error!("Write failed: {}", e);
                Err(e.raw_os_error().unwrap_or(libc::EIO))
            }
        }
    }

    fn create_impl(
        &self,
        req: Request,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<(FileAttr, FileHandle), libc::c_int> {
        debug!(
            "create: {:?}/{:?} flags={} mode={}",
            parent, name, flags, mode
        );
        self.ensure_writable()?;
        let path = parent.join(name);
        let (real_path, path_iv) = self.encrypt_path(&path)?;

        // O_EXCL: fail if file already exists (POSIX open(2)).
        if (flags as i32 & libc::O_EXCL) != 0 && real_path.exists() {
            return Err(libc::EEXIST);
        }

        use std::os::unix::fs::OpenOptionsExt;
        // Not `.truncate(true)`: as in `open_impl`, resetting an existing file
        // has to happen under the per-file lock rather than inside open(2).
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(mode)
            .open(&real_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let header_size = self.config.header_size();
        let external_iv = if self.config.external_iv_chaining {
            path_iv
        } else {
            0
        };
        let headerless_iv = headerless_file_iv(header_size, external_iv);

        let state = self.file_states.get(&file)?;
        let mut meta = state.write();

        file.set_len(0)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        meta.header_iv = if header_size > 0 {
            Some(self.write_file_header(&file, external_iv)?)
        } else {
            None
        };
        drop(meta);

        set_ownership_fd(file.as_raw_fd(), &req).map_err(|e| e.raw())?;

        // Build the reply attributes from the freshly created backing file
        // (ownership was just set above); logical size of a new file is 0.
        let metadata = file
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let attr = file_attr_from_metadata(&metadata, 0);

        Ok((
            attr,
            FileHandle {
                file,
                headerless_iv,
                state,
            },
        ))
    }

    fn unlink_impl(&self, parent: &Path, name: &OsStr) -> OpResult {
        let path = parent.join(name);
        debug!("unlink: {:?}", path);
        self.ensure_writable()?;
        let (real_path, _) = self.encrypt_path(&path)?;
        fs::remove_file(real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
    }

    fn mkdir_impl(
        &self,
        req: Request,
        parent: &Path,
        name: &OsStr,
        mode: u32,
    ) -> Result<FileAttr, libc::c_int> {
        let path = parent.join(name);
        debug!("mkdir: {:?} mode={:o}", path, mode);
        self.ensure_writable()?;
        let (real_path, _) = self.encrypt_path(&path)?;

        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(mode)
            .create(&real_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        set_ownership_path(&real_path, &req).map_err(|e| e.raw())?;

        self.attr_for_path(Some(&path), None)
    }

    fn mknod_impl(
        &self,
        req: Request,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        rdev: u32,
    ) -> Result<FileAttr, libc::c_int> {
        let path = parent.join(name);
        debug!("mknod: {:?} mode={:o} rdev={}", path, mode, rdev);
        self.ensure_writable()?;
        let (real_path, path_iv) = self.encrypt_path(&path)?;

        let mode_t = mode as libc::mode_t;
        let mode_bits = mode_t & libc::S_IFMT;
        if mode_bits != libc::S_IFREG {
            passthrough::mknod(&real_path, mode, rdev).map_err(|e| e.raw())?;
        } else {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let header_size = self.config.header_size();
            let external_iv = if self.config.external_iv_chaining {
                path_iv
            } else {
                0
            };
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&real_path)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            if header_size > 0 {
                let (header, _iv) = self.cipher.encrypt_header(external_iv).map_err(|e| {
                    error!("Failed to generate header for mknod: {}", e);
                    libc::EIO
                })?;
                f.write_all(&header)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            }
        }

        set_ownership_path(&real_path, &req).map_err(|e| e.raw())?;

        self.attr_for_path(Some(&path), None)
    }

    fn rmdir_impl(&self, parent: &Path, name: &OsStr) -> OpResult {
        let path = parent.join(name);
        debug!("rmdir: {:?}", path);
        self.ensure_writable()?;
        let (real_path, _) = self.encrypt_path(&path)?;
        fs::remove_dir(real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
    }

    fn setxattr_impl(
        &self,
        path: &Path,
        name: &OsStr,
        value: &[u8],
        flags: u32,
        position: u32,
    ) -> OpResult {
        debug!(
            "setxattr: {:?} name={:?} value_len={} flags={} position={}",
            path,
            name,
            value.len(),
            flags,
            position
        );
        self.ensure_writable()?;

        let (real_path, path_iv) = self.encrypt_path(path)?;

        let name_bytes = name.as_bytes();

        // Encrypt all attributes
        // Store them with "user.encfs." prefix on disk
        // Encrypt the full xattr name
        let encrypted_name = self
            .cipher
            .encrypt_xattr_name(name_bytes, path_iv)
            .map_err(|e| {
                error!("Failed to encrypt xattr name: {}", e);
                libc::EIO
            })?;

        // Encrypt xattr value
        let encrypted_value = self
            .cipher
            .encrypt_xattr_value(value, path_iv)
            .map_err(|e| {
                error!("Failed to encrypt xattr value: {}", e);
                libc::EIO
            })?;

        // Store with "user.encfs." prefix + base64-encoded encrypted name
        // Use base64 encoding for the encrypted name to make it filesystem-safe
        let encoded_name = STANDARD_NO_PAD.encode(&encrypted_name);
        let final_name = format!("user.encfs.{}", encoded_name);

        let c_name = std::ffi::CString::new(final_name).map_err(|_| libc::EINVAL)?;
        let c_path = c_path(&real_path).map_err(|e| e.raw())?;

        // Set xattr on underlying filesystem
        passthrough::setxattr_nofollow(&c_path, &c_name, &encrypted_value, flags as i32)
            .map_err(|e| e.raw())
    }

    fn getxattr_impl(&self, path: &Path, name: &OsStr) -> Result<Vec<u8>, libc::c_int> {
        debug!("getxattr: {:?} name={:?}", path, name);

        let (real_path, path_iv) = self.encrypt_path(path)?;

        let name_bytes = name.as_bytes();

        // Encrypt all attributes
        // Look them up with "user.encfs." prefix on disk
        // Encrypt the full xattr name to find it on disk
        let encrypted_name = self
            .cipher
            .encrypt_xattr_name(name_bytes, path_iv)
            .map_err(|e| {
                error!("Failed to encrypt xattr name: {}", e);
                libc::EIO
            })?;

        // Encode encrypted name for storage lookup
        let encoded_name = STANDARD_NO_PAD.encode(&encrypted_name);
        let lookup_name = format!("user.encfs.{}", encoded_name);

        let c_name = std::ffi::CString::new(lookup_name).map_err(|_| libc::EINVAL)?;
        let c_path = c_path(&real_path).map_err(|e| e.raw())?;

        // Read the on-disk (encrypted) value; the caller's size limit is
        // applied by the trait wrapper against the decrypted length.
        let encrypted_value =
            passthrough::getxattr_value_nofollow(&c_path, &c_name).map_err(|e| e.raw())?;

        // Decrypt value
        let decrypted_value = self
            .cipher
            .decrypt_xattr_value(&encrypted_value, path_iv)
            .map_err(|e| {
                error!("Failed to decrypt xattr value: {}", e);
                libc::EIO
            })?;

        Ok(decrypted_value)
    }

    fn listxattr_impl(&self, path: &Path) -> Result<Vec<u8>, libc::c_int> {
        debug!("listxattr: {:?}", path);

        let (real_path, path_iv) = self.encrypt_path(path)?;

        let c_path = c_path(&real_path).map_err(|e| e.raw())?;

        // Read the on-disk list of xattr names; the caller's size limit is
        // applied by the trait wrapper against the decrypted list length.
        let names = passthrough::listxattr_names_nofollow(&c_path).map_err(|e| e.raw())?;

        // Process all xattr names in the list
        let mut decrypted_list = Vec::new();

        for name_bytes in names {
            let name_str = match std::str::from_utf8(&name_bytes) {
                Ok(s) => s,
                Err(_) => continue, // Invalid UTF-8, skip
            };

            if let Some(encoded_part) = name_str.strip_prefix("user.encfs.") {
                // This is an encrypted encfs attribute stored on disk
                // Extract the base64-encoded encrypted name
                match STANDARD_NO_PAD.decode(encoded_part) {
                    Ok(encrypted_name_bytes) => {
                        match self
                            .cipher
                            .decrypt_xattr_name(&encrypted_name_bytes, path_iv)
                        {
                            Ok(decrypted_name) => {
                                // Return the decrypted name without the "user.encfs." prefix
                                decrypted_list.extend_from_slice(&decrypted_name);
                                decrypted_list.push(0); // null separator
                            }
                            Err(e) => {
                                warn!("Failed to decrypt xattr name: {}", e);
                                // Skip this name but continue
                            }
                        }
                    }
                    Err(_) => {
                        warn!("Failed to decode base64 xattr name: {}", name_str);
                        // Skip this name but continue
                    }
                }
            } else {
                // Non-encfs attribute (shouldn't happen if we encrypt all), skip it
                // or pass through if there are any legacy unencrypted attributes
                if !is_apple_xattr(name_str) {
                    warn!("Found non-encfs xattr on disk: {}, skipping", name_str);
                }
            }
        }

        Ok(decrypted_list)
    }

    fn removexattr_impl(&self, path: &Path, name: &OsStr) -> OpResult {
        debug!("removexattr: {:?} name={:?}", path, name);
        self.ensure_writable()?;

        let (real_path, path_iv) = self.encrypt_path(path)?;

        let name_bytes = name.as_bytes();

        // Encrypt all attributes
        // Look them up with "user.encfs." prefix on disk
        // Encrypt the full xattr name
        let encrypted_name = self
            .cipher
            .encrypt_xattr_name(name_bytes, path_iv)
            .map_err(|e| {
                error!("Failed to encrypt xattr name: {}", e);
                libc::EIO
            })?;

        // Encode encrypted name for storage lookup
        let encoded_name = STANDARD_NO_PAD.encode(&encrypted_name);
        let lookup_name = format!("user.encfs.{}", encoded_name);

        let c_name = std::ffi::CString::new(lookup_name).map_err(|_| libc::EINVAL)?;
        let c_path = c_path(&real_path).map_err(|e| e.raw())?;

        // Remove xattr from underlying filesystem
        passthrough::removexattr_nofollow(&c_path, &c_name).map_err(|e| e.raw())
    }
}

impl PathFilesystem for EncFs {
    type Handle = FileHandle;
    type DirHandle = DirBuffer;

    // POSIX record locks are deliberately left to the kernel. Forwarding them
    // would mean taking every client's lock with `fcntl` in this one daemon
    // process, and POSIX locks are keyed by (process, inode): two clients could
    // never conflict, and either one closing a handle would drop the other's
    // locks. Leaving `getlk`/`setlk` unimplemented keeps `FUSE_POSIX_LOCKS` out
    // of the INIT reply, so the kernel enforces locks locally with the right
    // per-process semantics.
    const SUPPORTS_POSIX_LOCKS: bool = false;
    const SUPPORTS_READDIRPLUS: bool = true;

    fn init(&self, _conn: &mut typed_fuse::ConnInfo) {
        debug!("init");
    }

    fn destroy(&self) {
        debug!("destroy");
    }

    fn lookup(
        &self,
        parent: &Path,
        name: &OsStr,
        _caller: &Request,
    ) -> Result<Option<FileAttr>, Errno> {
        let path = parent.join(name);
        match self.attr_for_path(Some(&path), None) {
            Ok(attr) => Ok(Some(attr)),
            Err(libc::ENOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn getattr(
        &self,
        path: Option<&Path>,
        handle: Option<&FileHandle>,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Ok(self.attr_for_path(path, handle)?)
    }

    fn setattr(
        &self,
        path: Option<&Path>,
        handle: Option<&FileHandle>,
        set_attr: &SetAttr,
        caller: &Request,
    ) -> Result<FileAttr, Errno> {
        if let Some(size) = set_attr.size {
            self.do_truncate(path, handle, size)?;
        }
        if let Some(mode) = set_attr.mode {
            self.do_chmod(path, handle, mode)?;
        }
        if set_attr.uid.is_some() || set_attr.gid.is_some() {
            self.do_chown(path, handle, set_attr.uid, set_attr.gid)?;
        }
        if set_attr.atime.is_some() || set_attr.mtime.is_some() {
            let resolve_time = |time: Option<TimeOrNow>| {
                time.map(|time| match time {
                    TimeOrNow::SpecificTime(time) => time,
                    TimeOrNow::Now => SystemTime::now(),
                })
            };
            self.do_utimens(
                *caller,
                path,
                handle,
                resolve_time(set_attr.atime),
                resolve_time(set_attr.mtime),
            )?;
        }
        Ok(self.attr_for_path(path, handle)?)
    }

    fn access(&self, path: &Path, mask: i32, caller: &Request) -> Result<(), Errno> {
        Ok(self.access_impl(*caller, path, mask as u32)?)
    }

    fn statfs(&self, path: &Path, _caller: &Request) -> Result<ReplyStatFs, Errno> {
        Ok(self.statfs_impl(path)?)
    }

    fn readlink(&self, path: &Path, _caller: &Request) -> Result<PathBuf, Errno> {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(self.readlink_impl(path)?)))
    }

    fn symlink(
        &self,
        parent: &Path,
        name: &OsStr,
        target: &Path,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Ok(self.symlink_impl(parent, name, target)?)
    }

    fn link(
        &self,
        path: &Path,
        new_parent: &Path,
        new_name: &OsStr,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Ok(self.link_impl(path, new_parent, new_name)?)
    }

    fn mknod(
        &self,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        rdev: u32,
        _umask: u32,
        caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Ok(self.mknod_impl(*caller, parent, name, mode, rdev)?)
    }

    fn mkdir(
        &self,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Ok(self.mkdir_impl(*caller, parent, name, mode)?)
    }

    fn unlink(&self, parent: &Path, name: &OsStr, _caller: &Request) -> Result<(), Errno> {
        Ok(self.unlink_impl(parent, name)?)
    }

    fn rmdir(&self, parent: &Path, name: &OsStr, _caller: &Request) -> Result<(), Errno> {
        Ok(self.rmdir_impl(parent, name)?)
    }

    fn rename(
        &self,
        parent: &Path,
        name: &OsStr,
        new_parent: &Path,
        new_name: &OsStr,
        _caller: &Request,
    ) -> Result<(), Errno> {
        Ok(self.rename_internal(parent, name, new_parent, new_name)?)
    }

    fn opendir(
        &self,
        path: &Path,
        _flags: i32,
        _caller: &Request,
    ) -> Result<Opened<DirBuffer>, Errno> {
        Ok(Opened::new(self.directory_snapshot(path)?))
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
    ) -> Result<Opened<FileHandle>, Errno> {
        Ok(Opened::new(self.open_impl(path, flags as u32)?))
    }

    fn read<'a>(
        &'a self,
        _path: Option<&Path>,
        handle: &'a FileHandle,
        offset: u64,
        size: usize,
        _caller: &Request,
    ) -> Result<Cow<'a, [u8]>, Errno> {
        let size = u32::try_from(size).unwrap_or(u32::MAX);
        Ok(Cow::Owned(self.read_impl(handle, offset, size)?))
    }

    fn write(
        &self,
        _path: Option<&Path>,
        handle: &FileHandle,
        data: &[u8],
        offset: u64,
        _caller: &Request,
    ) -> Result<usize, Errno> {
        Ok(self.write_impl(handle, offset, data)? as usize)
    }

    fn create(
        &self,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        caller: &Request,
    ) -> Result<(FileAttr, Opened<FileHandle>), Errno> {
        let (attr, handle) = self.create_impl(*caller, parent, name, mode, flags as u32)?;
        Ok((attr, Opened::new(handle)))
    }

    fn setxattr(
        &self,
        path: &Path,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        _caller: &Request,
    ) -> Result<(), Errno> {
        Ok(self.setxattr_impl(path, name, value, flags as u32, 0)?)
    }

    fn getxattr(
        &self,
        path: &Path,
        name: &OsStr,
        size: usize,
        _caller: &Request,
    ) -> Result<ReplyXAttr, Errno> {
        ReplyXAttr::sized(self.getxattr_impl(path, name)?, size)
    }

    fn listxattr(&self, path: &Path, size: usize, _caller: &Request) -> Result<ReplyXAttr, Errno> {
        ReplyXAttr::sized(self.listxattr_impl(path)?, size)
    }

    fn removexattr(&self, path: &Path, name: &OsStr, _caller: &Request) -> Result<(), Errno> {
        Ok(self.removexattr_impl(path, name)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FILE_STATE_SWEEP_FLOOR, FileStates, headerless_file_iv, is_apple_xattr,
        lock_source_and_dest,
    };

    fn table_len(states: &FileStates) -> usize {
        states.table.lock().unwrap().entries.len()
    }

    #[test]
    fn same_inode_shares_one_state() {
        let states = FileStates::default();
        let a = states.get_by_key((1, 42));
        let b = states.get_by_key((1, 42));
        assert!(std::sync::Arc::ptr_eq(&a, &b));

        // Same inode number on a different device is a different file.
        let c = states.get_by_key((2, 42));
        assert!(!std::sync::Arc::ptr_eq(&a, &c));
    }

    #[test]
    fn state_is_recreated_after_last_reference_drops() {
        let states = FileStates::default();
        let first = states.get_by_key((1, 7));
        drop(first);
        let second = states.get_by_key((1, 7));
        assert_eq!(second.key, (1, 7));
    }

    #[test]
    fn dead_entries_are_swept() {
        let states = FileStates::default();

        // Churn well past the sweep floor with no live references.
        for ino in 0..(FILE_STATE_SWEEP_FLOOR as u64 * 8) {
            drop(states.get_by_key((1, ino)));
        }
        assert!(
            table_len(&states) <= FILE_STATE_SWEEP_FLOOR + 1,
            "dead entries accumulated: {}",
            table_len(&states)
        );

        // Live references must survive a sweep.
        let live: Vec<_> = (0..10).map(|ino| states.get_by_key((2, ino))).collect();
        for ino in 0..(FILE_STATE_SWEEP_FLOOR as u64 * 8) {
            drop(states.get_by_key((3, ino)));
        }
        for (ino, state) in live.iter().enumerate() {
            assert!(std::sync::Arc::ptr_eq(
                state,
                &states.get_by_key((2, ino as u64))
            ));
        }
    }

    #[test]
    fn pair_locking_is_deadlock_free_in_both_directions() {
        let states = FileStates::default();
        let low = states.get_by_key((1, 1));
        let high = states.get_by_key((1, 2));

        // Same inode: one lock, taken once. Taking it twice would self-deadlock.
        {
            let (src, _dest) = lock_source_and_dest(&low, &low);
            assert!(src.is_none());
        }

        // Copies contending in opposite directions over the same pair. An
        // implementation that locked in argument order rather than key order
        // would wedge here.
        let (tx, rx) = std::sync::mpsc::channel();
        for (first, second) in [(low.clone(), high.clone()), (high.clone(), low.clone())] {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for _ in 0..5000 {
                    let (src, dest) = lock_source_and_dest(&first, &second);
                    assert!(src.is_some());
                    drop((src, dest));
                }
                let _ = tx.send(());
            });
        }
        drop(tx);

        for _ in 0..2 {
            rx.recv_timeout(std::time::Duration::from_secs(60))
                .expect("pair locking deadlocked");
        }
    }

    #[test]
    fn headerless_files_use_external_iv() {
        assert_eq!(
            headerless_file_iv(0, 0x1234_5678_9abc_def0),
            0x1234_5678_9abc_def0
        );
    }

    #[test]
    fn headered_files_ignore_external_iv() {
        assert_eq!(headerless_file_iv(8, 0x1234_5678_9abc_def0), 0);
    }

    #[test]
    fn recognizes_apple_xattrs() {
        assert!(is_apple_xattr("com.apple.provenance"));
        assert!(!is_apple_xattr("user.encfs.attribute"));
        assert!(!is_apple_xattr("com.example.attribute"));
    }
}
