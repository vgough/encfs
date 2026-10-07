use crate::crypto::block::BlockLayout;
use crate::crypto::cipher::Cipher;
use crate::crypto::file::{FileDecoder, FileEncoder};
use crate::crypto::file_iv::FileIv;
use crate::diriv::{self, CachedDir, DirIvCache, DirIvs};
use crate::idle_lock::{Access, IdleLock};
use crate::symlink_target;
use crate::xattr_name;
use libc;
use log::{debug, error, warn};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak};
use std::time::SystemTime;
use typed_fuse::passthrough::{
    self, access_check, c_path, file_attr_from_metadata, file_type_from_metadata, is_apple_xattr,
    set_ownership_fd, set_ownership_path, statfs_path, symlink as passthrough_symlink,
    utimens_permission_check,
};
use typed_fuse::{
    Caller as Request, DirBuffer, Errno, NodeAttr as FileAttr, Opened, PathDirSink, PathEntry,
    PathFilesystem, PathNodeRef, PathPlusDirSink, SetAttr, StatFs as ReplyStatFs, TimeOrNow,
    XattrReply as ReplyXAttr,
};

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
    header_iv: Option<FileIv>,
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
///
/// This also serves as the runtime's per-node state, so a node discovered by
/// name and a handle opened on it converge on the same `Arc` via [`FileStates`].
#[derive(Debug)]
pub struct FileState {
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
    headerless_iv: FileIv,
    /// Shared state for the backing inode; guards every RMW on this file.
    state: Arc<FileState>,
}

impl FileHandle {
    /// The IV this file's blocks are encrypted under, as of `meta`.
    fn file_iv(&self, meta: &FileMeta) -> FileIv {
        meta.header_iv.unwrap_or(self.headerless_iv)
    }
}

struct PathInfo<'a> {
    logical: &'a Path,
    physical: &'a Path,
    iv: u64,
}

/// Where an entry is about to be created (or renamed into place): its backing
/// path and path IV, plus the directory and name to hand to `*at` calls.
///
/// In directory IV mode the parent directory is held open, and the name was
/// encrypted under that very directory's IVs (see [`EncFs::new_entry`]).
/// Creating through the descriptor puts the entry in that directory or
/// nowhere, even if another directory has since replaced it at its path,
/// where the name would be unreadable. In other modes names depend only on
/// the path, and the entry is addressed by its full path.
struct NewEntry {
    real_path: PathBuf,
    iv: u64,
    /// The pinned parent directory, in directory IV mode.
    dir: Option<File>,
    /// The encrypted name within `dir`, or the full backing path without one.
    name: CString,
}

impl NewEntry {
    /// An entry addressed by its full backing path.
    fn from_path(real_path: PathBuf, iv: u64) -> Result<Self, libc::c_int> {
        let name = c_path(&real_path).map_err(|e| e.raw())?;
        Ok(Self {
            real_path,
            iv,
            dir: None,
            name,
        })
    }

    fn dirfd(&self) -> RawFd {
        self.dir
            .as_ref()
            .map_or(libc::AT_FDCWD, |dir| dir.as_raw_fd())
    }

    /// openat(2), always close-on-exec.
    fn open(&self, flags: libc::c_int, mode: u32) -> Result<File, libc::c_int> {
        let fd = unsafe {
            libc::openat(
                self.dirfd(),
                self.name.as_ptr(),
                flags | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(last_errno());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Creates a FIFO, device, or socket node.
    fn mknod(&self, mode: u32, rdev: u32) -> OpResult {
        let mode_t = mode as libc::mode_t;
        let kind = mode_t & libc::S_IFMT;
        if kind == libc::S_IFIFO {
            check(unsafe { libc::mkfifoat(self.dirfd(), self.name.as_ptr(), mode_t) })
        } else if kind == libc::S_IFCHR || kind == libc::S_IFBLK || kind == libc::S_IFSOCK {
            check(unsafe {
                libc::mknodat(
                    self.dirfd(),
                    self.name.as_ptr(),
                    mode_t,
                    rdev as libc::dev_t,
                )
            })
        } else {
            Err(libc::EINVAL)
        }
    }

    /// Creates the entry as a symlink to `target`, an arbitrary byte string.
    fn symlink(&self, target: &OsStr) -> OpResult {
        let target = CString::new(target.as_bytes()).map_err(|_| libc::EINVAL)?;
        check(unsafe { libc::symlinkat(target.as_ptr(), self.dirfd(), self.name.as_ptr()) })
    }

    /// Creates the entry as a hard link to `real_source`.
    fn link_from(&self, real_source: &Path) -> OpResult {
        let source = c_path(real_source).map_err(|e| e.raw())?;
        check(unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                source.as_ptr(),
                self.dirfd(),
                self.name.as_ptr(),
                0,
            )
        })
    }

    /// Moves `real_source` to the entry, replacing it as rename(2) does.
    fn rename_from(&self, real_source: &Path) -> OpResult {
        let source = c_path(real_source).map_err(|e| e.raw())?;
        check(unsafe {
            libc::renameat(
                libc::AT_FDCWD,
                source.as_ptr(),
                self.dirfd(),
                self.name.as_ptr(),
            )
        })
    }

    /// Removes the entry, if it is not a directory.
    fn unlink(&self) -> OpResult {
        check(unsafe { libc::unlinkat(self.dirfd(), self.name.as_ptr(), 0) })
    }

    /// As `set_ownership_path`: gives the entry the caller's uid and gid when
    /// they differ from this process's, ignoring `EPERM`.
    fn set_ownership(&self, caller: &Request) -> OpResult {
        if caller.uid == unsafe { libc::getuid() } && caller.gid == unsafe { libc::getgid() } {
            return Ok(());
        }
        match check(unsafe {
            libc::fchownat(
                self.dirfd(),
                self.name.as_ptr(),
                caller.uid as libc::uid_t,
                caller.gid as libc::gid_t,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        }) {
            Err(libc::EPERM) => Ok(()),
            other => other,
        }
    }
}

fn last_errno() -> libc::c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// The result of a libc call returning 0 on success and -1 with `errno`.
fn check(ret: libc::c_int) -> OpResult {
    if ret == 0 { Ok(()) } else { Err(last_errno()) }
}

/// Opens a backing directory to pin it for `*at` calls. Asks only for search
/// access where the platform allows, so a directory without read permission
/// can still be written into.
fn open_dir(dir: &Path) -> Result<File, libc::c_int> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    const PIN: libc::c_int = libc::O_PATH;
    #[cfg(target_os = "macos")]
    const PIN: libc::c_int = libc::O_SEARCH;
    #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
    const PIN: libc::c_int = libc::O_RDONLY;

    let c_dir = c_path(dir).map_err(|e| e.raw())?;
    let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut fd = unsafe { libc::open(c_dir.as_ptr(), flags | PIN) };
    // Kernels older than the search-only flag reject it.
    if fd < 0 && PIN != libc::O_RDONLY && last_errno() == libc::EINVAL {
        fd = unsafe { libc::open(c_dir.as_ptr(), flags | libc::O_RDONLY) };
    }
    if fd < 0 {
        return Err(last_errno());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
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
    /// Optional inactivity lock gating data access (on-demand mode).
    idle_lock: Option<IdleLock>,
    /// Derived directory IVs (directory IV mode only). Trusted without
    /// rereading: while mounted, every change to the backing directory comes
    /// through this filesystem, which updates the cache as it makes them.
    diriv_cache: DirIvCache,
    /// Orders directory lifecycle against sidecar reads (directory IV mode).
    /// Held for write by mkdir, rmdir, and directory rename, which create,
    /// remove, or move sidecars and update the cache to match, and for read
    /// while reading a sidecar into the cache on a miss. In-process lookups
    /// therefore never observe a directory between its creation and its
    /// sidecar's, and a miss can't cache a path a rename just vacated.
    /// Never held while resolving a path: the lock is not reentrant.
    ///
    /// The lock does not keep a directory in place while an operation uses
    /// its IVs. Operations that write IV-dependent names or attributes bind
    /// those IVs to the directory itself instead: entry creation through a
    /// pinned parent ([`EncFs::new_entry`]); mkdir and directory rename by
    /// encrypting the new name under the write lock they already take; and
    /// directory xattr writes under the read lock.
    sidecar_lock: RwLock<()>,
    /// Runs once at the point where an entry's name has been derived but not
    /// yet created, so tests can replace the parent directory there.
    #[cfg(test)]
    race_hook: Mutex<Option<RaceHook>>,
}

#[cfg(test)]
type RaceHook = Box<dyn FnOnce(&EncFs) + Send>;

impl EncFs {
    pub fn new(root: PathBuf, cipher: Box<dyn Cipher>, config: crate::config::EncfsConfig) -> Self {
        Self {
            root,
            cipher,
            config,
            read_only: false,
            file_states: FileStates::default(),
            idle_lock: None,
            diriv_cache: DirIvCache::default(),
            sidecar_lock: RwLock::new(()),
            #[cfg(test)]
            race_hook: Mutex::new(None),
        }
    }

    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Require re-authentication for data access after a period of
    /// inactivity. See [`IdleLock`] for which operations it gates.
    pub fn with_idle_lock(mut self, idle_lock: IdleLock) -> Self {
        self.idle_lock = Some(idle_lock);
        self
    }

    fn check_idle_lock(&self, access: Access, caller: &Request) -> OpResult {
        match &self.idle_lock {
            Some(lock) => lock.check(access, caller.pid),
            None => Ok(()),
        }
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
    /// This walks the path component by component, encrypting each filename
    /// under the IV for names in its parent directory (see [`EncFs::names_iv`]):
    /// the parent's path IV with IV chaining (standard), 0 without, or the
    /// parent's sidecar IV in directory IV mode.
    /// Returns the full encrypted path and the path IV of the final component
    /// (its entry IV in directory IV mode; 0 for the root).
    pub fn encrypt_path(&self, path: &Path) -> Result<(PathBuf, u64), libc::c_int> {
        let mut encrypted_path = PathBuf::new();
        let mut iv = 0u64;
        for component in path.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::CurDir => {}
                std::path::Component::Normal(name) => {
                    let name_bytes = name.as_bytes();
                    let names_iv = if self.config.directory_iv {
                        self.dir_ivs(&self.root.join(&encrypted_path))?.name_iv
                    } else {
                        iv
                    };
                    let (encrypted_name, new_iv) = self
                        .cipher
                        .encrypt_filename(name_bytes, names_iv)
                        .map_err(|e| {
                            error!("Encrypt filename failed: {}", e);
                            libc::EIO
                        })?;
                    encrypted_path.push(encrypted_name);
                    iv = diriv::child_path_iv(&self.config, new_iv);
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
        let mut backing_dir = self.root.clone();
        let mut iv = 0u64;
        for component in encrypted_path.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => {
                    let name_str = name.to_str().ok_or(libc::EILSEQ)?;
                    let names_iv = self.names_iv(&backing_dir, iv)?;
                    let (decrypted_name_bytes, new_iv) = self
                        .cipher
                        .decrypt_filename(name_str, names_iv)
                        .map_err(|e| {
                            error!("Failed to decrypt filename {}: {}", name_str, e);
                            libc::EIO
                        })?;
                    decrypted_path.push(OsStr::from_bytes(&decrypted_name_bytes));
                    backing_dir.push(name);
                    iv = diriv::child_path_iv(&self.config, new_iv);
                }
                _ => return Err(libc::EINVAL),
            }
        }
        Ok((decrypted_path, iv))
    }

    /// The IVs of a backing directory's sidecar (directory IV mode), from the
    /// cache when its sidecar is unchanged.
    fn dir_ivs(&self, backing_dir: &Path) -> Result<DirIvs, libc::c_int> {
        if let Some(cached) = self.diriv_cache.get(backing_dir) {
            return Ok(cached.ivs);
        }
        let _guard = self.sidecar_read_lock();
        Ok(self.dir_ivs_locked(backing_dir)?.ivs)
    }

    /// As [`EncFs::dir_ivs`], with the directory's identity, for callers
    /// already holding the sidecar lock (for read or write).
    fn dir_ivs_locked(&self, backing_dir: &Path) -> Result<CachedDir, libc::c_int> {
        if let Some(cached) = self.diriv_cache.get(backing_dir) {
            return Ok(cached);
        }
        self.diriv_cache
            .load(self.cipher.as_ref(), backing_dir)
            .map_err(|e| {
                if e.is_damaged() {
                    error!("Directory {:?} is unreadable: {}", backing_dir, e);
                } else {
                    debug!("No directory IVs for {:?}: {}", backing_dir, e);
                }
                e.errno()
            })
    }

    /// The IVs of `dir`, a directory opened at `backing_dir`.
    ///
    /// Fails with `ENOENT` if they are cached for a different directory than
    /// `dir`: another directory has replaced it at that path since it was
    /// opened (or the replacement is mid-way), so names encrypted for one
    /// would be unreadable in the other. The entry is dropped so that a retry
    /// reloads it.
    fn pinned_dir_ivs(&self, backing_dir: &Path, dir: &File) -> Result<DirIvs, libc::c_int> {
        let meta = dir
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let id = (meta.dev(), meta.ino());
        let cached = match self.diriv_cache.get(backing_dir) {
            Some(cached) => cached,
            None => {
                let _guard = self.sidecar_read_lock();
                self.dir_ivs_locked(backing_dir)?
            }
        };
        if cached.id != id {
            debug!("Directory {:?} was replaced while in use", backing_dir);
            self.diriv_cache.forget_if(backing_dir, cached.id);
            return Err(libc::ENOENT);
        }
        Ok(cached.ivs)
    }

    /// Resolves the plaintext path of an entry about to be created, or
    /// renamed into place. In directory IV mode the parent is opened first
    /// and its name IV bound to it, so the entry can only be created in the
    /// directory its name was encrypted for. See [`NewEntry`].
    fn new_entry(&self, path: &Path) -> Result<NewEntry, libc::c_int> {
        if !self.config.directory_iv {
            let (real_path, iv) = self.encrypt_path(path)?;
            return NewEntry::from_path(real_path, iv);
        }
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(libc::EINVAL);
        };
        let (real_parent, _) = self.encrypt_path(parent)?;
        let dir = open_dir(&real_parent)?;
        let ivs = self.pinned_dir_ivs(&real_parent, &dir)?;
        let (encrypted_name, next_iv) = self
            .cipher
            .encrypt_filename(name.as_bytes(), ivs.name_iv)
            .map_err(|e| {
                error!("Encrypt filename failed: {}", e);
                libc::EIO
            })?;

        #[cfg(test)]
        {
            let hook = self
                .race_hook
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take();
            if let Some(hook) = hook {
                hook(self);
            }
        }

        let real_path = real_parent.join(&encrypted_name);
        let name = c_path(Path::new(&encrypted_name)).map_err(|e| e.raw())?;
        Ok(NewEntry {
            real_path,
            iv: diriv::child_path_iv(&self.config, next_iv),
            dir: Some(dir),
            name,
        })
    }

    /// The backing path of `name` inside the backing directory `real_parent`
    /// (directory IV mode). The caller holds the sidecar write lock, which
    /// keeps `real_parent` the directory the name is encrypted for until the
    /// lock is released.
    fn encrypt_name_in(&self, real_parent: &Path, name: &OsStr) -> Result<PathBuf, libc::c_int> {
        let ivs = self.dir_ivs_locked(real_parent)?.ivs;
        let (encrypted_name, _) = self
            .cipher
            .encrypt_filename(name.as_bytes(), ivs.name_iv)
            .map_err(|e| {
                error!("Encrypt filename failed: {}", e);
                libc::EIO
            })?;
        Ok(real_parent.join(encrypted_name))
    }

    /// The IV for the names inside `backing_dir`, whose own path IV is
    /// `path_iv`. See [`diriv::names_iv`]; this is the cached form.
    fn names_iv(&self, backing_dir: &Path, path_iv: u64) -> Result<u64, libc::c_int> {
        if self.config.directory_iv {
            Ok(self.dir_ivs(backing_dir)?.name_iv)
        } else {
            Ok(path_iv)
        }
    }

    /// The IV for the extended attributes of the entry at `backing_path`,
    /// whose path IV is `entry_iv`. See [`diriv::xattr_iv`]; this is the
    /// cached form.
    fn xattr_iv(&self, backing_path: &Path, entry_iv: u64) -> Result<u64, libc::c_int> {
        if self.has_own_xattr_iv(backing_path)? {
            Ok(self.dir_ivs(backing_path)?.node_iv)
        } else {
            Ok(entry_iv)
        }
    }

    /// As [`EncFs::xattr_iv`], for callers holding the sidecar lock. Writers
    /// of attributes hold it so that a directory can't be replaced between
    /// reading its `node_iv` and storing attributes encrypted under it.
    fn xattr_iv_locked(&self, backing_path: &Path, entry_iv: u64) -> Result<u64, libc::c_int> {
        if self.has_own_xattr_iv(backing_path)? {
            Ok(self.dir_ivs_locked(backing_path)?.ivs.node_iv)
        } else {
            Ok(entry_iv)
        }
    }

    /// Whether the entry at `backing_path` is a directory whose attributes
    /// are keyed by its own sidecar (directory IV mode).
    fn has_own_xattr_iv(&self, backing_path: &Path) -> Result<bool, libc::c_int> {
        if !self.config.directory_iv {
            return Ok(false);
        }
        let metadata = fs::symlink_metadata(backing_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        Ok(metadata.is_dir())
    }

    fn sidecar_read_lock(&self) -> RwLockReadGuard<'_, ()> {
        self.sidecar_lock.read().unwrap_or_else(|p| p.into_inner())
    }

    fn sidecar_write_lock(&self) -> RwLockWriteGuard<'_, ()> {
        self.sidecar_lock.write().unwrap_or_else(|p| p.into_inner())
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

        let (real_source, source_iv) = self.encrypt_path(&source)?;

        if self.config.directory_iv {
            let meta = fs::symlink_metadata(&real_source)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            return self.rename_with_directory_ivs(
                &real_source,
                source_iv,
                newparent,
                newname,
                &meta,
            );
        }

        let (real_dest, dest_iv) = self.encrypt_path(&dest)?;

        let meta = fs::symlink_metadata(&real_source)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        if (meta.is_dir() && (self.config.chained_name_iv || self.config.external_iv_chaining))
            || (meta.is_file() && self.config.external_iv_chaining)
        {
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

        // V7 symlink targets are encrypted using a path-derived IV (see `symlink`/`readlink`).
        // If the symlink name changes while `chained_name_iv` is enabled, the IV used to
        // decrypt/encrypt the symlink target changes. A plain `rename` would therefore
        // break `readlink`. Rewrite the symlink target under the destination IV.
        // Legacy targets don't depend on the link's path, so a plain rename works.
        // External IV chaining only affects file headers, which symlinks lack.
        if meta.is_symlink() && self.config.symlink_target_depends_on_path() {
            let dest_entry = NewEntry::from_path(real_dest, dest_iv)?;
            self.recreate_symlink(&real_source, &dest_entry, source_iv, &meta)?;

            // Remove source symlink.
            fs::remove_file(&real_source).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            return Ok(());
        }

        fs::rename(real_source, real_dest).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
    }

    /// Re-creates the symlink at `real_source` as `dest`, with its target
    /// re-encrypted from the source path IV to the destination's. Replaces
    /// any existing destination, as rename(2) would. The source is left in
    /// place.
    fn recreate_symlink(
        &self,
        real_source: &Path,
        dest: &NewEntry,
        source_iv: u64,
        meta: &fs::Metadata,
    ) -> OpResult {
        let target =
            fs::read_link(real_source).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
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
            .encrypt_filename(&plain_target, dest.iv)
            .map_err(|e| {
                error!("Failed to encrypt symlink target during rename: {}", e);
                libc::EIO
            })?;

        // Best-effort remove existing destination (rename(2) would replace).
        match dest.unlink() {
            Ok(()) | Err(libc::ENOENT) => {}
            Err(e) => return Err(e),
        }

        dest.symlink(OsStr::new(&enc_target))?;
        let atime = meta.accessed().ok();
        let mtime = meta.modified().ok();
        let _ = passthrough::utimens_path(&dest.real_path, atime, mtime);
        Ok(())
    }

    /// Rename in directory IV mode. Nothing below a directory depends on its
    /// name or location, so a directory moves with one rename(2). Entries
    /// whose own IVs derive from their entry IV are moved as in chained mode,
    /// and their encrypted xattrs are re-keyed to the new entry IV.
    fn rename_with_directory_ivs(
        &self,
        real_source: &Path,
        source_iv: u64,
        newparent: &Path,
        newname: &OsStr,
        meta: &fs::Metadata,
    ) -> OpResult {
        if meta.is_dir() {
            let (real_parent, _) = self.encrypt_path(newparent)?;
            return self.rename_directory_with_sidecar(real_source, &real_parent, newname, meta);
        }

        let dest = self.new_entry(&newparent.join(newname))?;

        if meta.is_file() && self.config.external_iv_chaining {
            // A copy rather than rename + in-place header rewrite: the copy
            // leaves the source readable if we die partway.
            if let Err(e) = self.copy_file_with_header_rewrite(real_source, &dest, source_iv) {
                let _ = dest.unlink();
                return Err(e);
            }
            self.rekey_xattrs_best_effort(real_source, &dest.real_path, source_iv, dest.iv);
            return fs::remove_file(real_source).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO));
        }

        if meta.is_symlink() && self.config.symlink_target_depends_on_path() {
            self.recreate_symlink(real_source, &dest, source_iv, meta)?;
            self.rekey_xattrs_best_effort(real_source, &dest.real_path, source_iv, dest.iv);
            return fs::remove_file(real_source).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO));
        }

        dest.rename_from(real_source)?;
        self.rekey_xattrs_best_effort(&dest.real_path, &dest.real_path, source_iv, dest.iv);
        Ok(())
    }

    /// Directory rename in directory IV mode: a single rename(2). Replacing
    /// an existing directory requires it to be empty but for its sidecar,
    /// which is removed first (so rename(2) sees an empty directory) and put
    /// back if the rename fails.
    fn rename_directory_with_sidecar(
        &self,
        real_source: &Path,
        real_dest_parent: &Path,
        newname: &OsStr,
        source_meta: &fs::Metadata,
    ) -> OpResult {
        let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
        // Held across the rename and the cache update, so a concurrent cache
        // miss can't re-insert the old path in between. The new name is
        // encrypted under it too, so the destination's parent can't be
        // replaced between choosing the name and moving into it.
        let _guard = self.sidecar_write_lock();
        let real_dest = &self.encrypt_name_in(real_dest_parent, newname)?;
        let removed = match fs::symlink_metadata(real_dest) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(errno(e)),
            Ok(dest_meta) if !dest_meta.is_dir() => return Err(libc::ENOTDIR),
            Ok(dest_meta)
                if (dest_meta.dev(), dest_meta.ino()) == (source_meta.dev(), source_meta.ino()) =>
            {
                // Renaming a directory onto itself does nothing.
                return Ok(());
            }
            Ok(_) => Some(self.remove_sidecar_of_empty_dir(real_dest)?),
        };
        match fs::rename(real_source, real_dest) {
            Ok(()) => {
                self.diriv_cache.rename_tree(real_source, real_dest);
                Ok(())
            }
            Err(e) => {
                if let Some(removed) = removed {
                    removed.restore(real_dest);
                }
                Err(errno(e))
            }
        }
    }

    /// Removes the sidecar of `dir`, which must hold nothing else, so the
    /// directory can be removed or replaced. Caller holds the sidecar write
    /// lock. Returns what is needed to put it back if that then fails.
    fn remove_sidecar_of_empty_dir(&self, dir: &Path) -> Result<RemovedSidecar, libc::c_int> {
        let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
        for entry in fs::read_dir(dir).map_err(errno)? {
            if entry.map_err(errno)?.file_name() != diriv::SIDECAR_NAME {
                return Err(libc::ENOTEMPTY);
            }
        }

        let sidecar = diriv::sidecar_path(dir);
        let (bytes, owner) = match diriv::read_sidecar(dir) {
            Ok(bytes) => {
                let owner = fs::symlink_metadata(&sidecar)
                    .ok()
                    .map(|m| (m.uid(), m.gid()));
                (Some(bytes), owner)
            }
            // An empty directory without a sidecar is what a crash
            // between the two steps of rmdir leaves behind.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
            Err(e) => {
                error!(
                    "Cannot remove {:?}: damaged {}: {}",
                    dir,
                    diriv::SIDECAR_NAME,
                    e
                );
                return Err(libc::EIO);
            }
        };

        // Unlinking needs write and search access to the directory itself,
        // which a read-only directory denies even though removing it doesn't.
        let original_mode = grant_dir_access(dir)?;
        let removed = RemovedSidecar {
            bytes,
            owner,
            original_mode,
        };
        if removed.bytes.is_some()
            && let Err(e) = fs::remove_file(&sidecar)
        {
            restore_dir_mode(dir, original_mode);
            return Err(errno(e));
        }
        Ok(removed)
    }

    /// Re-encrypts the encrypted xattrs of `real_src` from `old_iv` to
    /// `new_iv` and stores them on `real_dst` (which may be the same entry,
    /// after a rename). Failures are logged rather than failing the rename
    /// that has already happened.
    fn rekey_xattrs_best_effort(&self, real_src: &Path, real_dst: &Path, old_iv: u64, new_iv: u64) {
        if !self.config.encrypts_xattrs() || (real_src == real_dst && old_iv == new_iv) {
            return;
        }
        if let Err(e) = self.rekey_xattrs(real_src, real_dst, old_iv, new_iv) {
            warn!(
                "Failed to carry extended attributes from {:?} to {:?}: errno {}",
                real_src, real_dst, e
            );
        }
    }

    fn rekey_xattrs(&self, real_src: &Path, real_dst: &Path, old_iv: u64, new_iv: u64) -> OpResult {
        let c_src = c_path(real_src).map_err(|e| e.raw())?;
        let c_dst = c_path(real_dst).map_err(|e| e.raw())?;
        let names = match passthrough::listxattr_names_nofollow(&c_src) {
            Ok(names) => names,
            // No xattr support on the backing filesystem: nothing to carry.
            Err(e) if e.raw() == libc::ENOTSUP => return Ok(()),
            Err(e) => return Err(e.raw()),
        };
        let mut first_error = None;
        for stored_name in names {
            let Some(encoded) = std::str::from_utf8(&stored_name)
                .ok()
                .and_then(|n| n.strip_prefix(xattr_name::PREFIX))
            else {
                continue;
            };
            let result = (|| -> OpResult {
                let encrypted_name = xattr_name::decode(encoded).ok_or(libc::EINVAL)?;
                let name = self
                    .cipher
                    .decrypt_xattr_name(&encrypted_name, old_iv)
                    .map_err(|_| libc::EIO)?;
                let c_old =
                    std::ffi::CString::new(stored_name.clone()).map_err(|_| libc::EINVAL)?;
                let value =
                    passthrough::getxattr_value_nofollow(&c_src, &c_old).map_err(|e| e.raw())?;
                let value = self
                    .cipher
                    .decrypt_xattr_value(&value, old_iv)
                    .map_err(|_| libc::EIO)?;

                let new_name = xattr_name::encode(
                    &self
                        .cipher
                        .encrypt_xattr_name(&name, new_iv)
                        .map_err(|_| libc::EIO)?,
                );
                let new_value = self
                    .cipher
                    .encrypt_xattr_value(&value, new_iv)
                    .map_err(|_| libc::EIO)?;
                let c_new = std::ffi::CString::new(new_name).map_err(|_| libc::EINVAL)?;
                passthrough::setxattr_nofollow(&c_dst, &c_new, &new_value, 0)
                    .map_err(|e| e.raw())?;
                if real_src == real_dst && c_new != c_old {
                    passthrough::removexattr_nofollow(&c_src, &c_old).map_err(|e| e.raw())?;
                }
                Ok(())
            })();
            if let Err(e) = result {
                warn!(
                    "Skipping xattr {:?} on {:?}: errno {}",
                    encoded, real_src, e
                );
                first_error.get_or_insert(e);
            }
        }
        first_error.map_or(Ok(()), Err)
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
            let _ = fs::set_permissions(dest.physical, meta.permissions());
            let atime = meta.accessed().ok();
            let mtime = meta.modified().ok();
            let _ = passthrough::utimens_path(dest.physical, atime, mtime);
        } else if self.config.external_iv_chaining && meta.is_file() {
            let dest_entry = NewEntry::from_path(dest.physical.to_path_buf(), dest.iv)?;
            self.copy_file_with_header_rewrite(source.physical, &dest_entry, source.iv)?;
        } else if meta.is_symlink() {
            // Handle symlinks during recursive directory copies.
            // On V7 with chained_name_iv, symlink targets are encrypted using
            // the path IV of the symlink. If the symlink's path changes (due to parent
            // directory rename), we need to re-encrypt the target with the new IV.
            if self.config.symlink_target_depends_on_path() {
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
                // The target doesn't depend on the link's path - copy it as-is
                let target = fs::read_link(source.physical)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                passthrough_symlink(target.as_os_str(), dest.physical).map_err(|e| e.raw())?;
            }
            let atime = meta.accessed().ok();
            let mtime = meta.modified().ok();
            let _ = passthrough::utimens_path(dest.physical, atime, mtime);
        } else {
            // Standard copy for regular files without external IV chaining
            fs::copy(source.physical, dest.physical)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            // Best effort metadata copy
            let _ = fs::set_permissions(dest.physical, meta.permissions());
            let atime = meta.accessed().ok();
            let mtime = meta.modified().ok();
            let _ = passthrough::utimens_path(dest.physical, atime, mtime);
        }
        Ok(())
    }

    fn copy_file_with_header_rewrite(
        &self,
        real_src: &Path,
        dest: &NewEntry,
        src_iv: u64,
    ) -> OpResult {
        let real_dest = &dest.real_path;
        let dst_iv = dest.iv;
        // 1. Open both ends. The destination is opened without O_TRUNC so that,
        //    as in `open_impl`, it is reset under the lock rather than by
        //    open(2) — otherwise the reset lands on top of an in-flight
        //    read-modify-write by whoever already has it open.
        let mut src_f = File::open(real_src).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let mut dst_f = dest.open(libc::O_RDWR | libc::O_CREAT, 0o666)?;

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

        // 8. Copy permissions and timestamps
        if let Some(meta) = metadata {
            let _ = fs::set_permissions(real_dest, meta.permissions());
            let atime = meta.accessed().ok();
            let mtime = meta.modified().ok();
            let _ = passthrough::utimens_path(real_dest, atime, mtime);
        }

        Ok(())
    }
}

fn headerless_file_iv(header_size: u64, external_iv: u64) -> FileIv {
    FileIv::from_u64(if header_size == 0 { external_iv } else { 0 })
}

/// A sidecar removed so its directory could be removed or replaced, with what
/// is needed to put it back.
struct RemovedSidecar {
    /// `None` when the directory had no sidecar to begin with.
    bytes: Option<diriv::Sidecar>,
    owner: Option<(u32, u32)>,
    /// Mode to restore if write access was granted temporarily.
    original_mode: Option<u32>,
}

impl RemovedSidecar {
    /// Re-creates the sidecar with the same bytes, so the names already in
    /// the directory stay valid, and restores the directory's mode.
    fn restore(self, dir: &Path) {
        if let Some(bytes) = self.bytes {
            match diriv::create_sidecar(dir, &bytes) {
                Ok(()) => {
                    if let Some((uid, gid)) = self.owner {
                        let _ = std::os::unix::fs::lchown(
                            diriv::sidecar_path(dir),
                            Some(uid),
                            Some(gid),
                        );
                    }
                }
                Err(e) => error!(
                    "Failed to restore {} in {:?}; its names are now unreadable: {}",
                    diriv::SIDECAR_NAME,
                    dir,
                    e
                ),
            }
        }
        restore_dir_mode(dir, self.original_mode);
    }
}

/// Adds owner write and search permission to `dir` when this process lacks
/// them, returning the original mode to restore afterwards.
fn grant_dir_access(dir: &Path) -> Result<Option<u32>, libc::c_int> {
    use std::os::unix::fs::PermissionsExt;
    let c_dir = c_path(dir).map_err(|e| e.raw())?;
    if unsafe { libc::access(c_dir.as_ptr(), libc::W_OK | libc::X_OK) } == 0 {
        return Ok(None);
    }
    let mode = fs::symlink_metadata(dir)
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?
        .mode()
        & 0o7777;
    fs::set_permissions(dir, fs::Permissions::from_mode(mode | 0o700))
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    Ok(Some(mode))
}

fn restore_dir_mode(dir: &Path, original_mode: Option<u32>) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = original_mode {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(mode));
    }
}

impl EncFs {
    /// Generates a fresh per-file IV and writes its header at offset 0.
    ///
    /// Callers must hold the file's write lock: this replaces the IV every
    /// existing handle on the inode encrypts under.
    fn write_file_header(&self, file: &File, external_iv: u64) -> Result<FileIv, libc::c_int> {
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
    ) -> Result<Option<FileIv>, libc::c_int> {
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
        file_iv: FileIv,
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
        file_iv: FileIv,
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
            FileIv::from_u64(path_iv)
        } else {
            FileIv::from_u64(0)
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

        let plain_target_bytes = symlink_target::decrypt(
            self.cipher.as_ref(),
            &self.config,
            target.as_os_str().as_bytes(),
            path_iv,
        )
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
        self.new_entry(&new_path)?.link_from(&real_path)?;

        self.attr_for_path(Some(&new_path), None)
    }

    fn symlink_impl(
        &self,
        parent: &Path,
        name: &std::ffi::OsStr,
        target: &std::path::Path,
    ) -> Result<PathEntry<FileState>, libc::c_int> {
        debug!("symlink: {:?}/{:?} -> {:?}", parent, name, target);
        self.ensure_writable()?;

        let path = parent.join(name);
        let entry = self.new_entry(&path)?;

        let enc_target = symlink_target::encrypt(
            self.cipher.as_ref(),
            &self.config,
            target.as_os_str().as_bytes(),
            entry.iv,
        )
        .map_err(|e| {
            error!("Failed to encrypt symlink target: {}", e);
            libc::EIO
        })?;

        entry.symlink(OsStr::from_bytes(&enc_target))?;

        // Return the attributes of the entry we just created.
        self.entry_for_path(&path)
    }

    fn attr_for_path(
        &self,
        path: Option<&Path>,
        handle: Option<&FileHandle>,
    ) -> Result<FileAttr, libc::c_int> {
        Ok(self.attr_and_key_for_path(path, handle)?.0)
    }

    /// As [`EncFs::attr_for_path`], but also reports the backing file's
    /// identity, which the discovery operations need in order to attach the
    /// matching [`FileState`] to the entry they return.
    fn attr_and_key_for_path(
        &self,
        path: Option<&Path>,
        handle: Option<&FileHandle>,
    ) -> Result<(FileAttr, FileKey), libc::c_int> {
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

        Ok((
            self.attr_from_metadata(&metadata),
            (metadata.dev(), metadata.ino()),
        ))
    }

    /// Attributes plus node state for a path, as returned by the operations
    /// that hand a node back to the runtime.
    fn entry_for_path(&self, path: &Path) -> Result<PathEntry<FileState>, libc::c_int> {
        let (attr, key) = self.attr_and_key_for_path(Some(path), None)?;
        Ok(PathEntry::new(attr, self.file_states.get_by_key(key)))
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

    fn directory_snapshot(&self, path: &Path) -> Result<DirBuffer<FileState>, libc::c_int> {
        let (real_path, path_iv) = self.encrypt_path(path)?;
        let dir_iv = self.names_iv(&real_path, path_iv)?;

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
                        self.file_states
                            .get_by_key((metadata.dev(), metadata.ino())),
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
                        .unwrap_or(FileIv::from_u64(0)),
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
    ) -> Result<(PathEntry<FileState>, FileHandle), libc::c_int> {
        debug!(
            "create: {:?}/{:?} flags={} mode={}",
            parent, name, flags, mode
        );
        self.ensure_writable()?;
        let path = parent.join(name);
        let entry = self.new_entry(&path)?;
        let path_iv = entry.iv;

        // O_EXCL: fail if file already exists (POSIX open(2)).
        let mut open_flags = libc::O_RDWR | libc::O_CREAT;
        if (flags as i32 & libc::O_EXCL) != 0 {
            open_flags |= libc::O_EXCL;
        }
        // Not O_TRUNC: as in `open_impl`, resetting an existing file has to
        // happen under the per-file lock rather than inside open(2).
        let file = entry.open(open_flags, mode)?;

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
            PathEntry::new(attr, Arc::clone(&state)),
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
    ) -> Result<PathEntry<FileState>, libc::c_int> {
        let path = parent.join(name);
        debug!("mkdir: {:?} mode={:o}", path, mode);
        self.ensure_writable()?;

        if self.config.directory_iv {
            let (real_parent, _) = self.encrypt_path(parent)?;
            self.mkdir_with_sidecar(&req, &real_parent, name, mode)?;
        } else {
            use std::os::unix::fs::DirBuilderExt;
            let (real_path, _) = self.encrypt_path(&path)?;
            std::fs::DirBuilder::new()
                .mode(mode)
                .create(&real_path)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            set_ownership_path(&real_path, &req).map_err(|e| e.raw())?;
        }

        // Outside the sidecar lock: resolving the path may need to take it.
        self.entry_for_path(&path)
    }

    /// Creates directory `name` in `real_parent`, with its sidecar, under the
    /// sidecar write lock, removing the directory again if the sidecar cannot
    /// be written. The name is encrypted under the lock as well, so the
    /// parent can't be replaced by a directory it would be unreadable in.
    fn mkdir_with_sidecar(
        &self,
        req: &Request,
        real_parent: &Path,
        name: &OsStr,
        mode: u32,
    ) -> OpResult {
        use std::os::unix::fs::DirBuilderExt;
        let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
        let bytes = diriv::new_sidecar().map_err(|e| {
            error!("Failed to generate directory IV: {}", e);
            libc::EIO
        })?;
        let ivs = diriv::derive(self.cipher.as_ref(), &bytes).map_err(|e| {
            error!("Failed to derive directory IVs: {}", e);
            libc::EIO
        })?;

        let _guard = self.sidecar_write_lock();
        let real_path = &self.encrypt_name_in(real_parent, name)?;
        std::fs::DirBuilder::new()
            .mode(mode)
            .create(real_path)
            .map_err(errno)?;

        let result = grant_dir_access(real_path).and_then(|original_mode| {
            let created = diriv::create_sidecar(real_path, &bytes).map_err(errno);
            restore_dir_mode(real_path, original_mode);
            created
        });
        if let Err(e) = result {
            error!(
                "Failed to create {} in {:?}: errno {}",
                diriv::SIDECAR_NAME,
                real_path,
                e
            );
            let _ = fs::remove_file(diriv::sidecar_path(real_path));
            let _ = fs::remove_dir(real_path);
            return Err(e);
        }
        // Best effort, like the directory's own ownership.
        let _ = set_ownership_path(&diriv::sidecar_path(real_path), req);
        // Uncached if this fails; the first use loads it instead.
        if let Ok(id) = diriv::dir_id(real_path) {
            self.diriv_cache.insert(real_path, CachedDir { ivs, id });
        }
        // Still under the lock, so this can't land on a directory that has
        // replaced the new one.
        set_ownership_path(real_path, req).map_err(|e| e.raw())
    }

    fn mknod_impl(
        &self,
        req: Request,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        rdev: u32,
    ) -> Result<PathEntry<FileState>, libc::c_int> {
        let path = parent.join(name);
        debug!("mknod: {:?} mode={:o} rdev={}", path, mode, rdev);
        self.ensure_writable()?;
        let entry = self.new_entry(&path)?;

        let mode_t = mode as libc::mode_t;
        let mode_bits = mode_t & libc::S_IFMT;
        if mode_bits != libc::S_IFREG {
            entry.mknod(mode, rdev)?;
        } else {
            use std::io::Write;
            let header_size = self.config.header_size();
            let external_iv = if self.config.external_iv_chaining {
                entry.iv
            } else {
                0
            };
            let mut f = entry.open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode & 0o7777)?;
            if header_size > 0 {
                let (header, _iv) = self.cipher.encrypt_header(external_iv).map_err(|e| {
                    error!("Failed to generate header for mknod: {}", e);
                    libc::EIO
                })?;
                f.write_all(&header)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            }
        }

        entry.set_ownership(&req)?;

        self.entry_for_path(&path)
    }

    fn rmdir_impl(&self, parent: &Path, name: &OsStr) -> OpResult {
        let path = parent.join(name);
        debug!("rmdir: {:?}", path);
        self.ensure_writable()?;
        let (real_path, _) = self.encrypt_path(&path)?;
        if self.config.directory_iv {
            return self.rmdir_with_sidecar(&real_path);
        }
        fs::remove_dir(real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
    }

    /// Removes a directory whose only entry is its sidecar. If the removal
    /// still fails (say, an entry appeared behind the mount), the sidecar is
    /// put back with the same bytes so existing names stay valid.
    fn rmdir_with_sidecar(&self, real_path: &Path) -> OpResult {
        let errno = |e: std::io::Error| e.raw_os_error().unwrap_or(libc::EIO);
        let _guard = self.sidecar_write_lock();
        let meta = fs::symlink_metadata(real_path).map_err(errno)?;
        if !meta.is_dir() {
            return Err(libc::ENOTDIR);
        }
        let removed = self.remove_sidecar_of_empty_dir(real_path)?;
        match fs::remove_dir(real_path) {
            Ok(()) => {
                self.diriv_cache.forget_tree(real_path);
                Ok(())
            }
            Err(e) => {
                removed.restore(real_path);
                Err(errno(e))
            }
        }
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

        let (real_path, entry_iv) = self.encrypt_path(path)?;
        // Held until the attribute is written: see `xattr_iv_locked`.
        let _guard = self.config.directory_iv.then(|| self.sidecar_read_lock());
        let path_iv = self.xattr_iv_locked(&real_path, entry_iv)?;

        let name_bytes = name.as_bytes();

        if !self.config.encrypts_xattrs() {
            // Legacy volumes store attributes as-is, like C++ EncFS.
            let c_name = std::ffi::CString::new(name_bytes).map_err(|_| libc::EINVAL)?;
            let c_path = c_path(&real_path).map_err(|e| e.raw())?;
            passthrough::setxattr_nofollow(&c_path, &c_name, value, flags as i32)
                .map_err(|e| e.raw())?;
            // Drop any encrypted copy an earlier build stored, so the name
            // isn't listed twice.
            let _ = self.remove_encrypted_xattr(&real_path, name_bytes, path_iv);
            return Ok(());
        }

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

        // Store under the "user.encfs." prefix, with the encrypted name
        // base64-encoded so it is a legal attribute name everywhere.
        let final_name = xattr_name::encode(&encrypted_name);

        let c_name = std::ffi::CString::new(final_name).map_err(|_| libc::EINVAL)?;
        let c_path = c_path(&real_path).map_err(|e| e.raw())?;

        // Set xattr on underlying filesystem
        passthrough::setxattr_nofollow(&c_path, &c_name, &encrypted_value, flags as i32)
            .map_err(|e| e.raw())
    }

    fn getxattr_impl(&self, path: &Path, name: &OsStr) -> Result<Vec<u8>, libc::c_int> {
        debug!("getxattr: {:?} name={:?}", path, name);

        let (real_path, entry_iv) = self.encrypt_path(path)?;
        let path_iv = self.xattr_iv(&real_path, entry_iv)?;

        let name_bytes = name.as_bytes();

        if !self.config.encrypts_xattrs() {
            // Legacy volumes store attributes as-is, like C++ EncFS. Fall back
            // to an encrypted copy written by an earlier build.
            let c_name = std::ffi::CString::new(name_bytes).map_err(|_| libc::EINVAL)?;
            let c_path = c_path(&real_path).map_err(|e| e.raw())?;
            match passthrough::getxattr_value_nofollow(&c_path, &c_name) {
                Err(e) if e == Errno::ENOATTR => {}
                other => return other.map_err(|e| e.raw()),
            }
        }

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
        let lookup_name = xattr_name::encode(&encrypted_name);

        let c_name = std::ffi::CString::new(lookup_name).map_err(|_| libc::EINVAL)?;
        let c_path = c_path(&real_path).map_err(|e| e.raw())?;

        // Read the on-disk (encrypted) value; the caller's size limit is
        // applied by the trait wrapper against the decrypted length.
        let encrypted_value = match passthrough::getxattr_value_nofollow(&c_path, &c_name) {
            Ok(value) => value,
            // An attribute written before the alphabet change carries the
            // older spelling; try that before reporting it missing.
            Err(e) if e == Errno::ENOATTR => {
                let legacy = xattr_name::encode_legacy(&encrypted_name);
                let c_legacy = std::ffi::CString::new(legacy).map_err(|_| libc::EINVAL)?;
                passthrough::getxattr_value_nofollow(&c_path, &c_legacy).map_err(|e| e.raw())?
            }
            Err(e) => return Err(e.raw()),
        };

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

        let (real_path, entry_iv) = self.encrypt_path(path)?;
        let path_iv = self.xattr_iv(&real_path, entry_iv)?;

        let c_path = c_path(&real_path).map_err(|e| e.raw())?;

        // Read the on-disk list of xattr names; the caller's size limit is
        // applied by the trait wrapper against the decrypted list length.
        let names = passthrough::listxattr_names_nofollow(&c_path).map_err(|e| e.raw())?;

        // Process all xattr names in the list
        let mut decrypted_list = Vec::new();

        for name_bytes in names {
            let name_str = match std::str::from_utf8(&name_bytes) {
                Ok(s) => s,
                Err(_) if !self.config.encrypts_xattrs() => {
                    decrypted_list.extend_from_slice(&name_bytes);
                    decrypted_list.push(0);
                    continue;
                }
                Err(_) => continue, // Invalid UTF-8, skip
            };

            if let Some(encoded_part) = name_str.strip_prefix(xattr_name::PREFIX) {
                // This is an encrypted encfs attribute stored on disk
                // Extract the base64-encoded encrypted name
                match xattr_name::decode(encoded_part) {
                    Some(encrypted_name_bytes) => {
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
                    None => {
                        warn!("Failed to decode base64 xattr name: {}", name_str);
                        // Skip this name but continue
                    }
                }
            } else if !self.config.encrypts_xattrs() {
                // Legacy volumes store attributes as-is, like C++ EncFS.
                decrypted_list.extend_from_slice(&name_bytes);
                decrypted_list.push(0);
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

        let (real_path, entry_iv) = self.encrypt_path(path)?;
        // Held until the attribute is written: see `xattr_iv_locked`.
        let _guard = self.config.directory_iv.then(|| self.sidecar_read_lock());
        let path_iv = self.xattr_iv_locked(&real_path, entry_iv)?;

        let name_bytes = name.as_bytes();

        if !self.config.encrypts_xattrs() {
            // Legacy volumes store attributes as-is, like C++ EncFS. Fall back
            // to an encrypted copy written by an earlier build.
            let c_name = std::ffi::CString::new(name_bytes).map_err(|_| libc::EINVAL)?;
            let c_path = c_path(&real_path).map_err(|e| e.raw())?;
            match passthrough::removexattr_nofollow(&c_path, &c_name) {
                Err(e) if e == Errno::ENOATTR => {}
                other => return other.map_err(|e| e.raw()),
            }
        }

        self.remove_encrypted_xattr(&real_path, name_bytes, path_iv)
    }

    /// Removes the encrypted (`user.encfs.`-prefixed) form of attribute `name`.
    fn remove_encrypted_xattr(
        &self,
        real_path: &Path,
        name_bytes: &[u8],
        path_iv: u64,
    ) -> OpResult {
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
        let lookup_name = xattr_name::encode(&encrypted_name);

        let c_name = std::ffi::CString::new(lookup_name).map_err(|_| libc::EINVAL)?;
        let c_path = c_path(real_path).map_err(|e| e.raw())?;

        // Remove xattr from underlying filesystem, falling back to the older
        // spelling for attributes written before the alphabet change.
        match passthrough::removexattr_nofollow(&c_path, &c_name) {
            Err(e) if e == Errno::ENOATTR => {
                let legacy = xattr_name::encode_legacy(&encrypted_name);
                let c_legacy = std::ffi::CString::new(legacy).map_err(|_| libc::EINVAL)?;
                passthrough::removexattr_nofollow(&c_path, &c_legacy).map_err(|e| e.raw())
            }
            other => other.map_err(|e| e.raw()),
        }
    }
}

impl PathFilesystem for EncFs {
    type NodeState = FileState;
    type Handle = FileHandle;
    type DirHandle = DirBuffer<FileState>;

    // POSIX record locks are deliberately left to the kernel. Forwarding them
    // would mean taking every client's lock with `fcntl` in this one daemon
    // process, and POSIX locks are keyed by (process, inode): two clients could
    // never conflict, and either one closing a handle would drop the other's
    // locks. Leaving `getlk`/`setlk` unimplemented keeps `FUSE_POSIX_LOCKS` out
    // of the INIT reply, so the kernel enforces locks locally with the right
    // per-process semantics.
    const SUPPORTS_POSIX_LOCKS: bool = false;
    const SUPPORTS_FLOCK: bool = true;
    const SUPPORTS_READDIRPLUS: bool = true;

    /// A root whose backing directory cannot be stat'd is a broken mount, so
    /// rather than fail here (which the runtime cannot report) fall back to a
    /// sentinel key; every operation through it will fail on its own.
    fn root_state(&mut self) -> Arc<FileState> {
        let key = fs::symlink_metadata(&self.root)
            .map(|metadata| (metadata.dev(), metadata.ino()))
            .unwrap_or_default();
        self.file_states.get_by_key(key)
    }

    fn init(&self, _conn: &mut typed_fuse::ConnInfo) {
        debug!("init");
    }

    fn destroy(&self) {
        debug!("destroy");
    }

    fn lookup(
        &self,
        parent: PathNodeRef<'_, FileState>,
        name: &OsStr,
        _caller: &Request,
    ) -> Result<Option<PathEntry<FileState>>, Errno> {
        let path = parent.path().ok_or(Errno::ENOENT)?.join(name);
        match self.entry_for_path(&path) {
            Ok(entry) => Ok(Some(entry)),
            Err(libc::ENOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn getattr(
        &self,
        node: PathNodeRef<'_, FileState>,
        handle: Option<&FileHandle>,
        _caller: &Request,
    ) -> Result<FileAttr, Errno> {
        Ok(self.attr_for_path(node.path(), handle)?)
    }

    fn setattr(
        &self,
        node: PathNodeRef<'_, FileState>,
        handle: Option<&FileHandle>,
        set_attr: &SetAttr,
        caller: &Request,
    ) -> Result<FileAttr, Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let path = node.path();
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

    fn access(
        &self,
        node: PathNodeRef<'_, FileState>,
        mask: i32,
        caller: &Request,
    ) -> Result<(), Errno> {
        let path = node.path().ok_or(Errno::ENOENT)?;
        Ok(self.access_impl(*caller, path, mask as u32)?)
    }

    fn statfs(&self, path: &Path, _caller: &Request) -> Result<ReplyStatFs, Errno> {
        Ok(self.statfs_impl(path)?)
    }

    fn readlink(
        &self,
        node: PathNodeRef<'_, FileState>,
        caller: &Request,
    ) -> Result<PathBuf, Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        use std::os::unix::ffi::OsStringExt;
        let path = node.path().ok_or(Errno::ENOENT)?;
        Ok(PathBuf::from(OsString::from_vec(self.readlink_impl(path)?)))
    }

    fn symlink(
        &self,
        parent: PathNodeRef<'_, FileState>,
        name: &OsStr,
        target: &Path,
        caller: &Request,
    ) -> Result<PathEntry<FileState>, Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let parent = parent.path().ok_or(Errno::ENOENT)?;
        Ok(self.symlink_impl(parent, name, target)?)
    }

    fn link(
        &self,
        node: PathNodeRef<'_, FileState>,
        new_parent: PathNodeRef<'_, FileState>,
        new_name: &OsStr,
        caller: &Request,
    ) -> Result<FileAttr, Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let path = node.path().ok_or(Errno::ENOENT)?;
        let new_parent = new_parent.path().ok_or(Errno::ENOENT)?;
        Ok(self.link_impl(path, new_parent, new_name)?)
    }

    fn mknod(
        &self,
        parent: PathNodeRef<'_, FileState>,
        name: &OsStr,
        mode: u32,
        rdev: u32,
        _umask: u32,
        caller: &Request,
    ) -> Result<PathEntry<FileState>, Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let parent = parent.path().ok_or(Errno::ENOENT)?;
        Ok(self.mknod_impl(*caller, parent, name, mode, rdev)?)
    }

    fn mkdir(
        &self,
        parent: PathNodeRef<'_, FileState>,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        caller: &Request,
    ) -> Result<PathEntry<FileState>, Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let parent = parent.path().ok_or(Errno::ENOENT)?;
        Ok(self.mkdir_impl(*caller, parent, name, mode)?)
    }

    fn unlink(
        &self,
        parent: PathNodeRef<'_, FileState>,
        name: &OsStr,
        caller: &Request,
    ) -> Result<(), Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let parent = parent.path().ok_or(Errno::ENOENT)?;
        Ok(self.unlink_impl(parent, name)?)
    }

    fn rmdir(
        &self,
        parent: PathNodeRef<'_, FileState>,
        name: &OsStr,
        caller: &Request,
    ) -> Result<(), Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let parent = parent.path().ok_or(Errno::ENOENT)?;
        Ok(self.rmdir_impl(parent, name)?)
    }

    fn rename(
        &self,
        parent: PathNodeRef<'_, FileState>,
        name: &OsStr,
        new_parent: PathNodeRef<'_, FileState>,
        new_name: &OsStr,
        caller: &Request,
    ) -> Result<(), Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let parent = parent.path().ok_or(Errno::ENOENT)?;
        let new_parent = new_parent.path().ok_or(Errno::ENOENT)?;
        Ok(self.rename_internal(parent, name, new_parent, new_name)?)
    }

    fn opendir(
        &self,
        node: PathNodeRef<'_, FileState>,
        _flags: i32,
        caller: &Request,
    ) -> Result<Opened<DirBuffer<FileState>>, Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let path = node.path().ok_or(Errno::ENOENT)?;
        Ok(Opened::new(self.directory_snapshot(path)?))
    }

    fn readdir(
        &self,
        _node: PathNodeRef<'_, FileState>,
        handle: &DirBuffer<FileState>,
        offset: u64,
        sink: &mut dyn PathDirSink<FileState>,
        caller: &Request,
    ) -> Result<(), Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        handle.fill(offset, sink);
        Ok(())
    }

    fn readdirplus(
        &self,
        _node: PathNodeRef<'_, FileState>,
        handle: &DirBuffer<FileState>,
        offset: u64,
        sink: &mut dyn PathPlusDirSink<FileState>,
        caller: &Request,
    ) -> Result<(), Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        handle.fill_plus(offset, sink);
        Ok(())
    }

    fn open(
        &self,
        node: PathNodeRef<'_, FileState>,
        flags: i32,
        caller: &Request,
    ) -> Result<Opened<FileHandle>, Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let path = node.path().ok_or(Errno::ENOENT)?;
        Ok(Opened::new(self.open_impl(path, flags as u32)?))
    }

    fn read<'a>(
        &'a self,
        _node: PathNodeRef<'_, FileState>,
        handle: &'a FileHandle,
        offset: u64,
        size: usize,
        caller: &Request,
    ) -> Result<Cow<'a, [u8]>, Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let size = u32::try_from(size).unwrap_or(u32::MAX);
        Ok(Cow::Owned(self.read_impl(handle, offset, size)?))
    }

    fn write(
        &self,
        _node: PathNodeRef<'_, FileState>,
        handle: &FileHandle,
        data: &[u8],
        offset: u64,
        caller: &Request,
    ) -> Result<usize, Errno> {
        self.check_idle_lock(Access::HandleWrite, caller)?;
        Ok(self.write_impl(handle, offset, data)? as usize)
    }

    fn fsync(
        &self,
        _node: PathNodeRef<'_, FileState>,
        handle: &FileHandle,
        datasync: bool,
        _caller: &Request,
    ) -> Result<(), Errno> {
        let sync_result = if datasync {
            handle.file.sync_data()
        } else {
            handle.file.sync_all()
        };
        sync_result.map_err(|e| e.raw_os_error().unwrap_or(libc::EIO).into())
    }

    fn flock(
        &self,
        _node: PathNodeRef<'_, FileState>,
        handle: &FileHandle,
        operation: i32,
        _caller: &Request,
    ) -> Result<(), Errno> {
        let result = unsafe { libc::flock(handle.file.as_raw_fd(), operation) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }

    fn create(
        &self,
        parent: PathNodeRef<'_, FileState>,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        caller: &Request,
    ) -> Result<(PathEntry<FileState>, Opened<FileHandle>), Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let parent = parent.path().ok_or(Errno::ENOENT)?;
        let (entry, handle) = self.create_impl(*caller, parent, name, mode, flags as u32)?;
        Ok((entry, Opened::new(handle)))
    }

    fn setxattr(
        &self,
        node: PathNodeRef<'_, FileState>,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        caller: &Request,
    ) -> Result<(), Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let path = node.path().ok_or(Errno::ENOENT)?;
        Ok(self.setxattr_impl(path, name, value, flags as u32, 0)?)
    }

    fn getxattr(
        &self,
        node: PathNodeRef<'_, FileState>,
        name: &OsStr,
        size: usize,
        caller: &Request,
    ) -> Result<ReplyXAttr, Errno> {
        self.check_idle_lock(Access::XattrRead, caller)?;
        let path = node.path().ok_or(Errno::ENOENT)?;
        ReplyXAttr::sized(self.getxattr_impl(path, name)?, size)
    }

    fn listxattr(
        &self,
        node: PathNodeRef<'_, FileState>,
        size: usize,
        caller: &Request,
    ) -> Result<ReplyXAttr, Errno> {
        self.check_idle_lock(Access::XattrRead, caller)?;
        let path = node.path().ok_or(Errno::ENOENT)?;
        ReplyXAttr::sized(self.listxattr_impl(path)?, size)
    }

    fn removexattr(
        &self,
        node: PathNodeRef<'_, FileState>,
        name: &OsStr,
        caller: &Request,
    ) -> Result<(), Errno> {
        self.check_idle_lock(Access::Data, caller)?;
        let path = node.path().ok_or(Errno::ENOENT)?;
        Ok(self.removexattr_impl(path, name)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EncFs, FILE_STATE_SWEEP_FLOOR, FileHandle, FileState, FileStates, headerless_file_iv,
        is_apple_xattr, lock_source_and_dest,
    };
    use crate::config::{EncfsConfig, Interface};
    use crate::crypto::file_iv::FileIv;
    use crate::crypto::ssl::SslCipher;
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use typed_fuse::{Caller, PathFilesystem, PathNodeRef};

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
            FileIv::from_u64(0x1234_5678_9abc_def0)
        );
    }

    #[test]
    fn headered_files_ignore_external_iv() {
        assert_eq!(
            headerless_file_iv(8, 0x1234_5678_9abc_def0),
            FileIv::from_u64(0)
        );
    }

    #[test]
    fn recognizes_apple_xattrs() {
        assert!(is_apple_xattr("com.apple.provenance"));
        assert!(!is_apple_xattr("user.encfs.attribute"));
        assert!(!is_apple_xattr("com.example.attribute"));
    }

    fn test_fs() -> EncFs {
        let interface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let mut cipher = SslCipher::new(&interface, 192).unwrap();
        cipher.set_key(&[1u8; 24], &[2u8; 16]);
        EncFs::new(
            PathBuf::new(),
            Box::new(cipher),
            EncfsConfig::test_default(),
        )
    }

    fn test_caller() -> Caller {
        Caller {
            pid: 1,
            gid: 0,
            uid: 0,
            umask: 0,
        }
    }

    #[test]
    fn flush_is_a_noop_and_fsync_callbacks_forward_backing_file_errors() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::close(fds[0]) }, 0);

        // A pipe does not support synchronization. Using it as the backing
        // file proves these callbacks issue real sync syscalls rather than
        // inheriting PathFilesystem's successful no-op defaults. The errno
        // differs across platforms, so the regression condition is simply that
        // it propagates.
        let handle = FileHandle {
            file: unsafe { File::from_raw_fd(fds[1]) },
            headerless_iv: FileIv::from_u64(0),
            state: Arc::new(FileState::new((0, 0))),
        };
        let fs = test_fs();
        let caller = test_caller();

        let node = || PathNodeRef::new(None, &handle.state);

        assert!(fs.flush(node(), &handle, &caller).is_ok());
        assert!(fs.fsync(node(), &handle, false, &caller).is_err());
        assert!(fs.fsync(node(), &handle, true, &caller).is_err());
    }

    /// A directory IV volume in a fresh temporary directory.
    struct DirIvVolume {
        root: PathBuf,
        config: EncfsConfig,
        fs: EncFs,
    }

    impl DirIvVolume {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "encfs_fs_diriv_{}_{}",
                name,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir(&root).unwrap();
            crate::diriv::ensure_root(&root, true).unwrap();
            let mut config = EncfsConfig::standard_v7();
            config.chained_name_iv = false;
            config.directory_iv = true;
            config.external_iv_chaining = false;
            config.minimum_reader_version = config.required_v7_reader_version();
            let fs = Self::mount(&root, &config);
            Self { root, config, fs }
        }

        fn mount(root: &Path, config: &EncfsConfig) -> EncFs {
            let interface = Interface {
                name: "ssl/aes".to_string(),
                major: 3,
                minor: 0,
                age: 0,
            };
            let mut cipher = SslCipher::new(&interface, config.key_size).unwrap();
            cipher.set_key(&[3u8; 32], &[4u8; 16]);
            cipher.set_name_encoding(&config.name_iface);
            cipher.set_wide_file_iv(config.wide_file_iv);
            cipher.set_name_mac_includes_iv(true);
            EncFs::new(root.to_path_buf(), Box::new(cipher), config.clone())
        }

        /// Asserts that every entry in plaintext directory `dir` decodes on a
        /// fresh mount, and returns their names.
        fn names_after_remount(&self, dir: &str) -> Vec<OsString> {
            let fs = Self::mount(&self.root, &self.config);
            let (real_dir, _) = fs.encrypt_path(Path::new(dir)).unwrap();
            let mut names = Vec::new();
            for entry in std::fs::read_dir(&real_dir).unwrap() {
                let name = entry.unwrap().file_name();
                if name.as_bytes().starts_with(b".") {
                    continue;
                }
                let relative = real_dir.strip_prefix(&self.root).unwrap().join(&name);
                let (plain, _) = fs
                    .decrypt_path(&relative)
                    .unwrap_or_else(|e| panic!("{:?} in {} is unreadable: errno {}", name, dir, e));
                names.push(plain.file_name().unwrap().to_os_string());
            }
            names.sort();
            names
        }
    }

    impl Drop for DirIvVolume {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn caller() -> Caller {
        Caller {
            pid: 1,
            gid: unsafe { libc::getgid() },
            uid: unsafe { libc::getuid() },
            umask: 0,
        }
    }

    /// Ways of putting a different directory at `/dst`.
    #[derive(Clone, Copy, Debug)]
    enum Replace {
        /// `rename /src /dst`, onto the empty `/dst`.
        RenameOver,
        /// `rmdir /dst; mkdir /dst`.
        Recreate,
    }

    impl Replace {
        fn run(self, fs: &EncFs) {
            match self {
                Replace::RenameOver => fs
                    .rename_internal(
                        Path::new("/"),
                        OsStr::new("src"),
                        Path::new("/"),
                        OsStr::new("dst"),
                    )
                    .unwrap(),
                Replace::Recreate => {
                    fs.rmdir_impl(Path::new("/"), OsStr::new("dst")).unwrap();
                    fs.mkdir_impl(caller(), Path::new("/"), OsStr::new("dst"), 0o755)
                        .unwrap();
                }
            }
        }
    }

    type CreateOp = fn(&EncFs) -> Result<(), libc::c_int>;

    /// Ways of creating `/dst/new`.
    const CREATE_OPS: &[(&str, CreateOp)] = &[
        ("create", |fs| {
            fs.create_impl(caller(), Path::new("/dst"), OsStr::new("new"), 0o644, 0)
                .map(drop)
        }),
        ("mknod", |fs| {
            fs.mknod_impl(
                caller(),
                Path::new("/dst"),
                OsStr::new("new"),
                libc::S_IFREG as u32 | 0o644,
                0,
            )
            .map(drop)
        }),
        ("mkfifo", |fs| {
            fs.mknod_impl(
                caller(),
                Path::new("/dst"),
                OsStr::new("new"),
                libc::S_IFIFO as u32 | 0o644,
                0,
            )
            .map(drop)
        }),
        ("symlink", |fs| {
            fs.symlink_impl(Path::new("/dst"), OsStr::new("new"), Path::new("target"))
                .map(drop)
        }),
        ("link", |fs| {
            fs.link_impl(Path::new("/file"), Path::new("/dst"), OsStr::new("new"))
                .map(drop)
        }),
        ("rename", |fs| {
            fs.rename_internal(
                Path::new("/"),
                OsStr::new("file"),
                Path::new("/dst"),
                OsStr::new("new"),
            )
        }),
    ];

    /// The review scenario: `/dst` is replaced after an operation has
    /// encrypted a name for it but before the backing entry is created. The
    /// operation must fail rather than leave a name encrypted for the old
    /// directory inside the new one.
    #[test]
    fn creation_fails_when_its_directory_is_replaced_midway() {
        for replace in [Replace::RenameOver, Replace::Recreate] {
            for (op_name, op) in CREATE_OPS {
                let vol = DirIvVolume::new(&format!("race_{:?}_{}", replace, op_name));
                let fs = &vol.fs;
                let root = Path::new("/");
                fs.mkdir_impl(caller(), root, OsStr::new("dst"), 0o755)
                    .unwrap();
                fs.mkdir_impl(caller(), root, OsStr::new("src"), 0o755)
                    .unwrap();
                fs.create_impl(caller(), Path::new("/src"), OsStr::new("kept"), 0o644, 0)
                    .unwrap();
                fs.create_impl(caller(), root, OsStr::new("file"), 0o644, 0)
                    .unwrap();

                *fs.race_hook.lock().unwrap() = Some(Box::new(move |fs: &EncFs| replace.run(fs)));
                let result = op(fs);
                assert!(
                    fs.race_hook.lock().unwrap().is_none(),
                    "{op_name}: the hook never ran"
                );
                assert_eq!(result, Err(libc::ENOENT), "{replace:?} during {op_name}");

                let expected: Vec<OsString> = match replace {
                    Replace::RenameOver => vec!["kept".into()],
                    Replace::Recreate => vec![],
                };
                assert_eq!(
                    vol.names_after_remount("/dst"),
                    expected,
                    "{replace:?} during {op_name}"
                );
            }
        }
    }

    /// Without the race, the same operations go through.
    #[test]
    fn creation_succeeds_in_an_unreplaced_directory() {
        for (op_name, op) in CREATE_OPS {
            let vol = DirIvVolume::new(&format!("norace_{}", op_name));
            let fs = &vol.fs;
            fs.mkdir_impl(caller(), Path::new("/"), OsStr::new("dst"), 0o755)
                .unwrap();
            fs.create_impl(caller(), Path::new("/"), OsStr::new("file"), 0o644, 0)
                .unwrap();
            assert_eq!(op(fs), Ok(()), "{op_name}");
            assert_eq!(vol.names_after_remount("/dst"), vec![OsString::from("new")]);
        }
    }

    /// A cached IV for a path now holding another directory (here, swapped
    /// behind the mount) fails the operation once, then is reloaded.
    #[test]
    fn stale_cache_entry_fails_once_and_is_reloaded() {
        let vol = DirIvVolume::new("stale_cache");
        let fs = &vol.fs;
        let root = Path::new("/");
        fs.mkdir_impl(caller(), root, OsStr::new("dst"), 0o755)
            .unwrap();
        fs.mkdir_impl(caller(), root, OsStr::new("other"), 0o755)
            .unwrap();
        fs.create_impl(caller(), Path::new("/dst"), OsStr::new("a"), 0o644, 0)
            .unwrap();

        let (real_dst, _) = fs.encrypt_path(Path::new("/dst")).unwrap();
        let (real_other, _) = fs.encrypt_path(Path::new("/other")).unwrap();
        std::fs::rename(&real_dst, vol.root.join("moved-away")).unwrap();
        std::fs::rename(&real_other, &real_dst).unwrap();

        let create = || {
            fs.create_impl(caller(), Path::new("/dst"), OsStr::new("b"), 0o644, 0)
                .map(drop)
        };
        assert_eq!(create(), Err(libc::ENOENT));
        assert_eq!(create(), Ok(()));
        assert_eq!(vol.names_after_remount("/dst"), vec![OsString::from("b")]);
    }
}
