//! Per-directory name IVs ("directory IV" mode, V7 only).
//!
//! Every ciphertext directory, including the volume root, holds a sidecar file
//! [`SIDECAR_NAME`] with [`SIDECAR_LEN`] random plaintext bytes. The names
//! inside the directory are encrypted under an IV derived from those bytes
//! (see [`crate::crypto::cipher::Cipher::directory_ivs`]) rather than from the
//! directory's path, so a directory moves with a single `rename(2)` and takes
//! its IV with it. See `docs/adr/0002-per-directory-name-iv.md`.
//!
//! The sidecar name starts with `.`, which neither filename alphabet contains,
//! so it never collides with an encrypted name, and every tree walker already
//! skips dot-prefixed entries.

use crate::config::EncfsConfig;
use crate::crypto::cipher::Cipher;
use rust_i18n::t;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// File name of the sidecar inside each ciphertext directory.
pub const SIDECAR_NAME: &str = ".encfs.diriv";

/// Exact size of a sidecar in bytes.
pub const SIDECAR_LEN: usize = 16;

/// The raw contents of a sidecar.
pub type Sidecar = [u8; SIDECAR_LEN];

/// The IVs a directory's sidecar yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirIvs {
    /// IV for the names inside the directory.
    pub name_iv: u64,
}

/// Why a directory's IVs could not be determined.
#[derive(Debug)]
pub enum Error {
    /// The directory itself does not exist or is not a directory.
    NoDirectory(io::Error),
    /// The directory exists but has no sidecar.
    MissingSidecar,
    /// The sidecar is not a regular file of exactly [`SIDECAR_LEN`] bytes.
    InvalidSidecar,
    /// Any other failure reading the sidecar or deriving the IVs.
    Io(io::Error),
}

impl Error {
    /// The errno a filesystem operation reports for this error: the
    /// directory's own lookup error when it is missing, and `EIO` for a
    /// directory whose sidecar is missing or damaged.
    pub fn errno(&self) -> libc::c_int {
        match self {
            Error::NoDirectory(e) => e.raw_os_error().unwrap_or(libc::ENOENT),
            Error::MissingSidecar | Error::InvalidSidecar => libc::EIO,
            Error::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
        }
    }

    /// Whether this is a damaged directory (as opposed to a missing one).
    pub fn is_damaged(&self) -> bool {
        matches!(self, Error::MissingSidecar | Error::InvalidSidecar)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoDirectory(e) => write!(f, "{}", e),
            Error::MissingSidecar => write!(f, "missing {} file", SIDECAR_NAME),
            Error::InvalidSidecar => write!(
                f,
                "{} is not a regular file of {} bytes",
                SIDECAR_NAME, SIDECAR_LEN
            ),
            Error::Io(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}

/// Path of the sidecar inside `dir`.
pub fn sidecar_path(dir: &Path) -> PathBuf {
    dir.join(SIDECAR_NAME)
}

/// Generates fresh random sidecar contents.
pub fn new_sidecar() -> io::Result<Sidecar> {
    let mut bytes = [0u8; SIDECAR_LEN];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes)
}

/// Reads the sidecar in `dir`, returning its bytes and the metadata of the
/// file they were read from.
///
/// Fails with `NotFound` when there is no sidecar, and `InvalidData` when the
/// entry is a symlink or anything other than a regular file of exactly
/// [`SIDECAR_LEN`] bytes.
fn read_sidecar_with_metadata(dir: &Path) -> io::Result<(Sidecar, fs::Metadata)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, Error::InvalidSidecar);
    // O_NONBLOCK so a FIFO planted under the name cannot hang the open.
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(sidecar_path(dir))
    {
        Ok(file) => file,
        // O_NOFOLLOW on a symlink: ELOOP, or EMLINK on FreeBSD.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK)) => {
            return Err(invalid());
        }
        Err(e) => return Err(e),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != SIDECAR_LEN as u64 {
        return Err(invalid());
    }
    let mut bytes = [0u8; SIDECAR_LEN];
    read_exact_at(&file, &mut bytes)?;
    Ok((bytes, metadata))
}

fn read_exact_at(file: &File, buf: &mut [u8]) -> io::Result<()> {
    file.read_exact_at(buf, 0).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::new(io::ErrorKind::InvalidData, Error::InvalidSidecar)
        } else {
            e
        }
    })
}

/// Reads the sidecar in `dir`. See [`read_sidecar_with_metadata`] for errors.
pub fn read_sidecar(dir: &Path) -> io::Result<Sidecar> {
    read_sidecar_with_metadata(dir).map(|(bytes, _)| bytes)
}

/// Creates the sidecar in `dir` with the given contents, mode 0444.
///
/// Never replaces an existing entry (`O_EXCL`, `O_NOFOLLOW`), so it fails with
/// `AlreadyExists` if one is present. A partially written file is removed.
pub fn create_sidecar(dir: &Path, bytes: &Sidecar) -> io::Result<()> {
    let path = sidecar_path(dir);
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    if let Err(e) = file.write_all_at(bytes, 0) {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(e);
    }
    Ok(())
}

/// The IVs a sidecar's contents yield.
pub fn derive(cipher: &dyn Cipher, bytes: &Sidecar) -> Result<DirIvs, Error> {
    let (name_iv, _reserved) = cipher
        .directory_ivs(bytes)
        .map_err(|e| Error::Io(io::Error::other(e.to_string())))?;
    Ok(DirIvs { name_iv })
}

/// Turns a failed sidecar read into an [`Error`], checking whether the
/// directory itself exists to tell a missing directory from a damaged one.
fn classify(dir: &Path, err: io::Error) -> Error {
    if err.kind() == io::ErrorKind::InvalidData {
        return Error::InvalidSidecar;
    }
    let missing = err.kind() == io::ErrorKind::NotFound;
    if missing || err.raw_os_error() == Some(libc::ENOTDIR) {
        match fs::symlink_metadata(dir) {
            Err(e) => return Error::NoDirectory(e),
            Ok(m) if !m.is_dir() => {
                return Error::NoDirectory(io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            Ok(_) if missing => return Error::MissingSidecar,
            Ok(_) => {}
        }
    }
    Error::Io(err)
}

/// Reads and derives the IVs of `dir`, uncached.
pub fn load(cipher: &dyn Cipher, dir: &Path) -> Result<DirIvs, Error> {
    let bytes = read_sidecar(dir).map_err(|e| classify(dir, e))?;
    derive(cipher, &bytes)
}

/// The IV for the names inside `backing_dir`, whose own path IV is `path_iv`.
///
/// Legacy modes return `path_iv` unchanged (the chain value, or 0 when names
/// are unchained); directory IV mode reads the directory's sidecar. Together
/// with [`child_path_iv`] this lets one walk loop serve every mode.
pub fn names_iv(
    config: &EncfsConfig,
    cipher: &dyn Cipher,
    backing_dir: &Path,
    path_iv: u64,
) -> Result<u64, Error> {
    if config.directory_iv {
        Ok(load(cipher, backing_dir)?.name_iv)
    } else {
        Ok(path_iv)
    }
}

/// The path IV of an entry whose name encrypted to `next_iv`: `next_iv` when
/// IVs depend on the entry's name (`chained_name_iv` or directory IV mode),
/// else 0.
pub fn child_path_iv(config: &EncfsConfig, next_iv: u64) -> u64 {
    if config.chained_name_iv || config.directory_iv {
        next_iv
    } else {
        0
    }
}

/// Makes sure the volume root has a sidecar before mounting.
///
/// A missing root sidecar is created only when the root holds no ciphertext
/// entries (nothing whose name was encrypted under the lost IV) and the mount
/// is writable. Otherwise the mount must fail rather than run with names that
/// cannot be decrypted.
pub fn ensure_root(root: &Path, writable: bool) -> anyhow::Result<()> {
    match read_sidecar(root) {
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            anyhow::bail!(
                "{}",
                t!(
                    "lib.diriv_root_invalid",
                    path = sidecar_path(root).display()
                )
            );
        }
        Err(e) => return Err(e.into()),
    }

    let has_ciphertext = fs::read_dir(root)?.any(|entry| {
        entry
            .map(|e| !e.file_name().as_encoded_bytes().starts_with(b"."))
            .unwrap_or(true)
    });
    if has_ciphertext {
        anyhow::bail!(
            "{}",
            t!(
                "lib.diriv_root_missing",
                path = sidecar_path(root).display()
            )
        );
    }
    if !writable {
        anyhow::bail!(
            "{}",
            t!(
                "lib.diriv_root_missing_read_only",
                path = sidecar_path(root).display()
            )
        );
    }
    match create_sidecar(root, &new_sidecar()?) {
        // Lost a race with another creator; theirs is as good as ours.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            read_sidecar(root)?;
            Ok(())
        }
        other => Ok(other?),
    }
}

/// Entries kept before the cache is cleared wholesale.
const CACHE_LIMIT: usize = 4096;

/// Identity of a backing directory: `(st_dev, st_ino)`.
pub type DirId = (u64, u64);

/// The identity of the directory at `dir`, without following a final
/// symlink.
pub fn dir_id(dir: &Path) -> io::Result<DirId> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(dir)?;
    Ok((m.dev(), m.ino()))
}

/// A cached directory: its IVs and the identity of the directory they were
/// read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachedDir {
    pub ivs: DirIvs,
    pub id: DirId,
}

/// Cache of derived directory IVs, keyed by backing directory path.
///
/// Entries are trusted without touching the disk. That is sound because,
/// while a volume is mounted, every change to its backing directory goes
/// through the mount: modifying it behind a live mount is unsupported. The
/// filesystem keeps the cache in step with its own changes instead:
/// [`DirIvCache::insert`] on mkdir, [`DirIvCache::forget_tree`] on rmdir, and
/// [`DirIvCache::rename_tree`] when a directory moves. Callers serialize those
/// against [`DirIvCache::load`] (the sidecar lock in `crate::fs`), so a
/// concurrent miss cannot re-insert a path that was just moved or removed.
///
/// That keeps each entry true of the directory *at its path*, but the
/// directory at a path can still be replaced between a lookup and the
/// operation that uses it. Each entry therefore records the directory's
/// identity, so a caller holding the directory open can check that the IVs
/// belong to the directory it is about to write into.
#[derive(Default)]
pub struct DirIvCache {
    entries: Mutex<HashMap<PathBuf, CachedDir>>,
}

impl DirIvCache {
    /// The cached IVs of `dir`.
    pub fn get(&self, dir: &Path) -> Option<CachedDir> {
        self.lock().get(dir).copied()
    }

    /// Reads and derives the IVs of `dir`, and caches them. The caller must
    /// keep directory lifecycle changes out while this runs, so the sidecar
    /// and the identity are those of the same directory.
    pub fn load(&self, cipher: &dyn Cipher, dir: &Path) -> Result<CachedDir, Error> {
        let ivs = load(cipher, dir)?;
        let id = dir_id(dir).map_err(Error::NoDirectory)?;
        let entry = CachedDir { ivs, id };
        self.insert(dir, entry);
        Ok(entry)
    }

    /// Records the IVs of a directory whose sidecar was just written.
    pub fn insert(&self, dir: &Path, entry: CachedDir) {
        let mut entries = self.lock();
        if entries.len() >= CACHE_LIMIT {
            entries.clear();
        }
        entries.insert(dir.to_path_buf(), entry);
    }

    /// Drops the entry for `dir` if it still describes the directory `id`.
    pub fn forget_if(&self, dir: &Path, id: DirId) {
        let mut entries = self.lock();
        if entries.get(dir).is_some_and(|entry| entry.id == id) {
            entries.remove(dir);
        }
    }

    /// Drops the entries for `dir` and everything below it.
    pub fn forget_tree(&self, dir: &Path) {
        self.lock().retain(|path, _| !path.starts_with(dir));
    }

    /// Moves the entries for `from` and everything below it to the same
    /// place under `to`, replacing whatever was cached under `to`.
    pub fn rename_tree(&self, from: &Path, to: &Path) {
        let mut entries = self.lock();
        let moved: Vec<_> = entries
            .iter()
            .filter_map(|(path, entry)| {
                let rest = path.strip_prefix(from).ok()?;
                Some((to.join(rest), *entry))
            })
            .collect();
        entries.retain(|path, _| !path.starts_with(from) && !path.starts_with(to));
        entries.extend(moved);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, CachedDir>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Interface;
    use crate::crypto::ssl::SslCipher;
    use std::os::unix::fs::MetadataExt;

    fn cipher() -> Box<dyn Cipher> {
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let mut cipher = SslCipher::new(&iface, 256).unwrap();
        cipher.set_key(&[7u8; 32], &[8u8; 16]);
        Box::new(cipher)
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("encfs_diriv_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn create_then_read_round_trips() {
        let dir = temp_dir("roundtrip");
        let bytes = new_sidecar().unwrap();
        create_sidecar(&dir, &bytes).unwrap();
        assert_eq!(read_sidecar(&dir).unwrap(), bytes);
        let mode = fs::metadata(sidecar_path(&dir)).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o444);
        // Written once: a second create never replaces it.
        let err = create_sidecar(&dir, &[0u8; SIDECAR_LEN]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(read_sidecar(&dir).unwrap(), bytes);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn damaged_sidecars_fail_closed() {
        let cipher = cipher();
        let dir = temp_dir("damaged");

        // Missing, in an existing directory.
        let err = load(cipher.as_ref(), &dir).unwrap_err();
        assert!(matches!(err, Error::MissingSidecar), "{err:?}");
        assert_eq!(err.errno(), libc::EIO);

        for contents in [&[1u8; 15][..], &[1u8; 17][..], &[][..]] {
            fs::write(sidecar_path(&dir), contents).unwrap();
            let err = load(cipher.as_ref(), &dir).unwrap_err();
            assert!(matches!(err, Error::InvalidSidecar), "{err:?}");
            assert_eq!(err.errno(), libc::EIO);
            fs::remove_file(sidecar_path(&dir)).unwrap();
        }

        // A directory, and a symlink to a valid file, are not sidecars.
        fs::create_dir(sidecar_path(&dir)).unwrap();
        assert!(matches!(
            load(cipher.as_ref(), &dir).unwrap_err(),
            Error::InvalidSidecar
        ));
        fs::remove_dir(sidecar_path(&dir)).unwrap();
        let target = dir.join("target");
        fs::write(&target, [1u8; SIDECAR_LEN]).unwrap();
        std::os::unix::fs::symlink(&target, sidecar_path(&dir)).unwrap();
        assert!(matches!(
            load(cipher.as_ref(), &dir).unwrap_err(),
            Error::InvalidSidecar
        ));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_directory_is_enoent_not_eio() {
        let cipher = cipher();
        let dir = temp_dir("nodir");
        let err = load(cipher.as_ref(), &dir.join("absent")).unwrap_err();
        assert_eq!(err.errno(), libc::ENOENT);
        assert!(!err.is_damaged());

        fs::write(dir.join("file"), b"x").unwrap();
        let err = load(cipher.as_ref(), &dir.join("file")).unwrap_err();
        assert_eq!(err.errno(), libc::ENOTDIR);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn walk_helpers_keep_legacy_modes_unchanged() {
        let cipher = cipher();
        let mut config = EncfsConfig::test_default();
        let nowhere = Path::new("/nonexistent/encfs/diriv");
        assert_eq!(names_iv(&config, cipher.as_ref(), nowhere, 42).unwrap(), 42);
        assert_eq!(child_path_iv(&config, 42), 42);
        config.chained_name_iv = false;
        assert_eq!(child_path_iv(&config, 42), 0);
        config.directory_iv = true;
        assert_eq!(child_path_iv(&config, 42), 42);
        assert!(names_iv(&config, cipher.as_ref(), nowhere, 42).is_err());
    }

    fn ivs(n: u64) -> CachedDir {
        CachedDir {
            ivs: DirIvs { name_iv: n },
            id: (1, n),
        }
    }

    #[test]
    fn cache_serves_loaded_ivs_without_rereading() {
        let cipher = cipher();
        let dir = temp_dir("cache");
        create_sidecar(&dir, &[1u8; SIDECAR_LEN]).unwrap();
        let cache = DirIvCache::default();
        assert_eq!(cache.get(&dir), None);
        let loaded = cache.load(cipher.as_ref(), &dir).unwrap();
        assert_eq!(
            loaded.ivs,
            derive(cipher.as_ref(), &[1u8; SIDECAR_LEN]).unwrap()
        );
        assert_eq!(loaded.id, dir_id(&dir).unwrap());

        // Trusted as is: nothing changes behind a live mount.
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(cache.get(&dir), Some(loaded));
    }

    #[test]
    fn rename_tree_moves_a_directory_and_its_descendants() {
        let cache = DirIvCache::default();
        cache.insert(Path::new("/r/a"), ivs(1));
        cache.insert(Path::new("/r/a/x"), ivs(2));
        cache.insert(Path::new("/r/ab"), ivs(3));
        cache.insert(Path::new("/r/b/old"), ivs(4));
        cache.insert(Path::new("/r/b"), ivs(5));

        cache.rename_tree(Path::new("/r/a"), Path::new("/r/b"));
        assert_eq!(cache.get(Path::new("/r/a")), None);
        assert_eq!(cache.get(Path::new("/r/a/x")), None);
        assert_eq!(cache.get(Path::new("/r/b")), Some(ivs(1)));
        assert_eq!(cache.get(Path::new("/r/b/x")), Some(ivs(2)));
        assert_eq!(
            cache.get(Path::new("/r/b/old")),
            None,
            "whatever was under the destination is gone"
        );
        assert_eq!(
            cache.get(Path::new("/r/ab")),
            Some(ivs(3)),
            "a sibling sharing a name prefix is not part of the tree"
        );

        cache.forget_if(Path::new("/r/b"), ivs(9).id);
        assert_eq!(
            cache.get(Path::new("/r/b")),
            Some(ivs(1)),
            "an entry for another directory is kept"
        );
        cache.forget_if(Path::new("/r/b"), ivs(1).id);
        assert_eq!(cache.get(Path::new("/r/b")), None);
        cache.insert(Path::new("/r/b"), ivs(1));

        cache.forget_tree(Path::new("/r/b"));
        assert_eq!(cache.get(Path::new("/r/b")), None);
        assert_eq!(cache.get(Path::new("/r/b/x")), None);
        assert_eq!(cache.get(Path::new("/r/ab")), Some(ivs(3)));
    }

    #[test]
    fn cache_is_bounded() {
        let cache = DirIvCache::default();
        for n in 0..(CACHE_LIMIT as u64 + 10) {
            cache.insert(&PathBuf::from(format!("/r/{n}")), ivs(n));
        }
        assert!(cache.lock().len() <= CACHE_LIMIT);
    }

    #[test]
    fn ensure_root_creates_only_for_empty_writable_roots() {
        let root = temp_dir("root");
        fs::write(root.join(".encfs7"), b"config").unwrap();

        assert!(ensure_root(&root, false).is_err(), "read-only mount");
        assert!(!sidecar_path(&root).exists());

        ensure_root(&root, true).unwrap();
        let bytes = read_sidecar(&root).unwrap();
        ensure_root(&root, true).unwrap();
        assert_eq!(read_sidecar(&root).unwrap(), bytes, "never regenerated");

        // A root with ciphertext entries but no sidecar is refused.
        fs::remove_file(sidecar_path(&root)).unwrap();
        fs::write(root.join("CIPHERTEXTNAME"), b"x").unwrap();
        assert!(ensure_root(&root, true).is_err());
        assert!(!sidecar_path(&root).exists());

        fs::write(sidecar_path(&root), [0u8; 3]).unwrap();
        assert!(ensure_root(&root, true).is_err(), "invalid sidecar");

        fs::remove_dir_all(root).unwrap();
    }
}
