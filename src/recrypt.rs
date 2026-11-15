//! Copies of backing entries under a new path IV: what moving an entry
//! takes where its stored bytes depend on its path (see
//! [`EncfsConfig::file_contents_depend_on_path`],
//! [`EncfsConfig::children_depend_on_path`] and
//! [`EncfsConfig::symlink_target_depends_on_path`]). Forward-mode rename
//! and `encfsctl fsck` (ADR 0007) both build their copies here, on backing
//! paths alone; [`Hooks`] carries what differs between them.
//!
//! A copy never removes its source. Every file it writes, and every
//! directory it builds once its entries are in place, is synced through
//! [`Hooks::sync`], so the caller can remove the source as soon as the copy
//! is in place.

use crate::config::EncfsConfig;
use crate::conflict::{Candidate, Probe, sorted_entries};
use crate::crypto::cipher::Cipher;
use crate::crypto::file::reencrypt_blocks;
use crate::crypto::file_iv::FileIv;
use crate::diriv;
use crate::symlink_target;
use anyhow::{Context, Result, bail};
use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use typed_fuse::passthrough;

/// What the caller of [`Recrypt::copy_tree`] adds around the copy.
pub trait Hooks {
    /// Writes the new regular file `dst` with the contents of `src`
    /// re-encrypted from path IV `src_iv` to `dst_iv`, and syncs it.
    /// Metadata is the tree copy's job.
    fn copy_file(
        &mut self,
        r: &Recrypt<'_>,
        src: &Path,
        src_iv: u64,
        dst: &Path,
        dst_iv: u64,
    ) -> Result<()> {
        let input = File::open(src)?;
        let output = create_file(dst)?;
        r.copy_file_contents(&input, src_iv, &output, dst_iv)?;
        self.sync(&output)
    }

    /// Syncs a file or directory of the copy: in full by default, so it
    /// survives a crash once the source is gone.
    fn sync(&mut self, file: &File) -> Result<()> {
        diriv::sync_file(file, false).context("syncing the copy")?;
        Ok(())
    }

    /// The new inode `dst` was made from the source inode behind `meta`
    /// and given its attributes, mode and times. The source inode goes
    /// away with the source; a linked one is never reported.
    fn finished(&mut self, _meta: &fs::Metadata, _dst: &Path) {}

    /// A problem that didn't stop the copy.
    fn warning(&mut self, path: &Path, error: &anyhow::Error);
}

/// Re-encrypting copies for one volume.
pub struct Recrypt<'a> {
    config: &'a EncfsConfig,
    cipher: &'a dyn Cipher,
}

impl<'a> Recrypt<'a> {
    pub fn new(config: &'a EncfsConfig, cipher: &'a dyn Cipher) -> Self {
        Self { config, cipher }
    }

    /// Whether moving the entry `meta` describes to a new path IV changes
    /// its stored bytes, or those of anything below it.
    pub fn depends_on_path(&self, meta: &fs::Metadata) -> bool {
        let t = meta.file_type();
        if t.is_file() {
            self.config.file_contents_depend_on_path()
        } else if t.is_symlink() {
            self.config.symlink_target_depends_on_path()
        } else if t.is_dir() {
            self.config.children_depend_on_path()
        } else {
            false
        }
    }

    /// Writes the contents of `src`, a file at path IV `src_iv`, into the
    /// empty file `dst` for path IV `dst_iv`. The caller syncs it. With a
    /// header, only the header is re-encrypted: the blocks depend on the
    /// file IV, which carries over. Without one every block is
    /// re-encrypted. Returns the file IV `dst`'s header holds.
    pub fn copy_file_contents(
        &self,
        src: &File,
        src_iv: u64,
        dst: &File,
        dst_iv: u64,
    ) -> Result<Option<FileIv>> {
        let len = src.metadata()?.len();
        let header_size = self.config.header_size();
        let mut out = BufWriter::new(dst);
        let header_iv = if len == 0 {
            None
        } else if header_size > 0 {
            let file_iv = self.config.read_file_iv(self.cipher, src, src_iv)?;
            let header = self
                .cipher
                .encrypt_header_with_iv(file_iv, self.config.external_iv(dst_iv))?;
            out.write_all(&header)?;
            let mut reader = src;
            reader.seek(SeekFrom::Start(header_size))?;
            io::copy(&mut reader, &mut out)?;
            Some(file_iv)
        } else {
            reencrypt_blocks(
                self.cipher,
                &self.config.file_codec_params(),
                src,
                len,
                &mut out,
                self.config.headerless_file_iv(src_iv),
                self.config.headerless_file_iv(dst_iv),
            )?;
            None
        };
        out.flush()?;
        Ok(header_iv)
    }

    /// The stored target of a symlink at path IV `dst_iv` that points
    /// where `stored`, stored for path IV `src_iv`, does.
    pub fn symlink_target(&self, stored: &[u8], src_iv: u64, dst_iv: u64) -> Result<Vec<u8>> {
        if !self.config.symlink_target_depends_on_path() || src_iv == dst_iv {
            return Ok(stored.to_vec());
        }
        let plain = symlink_target::decrypt(self.cipher, self.config, stored, src_iv)?;
        symlink_target::encrypt(self.cipher, self.config, &plain, dst_iv)
    }

    /// Copies the entry at `src` (path IV `src_iv`, described by `meta`) to
    /// the new path `dst` (path IV `dst_iv`). What depends on the path is
    /// re-encrypted; files whose contents don't are hard-linked where the
    /// backing filesystem allows it. Mode, timestamps and the attributes a
    /// mount shows carry over. `dst` may be an existing empty directory
    /// when `src` is a directory.
    pub fn copy_tree(
        &self,
        src: &Path,
        src_iv: u64,
        dst: &Path,
        dst_iv: u64,
        meta: &fs::Metadata,
        hooks: &mut dyn Hooks,
    ) -> Result<()> {
        let t = meta.file_type();
        if t.is_file() && self.config.file_contents_depend_on_path() && src_iv != dst_iv {
            hooks.copy_file(self, src, src_iv, dst, dst_iv)?;
            self.finish(src, dst, meta, hooks)
        } else if t.is_symlink() {
            let stored = fs::read_link(src)?;
            let target = self.symlink_target(stored.as_os_str().as_bytes(), src_iv, dst_iv)?;
            std::os::unix::fs::symlink(OsStr::from_bytes(&target), dst)?;
            self.finish(src, dst, meta, hooks)
        } else if t.is_dir() && self.config.children_depend_on_path() {
            create_dir(dst)?;
            let children = sorted_entries(src)?;
            // The decodable names, wanted only once a name doesn't decode.
            let mut plain_names = None;
            for entry in &children {
                let name = entry.file_name();
                let child = src.join(&name);
                let child_meta = entry.metadata()?;
                let Some(s) = name.to_str().filter(|s| !s.starts_with('.')) else {
                    self.copy_raw(&child, &dst.join(&name), &child_meta, hooks)?;
                    continue;
                };
                // A conflict copy's base, and the IV its contents were
                // written under, stand in for a name that doesn't decode.
                let (plain, suffix, next_src) = match self.cipher.decrypt_entry_name(s, src_iv) {
                    Ok((plain, next_iv)) => (plain, "", diriv::child_path_iv(self.config, next_iv)),
                    Err(_) => {
                        let names = plain_names
                            .get_or_insert_with(|| self.decodable_names(&children, src_iv));
                        match self.conflict_base(src, src_iv, s, &child_meta, names, hooks) {
                            Some(c) => (c.plain, &s[s.len() - c.suffix.len()..], c.path_iv),
                            None => {
                                self.copy_raw(&child, &dst.join(&name), &child_meta, hooks)?;
                                continue;
                            }
                        }
                    }
                };
                let (encrypted, next_dst) = self.cipher.encrypt_filename(&plain, dst_iv)?;
                self.copy_tree(
                    &child,
                    next_src,
                    &dst.join(format!("{encrypted}{suffix}")),
                    diriv::child_path_iv(self.config, next_dst),
                    &child_meta,
                    hooks,
                )?;
            }
            self.finish(src, dst, meta, hooks)?;
            self.sync_dir(dst, hooks)
        } else {
            self.copy_raw(src, dst, meta, hooks)
        }
    }

    /// The plaintext names of `entries`, children of a directory whose
    /// names IV is `names_iv`, that decode.
    fn decodable_names(&self, entries: &[fs::DirEntry], names_iv: u64) -> HashSet<Vec<u8>> {
        entries
            .iter()
            .filter_map(|e| {
                let name = e.file_name();
                let s = name.to_str()?;
                Some(self.cipher.decrypt_entry_name(s, names_iv).ok()?.0)
            })
            .collect()
    }

    /// The base a child of a directory being re-encrypted whose name
    /// doesn't decode would be recovered with, if it is a sync tool's
    /// conflict copy that `encfsctl fsck --fix --yes` would recover. It is
    /// then renamed along with the directory (its base re-encrypted, its
    /// suffix kept) so it stays recoverable under the new path. A conflict
    /// copy whose base is uncertain keeps its old name, with a warning.
    fn conflict_base(
        &self,
        dir: &Path,
        names_iv: u64,
        name: &str,
        meta: &fs::Metadata,
        plain_names: &HashSet<Vec<u8>>,
        hooks: &mut dyn Hooks,
    ) -> Option<Candidate> {
        let notes = RefCell::new(Vec::new());
        let base = Probe::new(self.config, self.cipher, &notes).default_conflict_base(
            dir,
            names_iv,
            name,
            meta,
            plain_names,
        );
        for (path, error) in notes.take() {
            hooks.warning(&path, &error);
        }
        base.unwrap_or_else(|e| {
            hooks.warning(
                &dir.join(name),
                &e.context(
                    "a conflict copy whose base isn't certain keeps its name, \
                     encrypted for the old path",
                ),
            );
            None
        })
    }

    /// Copies `src` to `dst` as it is, names and bytes: a hard link for
    /// anything but a directory or symlink where the backing filesystem
    /// allows one, a byte copy otherwise.
    fn copy_raw(
        &self,
        src: &Path,
        dst: &Path,
        meta: &fs::Metadata,
        hooks: &mut dyn Hooks,
    ) -> Result<()> {
        let t = meta.file_type();
        if t.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(src)?, dst)?;
            return self.finish(src, dst, meta, hooks);
        }
        if t.is_dir() {
            create_dir(dst)?;
            for entry in sorted_entries(src)? {
                let name = entry.file_name();
                self.copy_raw(
                    &src.join(&name),
                    &dst.join(&name),
                    &entry.metadata()?,
                    hooks,
                )?;
            }
            self.finish(src, dst, meta, hooks)?;
            return self.sync_dir(dst, hooks);
        }
        match fs::hard_link(src, dst) {
            // The same inode, with its attributes, mode and times.
            Ok(()) => return Ok(()),
            Err(e) if !link_unsupported(&e) => {
                return Err(e).with_context(|| format!("linking {}", dst.display()));
            }
            Err(_) => {}
        }
        if !t.is_file() {
            bail!("can't copy {}", src.display());
        }
        let mut input = File::open(src)?;
        let output = create_file(dst)?;
        io::copy(&mut input, &mut &output)?;
        hooks.sync(&output)?;
        self.finish(src, dst, meta, hooks)
    }

    /// Gives the new inode `dst` the attributes, mode and timestamps of
    /// `src`, and tells `hooks` about both.
    fn finish(
        &self,
        src: &Path,
        dst: &Path,
        meta: &fs::Metadata,
        hooks: &mut dyn Hooks,
    ) -> Result<()> {
        copy_metadata(self.config, src, dst, meta)?;
        hooks.finished(meta, dst);
        Ok(())
    }

    /// Syncs the directory `dir` of the copy, so its entries are durable.
    fn sync_dir(&self, dir: &Path, hooks: &mut dyn Hooks) -> Result<()> {
        let d =
            diriv::open_dir_to_sync(dir).with_context(|| format!("opening {}", dir.display()))?;
        hooks
            .sync(&d)
            .with_context(|| format!("syncing {}", dir.display()))
    }
}

/// Gives `dst` the attributes a mount shows of `src` (see
/// [`crate::fs::copy_backing_xattrs`]), then `meta`'s mode and timestamps.
/// The attributes go first, while `dst` is still writable.
pub fn copy_metadata(
    config: &EncfsConfig,
    src: &Path,
    dst: &Path,
    meta: &fs::Metadata,
) -> Result<()> {
    crate::fs::copy_backing_xattrs(config, src, dst)
        .map_err(from_errno)
        .with_context(|| format!("copying extended attributes to {}", dst.display()))?;
    if !meta.file_type().is_symlink() {
        fs::set_permissions(dst, fs::Permissions::from_mode(meta.mode() & 0o7777))?;
    }
    let _ = passthrough::utimens_path(dst, meta.accessed().ok(), meta.modified().ok());
    Ok(())
}

/// An error for the errno `e`.
pub fn from_errno(e: libc::c_int) -> anyhow::Error {
    io::Error::from_raw_os_error(e).into()
}

/// The errno behind `error`, for callers that report one: the first OS
/// error in its chain, or `EIO`.
pub fn errno(error: &anyhow::Error) -> libc::c_int {
    error
        .chain()
        .find_map(|e| e.downcast_ref::<io::Error>()?.raw_os_error())
        .unwrap_or(libc::EIO)
}

/// Whether a failed `link(2)` means the backing filesystem won't link
/// this entry, so a copy has to do.
fn link_unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EPERM | libc::EXDEV | libc::ENOTSUP | libc::EMLINK | libc::ENOSYS)
    ) || e.raw_os_error() == Some(libc::EOPNOTSUPP)
}

/// Creates the file `dst` for a copy, private until the copy is finished.
pub fn create_file(dst: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dst)
}

/// Creates the directory `dst` for a copy, private until the copy is
/// finished, or takes over an existing empty one (a rename may replace it).
fn create_dir(dst: &Path) -> Result<()> {
    match fs::create_dir(dst) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(dst)?.is_dir() || fs::read_dir(dst)?.next().is_some() {
                return Err(from_errno(libc::ENOTEMPTY))
                    .with_context(|| format!("{} is in the way", dst.display()));
            }
        }
        Err(e) => return Err(e).with_context(|| format!("creating {}", dst.display())),
    }
    fs::set_permissions(dst, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// `fsync` of a directory, so the entries just made in it are durable.
pub fn sync_dir(dir: &Path) -> Result<()> {
    let d = diriv::open_dir_to_sync(dir).with_context(|| format!("opening {}", dir.display()))?;
    diriv::sync_file(&d, false).with_context(|| format!("syncing {}", dir.display()))?;
    Ok(())
}

/// Removes the entry at `path`, a whole tree for a directory.
pub fn remove_entry(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}
