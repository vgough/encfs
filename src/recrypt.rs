//! Copies of backing entries under a new path IV: what moving an entry
//! takes where its stored bytes depend on its path (see
//! [`EncfsConfig::file_contents_depend_on_path`],
//! [`EncfsConfig::children_depend_on_path`] and
//! [`EncfsConfig::symlink_target_depends_on_path`]). Forward-mode rename
//! and `encfsctl fsck` (ADR 0007) both build their copies here, on backing
//! paths alone; [`Hooks`] carries what differs between them.
//!
//! A copy never removes its source. Every file it writes is synced, and
//! every directory it builds is synced once its entries are in place, so
//! the caller can remove the source as soon as the copy is in place.

use crate::config::EncfsConfig;
use crate::crypto::cipher::Cipher;
use crate::crypto::file::reencrypt_blocks;
use crate::crypto::file_iv::FileIv;
use crate::diriv;
use crate::symlink_target;
use anyhow::{Context, Result, anyhow, bail};
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
    /// re-encrypted from path IV `src_iv` to `dst_iv`. Metadata is the
    /// tree copy's job.
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
        Ok(())
    }

    /// The source inode behind `meta` was copied rather than linked, so it
    /// goes away with the source.
    fn copied(&mut self, _meta: &fs::Metadata) {}

    /// `dst` is a new inode that was just given its source's stored
    /// attributes.
    fn created(&mut self, _dst: &Path) {}

    /// A problem that didn't stop the copy.
    fn warning(&mut self, path: &Path, error: &anyhow::Error);
}

/// Re-encrypting copies for one volume.
pub struct Recrypt<'a> {
    pub config: &'a EncfsConfig,
    pub cipher: &'a dyn Cipher,
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

    /// The file IV of `file`, a file whose path IV is `path_iv`: from its
    /// header, or [`EncfsConfig::headerless_file_iv`] without one.
    pub fn file_iv(&self, file: &File, path_iv: u64) -> Result<FileIv> {
        let header_size = self.config.header_size() as usize;
        if header_size == 0 {
            return Ok(self.config.headerless_file_iv(path_iv));
        }
        let mut header = vec![0u8; header_size];
        std::os::unix::fs::FileExt::read_exact_at(file, &mut header, 0)?;
        self.cipher
            .decrypt_header(&mut header, self.config.external_iv(path_iv))
    }

    /// Writes the contents of `src`, a file at path IV `src_iv`, into the
    /// empty file `dst` for path IV `dst_iv`, then syncs `dst`. With a
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
            if len < header_size {
                bail!("the file is shorter than its header");
            }
            let file_iv = self.file_iv(src, src_iv)?;
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
        drop(out);
        diriv::sync_file(dst, false).context("syncing the copy")?;
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
            let mut children = Vec::new();
            let mut plain_names = HashSet::new();
            for entry in sorted_entries(src)? {
                let name = entry.file_name();
                let decoded = name
                    .to_str()
                    .filter(|s| !s.starts_with('.'))
                    .and_then(|s| self.cipher.decrypt_entry_name(s, src_iv).ok());
                if let Some((plain, _)) = &decoded {
                    plain_names.insert(plain.clone());
                }
                children.push((name, entry.metadata()?, decoded));
            }
            for (name, child_meta, decoded) in children {
                let child = src.join(&name);
                match decoded {
                    Some((plain, next_src)) => {
                        let (encrypted, next_dst) = self.cipher.encrypt_filename(&plain, dst_iv)?;
                        self.copy_tree(
                            &child,
                            diriv::child_path_iv(self.config, next_src),
                            &dst.join(encrypted),
                            diriv::child_path_iv(self.config, next_dst),
                            &child_meta,
                            hooks,
                        )?;
                    }
                    None => self.copy_undecodable(
                        src,
                        src_iv,
                        &name,
                        &child_meta,
                        dst,
                        dst_iv,
                        &plain_names,
                        hooks,
                    )?,
                }
            }
            self.finish(src, dst, meta, hooks)?;
            sync_dir(dst)
        } else {
            self.copy_raw(src, dst, meta, hooks)
        }
    }

    /// Copies a child of a directory being re-encrypted whose name doesn't
    /// decode. A sync tool's conflict copy whose base fsck would recover
    /// by default is renamed along with it (its base re-encrypted, its
    /// suffix kept) so it stays recoverable under the new path; anything
    /// else keeps its bytes and name.
    #[allow(clippy::too_many_arguments)]
    fn copy_undecodable(
        &self,
        src_dir: &Path,
        src_iv: u64,
        name: &OsStr,
        meta: &fs::Metadata,
        dst_dir: &Path,
        dst_iv: u64,
        plain_names: &HashSet<Vec<u8>>,
        hooks: &mut dyn Hooks,
    ) -> Result<()> {
        let src = src_dir.join(name);
        let base = name.to_str().filter(|s| !s.starts_with('.')).map(|s| {
            crate::fsck::default_conflict_base(
                self.config,
                self.cipher,
                src_dir,
                src_iv,
                s,
                meta,
                plain_names,
            )
        });
        match base {
            Some(Ok(Some(base))) => {
                let (encrypted, next_dst) = self.cipher.encrypt_filename(&base.plain, dst_iv)?;
                let new_name = format!("{encrypted}{}", base.suffix);
                return self.copy_tree(
                    &src,
                    base.path_iv,
                    &dst_dir.join(new_name),
                    diriv::child_path_iv(self.config, next_dst),
                    meta,
                    hooks,
                );
            }
            Some(Ok(None)) => {}
            Some(Err(e)) => hooks.warning(
                &src,
                &e.context(
                    "a conflict copy whose base isn't certain keeps its name, \
                     encrypted for the old path",
                ),
            ),
            None => {}
        }
        self.copy_raw(&src, &dst_dir.join(name), meta, hooks)
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
            return sync_dir(dst);
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
        diriv::sync_file(&output, false)?;
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
        hooks.copied(meta);
        hooks.created(dst);
        Ok(())
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
        .map_err(|e| anyhow!(io::Error::from_raw_os_error(e)))
        .with_context(|| format!("copying extended attributes to {}", dst.display()))?;
    if !meta.file_type().is_symlink() {
        fs::set_permissions(dst, fs::Permissions::from_mode(meta.mode() & 0o7777))?;
    }
    let _ = passthrough::utimens_path(dst, meta.accessed().ok(), meta.modified().ok());
    Ok(())
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
                return Err(anyhow!(io::Error::from_raw_os_error(libc::ENOTEMPTY)))
                    .with_context(|| format!("{} is in the way", dst.display()));
            }
        }
        Err(e) => return Err(e).with_context(|| format!("creating {}", dst.display())),
    }
    fs::set_permissions(dst, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Directory entries, sorted by name so runs are repeatable.
pub fn sorted_entries(dir: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut out = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<io::Result<Vec<_>>>()?;
    out.sort_by_cached_key(fs::DirEntry::file_name);
    Ok(out)
}

/// `fsync` of a directory, so the entries just made in it are durable.
pub fn sync_dir(dir: &Path) -> Result<()> {
    let d = diriv::open_dir_to_sync(dir).with_context(|| format!("opening {}", dir.display()))?;
    diriv::sync_file(&d, false).with_context(|| format!("syncing {}", dir.display()))?;
    Ok(())
}
