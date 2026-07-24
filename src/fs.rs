use crate::crypto::block::BlockLayout;
use crate::crypto::cipher::Cipher;
use crate::crypto::file::{FileDecoder, FileEncoder};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use fuse3::passthrough::{
    self, c_path, file_attr_from_metadata, file_type_from_metadata, is_apple_xattr,
    set_ownership_fd, set_ownership_path, utimens_permission_check,
};
use fuse3::{
    Caller as Request, Errno, FileKind as FileType, FileLock, NodeAttr as FileAttr, Opened,
    PathDirSink, PathFilesystem, PathPlusDirSink, SetAttr, StatFs as ReplyStatFs, TimeOrNow,
    XattrReply as ReplyXAttr,
};
use libc;
use log::{debug, error, warn};
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Errors from internal helpers are raw errno values; trait methods convert
/// them to typed FUSE errors via `?`.
type OpResult = Result<(), libc::c_int>;

pub struct FileHandle {
    file: File,
    file_iv: u64,
}

#[derive(Clone)]
struct DirectorySnapshotEntry {
    name: OsString,
    kind: FileType,
    attr: FileAttr,
}

/// An immutable view of a directory captured by `opendir`.
///
/// Mutations after the handle is opened are intentionally not visible through
/// that handle. A later `opendir` captures a new view, and retained attributes
/// allow `readdirplus` to finish even when an entry has since been removed.
pub struct DirectoryHandle {
    entries: Vec<DirectorySnapshotEntry>,
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
}

impl EncFs {
    pub fn new(root: PathBuf, cipher: Box<dyn Cipher>, config: crate::config::EncfsConfig) -> Self {
        Self {
            root,
            cipher,
            config,
            read_only: false,
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

                std::os::unix::fs::symlink(Path::new(&enc_target), &real_dest)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

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

                std::os::unix::fs::symlink(Path::new(&enc_target), dest.physical)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            } else {
                // No IV chaining - just copy the symlink as-is
                let target = fs::read_link(source.physical)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                std::os::unix::fs::symlink(&target, dest.physical)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
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
        // 1. Open source
        let mut src_f = File::open(real_src).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let metadata = src_f.metadata().ok();

        // 2. Read header
        let header_size = self.config.header_size();
        let mut header = vec![0u8; header_size as usize];
        if header_size > 0 {
            src_f
                .read_exact(&mut header)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            // 3. Decrypt header
            let file_iv = self
                .cipher
                .decrypt_header(&mut header, src_iv)
                .map_err(|_| libc::EIO)?;

            // 4. Encrypt header with new path IV
            let new_header = self
                .cipher
                .encrypt_header_with_iv(file_iv, dst_iv)
                .map_err(|_| libc::EIO)?;

            // 5. Create dest
            let mut dst_f =
                File::create(real_dest).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            // 6. Write new header
            dst_f
                .write_all(&new_header)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            // 7. Copy body
            let mut reader = BufReader::new(src_f);
            let mut writer = BufWriter::new(dst_f);

            std::io::copy(&mut reader, &mut writer)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            writer
                .flush()
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        } else {
            // 5. Create dest
            let dst_f =
                File::create(real_dest).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            // 7. Copy body (no header to copy/rewrite)
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
    fn physical_size_for_logical(&self, logical_size: u64, header_size: u64) -> u64 {
        FileEncoder::<File>::calculate_physical_size_with_mode(
            logical_size,
            header_size,
            self.config.block_size as u64,
            self.config.block_mac_bytes as u64,
            self.config.block_mode(),
        )
    }

    fn truncate_expand(
        &self,
        file_ref: &File,
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
        let c_path =
            std::ffi::CString::new(self.root.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

        let res = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if res != 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }

        Ok(ReplyStatFs {
            blocks: stat.f_blocks as u64,
            bfree: stat.f_bfree as u64,
            bavail: stat.f_bavail as u64,
            files: stat.f_files as u64,
            ffree: stat.f_ffree as u64,
            bsize: stat.f_bsize as u32,
            namelen: self.cipher.max_plaintext_name_len(stat.f_namemax as u32),
            frsize: stat.f_frsize as u32,
        })
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
    /// Uses the file's stored uid, gid, and mode from the backend and the request's
    /// uid/gid to apply standard Unix permission checks. Root (uid 0) is always allowed.
    /// Only the primary gid is considered (no supplementary groups).
    fn access_impl(&self, req: Request, path: &Path, mask: u32) -> OpResult {
        debug!(
            "access: {:?} mask={:#o} uid={} gid={}",
            path, mask, req.uid, req.gid
        );

        let (real_path, _) = self.encrypt_path(path)?;
        let metadata =
            fs::symlink_metadata(&real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        // F_OK (0): existence only
        if mask == 0 {
            return Ok(());
        }

        // Superuser bypasses permission checks
        if req.uid == 0 {
            return Ok(());
        }

        let mode = metadata.mode();
        let file_uid = metadata.uid();
        let file_gid = metadata.gid();

        // Pick the applicable mode triplet: owner (7-5), group (4-2), other (1-0)
        let effective = if req.uid == file_uid {
            (mode >> 6) & 0o7
        } else if req.gid == file_gid {
            (mode >> 3) & 0o7
        } else {
            mode & 0o7
        };

        // Map R_OK=4, W_OK=2, X_OK=1 to mode bits: read=4, write=2, execute=1
        let need = mask & 0o7;
        if (effective & need) == need {
            Ok(())
        } else {
            Err(libc::EACCES)
        }
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

        // These branches only run without an open handle, where `path` was
        // already required to open the file above.
        let file_iv = if let Some(h) = handle {
            h.file_iv
        } else if header_size > 0 {
            let mut header = vec![0u8; header_size as usize];
            file_ref
                .read_exact_at(&mut header, 0)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            let (_, path_iv) = self.encrypt_path(path.ok_or(libc::ESTALE)?)?;
            let external_iv = if self.config.external_iv_chaining {
                path_iv
            } else {
                0
            };
            self.cipher
                .decrypt_header(&mut header, external_iv)
                .map_err(|_| libc::EIO)?
        } else if self.config.external_iv_chaining {
            let (_, path_iv) = self.encrypt_path(path.ok_or(libc::ESTALE)?)?;
            path_iv
        } else {
            0
        };

        if size > current_logical_size {
            self.truncate_expand(
                file_ref,
                file_iv,
                header_size,
                current_logical_size,
                size,
                block_layout,
            )?;
        } else {
            self.truncate_shrink(file_ref, file_iv, header_size, size, block_layout)?;
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

        let enc_target_path = Path::new(&enc_target);

        let c_target = std::ffi::CString::new(enc_target_path.as_os_str().as_bytes())
            .map_err(|_| libc::EINVAL)?;
        let c_linkpath =
            std::ffi::CString::new(real_path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;

        let ret = unsafe { libc::symlink(c_target.as_ptr(), c_linkpath.as_ptr()) };

        if ret == 0 {
            // Return the attributes of the entry we just created.
            self.attr_for_path(Some(&path), None)
        } else {
            Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO))
        }
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

    fn directory_snapshot(&self, path: &Path) -> Result<DirectoryHandle, libc::c_int> {
        let (real_path, dir_iv) = self.encrypt_path(path)?;

        let entries =
            fs::read_dir(&real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let directory_metadata =
            fs::symlink_metadata(&real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let parent = path.parent().unwrap_or(path);
        let parent_attr = self.attr_for_path(Some(parent), None)?;

        // Rust's fs::read_dir doesn't include . and .. entries, so add them explicitly
        let mut result = vec![
            DirectorySnapshotEntry {
                name: OsString::from("."),
                kind: FileType::Directory,
                attr: self.attr_from_metadata(&directory_metadata),
            },
            DirectorySnapshotEntry {
                name: OsString::from(".."),
                kind: FileType::Directory,
                attr: parent_attr,
            },
        ];

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
                    result.push(DirectorySnapshotEntry {
                        name: OsStr::from_bytes(&decrypted_name).to_os_string(),
                        kind: file_type_from_metadata(&metadata),
                        attr: self.attr_from_metadata(&metadata),
                    });
                }
                Err(e) => {
                    warn!("Failed to decrypt filename {}: {}", name_str, e);
                }
            }
        }

        Ok(DirectoryHandle { entries: result })
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
        if want_trunc && want_write {
            opts.truncate(true);
        }

        let file = opts
            .open(&real_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let header_size = self.config.header_size();
        let external_iv = if self.config.external_iv_chaining {
            path_iv
        } else {
            0
        };
        let mut file_iv = headerless_file_iv(header_size, external_iv);

        if want_trunc && want_write {
            // If the file was truncated, we must generate and write a new header (if header_size > 0).
            if header_size > 0 {
                let (header, iv) = self.cipher.encrypt_header(external_iv).map_err(|e| {
                    error!("Failed to generate header: {}", e);
                    libc::EIO
                })?;

                use std::io::Write;
                let mut file_ref = &file;
                file_ref
                    .write_all(&header)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                file_iv = iv;
            } else {
                // Ensure physical file is truncated to 0 if header_size is 0
                let file_ref = &file;
                file_ref
                    .set_len(0)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            }
        } else {
            // Read header if exists, or initialize empty file (e.g. created via mknod)
            let physical_size = file
                .metadata()
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?
                .len();

            if header_size > 0 && physical_size < header_size {
                // Empty or undersized backing file (e.g. from mknod). Write header so
                // subsequent writes use correct physical offset and file format.
                if want_write {
                    let (header, iv) = self.cipher.encrypt_header(external_iv).map_err(|e| {
                        error!("Failed to generate header: {}", e);
                        libc::EIO
                    })?;

                    use std::io::Write;
                    let mut file_ref = &file;
                    file_ref
                        .write_all(&header)
                        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                    file_iv = iv;
                } else {
                    // Opening for read but file too small to have valid header
                    return Err(libc::EIO);
                }
            } else if header_size > 0 {
                let mut header = vec![0u8; header_size as usize];
                let bytes_read = file
                    .read_at(&mut header, 0)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

                if bytes_read == header_size as usize {
                    // Decrypt header
                    if let Ok(iv) = self.cipher.decrypt_header(&mut header, external_iv) {
                        file_iv = iv;
                    } else {
                        warn!("Failed to decrypt file header for {:?}", path);
                        return Err(libc::EIO);
                    }
                }
            }
        }

        Ok(FileHandle { file, file_iv })
    }

    fn read_impl(
        &self,
        handle: &FileHandle,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, libc::c_int> {
        debug!("read: offset={} size={}", offset, size);

        let decoder = FileDecoder::new_from_config(
            self.cipher.as_ref(),
            &handle.file,
            handle.file_iv,
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

        let encoder = FileEncoder::new_from_config(
            self.cipher.as_ref(),
            &handle.file,
            handle.file_iv,
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
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&real_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        // Encrypt and write header if header_size > 0
        let header_size = self.config.header_size();
        let external_iv = if self.config.external_iv_chaining {
            path_iv
        } else {
            0
        };
        let mut file_iv = headerless_file_iv(header_size, external_iv);

        if header_size > 0 {
            let external_iv = if self.config.external_iv_chaining {
                path_iv
            } else {
                0
            };

            let (header, iv) = self.cipher.encrypt_header(external_iv).map_err(|e| {
                error!("Failed to generate header: {}", e);
                libc::EIO
            })?;
            file_iv = iv;

            use std::io::Write;
            file.write_all(&header)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        }

        set_ownership_fd(file.as_raw_fd(), &req).map_err(|e| e.raw())?;

        // Build the reply attributes from the freshly created backing file
        // (ownership was just set above); logical size of a new file is 0.
        let metadata = file
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let attr = file_attr_from_metadata(&metadata, 0);

        Ok((attr, FileHandle { file, file_iv }))
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

/// Apply FUSE getxattr/listxattr size semantics: a zero-size request probes
/// the value length; otherwise the data must fit in the caller's buffer.
fn xattr_reply(data: Vec<u8>, size: usize) -> Result<ReplyXAttr, Errno> {
    if size == 0 {
        Ok(ReplyXAttr::Size(data.len()))
    } else if data.len() > size {
        Err(Errno::from(libc::ERANGE))
    } else {
        Ok(ReplyXAttr::Data(data))
    }
}

impl PathFilesystem for EncFs {
    type Handle = FileHandle;
    type DirHandle = DirectoryHandle;

    const SUPPORTS_POSIX_LOCKS: bool = true;
    const SUPPORTS_READDIRPLUS: bool = true;

    fn init(&self, _conn: &mut fuse3::ConnInfo) {
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
    ) -> Result<Opened<DirectoryHandle>, Errno> {
        Ok(Opened::new(self.directory_snapshot(path)?))
    }

    fn readdir(
        &self,
        _path: &Path,
        handle: &DirectoryHandle,
        offset: u64,
        sink: &mut dyn PathDirSink,
        _caller: &Request,
    ) -> Result<(), Errno> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (index, entry) in handle.entries.iter().enumerate().skip(start) {
            if !sink.add(&entry.name, entry.kind, index as u64 + 1) {
                break;
            }
        }
        Ok(())
    }

    fn readdirplus(
        &self,
        _path: &Path,
        handle: &DirectoryHandle,
        offset: u64,
        sink: &mut dyn PathPlusDirSink,
        _caller: &Request,
    ) -> Result<(), Errno> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (index, entry) in handle.entries.iter().enumerate().skip(start) {
            if !sink.add(&entry.name, entry.attr, index as u64 + 1) {
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

    fn getlk(
        &self,
        _path: Option<&Path>,
        handle: &FileHandle,
        _owner: u64,
        lock: FileLock,
        _caller: &Request,
    ) -> Result<FileLock, Errno> {
        fuse3::file_lock::getlk(&handle.file, lock)
    }

    fn setlk(
        &self,
        _path: Option<&Path>,
        handle: &FileHandle,
        _owner: u64,
        lock: FileLock,
        sleep: bool,
        _caller: &Request,
    ) -> Result<(), Errno> {
        fuse3::file_lock::setlk(&handle.file, lock, sleep)
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
        xattr_reply(self.getxattr_impl(path, name)?, size)
    }

    fn listxattr(&self, path: &Path, size: usize, _caller: &Request) -> Result<ReplyXAttr, Errno> {
        xattr_reply(self.listxattr_impl(path)?, size)
    }

    fn removexattr(&self, path: &Path, name: &OsStr, _caller: &Request) -> Result<(), Errno> {
        Ok(self.removexattr_impl(path, name)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{headerless_file_iv, is_apple_xattr};

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
