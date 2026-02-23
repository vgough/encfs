use crate::crypto::block::BlockLayout;
use crate::crypto::file::{FileDecoder, FileEncoder};
use crate::crypto::ssl::SslCipher;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use fuse_mt::{
    CallbackResult, CreatedEntry, DirectoryEntry, FileAttr, FileType, FilesystemMT, RequestInfo,
    ResultCreate, ResultEmpty, ResultEntry, ResultOpen, ResultReaddir, ResultSlice, ResultStatfs,
    ResultWrite, Statfs, Xattr,
};
use libc;
use log::{debug, error, warn};
use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

struct FileHandle {
    file: File,
    file_iv: u64,
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
    pub cipher: SslCipher,
    handles: Mutex<HashMap<u64, Arc<FileHandle>>>,
    next_fh: AtomicU64,
    pub config: crate::config::EncfsConfig,
}

impl EncFs {
    pub fn new(root: PathBuf, cipher: SslCipher, config: crate::config::EncfsConfig) -> Self {
        Self {
            root,
            cipher,
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            config,
        }
    }

    fn handles_guard(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<FileHandle>>> {
        self.handles.lock().unwrap_or_else(|e| e.into_inner())
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
        _req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        newparent: &Path,
        newname: &OsStr,
    ) -> ResultEmpty {
        debug!(
            "rename: {:?}/{:?} -> {:?}/{:?}",
            parent, name, newparent, newname
        );
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
    ) -> ResultEmpty {
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
    ) -> ResultEmpty {
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

/// Map std::fs::Metadata file type to FUSE FileType (for getattr/readdir).
fn metadata_to_file_type(metadata: &std::fs::Metadata) -> FileType {
    if metadata.is_dir() {
        FileType::Directory
    } else if metadata.is_symlink() {
        FileType::Symlink
    } else {
        let ft = metadata.file_type();
        if ft.is_fifo() {
            FileType::NamedPipe
        } else if ft.is_char_device() {
            FileType::CharDevice
        } else if ft.is_block_device() {
            FileType::BlockDevice
        } else if ft.is_socket() {
            FileType::Socket
        } else {
            FileType::RegularFile
        }
    }
}

impl EncFs {
    /// POSIX utime permission check: owner and root may always set; others may set to
    /// current time only if they have write access; setting explicit time requires owner or root.
    fn utimens_permission_check(
        &self,
        req: &RequestInfo,
        file_uid: u32,
        file_gid: u32,
        mode: u32,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> Result<(), libc::c_int> {
        if req.uid == 0 {
            return Ok(());
        }
        if req.uid == file_uid {
            return Ok(());
        }
        let setting_atime = atime.is_some();
        let setting_mtime = mtime.is_some();
        if !setting_atime && !setting_mtime {
            return Ok(());
        }
        let now = SystemTime::now();
        // FUSE passes UTIME_NOW as SystemTime::now() at callback time; explicit times (e.g.
        // utime $now $now) can be tens of ms in the past. Use 10ms to distinguish.
        let near_now = |t: SystemTime| {
            now.duration_since(t).unwrap_or(Duration::MAX) < Duration::from_millis(10)
                || t.duration_since(now).unwrap_or(Duration::MAX) < Duration::from_millis(10)
        };
        let setting_to_current = atime.is_none_or(near_now) && mtime.is_none_or(near_now);
        if setting_to_current {
            let has_write = (req.uid == file_uid && (mode & 0o200) != 0)
                || (req.gid == file_gid && (mode & 0o020) != 0)
                || (mode & 0o002) != 0;
            if has_write {
                return Ok(());
            }
            return Err(libc::EACCES);
        }
        Err(libc::EPERM)
    }

    /// Sets ownership to req.uid/req.gid if different from current process.
    /// Skips chown when already correct; ignores EPERM for unprivileged mounts.
    fn set_ownership_fd(
        &self,
        fd: std::os::unix::io::RawFd,
        req: &RequestInfo,
    ) -> Result<(), libc::c_int> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        if req.uid == uid && req.gid == gid {
            return Ok(());
        }
        if unsafe { libc::fchown(fd, req.uid as libc::uid_t, req.gid as libc::gid_t) } == -1 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno != libc::EPERM {
                return Err(errno);
            }
        }
        Ok(())
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

    fn truncate_expand(
        &self,
        file_ref: &File,
        file_iv: u64,
        header_size: u64,
        current_logical_size: u64,
        new_logical_size: u64,
        block_layout: BlockLayout,
    ) -> ResultEmpty {
        if new_logical_size <= current_logical_size {
            return Ok(());
        }

        let encoder = FileEncoder::new_from_config(
            &self.cipher,
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
    ) -> ResultEmpty {
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
            &self.cipher,
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
            &self.cipher,
            file_ref,
            file_iv,
            &self.config.file_codec_params(),
        );
        encoder
            .write_at(&buf, block_start)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        Ok(())
    }

    /// Sets ownership to req.uid/req.gid if different from current process.
    /// Skips chown when already correct; ignores EPERM for unprivileged mounts.
    fn set_ownership_path(&self, path: &Path, req: &RequestInfo) -> Result<(), libc::c_int> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        if req.uid == uid && req.gid == gid {
            return Ok(());
        }
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
        if unsafe {
            libc::chown(
                c_path.as_ptr(),
                req.uid as libc::uid_t,
                req.gid as libc::gid_t,
            )
        } == -1
        {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno != libc::EPERM {
                return Err(errno);
            }
        }
        Ok(())
    }
}

impl FilesystemMT for EncFs {
    fn init(&self, _req: RequestInfo) -> Result<(), libc::c_int> {
        debug!("init");
        Ok(())
    }

    fn statfs(&self, _req: RequestInfo, path: &Path) -> ResultStatfs {
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

        Ok(Statfs {
            blocks: stat.f_blocks,
            bfree: stat.f_bfree,
            bavail: stat.f_bavail,
            files: stat.f_files,
            ffree: stat.f_ffree,
            bsize: stat.f_bsize as u32,
            namelen: self.cipher.max_plaintext_name_len(stat.f_namemax as u32),
            frsize: stat.f_frsize as u32,
        })
    }

    fn chmod(&self, _req: RequestInfo, path: &Path, _fh: Option<u64>, mode: u32) -> ResultEmpty {
        debug!("chmod: {:?} mode={:o}", path, mode);
        let (real_path, _) = self.encrypt_path(path)?;

        // Convert mode to Permissions.
        // Note: fs::set_permissions takes std::fs::Permissions.
        // We use PermissionsExt to construct it from u32 mode.
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);

        fs::set_permissions(real_path, perms).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
    }

    fn chown(
        &self,
        _req: RequestInfo,
        path: &Path,
        _fh: Option<u64>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> ResultEmpty {
        debug!("chown: {:?} uid={:?} gid={:?}", path, uid, gid);
        let (real_path, _) = self.encrypt_path(path)?;

        let c_path =
            std::ffi::CString::new(real_path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;

        let ret = unsafe {
            libc::lchown(
                c_path.as_ptr(),
                uid.unwrap_or(u32::MAX), // -1 in u32 is u32::MAX? No, lchown takes uid_t (u32).
                // chown(2): "If the owner or group is specified as -1, then that ID is not changed."
                // uid_t is u32. -1 is casting.
                gid.unwrap_or(u32::MAX),
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO))
        }
    }

    /// Check if the requesting process has the requested access to the path.
    ///
    /// Uses the file's stored uid, gid, and mode from the backend and the request's
    /// uid/gid to apply standard Unix permission checks. Root (uid 0) is always allowed.
    /// Only the primary gid is considered (no supplementary groups).
    fn access(&self, req: RequestInfo, path: &Path, mask: u32) -> ResultEmpty {
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

    fn truncate(&self, _req: RequestInfo, path: &Path, fh: Option<u64>, size: u64) -> ResultEmpty {
        debug!("truncate: {:?} size={}", path, size);

        let handle: Option<Arc<FileHandle>> =
            fh.and_then(|fh| self.handles_guard().get(&fh).cloned());
        if fh.is_some() && handle.is_none() {
            return Err(libc::EBADF);
        }

        let owned_file: Option<File> = if handle.is_none() {
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

        let file_ref: &File = match (&handle, &owned_file) {
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

        let file_iv = if let Some(h) = &handle {
            h.file_iv
        } else if header_size > 0 {
            let mut header = vec![0u8; header_size as usize];
            file_ref
                .read_exact_at(&mut header, 0)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            let (_, path_iv) = self.encrypt_path(path)?;
            let external_iv = if self.config.external_iv_chaining {
                path_iv
            } else {
                0
            };
            self.cipher
                .decrypt_header(&mut header, external_iv)
                .map_err(|_| libc::EIO)?
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

    fn utimens(
        &self,
        req: RequestInfo,
        path: &Path,
        fh: Option<u64>,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> ResultEmpty {
        debug!("utimens: {:?} atime={:?} mtime={:?}", path, atime, mtime);

        // Get file metadata for permission check (owner/group/mode).
        let metadata = if let Some(fh) = fh {
            let handles = self.handles_guard();
            handles.get(&fh).and_then(|h| h.file.metadata().ok())
        } else {
            let (real_path, _) = self.encrypt_path(path)?;
            fs::symlink_metadata(real_path).ok()
        };

        let setting_times = atime.is_some() || mtime.is_some();
        if setting_times && req.uid != 0 {
            let meta = metadata.as_ref().ok_or(libc::EACCES)?;
            self.utimens_permission_check(&req, meta.uid(), meta.gid(), meta.mode(), atime, mtime)?
        } else if let Some(ref meta) = metadata {
            self.utimens_permission_check(&req, meta.uid(), meta.gid(), meta.mode(), atime, mtime)?;
        }
        // If metadata failed and we're root or not setting times, proceed and let utimensat/futimens return the error.

        // Map Option<SystemTime> to kernel timespec. None means UTIME_OMIT (leave timestamp
        // unchanged). Some(t) is either an explicit time or UTIME_NOW (fuse_mt converts UTIME_NOW
        // to Some(SystemTime::now()) before calling us).
        let to_timespec = |t: Option<std::time::SystemTime>| -> libc::timespec {
            match t {
                Some(ts) => {
                    let d = ts
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or(Duration::ZERO);
                    libc::timespec {
                        tv_sec: d.as_secs() as i64,
                        tv_nsec: d.subsec_nanos() as i64,
                    }
                }
                None => libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
            }
        };

        let times = [to_timespec(atime), to_timespec(mtime)];

        if let Some(fh) = fh {
            let handle = {
                let handles = self.handles_guard();
                handles.get(&fh).cloned()
            };
            if let Some(handle) = handle {
                use std::os::fd::AsRawFd;
                let ret = unsafe { libc::futimens(handle.file.as_raw_fd(), times.as_ptr()) };
                if ret == 0 {
                    return Ok(());
                } else {
                    return Err(std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO));
                }
            }
        }

        let (real_path, _) = self.encrypt_path(path)?;
        let c_path =
            std::ffi::CString::new(real_path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;

        let ret = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO))
        }
    }

    fn readlink(&self, _req: RequestInfo, path: &Path) -> Result<Vec<u8>, libc::c_int> {
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

    fn link(
        &self,
        req: RequestInfo,
        path: &Path,
        newparent: &Path,
        newname: &OsStr,
    ) -> ResultEntry {
        debug!("link: {:?} -> {:?}/{:?}", path, newparent, newname);

        if self.config.external_iv_chaining {
            return Err(libc::EPERM);
        }

        let new_path = newparent.join(newname);
        let (real_path, _) = self.encrypt_path(path)?;
        let (real_new_path, _) = self.encrypt_path(&new_path)?;

        if let Err(e) = std::fs::hard_link(&real_path, &real_new_path) {
            return Err(e.raw_os_error().unwrap_or(libc::EIO));
        }

        self.getattr(req, &new_path, None)
    }

    fn symlink(
        &self,
        req: RequestInfo,
        parent: &Path,
        name: &std::ffi::OsStr,
        target: &std::path::Path,
    ) -> ResultEntry {
        debug!("symlink: {:?}/{:?} -> {:?}", parent, name, target);

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
            // Need to return lookup of new entry.
            // But fuse_mt::ResultEntry expects a DirectoryEntry.
            // We can reuse lookup or construct it.
            // For simplicity, let's just lookup what we created.
            // Actually fuse_mt requires we return the entry.
            // Let's do a lookup.
            self.getattr(req, &path, None)
        } else {
            Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO))
        }
    }

    fn getattr(&self, _req: RequestInfo, path: &Path, fh: Option<u64>) -> ResultEntry {
        debug!("getattr: {:?} fh={:?}", path, fh);

        let metadata = if let Some(fh) = fh {
            let handle = {
                let handles = self.handles_guard();
                handles.get(&fh).cloned()
            };

            if let Some(handle) = handle {
                handle.file.metadata().ok()
            } else {
                None
            }
        } else {
            None
        };

        let metadata = if let Some(m) = metadata {
            m
        } else {
            let (real_path, _) = self.encrypt_path(path)?;
            debug!("real_path: {:?}", real_path);
            fs::symlink_metadata(&real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?
        };

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

        let attr = FileAttr {
            size,
            blocks: metadata.blocks(),
            atime: SystemTime::UNIX_EPOCH
                + Duration::new(metadata.atime() as u64, metadata.atime_nsec() as u32),
            mtime: SystemTime::UNIX_EPOCH
                + Duration::new(metadata.mtime() as u64, metadata.mtime_nsec() as u32),
            ctime: SystemTime::UNIX_EPOCH
                + Duration::new(metadata.ctime() as u64, metadata.ctime_nsec() as u32),
            crtime: SystemTime::UNIX_EPOCH,
            kind: metadata_to_file_type(&metadata),
            perm: metadata.mode() as u16,
            nlink: metadata.nlink() as u32,
            uid: metadata.uid(),
            gid: metadata.gid(),
            rdev: metadata.rdev() as u32,
            flags: 0,
        };

        Ok((Duration::from_secs(1), attr))
    }

    fn readdir(&self, _req: RequestInfo, path: &Path, _fh: u64) -> ResultReaddir {
        debug!("readdir: {:?}", path);
        let (real_path, dir_iv) = self.encrypt_path(path)?;

        let entries = fs::read_dir(real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let mut result = Vec::new();

        // Rust's fs::read_dir doesn't include . and .. entries, so add them explicitly
        result.push(DirectoryEntry {
            name: OsStr::new(".").to_os_string(),
            kind: FileType::Directory,
        });
        result.push(DirectoryEntry {
            name: OsStr::new("..").to_os_string(),
            kind: FileType::Directory,
        });

        for entry in entries {
            let entry = entry.map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            let file_name = entry.file_name();
            let name_str = file_name.to_str().ok_or(libc::EILSEQ)?;

            // Skip filenames starting with ".", since it isn't a valid encrypted filename.
            // Allows skipping over config files.
            if name_str.starts_with('.') {
                continue;
            }

            match self.cipher.decrypt_filename(name_str, dir_iv) {
                Ok((decrypted_name, _)) => {
                    let metadata = entry
                        .metadata()
                        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                    result.push(DirectoryEntry {
                        name: OsStr::from_bytes(&decrypted_name).to_os_string(),
                        kind: metadata_to_file_type(&metadata),
                    });
                }
                Err(e) => {
                    warn!("Failed to decrypt filename {}: {}", name_str, e);
                }
            }
        }

        Ok(result)
    }

    fn opendir(&self, _req: RequestInfo, path: &Path, _flags: u32) -> ResultOpen {
        debug!("opendir: {:?}", path);
        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        Ok((fh, 0))
    }

    fn releasedir(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        _flags: u32,
    ) -> Result<(), libc::c_int> {
        debug!("releasedir: fh={}", fh);
        Ok(())
    }

    fn open(&self, _req: RequestInfo, path: &Path, flags: u32) -> ResultOpen {
        debug!("open: {:?}", path);
        let (real_path, path_iv) = self.encrypt_path(path)?;

        // Respect requested open flags. In particular, writes must open the backing file with
        // write permissions; otherwise later `write`/`truncate` operations will fail with EBADF.
        let want_write = (flags as i32 & libc::O_WRONLY) != 0 || (flags as i32 & libc::O_RDWR) != 0;
        let want_trunc = (flags as i32 & libc::O_TRUNC) != 0;

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

        let mut file_iv = 0;
        let header_size = self.config.header_size();
        let external_iv = if self.config.external_iv_chaining {
            path_iv
        } else {
            0
        };

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

        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        let handle = Arc::new(FileHandle { file, file_iv });

        self.handles_guard().insert(fh, handle);

        Ok((fh, 0))
    }

    fn read(
        &self,
        _req: RequestInfo,
        path: &Path,
        fh: u64,
        offset: u64,
        size: u32,
        callback: impl FnOnce(ResultSlice<'_>) -> CallbackResult,
    ) -> CallbackResult {
        debug!("read: {:?} offset={} size={}", path, offset, size);

        let handle = {
            let handles = self.handles_guard();
            match handles.get(&fh).cloned() {
                Some(h) => h,
                None => return callback(Err(libc::EBADF)),
            }
        };

        let decoder = FileDecoder::new_from_config(
            &self.cipher,
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
                callback(Ok(&result_data))
            }
            Err(e) => {
                error!("Read failed on {:?}: {}", path, e);
                let err = e.raw_os_error().unwrap_or(libc::EIO);
                callback(Err(err))
            }
        }
    }

    fn release(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> Result<(), libc::c_int> {
        debug!("release: fh={}", fh);
        self.handles_guard().remove(&fh);
        Ok(())
    }

    fn write(
        &self,
        _req: RequestInfo,
        path: &Path,
        fh: u64,
        offset: u64,
        data: Vec<u8>,
        _flags: u32,
    ) -> ResultWrite {
        debug!("write: {:?} offset={} size={}", path, offset, data.len());

        let handle = {
            let handles = self.handles_guard();
            match handles.get(&fh).cloned() {
                Some(h) => h,
                None => return Err(libc::EBADF),
            }
        };

        let encoder = FileEncoder::new_from_config(
            &self.cipher,
            &handle.file,
            handle.file_iv,
            &self.config.file_codec_params(),
        );

        match encoder.write_at(&data, offset) {
            Ok(written) => Ok(written as u32),
            Err(e) => {
                error!("Write failed: {}", e);
                Err(e.raw_os_error().unwrap_or(libc::EIO))
            }
        }
    }

    fn create(
        &self,
        req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> ResultCreate {
        debug!(
            "create: {:?}/{:?} flags={} mode={}",
            parent, name, flags, mode
        );
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
        let mut file_iv = 0;

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

        self.set_ownership_fd(file.as_raw_fd(), &req)?;

        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        let handle = Arc::new(FileHandle { file, file_iv });

        self.handles_guard().insert(fh, handle);

        // We need to return CreatedEntry which includes FileAttr
        // We can get attributes from the open file or construct them
        let attr = FileAttr {
            size: 0,
            blocks: 1, // Header block
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: FileType::RegularFile,
            perm: mode as u16,
            nlink: 1,
            uid: req.uid,
            gid: req.gid,
            rdev: 0,
            flags: 0,
        };

        Ok(CreatedEntry {
            ttl: Duration::from_secs(1),
            attr,
            fh,
            flags: 0,
        })
    }

    fn unlink(&self, _req: RequestInfo, parent: &Path, name: &OsStr) -> ResultEmpty {
        let path = parent.join(name);
        debug!("unlink: {:?}", path);
        let (real_path, _) = self.encrypt_path(&path)?;
        fs::remove_file(real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
    }

    fn mkdir(&self, req: RequestInfo, parent: &Path, name: &OsStr, mode: u32) -> ResultEntry {
        let path = parent.join(name);
        debug!("mkdir: {:?} mode={:o}", path, mode);
        let (real_path, _) = self.encrypt_path(&path)?;

        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(mode)
            .create(&real_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        self.set_ownership_path(&real_path, &req)?;

        self.getattr(req, &path, None)
    }

    fn mknod(
        &self,
        req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        rdev: u32,
    ) -> ResultEntry {
        let path = parent.join(name);
        debug!("mknod: {:?} mode={:o} rdev={}", path, mode, rdev);
        let (real_path, path_iv) = self.encrypt_path(&path)?;

        let c_path = CString::new(real_path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;

        let mode_bits = mode & libc::S_IFMT;
        let res = if mode_bits == libc::S_IFIFO {
            unsafe { libc::mkfifo(c_path.as_ptr(), mode) }
        } else if mode_bits == libc::S_IFCHR
            || mode_bits == libc::S_IFBLK
            || mode_bits == libc::S_IFSOCK
        {
            unsafe { libc::mknod(c_path.as_ptr(), mode, rdev as libc::dev_t) }
        } else if mode_bits == libc::S_IFREG {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let header_size = self.config.header_size();
            let external_iv = if self.config.external_iv_chaining {
                path_iv
            } else {
                0
            };
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&real_path)
            {
                Ok(mut f) => {
                    if header_size > 0 {
                        let (header, _iv) =
                            self.cipher.encrypt_header(external_iv).map_err(|e| {
                                error!("Failed to generate header for mknod: {}", e);
                                libc::EIO
                            })?;
                        f.write_all(&header)
                            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                    }
                    drop(f);
                    0
                }
                Err(e) => {
                    return Err(e.raw_os_error().unwrap_or(libc::EIO));
                }
            }
        } else {
            return Err(libc::EINVAL);
        };

        if res == -1 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }

        self.set_ownership_path(&real_path, &req)?;

        self.getattr(req, &path, None)
    }

    fn rmdir(&self, _req: RequestInfo, parent: &Path, name: &OsStr) -> ResultEmpty {
        let path = parent.join(name);
        debug!("rmdir: {:?}", path);
        let (real_path, _) = self.encrypt_path(&path)?;
        fs::remove_dir(real_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
    }

    fn rename(
        &self,
        req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        newparent: &Path,
        newname: &OsStr,
    ) -> ResultEmpty {
        self.rename_internal(req, parent, name, newparent, newname)
    }

    fn setxattr(
        &self,
        _req: RequestInfo,
        path: &Path,
        name: &OsStr,
        value: &[u8],
        flags: u32,
        position: u32,
    ) -> ResultEmpty {
        debug!(
            "setxattr: {:?} name={:?} value_len={} flags={} position={}",
            path,
            name,
            value.len(),
            flags,
            position
        );

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
        let c_path =
            std::ffi::CString::new(real_path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;

        // Set xattr on underlying filesystem
        let ret = unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                encrypted_value.as_ptr() as *const libc::c_void,
                encrypted_value.len(),
                flags as i32,
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO))
        }
    }

    fn getxattr(
        &self,
        _req: RequestInfo,
        path: &Path,
        name: &OsStr,
        size: u32,
    ) -> Result<Xattr, libc::c_int> {
        debug!("getxattr: {:?} name={:?} size={}", path, name, size);

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
        let c_path =
            std::ffi::CString::new(real_path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;

        // Get xattr size first if size is 0
        let buf_size = if size == 0 {
            let ret = unsafe {
                libc::lgetxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0)
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO));
            }
            ret as usize
        } else {
            size as usize
        };

        // Read encrypted value
        let mut encrypted_value = vec![0u8; buf_size];
        let ret = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                encrypted_value.as_mut_ptr() as *mut libc::c_void,
                buf_size,
            )
        };

        if ret < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }

        encrypted_value.truncate(ret as usize);

        // Decrypt value
        let decrypted_value = self
            .cipher
            .decrypt_xattr_value(&encrypted_value, path_iv)
            .map_err(|e| {
                error!("Failed to decrypt xattr value: {}", e);
                libc::EIO
            })?;

        Ok(Xattr::Data(decrypted_value))
    }

    fn listxattr(&self, _req: RequestInfo, path: &Path, size: u32) -> Result<Xattr, libc::c_int> {
        debug!("listxattr: {:?} size={}", path, size);

        let (real_path, path_iv) = self.encrypt_path(path)?;

        let c_path =
            std::ffi::CString::new(real_path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;

        // Get list size first if size is 0
        let buf_size = if size == 0 {
            let ret = unsafe { libc::llistxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO));
            }
            ret as usize
        } else {
            size as usize
        };

        // Read xattr names list
        // llistxattr expects *mut c_char (i8), so we use a Vec<i8>
        let mut list = vec![0i8; buf_size];
        let ret = unsafe { libc::llistxattr(c_path.as_ptr(), list.as_mut_ptr(), buf_size) };

        if ret < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO));
        }

        list.truncate(ret as usize);

        // Process all xattr names in the list
        // xattr lists are null-separated strings (as i8, convert to u8)
        let list_u8: Vec<u8> = list.iter().map(|&b| b as u8).collect();
        let mut decrypted_list = Vec::new();
        let mut current_name = Vec::new();

        for &byte in &list_u8 {
            if byte == 0 {
                // End of current name, process it
                if !current_name.is_empty() {
                    let name_str = match std::str::from_utf8(&current_name) {
                        Ok(s) => s,
                        Err(_) => {
                            // Invalid UTF-8, skip
                            current_name.clear();
                            continue;
                        }
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
                        warn!("Found non-encfs xattr on disk: {}, skipping", name_str);
                    }
                    current_name.clear();
                }
            } else {
                current_name.push(byte);
            }
        }

        // Handle last name if list doesn't end with null
        if !current_name.is_empty() {
            let name_str = match std::str::from_utf8(&current_name) {
                Ok(s) => s,
                Err(_) => {
                    return Ok(Xattr::Data(decrypted_list));
                }
            };

            if let Some(encoded_part) = name_str.strip_prefix("user.encfs.") {
                match base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded_part) {
                    Ok(encrypted_name_bytes) => {
                        match self
                            .cipher
                            .decrypt_xattr_name(&encrypted_name_bytes, path_iv)
                        {
                            Ok(decrypted_name) => {
                                // Return the decrypted name without the "user.encfs." prefix
                                decrypted_list.extend_from_slice(&decrypted_name);
                                decrypted_list.push(0);
                            }
                            Err(e) => {
                                warn!("Failed to decrypt xattr name: {}", e);
                            }
                        }
                    }
                    Err(_) => {
                        warn!("Failed to decode base64 xattr name: {}", name_str);
                    }
                }
            } else {
                decrypted_list.extend_from_slice(&current_name);
                decrypted_list.push(0);
            }
        }

        Ok(Xattr::Data(decrypted_list))
    }

    fn removexattr(&self, _req: RequestInfo, path: &Path, name: &OsStr) -> ResultEmpty {
        debug!("removexattr: {:?} name={:?}", path, name);

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
        let c_path =
            std::ffi::CString::new(real_path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;

        // Remove xattr from underlying filesystem
        let ret = unsafe { libc::lremovexattr(c_path.as_ptr(), c_name.as_ptr()) };

        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO))
        }
    }
}
