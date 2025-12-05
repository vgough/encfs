use crate::crypto::file::{FileDecoder, FileEncoder};
use crate::crypto::ssl::SslCipher;
use fuse_mt::{
    CallbackResult, CreatedEntry, DirectoryEntry, FileAttr, FileType, FilesystemMT, RequestInfo,
    ResultCreate, ResultEmpty, ResultEntry, ResultOpen, ResultReaddir, ResultSlice, ResultStatfs,
    ResultWrite, Statfs,
};
use libc;
use log::{debug, error, warn};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

struct FileHandle {
    file: File,
    file_iv: u64,
    header_size: u64,
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
    block_size: u64,
    block_mac_bytes: u64,
    chained_name_iv: bool,
    external_iv_chaining: bool,
}

impl EncFs {
    pub fn new(
        root: PathBuf,
        cipher: SslCipher,
        block_size: u64,
        block_mac_bytes: u64,
        chained_name_iv: bool,
        external_iv_chaining: bool,
    ) -> Self {
        Self {
            root,
            cipher,
            handles: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
            block_size,
            block_mac_bytes,
            chained_name_iv,
            external_iv_chaining,
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
                std::path::Component::Normal(name) => {
                    let name_str = name.to_str().ok_or(libc::EILSEQ)?;
                    let (encrypted_name, new_iv) =
                        self.cipher.encrypt_filename(name_str, iv).map_err(|e| {
                            error!("Encrypt filename failed: {}", e);
                            libc::EIO
                        })?;
                    encrypted_path.push(encrypted_name);
                    if self.chained_name_iv {
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
    #[allow(dead_code)]
    pub fn decrypt_path(&self, encrypted_path: &Path) -> Result<(PathBuf, u64), libc::c_int> {
        let mut decrypted_path = PathBuf::new();
        let mut iv = 0u64;
        for component in encrypted_path.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => {
                    let name_str = name.to_str().ok_or(libc::EILSEQ)?;
                    let (decrypted_name, new_iv) =
                        self.cipher.decrypt_filename(name_str, iv).map_err(|e| {
                            error!("Failed to decrypt filename {}: {}", name_str, e);
                            libc::EIO
                        })?;
                    decrypted_path.push(decrypted_name);
                    if self.chained_name_iv {
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

        if (meta.is_dir() && (self.chained_name_iv || self.external_iv_chaining))
            || (meta.is_file() && self.external_iv_chaining)
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
            if self.external_iv_chaining {
                warn!("Renaming symlinks with external IV chaining is not supported");
                return Err(libc::ENOSYS);
            }

            if self.chained_name_iv {
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
                let fname_str = fname.to_str().ok_or(libc::EILSEQ)?;

                if fname_str == "." || fname_str == ".." || fname_str.starts_with('.') {
                    continue;
                }

                let (plain_name, _) = match self.cipher.decrypt_filename(fname_str, source.iv) {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("Skipping undecryptable child {:?}: {}", fname, e);
                        continue;
                    }
                };

                let child_name = OsStr::new(&plain_name);
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
        } else if self.external_iv_chaining && meta.is_file() {
            self.copy_file_with_header_rewrite(source.physical, dest.physical, source.iv, dest.iv)?;
        } else if meta.is_symlink() {
            // Handle symlinks during recursive directory copies.
            // When chained_name_iv is enabled, symlink targets are encrypted using
            // the path IV of the symlink. If the symlink's path changes (due to parent
            // directory rename), we need to re-encrypt the target with the new IV.
            if self.external_iv_chaining {
                // External IV chaining for symlinks is not supported
                return Err(libc::ENOSYS);
            }

            if self.chained_name_iv {
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
        let mut header = [0u8; 8];
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

        // 8. Copy permissions
        if let Some(meta) = metadata {
            let _ = fs::set_permissions(real_dest, meta.permissions());
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

    fn truncate(&self, _req: RequestInfo, path: &Path, fh: Option<u64>, size: u64) -> ResultEmpty {
        debug!("truncate: {:?} size={}", path, size);

        // We need to operate on an open file to support RMW
        // If we have a handle, use it. Otherwise open one.
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

        // 1. Get current size
        let metadata = file_ref
            .metadata()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let current_logical_size = FileDecoder::<File>::calculate_logical_size(
            metadata.len(),
            8, // header size
            self.block_size,
            self.block_mac_bytes,
        );

        if size == current_logical_size {
            return Ok(());
        }

        // Determine file IV / header size.
        let header_size = 8u64;
        let file_iv = if let Some(h) = &handle {
            h.file_iv
        } else {
            // Need cipher context (IV). Read header from file and decrypt.
            let mut header = [0u8; 8];
            file_ref
                .read_exact_at(&mut header, 0)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            // We need external IV (path IV) to decrypt header.
            let (_, path_iv) = self.encrypt_path(path)?;

            let external_iv = if self.external_iv_chaining {
                path_iv
            } else {
                0
            };
            self.cipher
                .decrypt_header(&mut header, external_iv)
                .map_err(|_| libc::EIO)?
        };

        let encoder = FileEncoder::new(
            &self.cipher,
            file_ref,
            file_iv,
            header_size,
            self.block_size,
            self.block_mac_bytes,
        );

        if size > current_logical_size {
            // Extension: Write zeros
            // We can do this in chunks
            const CHUNK_SIZE: usize = 128 * 1024;
            let mut remaining = size - current_logical_size;
            let mut offset = current_logical_size;
            let zeros = vec![0u8; CHUNK_SIZE];

            while remaining > 0 {
                let write_len = std::cmp::min(remaining, CHUNK_SIZE as u64);
                // encoder.write_at handles RMW of partial blocks and creation of new blocks
                encoder
                    .write_at(&zeros[..write_len as usize], offset)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                remaining -= write_len;
                offset += write_len;
            }
            // encoder writes ensure data is on disk.
            // We don't strictly need set_len unless calculate_physical_size differs?
            // But write_at will extend the file.
        } else {
            // Shrinking
            // We need to fix the last block.
            if self.block_size <= self.block_mac_bytes {
                return Err(libc::EINVAL);
            }
            let data_block_size = self.block_size - self.block_mac_bytes;
            let block_num = size / data_block_size;
            let offset_in_block = size % data_block_size;

            // If offset_in_block > 0, we must write the truncated partial block.
            if offset_in_block > 0 {
                // Read the plaintext of this block.
                // We use a decoder for this.
                let decoder = FileDecoder::new(
                    &self.cipher,
                    file_ref,
                    file_iv,
                    header_size,
                    self.block_size,
                    self.block_mac_bytes,
                );

                let mut buf = vec![0u8; data_block_size as usize];
                // Read at block start
                let read_start = block_num * data_block_size;
                let bytes_read = decoder
                    .read_at(&mut buf, read_start)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

                if (bytes_read as u64) < offset_in_block {
                    // Should not happen if we are shrinking to 'size' which is < current_size
                    // and 'size' is inside this block.
                    // Unless file is corrupt/shorter than expected.
                    return Err(libc::EIO);
                }

                // Truncate buffer
                buf.truncate(offset_in_block as usize);

                // Important: shrink the physical file *before* rewriting the last partial block.
                //
                // Otherwise, `FileEncoder::write_at` will decrypt the existing (larger) partial
                // block and re-encrypt it at the old length, and the subsequent `set_len()`
                // would truncate the ciphertext mid-stream, corrupting the last block.
                let physical_size = FileEncoder::<File>::calculate_physical_size(
                    size,
                    header_size,
                    self.block_size,
                    self.block_mac_bytes,
                );
                file_ref
                    .set_len(physical_size)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

                // Now write back using encoder with the new (shorter) on-disk size in place.
                // This will re-encrypt the block at the correct partial length.
                encoder
                    .write_at(&buf, read_start)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

                return Ok(());
            }

            // Now safe to physically truncate
            let physical_size = FileEncoder::<File>::calculate_physical_size(
                size,
                header_size,
                self.block_size,
                self.block_mac_bytes,
            );
            file_ref
                .set_len(physical_size)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        }

        Ok(())
    }

    fn utimens(
        &self,
        _req: RequestInfo,
        path: &Path,
        fh: Option<u64>,
        atime: Option<std::time::SystemTime>,
        mtime: Option<std::time::SystemTime>,
    ) -> ResultEmpty {
        debug!("utimens: {:?} atime={:?} mtime={:?}", path, atime, mtime);

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
        let target_str = target.to_str().ok_or(libc::EILSEQ)?;

        let (plain_target, _) = self
            .cipher
            .decrypt_filename(target_str, path_iv)
            .map_err(|e| {
                error!("Failed to decrypt symlink target: {}", e);
                libc::EIO
            })?;

        Ok(plain_target.into_bytes())
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

        let target_str = target.to_str().ok_or(libc::EILSEQ)?;
        let (enc_target, _) = self
            .cipher
            .encrypt_filename(target_str, path_iv)
            .map_err(|e| {
                error!("Failed to encrypt symlink target: {}", e);
                libc::EIO
            })?;

        let enc_target_path = Path::new(&enc_target);

        std::os::unix::fs::symlink(enc_target_path, &real_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        self.getattr(req, &path, None)
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
        let header_size = 8;
        if metadata.is_file() {
            size = FileDecoder::<std::fs::File>::calculate_logical_size(
                metadata.len(),
                header_size,
                self.block_size,
                self.block_mac_bytes,
            );
        }

        let attr = FileAttr {
            size,
            blocks: metadata.blocks(),
            atime: SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.atime() as u64),
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.mtime() as u64),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.ctime() as u64),
            crtime: SystemTime::UNIX_EPOCH,
            kind: if metadata.is_dir() {
                FileType::Directory
            } else if metadata.is_symlink() {
                FileType::Symlink
            } else {
                FileType::RegularFile
            },
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
                        name: OsStr::new(&decrypted_name).to_os_string(),
                        kind: if metadata.is_dir() {
                            FileType::Directory
                        } else if metadata.is_symlink() {
                            FileType::Symlink
                        } else {
                            FileType::RegularFile
                        },
                    });
                }
                Err(e) => {
                    warn!("Failed to decrypt filename {}: {}", name_str, e);
                }
            }
        }

        Ok(result)
    }

    fn opendir(&self, _req: RequestInfo, path: &Path, flags: u32) -> ResultOpen {
        debug!("opendir: {:?}", path);
        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        Ok((fh, flags))
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
        let header_size = 8;
        let external_iv = if self.external_iv_chaining {
            path_iv
        } else {
            0
        };

        if want_trunc && want_write {
            // If the file was truncated, we must generate and write a new header.
            let (header, iv) = self.cipher.encrypt_header(external_iv).map_err(|e| {
                error!("Failed to generate header: {}", e);
                libc::EIO
            })?;

            use std::io::Write;
            // Need to verify if file needs to be mutable or if we can use &file.
            // File implements Write.
            // But 'file' is owned here so we can borrow mutably.
            let mut file_ref = &file;
            file_ref
                .write_all(&header)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
            file_iv = iv;
        } else {
            // Read header
            let mut header = [0u8; 8];
            let bytes_read = file
                .read_at(&mut header, 0)
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

            if bytes_read == 8 {
                // Decrypt header
                if let Ok(iv) = self.cipher.decrypt_header(&mut header, external_iv) {
                    file_iv = iv;
                } else {
                    warn!("Failed to decrypt file header for {:?}", path);
                    // Return error? Or continue with 0 IV (garbage)?
                    // Return error.
                    return Err(libc::EIO);
                }
            }
        }

        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        let handle = Arc::new(FileHandle {
            file,
            file_iv,
            header_size,
        });

        self.handles_guard().insert(fh, handle);

        Ok((fh, flags))
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

        let decoder = FileDecoder::new(
            &self.cipher,
            &handle.file,
            handle.file_iv,
            handle.header_size,
            self.block_size,
            self.block_mac_bytes,
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
                error!("Read failed: {}", e);
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

        let encoder = FileEncoder::new(
            &self.cipher,
            &handle.file,
            handle.file_iv,
            handle.header_size,
            self.block_size,
            self.block_mac_bytes,
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

        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&real_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        // Encrypt header
        let external_iv = if self.external_iv_chaining {
            path_iv
        } else {
            0
        };

        let (header, file_iv) = self.cipher.encrypt_header(external_iv).map_err(|e| {
            error!("Failed to generate header: {}", e);
            libc::EIO
        })?;

        // Write header
        use std::io::Write;
        file.write_all(&header)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

        let fh = self.next_fh.fetch_add(1, Ordering::SeqCst);
        let handle = Arc::new(FileHandle {
            file,
            file_iv,
            header_size: 8,
        });

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
            flags,
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
            .create(real_path)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;

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
}
