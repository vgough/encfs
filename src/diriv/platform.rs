//! Syncing a new sidecar, which directory IV mode depends on. What each
//! operating system and backing filesystem offers differs, so the
//! differences are kept here. (Renaming without replacing is
//! `typed_fuse::passthrough::rename_noreplace_at`.)

use std::fs::File;
use std::io;

/// Makes the sidecar `file` and its entry in `dir` reach stable storage
/// before any later write, so that a crash can't keep names encrypted under
/// the sidecar while losing the sidecar (or keeping it empty), leaving them
/// undecryptable.
///
/// That is a need for ordering, not durability. On Apple platforms, where
/// `sync_all` flushes the drive's whole cache (`F_FULLFSYNC`), it is met by
/// an `fsync` of each followed by one `F_BARRIERFSYNC` write barrier, which
/// costs a fraction as much and which Apple recommends for write barriers:
/// <https://developer.apple.com/documentation/xcode/reducing-disk-writes#Minimize-explicit-storage-synchronization>.
/// If the barrier fails, a full sync of `dir` (`F_FULLFSYNC`) flushes the
/// drive's cache, taking the file's already `fsync`ed data along; where that
/// is unsupported too (smbfs directories), each is synced as [`sync_file`]
/// does. Elsewhere the directory is synced in full, and the file's data
/// (`fdatasync`, which covers its size, all a new file needs) unless
/// `owner_changed` says it was chowned since creation, which only a full
/// sync persists. A user's
/// `fsyncdir` still flushes in full, so mkdir followed by `fsyncdir` on the
/// parent stays durable.
pub fn sync_sidecar(file: &File, dir: &File, owner_changed: bool) -> io::Result<()> {
    // Apple's plain `fsync` below covers ownership as well.
    #[cfg(target_vendor = "apple")]
    let _ = owner_changed;
    #[cfg(target_vendor = "apple")]
    {
        use std::os::unix::io::AsRawFd;
        match fsync(file) {
            Err(e) if !sync_unsupported(&e) => return Err(e),
            _ => {}
        }
        // The barrier also fsyncs `dir`, then orders both before later I/O.
        // SAFETY: `dir` is open for the duration of the call.
        if unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_BARRIERFSYNC) } == 0 {
            return Ok(());
        }
        match dir.sync_all() {
            Err(e) if sync_unsupported(&e) => {
                sync_file(file, false)?;
                sync_file(dir, false)
            }
            other => other,
        }
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        sync_file(file, !owner_changed)?;
        sync_file(dir, false)
    }
}

/// Opens the directory `dir` so it can be synced: only a descriptor opened
/// for reading can be, so this needs read access to it.
pub fn open_dir_to_sync(dir: &std::path::Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(dir)
}

/// Syncs `file`, a regular file or directory, to stable storage: its data
/// only if `data_only` (`fdatasync`), else in full (`fsync`).
///
/// A filesystem that can't sync it (`EINVAL`, `ENOTSUP`) is taken to need no
/// sync, as databases do. On Apple platforms both are `F_FULLFSYNC`, which
/// some filesystems don't support (smbfs fails it on directories with
/// `ENOTSUP`, though `fsync` works), so an unsupported `F_FULLFSYNC` falls
/// back to a plain `fsync`. Other errors, such as `EIO`, are returned rather
/// than retried, so a failed flush isn't hidden.
pub fn sync_file(file: &File, data_only: bool) -> io::Result<()> {
    let result = if data_only {
        file.sync_data()
    } else {
        file.sync_all()
    };
    #[cfg(target_vendor = "apple")]
    let result = match result {
        Err(e) if sync_unsupported(&e) => fsync(file),
        other => other,
    };
    match result {
        Err(e) if sync_unsupported(&e) => Ok(()),
        other => other,
    }
}

/// A plain `fsync(2)`, which on Apple platforms, unlike `sync_all`, doesn't
/// flush the drive's cache.
#[cfg(target_vendor = "apple")]
fn fsync(file: &File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `file` is open for the duration of the call.
    if unsafe { libc::fsync(file.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Whether a sync failed because the filesystem doesn't support it.
fn sync_unsupported(err: &io::Error) -> bool {
    err.raw_os_error()
        .is_some_and(|n| n == libc::EINVAL || n == libc::ENOTSUP || n == libc::EOPNOTSUPP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_file_skips_unsupported_syncs_but_returns_other_errors() {
        use std::os::unix::io::FromRawFd;
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read, write) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
        assert!(write.sync_all().is_err());
        if cfg!(target_vendor = "apple") {
            // F_FULLFSYNC fails on a pipe with EBADF, not an unsupported
            // errno, so it must not fall back to fsync (which would fail with
            // EINVAL and so pass).
            assert!(sync_file(&write, false).is_err());
            assert!(sync_file(&read, true).is_err());
        } else {
            // fsync fails on a pipe with EINVAL, as directories do on some
            // filesystems.
            sync_file(&write, false).unwrap();
            sync_file(&read, true).unwrap();
        }
        let dir = File::open(std::env::temp_dir()).unwrap();
        sync_file(&dir, false).unwrap();
        sync_file(&dir, true).unwrap();
    }
}
