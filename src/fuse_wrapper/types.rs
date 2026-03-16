// Public types exported by the fuse wrapper.
//
// Based on fuse_mt types by William R. Fraser.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::time::{Duration, SystemTime};

pub use fuser::{FileAttr, FileType, INodeNo};

/// Info about a request.
#[derive(Clone, Copy, Debug)]
pub struct RequestInfo {
    /// The unique ID assigned to this request by FUSE.
    pub unique: u64,
    /// The user ID of the process making the request.
    pub uid: u32,
    /// The group ID of the process making the request.
    pub gid: u32,
    /// The process ID of the process making the request.
    pub pid: u32,
}

/// A directory entry.
#[derive(Clone, Debug)]
pub struct DirectoryEntry {
    /// Name of the entry
    pub name: OsString,
    /// Kind of file (directory, file, pipe, etc.)
    pub kind: FileType,
}

/// Filesystem statistics.
#[derive(Clone, Copy, Debug)]
pub struct Statfs {
    /// Total data blocks in the filesystem
    pub blocks: u64,
    /// Free blocks in filesystem
    pub bfree: u64,
    /// Free blocks available to unprivileged user
    pub bavail: u64,
    /// Total file nodes in filesystem
    pub files: u64,
    /// Free file nodes in filesystem
    pub ffree: u64,
    /// Optimal transfer block size
    pub bsize: u32,
    /// Maximum length of filenames
    pub namelen: u32,
    /// Fragment size
    pub frsize: u32,
}

/// The return value for `create`: contains info on the newly-created file, as well as a handle to
/// the opened file.
#[derive(Clone, Debug)]
pub struct CreatedEntry {
    pub ttl: Duration,
    pub attr: FileAttr,
    pub fh: u64,
    pub flags: u32,
}

/// Represents the return value from the `listxattr` and `getxattr` calls, which can be either a
/// size or contain data, depending on how they are called.
#[derive(Clone, Debug)]
pub enum Xattr {
    Size(u32),
    Data(Vec<u8>),
}

pub type ResultEmpty = Result<(), libc::c_int>;
pub type ResultEntry = Result<(Duration, FileAttr), libc::c_int>;
pub type ResultOpen = Result<(u64, u32), libc::c_int>;
pub type ResultReaddir = Result<Vec<DirectoryEntry>, libc::c_int>;
pub type ResultData = Result<Vec<u8>, libc::c_int>;
pub type ResultSlice<'a> = Result<&'a [u8], libc::c_int>;
pub type ResultWrite = Result<u32, libc::c_int>;
pub type ResultStatfs = Result<Statfs, libc::c_int>;
pub type ResultCreate = Result<CreatedEntry, libc::c_int>;
pub type ResultXattr = Result<Xattr, libc::c_int>;

/// Dummy struct returned by the callback in the `read()` method. Cannot be constructed outside
/// this crate, `read()` requires you to return it, thus ensuring that you don't forget to call the
/// callback.
pub struct CallbackResult {
    pub(crate) _private: std::marker::PhantomData<()>,
}

/// This trait must be implemented to implement a filesystem with the fuse wrapper.
pub trait FilesystemMT {
    /// Called on mount, before any other function.
    fn init(&self, _req: RequestInfo) -> ResultEmpty {
        Ok(())
    }

    /// Called on filesystem unmount.
    fn destroy(&self) {
        // Nothing.
    }

    /// Get the attributes of a filesystem entry.
    fn getattr(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>) -> ResultEntry {
        Err(libc::ENOSYS)
    }

    /// Change the mode of a filesystem entry.
    fn chmod(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _mode: u32) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Change the owner UID and/or group GID of a filesystem entry.
    fn chown(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _uid: Option<u32>, _gid: Option<u32>) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Set the length of a file.
    fn truncate(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _size: u64) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Set timestamps of a filesystem entry.
    fn utimens(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _atime: Option<SystemTime>, _mtime: Option<SystemTime>) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Set timestamps of a filesystem entry (with extra options only used on MacOS).
    #[allow(clippy::too_many_arguments)]
    fn utimens_macos(&self, _req: RequestInfo, _path: &Path, _fh: Option<u64>, _crtime: Option<SystemTime>, _chgtime: Option<SystemTime>, _bkuptime: Option<SystemTime>, _flags: Option<u32>) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Read a symbolic link.
    fn readlink(&self, _req: RequestInfo, _path: &Path) -> ResultData {
        Err(libc::ENOSYS)
    }

    /// Create a special file.
    fn mknod(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr, _mode: u32, _rdev: u32) -> ResultEntry {
        Err(libc::ENOSYS)
    }

    /// Create a directory.
    fn mkdir(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr, _mode: u32) -> ResultEntry {
        Err(libc::ENOSYS)
    }

    /// Remove a file.
    fn unlink(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Remove a directory.
    fn rmdir(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Create a symbolic link.
    fn symlink(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr, _target: &Path) -> ResultEntry {
        Err(libc::ENOSYS)
    }

    /// Rename a filesystem entry.
    fn rename(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr, _newparent: &Path, _newname: &OsStr) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Create a hard link.
    fn link(&self, _req: RequestInfo, _path: &Path, _newparent: &Path, _newname: &OsStr) -> ResultEntry {
        Err(libc::ENOSYS)
    }

    /// Open a file.
    fn open(&self, _req: RequestInfo, _path: &Path, _flags: u32) -> ResultOpen {
        Err(libc::ENOSYS)
    }

    /// Read from a file.
    fn read(&self, _req: RequestInfo, _path: &Path, _fh: u64, _offset: u64, _size: u32, callback: impl FnOnce(ResultSlice<'_>) -> CallbackResult) -> CallbackResult {
        callback(Err(libc::ENOSYS))
    }

    /// Write to a file.
    fn write(&self, _req: RequestInfo, _path: &Path, _fh: u64, _offset: u64, _data: Vec<u8>, _flags: u32) -> ResultWrite {
        Err(libc::ENOSYS)
    }

    /// Called each time a program calls `close` on an open file.
    fn flush(&self, _req: RequestInfo, _path: &Path, _fh: u64, _lock_owner: u64) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Called when an open file is closed.
    fn release(&self, _req: RequestInfo, _path: &Path, _fh: u64, _flags: u32, _lock_owner: u64, _flush: bool) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Write out any pending changes of a file.
    fn fsync(&self, _req: RequestInfo, _path: &Path, _fh: u64, _datasync: bool) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Open a directory.
    fn opendir(&self, _req: RequestInfo, _path: &Path, _flags: u32) -> ResultOpen {
        Err(libc::ENOSYS)
    }

    /// Get the entries of a directory.
    fn readdir(&self, _req: RequestInfo, _path: &Path, _fh: u64) -> ResultReaddir {
        Err(libc::ENOSYS)
    }

    /// Close an open directory.
    fn releasedir(&self, _req: RequestInfo, _path: &Path, _fh: u64, _flags: u32) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Write out any pending changes to a directory.
    fn fsyncdir(&self, _req: RequestInfo, _path: &Path, _fh: u64, _datasync: bool) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Get filesystem statistics.
    fn statfs(&self, _req: RequestInfo, _path: &Path) -> ResultStatfs {
        Err(libc::ENOSYS)
    }

    /// Set a file extended attribute.
    fn setxattr(&self, _req: RequestInfo, _path: &Path, _name: &OsStr, _value: &[u8], _flags: u32, _position: u32) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Get a file extended attribute.
    fn getxattr(&self, _req: RequestInfo, _path: &Path, _name: &OsStr, _size: u32) -> ResultXattr {
        Err(libc::ENOSYS)
    }

    /// List extended attributes for a file.
    fn listxattr(&self, _req: RequestInfo, _path: &Path, _size: u32) -> ResultXattr {
        Err(libc::ENOSYS)
    }

    /// Remove an extended attribute for a file.
    fn removexattr(&self, _req: RequestInfo, _path: &Path, _name: &OsStr) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Check for access to a file.
    fn access(&self, _req: RequestInfo, _path: &Path, _mask: u32) -> ResultEmpty {
        Err(libc::ENOSYS)
    }

    /// Create and open a new file.
    fn create(&self, _req: RequestInfo, _parent: &Path, _name: &OsStr, _mode: u32, _flags: u32) -> ResultCreate {
        Err(libc::ENOSYS)
    }
}
