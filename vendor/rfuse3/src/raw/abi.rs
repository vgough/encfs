//! FUSE kernel interface.
//!
//! Types and definitions used for communication between the kernel driver and the userspace
//! part of a FUSE filesystem. Since the kernel driver may be installed independently, the ABI
//! interface is versioned and capabilities are exchanged during the initialization (mounting)
//! of a filesystem.
//!
//! [OSXFUSE (macOS)](https://github.com/osxfuse/fuse/blob/master/include/fuse_kernel.h)
//! - supports ABI 7.8 in OSXFUSE 2.x
//! - supports ABI 7.19 since OSXFUSE 3.0.0
//!
//! [libfuse (Linux/BSD)](https://github.com/libfuse/libfuse/blob/master/include/fuse_kernel.h)
//! - supports ABI 7.8 since FUSE 2.6.0
//! - supports ABI 7.12 since FUSE 2.8.0
//! - supports ABI 7.18 since FUSE 2.9.0
//! - supports ABI 7.19 since FUSE 2.9.1
//! - supports ABI 7.26 since FUSE 3.0.0
//!
//! Items without a version annotation are valid with ABI 7.8 and later

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::mem;

use serde::{Deserialize, Serialize};

/// The min size of read buffer. In Linux kernel the `FUSE_MIN_READ_BUFFER` is
///
/// ```c
/// /* The read buffer is required to be at least 8k, but may be much larger */
/// #define FUSE_MIN_READ_BUFFER 8192
/// ```
pub const FUSE_MIN_READ_BUFFER_SIZE: usize = 8 * 1024;

pub const FUSE_KERNEL_VERSION: u32 = 7;

pub const FUSE_KERNEL_MINOR_VERSION: u32 = 31;

pub const DEFAULT_MAX_BACKGROUND: u16 = 12;

pub const DEFAULT_CONGESTION_THRESHOLD: u16 = DEFAULT_MAX_BACKGROUND * 3 / 4;

pub const DEFAULT_TIME_GRAN: u32 = 1;

pub const DEFAULT_MAX_PAGES: u16 = u16::MAX;

// TODO find valid value
pub const DEFAULT_MAP_ALIGNMENT: u16 = 0;

// Bitmasks for fuse_setattr_in.valid
pub const FATTR_MODE: u32 = 1 << 0;
pub const FATTR_UID: u32 = 1 << 1;
pub const FATTR_GID: u32 = 1 << 2;
pub const FATTR_SIZE: u32 = 1 << 3;
pub const FATTR_ATIME: u32 = 1 << 4;
pub const FATTR_MTIME: u32 = 1 << 5;
pub const FATTR_FH: u32 = 1 << 6;
pub const FATTR_ATIME_NOW: u32 = 1 << 7;
pub const FATTR_MTIME_NOW: u32 = 1 << 8;
pub const FATTR_LOCKOWNER: u32 = 1 << 9;
pub const FATTR_CTIME: u32 = 1 << 10;

#[cfg(target_os = "macos")]
pub const FATTR_CRTIME: u32 = 1 << 28;
#[cfg(target_os = "macos")]
pub const FATTR_CHGTIME: u32 = 1 << 29;
#[cfg(target_os = "macos")]
pub const FATTR_BKUPTIME: u32 = 1 << 30;
#[cfg(target_os = "macos")]
pub const FATTR_FLAGS: u32 = 1 << 31;

// Init request/reply flags
/// asynchronous read requests
pub const FUSE_ASYNC_READ: u32 = 1 << 0;

#[cfg(feature = "file-lock")]
/// locking for POSIX file locks
pub const FUSE_POSIX_LOCKS: u32 = 1 << 1;

/// kernel sends file handle for fstat, etc...
pub const FUSE_FILE_OPS: u32 = 1 << 2;

/// handles the O_TRUNC open flag in the filesystem
pub const FUSE_ATOMIC_O_TRUNC: u32 = 1 << 3;

/// filesystem handles lookups of "." and ".."
pub const FUSE_EXPORT_SUPPORT: u32 = 1 << 4;

/// filesystem can handle write size larger than 4kB
pub const FUSE_BIG_WRITES: u32 = 1 << 5;

/// don't apply umask to file mode on create operations
pub const FUSE_DONT_MASK: u32 = 1 << 6;

#[cfg(not(target_os = "macos"))]
/// kernel supports splice write on the device
pub const FUSE_SPLICE_WRITE: u32 = 1 << 7;

#[cfg(not(target_os = "macos"))]
/// kernel supports splice move on the device
pub const FUSE_SPLICE_MOVE: u32 = 1 << 8;

#[cfg(not(target_os = "macos"))]
/// kernel supports splice read on the device
pub const FUSE_SPLICE_READ: u32 = 1 << 9;

#[allow(dead_code)]
/// locking for BSD style file locks
pub const FUSE_FLOCK_LOCKS: u32 = 1 << 10;

#[allow(dead_code)]
/// kernel supports ioctl on directories
pub const FUSE_HAS_IOCTL_DIR: u32 = 1 << 11;

/// automatically invalidate cached pages
pub const FUSE_AUTO_INVAL_DATA: u32 = 1 << 12;

/// do READDIRPLUS (READDIR+LOOKUP in one)
pub const FUSE_DO_READDIRPLUS: u32 = 1 << 13;

/// adaptive readdirplus
pub const FUSE_READDIRPLUS_AUTO: u32 = 1 << 14;

/// asynchronous direct I/O submission
pub const FUSE_ASYNC_DIO: u32 = 1 << 15;

/// use writeback cache for buffered writes
pub const FUSE_WRITEBACK_CACHE: u32 = 1 << 16;

/// kernel supports zero-message opens
pub const FUSE_NO_OPEN_SUPPORT: u32 = 1 << 17;

/// allow parallel lookups and readdir
pub const FUSE_PARALLEL_DIROPS: u32 = 1 << 18;

/// fs handles killing suid/sgid/cap on write/chown/trunc
pub const FUSE_HANDLE_KILLPRIV: u32 = 1 << 19;

// if enable this, means use default_permissions
/// filesystem supports posix acls
pub const FUSE_POSIX_ACL: u32 = 1 << 20;

#[allow(dead_code)]
/// reading the device after abort returns ECONNABORTED
pub const FUSE_ABORT_ERROR: u32 = 1 << 21;

/// init_out.max_pages contains the max number of req pages
pub const FUSE_MAX_PAGES: u32 = 1 << 22;

/// cache READLINK responses
pub const FUSE_CACHE_SYMLINKS: u32 = 1 << 23;

/// kernel supports zero-message opendir
pub const FUSE_NO_OPENDIR_SUPPORT: u32 = 1 << 24;

#[allow(dead_code)]
/// only invalidate cached pages on explicit request
pub const FUSE_EXPLICIT_INVAL_DATA: u32 = 1 << 25;

#[allow(dead_code)]
/// map_alignment field is valid
pub const FUSE_MAP_ALIGNMENT: u32 = 1 << 26;

#[cfg(target_os = "macos")]
pub const FUSE_ALLOCATE: u32 = 1 << 27;
#[cfg(target_os = "macos")]
pub const FUSE_EXCHANGE_DATA: u32 = 1 << 28;
#[cfg(target_os = "macos")]
pub const FUSE_CASE_INSENSITIVE: u32 = 1 << 29;
#[cfg(target_os = "macos")]
pub const FUSE_VOL_RENAME: u32 = 1 << 30;
#[cfg(target_os = "macos")]
pub const FUSE_XTIMES: u32 = 1 << 31;

// CUSE init request/reply flags
// use unrestricted ioctl
// pub const CUSE_UNRESTRICTED_IOCTL: u32 = 1 << 0;

// Release flags
pub const FUSE_RELEASE_FLUSH: u32 = 1 << 0;

#[allow(dead_code)]
pub const FUSE_RELEASE_FLOCK_UNLOCK: u32 = 1 << 1;

// Getattr flags
pub const FUSE_GETATTR_FH: u32 = 1 << 0;

#[allow(dead_code)]
// Lock flags, this is BSD file lock
pub const FUSE_LK_FLOCK: u32 = 1 << 0;

#[allow(dead_code)]
// Write flags
/// delayed write from page cache, file handle is guessed
pub const FUSE_WRITE_CACHE: u32 = 1 << 0;

#[allow(dead_code)]
/// lock_owner field is valid
pub const FUSE_WRITE_LOCKOWNER: u32 = 1 << 1;

#[allow(dead_code)]
// Read flags
pub const FUSE_READ_LOCKOWNER: u32 = 1 << 1;

// Open flags (fuse_open_out.open_flags)
pub const FOPEN_DIRECT_IO: u32 = 1 << 0;
pub const FOPEN_KEEP_CACHE: u32 = 1 << 1;
pub const FOPEN_NONSEEKABLE: u32 = 1 << 2;

// IOCTL flags
#[allow(dead_code)]
/// 32bit compat ioctl on 64bit machine
pub const FUSE_IOCTL_COMPAT: u32 = 1 << 0;

#[allow(dead_code)]
/// not restricted to well-formed ioctls, retry allowed
pub const FUSE_IOCTL_UNRESTRICTED: u32 = 1 << 1;

#[allow(dead_code)]
/// retry with new iovecs
pub const FUSE_IOCTL_RETRY: u32 = 1 << 2;

#[allow(dead_code)]
/// 32bit ioctl
pub const FUSE_IOCTL_32BIT: u32 = 1 << 3;

#[allow(dead_code)]
/// is a directory
pub const FUSE_IOCTL_DIR: u32 = 1 << 4;

#[allow(dead_code)]
/// maximum of in_iovecs + out_iovecs
pub const FUSE_IOCTL_MAX_IOV: u32 = 256;

// Poll flags
/// request poll notify
pub const FUSE_POLL_SCHEDULE_NOTIFY: u32 = 1 << 0;

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    #[cfg(target_os = "macos")]
    pub crtime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    #[cfg(target_os = "macos")]
    pub crtimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    #[cfg(target_os = "macos")]
    // see chflags(2)
    pub flags: u32,
    pub blksize: u32,
    pub(crate) _padding: u32,
}

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_kstatfs {
    // Total blocks (in units of frsize)
    pub blocks: u64,
    // Free blocks
    pub bfree: u64,
    // Free blocks for unprivileged users
    pub bavail: u64,
    // Total inodes
    pub files: u64,
    // Free inodes
    pub ffree: u64,
    // Filesystem block size
    pub bsize: u32,
    // Maximum filename length
    pub namelen: u32,
    // Fundamental file system block size
    pub frsize: u32,
    pub(crate) _padding: u32,
    pub spare: [u32; 6],
}

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types, dead_code)]
pub struct fuse_file_lock {
    pub start: u64,
    pub end: u64,
    pub r#type: u32,
    pub pid: u32,
}

/// Invalid opcode error.
#[derive(Debug)]
pub struct UnknownOpcodeError(pub u32);

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum fuse_opcode {
    FUSE_LOOKUP = 1,
    // no reply
    FUSE_FORGET = 2,
    FUSE_GETATTR = 3,
    FUSE_SETATTR = 4,
    FUSE_READLINK = 5,
    FUSE_SYMLINK = 6,
    FUSE_MKNOD = 8,
    FUSE_MKDIR = 9,
    FUSE_UNLINK = 10,
    FUSE_RMDIR = 11,
    FUSE_RENAME = 12,
    FUSE_LINK = 13,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_WRITE = 16,
    FUSE_STATFS = 17,
    FUSE_RELEASE = 18,
    FUSE_FSYNC = 20,
    FUSE_SETXATTR = 21,
    FUSE_GETXATTR = 22,
    FUSE_LISTXATTR = 23,
    FUSE_REMOVEXATTR = 24,
    FUSE_FLUSH = 25,
    FUSE_INIT = 26,
    FUSE_OPENDIR = 27,
    FUSE_READDIR = 28,
    FUSE_RELEASEDIR = 29,
    FUSE_FSYNCDIR = 30,
    #[cfg(feature = "file-lock")]
    FUSE_GETLK = 31,
    #[cfg(feature = "file-lock")]
    FUSE_SETLK = 32,
    #[cfg(feature = "file-lock")]
    FUSE_SETLKW = 33,
    FUSE_ACCESS = 34,
    FUSE_CREATE = 35,
    FUSE_INTERRUPT = 36,
    FUSE_BMAP = 37,
    FUSE_DESTROY = 38,
    // TODO implement it after get enough info about it
    // FUSE_IOCTL = 39,
    FUSE_POLL = 40,
    FUSE_NOTIFY_REPLY = 41,
    FUSE_BATCH_FORGET = 42,
    FUSE_FALLOCATE = 43,
    FUSE_READDIRPLUS = 44,
    FUSE_RENAME2 = 45,
    FUSE_LSEEK = 46,
    FUSE_COPY_FILE_RANGE = 47,
    // FUSE_SETUPMAPPING = 48,
    // FUSE_REMOVEMAPPING = 49,
    #[cfg(target_os = "macos")]
    FUSE_SETVOLNAME = 61,
    #[cfg(target_os = "macos")]
    FUSE_GETXTIMES = 62,
    #[cfg(target_os = "macos")]
    FUSE_EXCHANGE = 63,
    // CUSE_INIT = 4096,
}

impl Display for fuse_opcode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl TryFrom<u32> for fuse_opcode {
    type Error = UnknownOpcodeError;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            1 => Ok(fuse_opcode::FUSE_LOOKUP),
            2 => Ok(fuse_opcode::FUSE_FORGET),
            3 => Ok(fuse_opcode::FUSE_GETATTR),
            4 => Ok(fuse_opcode::FUSE_SETATTR),
            5 => Ok(fuse_opcode::FUSE_READLINK),
            6 => Ok(fuse_opcode::FUSE_SYMLINK),
            8 => Ok(fuse_opcode::FUSE_MKNOD),
            9 => Ok(fuse_opcode::FUSE_MKDIR),
            10 => Ok(fuse_opcode::FUSE_UNLINK),
            11 => Ok(fuse_opcode::FUSE_RMDIR),
            12 => Ok(fuse_opcode::FUSE_RENAME),
            13 => Ok(fuse_opcode::FUSE_LINK),
            14 => Ok(fuse_opcode::FUSE_OPEN),
            15 => Ok(fuse_opcode::FUSE_READ),
            16 => Ok(fuse_opcode::FUSE_WRITE),
            17 => Ok(fuse_opcode::FUSE_STATFS),
            18 => Ok(fuse_opcode::FUSE_RELEASE),
            20 => Ok(fuse_opcode::FUSE_FSYNC),
            21 => Ok(fuse_opcode::FUSE_SETXATTR),
            22 => Ok(fuse_opcode::FUSE_GETXATTR),
            23 => Ok(fuse_opcode::FUSE_LISTXATTR),
            24 => Ok(fuse_opcode::FUSE_REMOVEXATTR),
            25 => Ok(fuse_opcode::FUSE_FLUSH),
            26 => Ok(fuse_opcode::FUSE_INIT),
            27 => Ok(fuse_opcode::FUSE_OPENDIR),
            28 => Ok(fuse_opcode::FUSE_READDIR),
            29 => Ok(fuse_opcode::FUSE_RELEASEDIR),
            30 => Ok(fuse_opcode::FUSE_FSYNCDIR),
            #[cfg(feature = "file-lock")]
            31 => Ok(fuse_opcode::FUSE_GETLK),
            #[cfg(feature = "file-lock")]
            32 => Ok(fuse_opcode::FUSE_SETLK),
            #[cfg(feature = "file-lock")]
            33 => Ok(fuse_opcode::FUSE_SETLKW),
            34 => Ok(fuse_opcode::FUSE_ACCESS),
            35 => Ok(fuse_opcode::FUSE_CREATE),
            36 => Ok(fuse_opcode::FUSE_INTERRUPT),
            37 => Ok(fuse_opcode::FUSE_BMAP),
            38 => Ok(fuse_opcode::FUSE_DESTROY),
            // 39 => Ok(fuse_opcode::FUSE_IOCTL),
            40 => Ok(fuse_opcode::FUSE_POLL),
            41 => Ok(fuse_opcode::FUSE_NOTIFY_REPLY),
            42 => Ok(fuse_opcode::FUSE_BATCH_FORGET),
            43 => Ok(fuse_opcode::FUSE_FALLOCATE),
            44 => Ok(fuse_opcode::FUSE_READDIRPLUS),
            45 => Ok(fuse_opcode::FUSE_RENAME2),
            46 => Ok(fuse_opcode::FUSE_LSEEK),
            47 => Ok(fuse_opcode::FUSE_COPY_FILE_RANGE),
            // 48 => Ok(fuse_opcode::FUSE_SETUPMAPPING),
            // 49 => Ok(fuse_opcode::FUSE_REMOVEMAPPING),
            #[cfg(target_os = "macos")]
            61 => Ok(fuse_opcode::FUSE_SETVOLNAME),
            #[cfg(target_os = "macos")]
            62 => Ok(fuse_opcode::FUSE_GETXTIMES),
            #[cfg(target_os = "macos")]
            63 => Ok(fuse_opcode::FUSE_EXCHANGE),

            // 4096 => Ok(fuse_opcode::CUSE_INIT),
            opcode => Err(UnknownOpcodeError(opcode)),
        }
    }
}

/// Invalid notify code error.
#[derive(Debug)]
pub struct InvalidNotifyCodeError(u32);

impl Display for InvalidNotifyCodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "InvalidNotifyCodeError({})", self.0)
    }
}

impl Error for InvalidNotifyCodeError {}

#[derive(Debug)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum fuse_notify_code {
    /// notify kernel that a poll waiting for IO on a file handle should wake up.
    FUSE_POLL = 1,

    /// notify kernel that an inode should be invalidated.
    FUSE_NOTIFY_INVAL_INODE = 2,

    /// notify kernel that a directory entry should be invalidated.
    FUSE_NOTIFY_INVAL_ENTRY = 3,

    /// store data into kernel cache of an inode
    FUSE_NOTIFY_STORE = 4,

    /// retrieve data from kernel cache of an inode
    FUSE_NOTIFY_RETRIEVE = 5,

    /// notify kernel that a directory entry has been deleted
    FUSE_NOTIFY_DELETE = 6,
}

impl TryFrom<u32> for fuse_notify_code {
    type Error = InvalidNotifyCodeError;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            1 => Ok(fuse_notify_code::FUSE_POLL),

            2 => Ok(fuse_notify_code::FUSE_NOTIFY_INVAL_INODE),

            3 => Ok(fuse_notify_code::FUSE_NOTIFY_INVAL_ENTRY),

            4 => Ok(fuse_notify_code::FUSE_NOTIFY_STORE),

            5 => Ok(fuse_notify_code::FUSE_NOTIFY_RETRIEVE),

            6 => Ok(fuse_notify_code::FUSE_NOTIFY_DELETE),

            invalid_code => Err(InvalidNotifyCodeError(invalid_code)),
        }
    }
}

pub const FUSE_ENTRY_OUT_SIZE: usize = mem::size_of::<fuse_entry_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_entry_out {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: fuse_attr,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_forget_in {
    pub nlookup: u64,
}

pub const FUSE_FORGET_ONE_SIZE: usize = mem::size_of::<fuse_forget_one>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_forget_one {
    pub nodeid: u64,
    pub(crate) _nlookup: u64,
}

pub const FUSE_BATCH_FORGET_IN_SIZE: usize = mem::size_of::<fuse_batch_forget_in>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_batch_forget_in {
    pub count: u32,
    pub(crate) _dummy: u32,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_getattr_in {
    pub getattr_flags: u32,
    pub dummy: u32,
    pub fh: u64,
}

pub const FUSE_ATTR_OUT_SIZE: usize = mem::size_of::<fuse_attr_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_attr_out {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: fuse_attr,
}

#[cfg(target_os = "macos")]
pub const FUSE_GETXTIMES_OUT_SIZE: usize = mem::size_of::<fuse_getxtimes_out>();

#[cfg(target_os = "macos")]
#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_getxtimes_out {
    pub bkuptime: u64,
    pub crtime: u64,
    pub bkuptimensec: u32,
    pub crtimensec: u32,
}

pub const FUSE_MKNOD_IN_SIZE: usize = mem::size_of::<fuse_mknod_in>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_mknod_in {
    pub mode: u32,
    pub rdev: u32,
    pub(crate) _umask: u32,
    _padding: u32,
}

pub const FUSE_MKDIR_IN_SIZE: usize = mem::size_of::<fuse_mkdir_in>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_mkdir_in {
    pub mode: u32,
    pub umask: u32,
}

pub const FUSE_RENAME_IN_SIZE: usize = mem::size_of::<fuse_rename_in>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_rename_in {
    pub newdir: u64,
    // https://github.com/osxfuse/fuse/blob/master/include/fuse_kernel.h#L448
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    pub flags: u32,
    #[cfg(target_os = "macos")]
    _padding: u32,
}

pub const FUSE_RENAME2_IN_SIZE: usize = mem::size_of::<fuse_rename2_in>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_rename2_in {
    pub newdir: u64,
    pub flags: u32,
    _padding: u32,
}

#[cfg(target_os = "macos")]
pub const FUSE_EXCHANGE_IN_SIZE: usize = mem::size_of::<fuse_exchange_in>();

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_exchange_in {
    pub olddir: u64,
    pub newdir: u64,
    pub options: u64,
}

pub const FUSE_LINK_IN_SIZE: usize = mem::size_of::<fuse_link_in>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_link_in {
    pub oldnodeid: u64,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_setattr_in {
    pub valid: u32,
    _padding: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub unused4: u32,
    pub uid: u32,
    pub gid: u32,
    pub unused5: u32,
    #[cfg(target_os = "macos")]
    pub bkuptime: u64,
    #[cfg(target_os = "macos")]
    pub chgtime: u64,
    #[cfg(target_os = "macos")]
    pub crtime: u64,
    #[cfg(target_os = "macos")]
    pub bkuptimensec: u32,
    #[cfg(target_os = "macos")]
    pub chgtimensec: u32,
    #[cfg(target_os = "macos")]
    pub crtimensec: u32,
    #[cfg(target_os = "macos")]
    pub flags: u32, // see chflags(2)
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_open_in {
    pub flags: u32,
    pub(crate) _unused: u32,
}

pub const FUSE_CREATE_IN_SIZE: usize = mem::size_of::<fuse_create_in>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_create_in {
    pub flags: u32,
    pub mode: u32,
    pub(crate) _umask: u32,
    _padding: u32,
}

pub const FUSE_OPEN_OUT_SIZE: usize = mem::size_of::<fuse_open_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_open_out {
    pub fh: u64,
    pub open_flags: u32,
    pub(crate) _padding: u32,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_release_in {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_flush_in {
    pub fh: u64,
    pub(crate) _unused: u32,
    _padding: u32,
    pub lock_owner: u64,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_read_in {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub(crate) _read_flags: u32,
    pub lock_owner: u64,
    pub(crate) _flags: u32,
    _padding: u32,
}

pub const FUSE_WRITE_IN_SIZE: usize = mem::size_of::<fuse_write_in>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_write_in {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub(crate) _lock_owner: u64,
    pub flags: u32,
    _padding: u32,
}

pub const FUSE_WRITE_OUT_SIZE: usize = mem::size_of::<fuse_write_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_write_out {
    pub size: u32,
    pub(crate) _padding: u32,
}

pub const FUSE_STATFS_OUT_SIZE: usize = mem::size_of::<fuse_statfs_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_statfs_out {
    pub st: fuse_kstatfs,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_fsync_in {
    pub fh: u64,
    pub fsync_flags: u32,
    _padding: u32,
}

pub const FUSE_SETXATTR_IN_SIZE: usize = mem::size_of::<fuse_setxattr_in>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_setxattr_in {
    pub size: u32,
    pub flags: u32,
    #[cfg(target_os = "macos")]
    pub position: u32,
    #[cfg(target_os = "macos")]
    _padding: u32,
}

pub const FUSE_GETXATTR_IN_SIZE: usize = mem::size_of::<fuse_getxattr_in>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_getxattr_in {
    pub size: u32,
    _padding: u32,
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    pub position: u32,
    #[cfg(target_os = "macos")]
    _padding2: u32,
}

pub const FUSE_GETXATTR_OUT_SIZE: usize = mem::size_of::<fuse_getxattr_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_getxattr_out {
    pub size: u32,
    pub(crate) _padding: u32,
}

#[cfg(feature = "file-lock")]
#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_lk_in {
    pub fh: u64,
    pub owner: u64,
    pub lk: fuse_file_lock,
    pub(crate) _lk_flags: u32,
    _padding: u32,
}

#[cfg(feature = "file-lock")]
pub const FUSE_LK_OUT_SIZE: usize = mem::size_of::<fuse_lk_out>();

#[cfg(feature = "file-lock")]
#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_lk_out {
    pub lk: fuse_file_lock,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_access_in {
    pub mask: u32,
    _padding: u32,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_init_in {
    pub(crate) _major: u32,
    pub(crate) _minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

pub const FUSE_INIT_OUT_SIZE: usize = mem::size_of::<fuse_init_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_init_out {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
    pub unused: [u32; 8],
}

/*#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct cuse_init_in {
    pub major: u32,
    pub minor: u32,
    pub unused: u32,
    pub flags: u32,
}*/

/*#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct cuse_init_out {
    pub major: u32,
    pub minor: u32,
    pub unused: u32,
    pub flags: u32,
    pub max_read: u32,
    pub max_write: u32,
    // chardev major
    pub dev_major: u32,
    // chardev minor
    pub dev_minor: u32,
    pub spare: [u32; 10],
}*/

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_interrupt_in {
    pub unique: u64,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_bmap_in {
    pub block: u64,
    pub blocksize: u32,
    _padding: u32,
}

pub const FUSE_BMAP_OUT_SIZE: usize = mem::size_of::<fuse_bmap_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_bmap_out {
    pub block: u64,
}

//#[derive(Debug, Deserialize)]
//#[allow(non_camel_case_types)]
//pub struct fuse_ioctl_in {
//pub fh: u64,
//pub flags: u32,
//pub cmd: u32,
//pub arg: u64,
//pub in_size: u32,
//pub out_size: u32,
//}

//#[derive(Debug)]
//#[allow(non_camel_case_types)]
//pub struct fuse_ioctl_iovec {
//pub base: u64,
//pub len: u64,
//}

//#[derive(Debug)]
//#[allow(non_camel_case_types)]
//pub struct fuse_ioctl_out {
//pub result: i32,
//pub flags: u32,
//pub in_iovs: u32,
//pub out_iovs: u32,
//}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_poll_in {
    pub fh: u64,
    pub kh: u64,
    pub flags: u32,
    pub events: u32,
}

pub const FUSE_POLL_OUT_SIZE: usize = mem::size_of::<fuse_poll_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_poll_out {
    pub revents: u32,
    pub(crate) _padding: u32,
}

pub const FUSE_NOTIFY_POLL_WAKEUP_OUT_SIZE: usize = mem::size_of::<fuse_notify_poll_wakeup_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_notify_poll_wakeup_out {
    pub kh: u64,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_fallocate_in {
    pub fh: u64,
    pub offset: u64,
    pub length: u64,
    pub mode: u32,
    _padding: u32,
}

pub const FUSE_IN_HEADER_SIZE: usize = mem::size_of::<fuse_in_header>();

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_in_header {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    _padding: u32,
}

pub const FUSE_OUT_HEADER_SIZE: usize = mem::size_of::<fuse_out_header>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_out_header {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

pub const FUSE_DIRENT_SIZE: usize = mem::size_of::<fuse_dirent>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_dirent {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub r#type: u32,
    // followed by name of namelen bytes
}

pub const FUSE_DIRENTPLUS_SIZE: usize = mem::size_of::<fuse_direntplus>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_direntplus {
    pub entry_out: fuse_entry_out,
    pub dirent: fuse_dirent,
}

pub const FUSE_NOTIFY_INVAL_INODE_OUT_SIZE: usize = mem::size_of::<fuse_notify_inval_inode_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_notify_inval_inode_out {
    pub ino: u64,
    pub off: i64,
    pub len: i64,
}

pub const FUSE_NOTIFY_INVAL_ENTRY_OUT_SIZE: usize = mem::size_of::<fuse_notify_inval_entry_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_notify_inval_entry_out {
    pub parent: u64,
    pub namelen: u32,
    pub(crate) _padding: u32,
}

pub const FUSE_NOTIFY_DELETE_OUT_SIZE: usize = mem::size_of::<fuse_notify_delete_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_notify_delete_out {
    pub parent: u64,
    pub child: u64,
    pub namelen: u32,
    pub(crate) _padding: u32,
}

pub const FUSE_NOTIFY_STORE_OUT_SIZE: usize = mem::size_of::<fuse_notify_store_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_notify_store_out {
    pub nodeid: u64,
    pub offset: u64,
    pub size: u32,
    pub(crate) _padding: u32,
}

pub const FUSE_NOTIFY_RETRIEVE_OUT_SIZE: usize = mem::size_of::<fuse_notify_retrieve_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_notify_retrieve_out {
    pub notify_unique: u64,
    pub nodeid: u64,
    pub offset: u64,
    pub size: u32,
    pub(crate) _padding: u32,
}

pub const FUSE_NOTIFY_RETRIEVE_IN_SIZE: usize = mem::size_of::<fuse_notify_retrieve_in>();

#[derive(Debug, Deserialize)]
// matches the size of fuse_write_in
#[allow(non_camel_case_types)]
pub struct fuse_notify_retrieve_in {
    _dummy1: u64,
    pub offset: u64,
    pub size: u32,
    _dummy2: u32,
    _dummy3: u64,
    _dummy4: u64,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_lseek_in {
    pub fh: u64,
    pub offset: u64,
    pub whence: u32,
    _padding: u32,
}

pub const FUSE_LSEEK_OUT_SIZE: usize = mem::size_of::<fuse_lseek_out>();

#[derive(Debug, Serialize)]
#[allow(non_camel_case_types)]
pub struct fuse_lseek_out {
    pub offset: u64,
}

#[derive(Debug, Deserialize)]
#[allow(non_camel_case_types)]
pub struct fuse_copy_file_range_in {
    pub fh_in: u64,
    pub off_in: u64,
    pub nodeid_out: u64,
    pub fh_out: u64,
    pub off_out: u64,
    pub len: u64,
    pub flags: u64,
}
