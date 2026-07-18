//! reply structures.
use std::ffi::OsString;
use std::num::NonZeroU32;
use std::time::{Duration, SystemTime};

use futures_util::stream::Stream;

use crate::mount_options::DEFAULT_MAX_WRITE;
#[cfg(feature = "file-lock")]
pub use crate::raw::reply::ReplyLock;
pub use crate::raw::reply::{
    ReplyBmap, ReplyCopyFileRange, ReplyData, ReplyLSeek, ReplyOpen, ReplyPoll, ReplyStatFs,
    ReplyWrite, ReplyXAttr,
};
use crate::{FileType, Inode, Result};

/// file attributes
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct FileAttr {
    /// Size in bytes
    pub size: u64,
    /// Size in blocks
    pub blocks: u64,
    /// Time of last access
    pub atime: SystemTime,
    /// Time of last modification
    pub mtime: SystemTime,
    /// Time of last change
    pub ctime: SystemTime,
    #[cfg(target_os = "macos")]
    /// Time of creation (macOS only)
    pub crtime: SystemTime,
    /// Kind of file (directory, file, pipe, etc)
    pub kind: FileType,
    /// Permissions
    pub perm: u16,
    /// Number of hard links
    pub nlink: u32,
    /// User id
    pub uid: u32,
    /// Group id
    pub gid: u32,
    /// Rdev
    pub rdev: u32,
    #[cfg(target_os = "macos")]
    /// Flags (macOS only, see chflags(2))
    pub flags: u32,
    pub blksize: u32,
}

impl From<(Inode, FileAttr)> for crate::raw::reply::FileAttr {
    fn from((inode, attr): (u64, FileAttr)) -> Self {
        crate::raw::reply::FileAttr {
            ino: inode,
            size: attr.size,
            blocks: attr.blocks,
            atime: attr.atime.into(),
            mtime: attr.mtime.into(),
            ctime: attr.ctime.into(),
            #[cfg(target_os = "macos")]
            crtime: attr.crtime.into(),
            kind: attr.kind,
            perm: attr.perm,
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
            rdev: attr.rdev,
            #[cfg(target_os = "macos")]
            flags: attr.flags,
            blksize: attr.blksize,
        }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// init reply.
pub struct ReplyInit {
    /// Maximum size of write requests.
    pub max_write: NonZeroU32,
}

impl Default for ReplyInit {
    fn default() -> Self {
        Self {
            max_write: NonZeroU32::new(DEFAULT_MAX_WRITE).expect("default max_write is non-zero"),
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// entry reply.
pub struct ReplyEntry {
    /// the attribute TTL.
    pub ttl: Duration,
    /// the attribute.
    pub attr: FileAttr,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// reply attr.
pub struct ReplyAttr {
    /// the attribute TTL.
    pub ttl: Duration,
    /// the attribute.
    pub attr: FileAttr,
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// crate reply.
pub struct ReplyCreated {
    /// the attribute TTL.
    pub ttl: Duration,
    /// the attribute of file.
    pub attr: FileAttr,
    /// the generation of file.
    pub generation: u64,
    /// the file handle.
    pub fh: u64,
    /// the flags.
    pub flags: u32,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// directory entry.
pub struct DirectoryEntry {
    /// entry kind.
    pub kind: FileType,
    /// entry name.
    pub name: OsString,
    /// Directory offset of the _next_ entry
    pub offset: i64,
}

/// readdir reply.
pub struct ReplyDirectory<S: Stream<Item = Result<DirectoryEntry>>> {
    pub entries: S,
}

/*#[derive(Debug)]
pub struct ReplyIoctl {
    pub result: i32,
    pub flags: u32,
    pub in_iovs: u32,
    pub out_iovs: u32,
}*/

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// directory entry with attribute
pub struct DirectoryEntryPlus {
    /// the entry kind.
    pub kind: FileType,
    /// the entry name.
    pub name: OsString,
    /// Directory offset of the _next_ entry
    pub offset: i64,
    /// the entry attribute.
    pub attr: FileAttr,
    /// the entry TTL.
    pub entry_ttl: Duration,
    /// the attribute TTL.
    pub attr_ttl: Duration,
}

/// the readdirplus reply.
pub struct ReplyDirectoryPlus<S: Stream<Item = Result<DirectoryEntryPlus>>> {
    pub entries: S,
}
