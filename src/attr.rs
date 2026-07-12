//! Shared helpers for building rfuse3 file attributes from filesystem metadata.

use rfuse3::FileType;
use rfuse3::path::reply::FileAttr;
use std::fs::Metadata;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::time::{Duration, SystemTime};

/// Map std::fs::Metadata file type to FUSE FileType.
pub fn file_type_from_metadata(metadata: &Metadata) -> FileType {
    let ft = metadata.file_type();
    if ft.is_dir() {
        FileType::Directory
    } else if ft.is_symlink() {
        FileType::Symlink
    } else if ft.is_block_device() {
        FileType::BlockDevice
    } else if ft.is_char_device() {
        FileType::CharDevice
    } else if ft.is_fifo() {
        FileType::NamedPipe
    } else if ft.is_socket() {
        FileType::Socket
    } else {
        FileType::RegularFile
    }
}

/// Convert metadata timestamps (seconds + nanoseconds since epoch) to SystemTime.
pub fn system_time_from_secs(secs: i64, nanos: i64) -> SystemTime {
    if secs >= 0 {
        SystemTime::UNIX_EPOCH + Duration::new(secs as u64, nanos as u32)
    } else {
        // POSIX timestamps use floor-based seconds, so (-1, 500_000_000)
        // denotes half a second before the epoch, not one-and-a-half seconds.
        let duration = if nanos == 0 {
            Duration::new(secs.unsigned_abs(), 0)
        } else {
            Duration::new(secs.unsigned_abs() - 1, 1_000_000_000 - nanos as u32)
        };
        SystemTime::UNIX_EPOCH
            .checked_sub(duration)
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

/// Build a FUSE FileAttr from file metadata, overriding the reported size
/// (encfs reports logical plaintext sizes, reverse encfs reports ciphertext sizes).
pub fn file_attr_from_metadata(metadata: &Metadata, size: u64) -> FileAttr {
    FileAttr {
        size,
        blocks: metadata.blocks(),
        atime: system_time_from_secs(metadata.atime(), metadata.atime_nsec()),
        mtime: system_time_from_secs(metadata.mtime(), metadata.mtime_nsec()),
        ctime: system_time_from_secs(metadata.ctime(), metadata.ctime_nsec()),
        #[cfg(target_os = "macos")]
        crtime: metadata.created().unwrap_or(SystemTime::UNIX_EPOCH),
        kind: file_type_from_metadata(metadata),
        // Mask to permission bits only; the file type is carried in `kind` and
        // rfuse3 ORs them together when building the kernel reply.
        perm: (metadata.mode() & 0o7777) as u16,
        nlink: metadata.nlink() as u32,
        uid: metadata.uid(),
        gid: metadata.gid(),
        rdev: metadata.rdev() as u32,
        #[cfg(target_os = "macos")]
        flags: 0,
        blksize: metadata.blksize() as u32,
    }
}

/// Build a FileAttr for a virtual (in-memory) regular file such as the
/// reverse-mount config file.
pub fn synthetic_file_attr(
    size: u64,
    mtime: SystemTime,
    perm: u16,
    uid: u32,
    gid: u32,
) -> FileAttr {
    FileAttr {
        size,
        blocks: size.div_ceil(512),
        atime: mtime,
        mtime,
        ctime: mtime,
        #[cfg(target_os = "macos")]
        crtime: mtime,
        kind: FileType::RegularFile,
        perm,
        nlink: 1,
        uid,
        gid,
        rdev: 0,
        #[cfg(target_os = "macos")]
        flags: 0,
        blksize: 4096,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_time_preserves_fractional_pre_epoch_timestamp() {
        let timestamp = system_time_from_secs(-1, 500_000_000);

        assert_eq!(
            SystemTime::UNIX_EPOCH.duration_since(timestamp).unwrap(),
            Duration::new(0, 500_000_000)
        );
    }

    #[test]
    fn system_time_converts_whole_second_pre_epoch_timestamp() {
        let timestamp = system_time_from_secs(-1, 0);

        assert_eq!(
            SystemTime::UNIX_EPOCH.duration_since(timestamp).unwrap(),
            Duration::new(1, 0)
        );
    }
}
