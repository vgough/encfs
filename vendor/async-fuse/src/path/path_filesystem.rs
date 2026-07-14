use std::ffi::OsStr;

use bytes::Bytes;
use futures_util::stream::{Empty, Stream};

use super::reply::*;
use super::Request;
use crate::notify::Notify;
use crate::{Result, SetAttr};

#[allow(unused_variables)]
#[trait_make::make(Send)]
/// Path based filesystem trait.
pub trait PathFilesystem {
    /// initialize filesystem. Called before any other filesystem method.
    async fn init(&self, req: Request) -> Result<ReplyInit>;

    /// clean up filesystem. Called on filesystem exit which is fuseblk, in normal fuse filesystem,
    /// kernel may call forget for root. There is some discuss for this
    /// <https://github.com/bazil/fuse/issues/82#issuecomment-88126886>,
    /// <https://sourceforge.net/p/fuse/mailman/message/31995737/>
    async fn destroy(&self, req: Request);

    /// look up a directory entry by name and get its attributes.
    async fn lookup(&self, req: Request, parent: &OsStr, name: &OsStr) -> Result<ReplyEntry> {
        Err(libc::ENOSYS.into())
    }

    /// forget an path. The nlookup parameter indicates the number of lookups previously
    /// performed on this path. If the filesystem implements path lifetimes, it is recommended
    /// that paths acquire a single reference on each lookup, and lose nlookup references on each
    /// forget. The filesystem may ignore forget calls, if the paths don't need to have a limited
    /// lifetime. On unmount it is not guaranteed, that all referenced paths will receive a forget
    /// message. When filesystem is normal(not fuseblk) and unmounting, kernel may send forget
    /// request for root and this library will stop session after call forget. There is some
    /// discussion for this <https://github.com/bazil/fuse/issues/82#issuecomment-88126886>,
    /// <https://sourceforge.net/p/fuse/mailman/message/31995737/>
    /// <https://sourceforge.net/p/fuse/mailman/message/31995737/>
    async fn forget(&self, req: Request, parent: &OsStr, nlookup: u64) {}

    /// get file attributes. If `fh` is None, means `fh` is not set. If `path` is None, means the
    /// path may be deleted.
    async fn getattr(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: Option<u64>,
        flags: u32,
    ) -> Result<ReplyAttr> {
        Err(libc::ENOSYS.into())
    }

    /// set file attributes. If `fh` is None, means `fh` is not set. If `path` is None, means the
    /// path may be deleted.
    async fn setattr(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: Option<u64>,
        set_attr: SetAttr,
    ) -> Result<ReplyAttr> {
        Err(libc::ENOSYS.into())
    }

    /// read symbolic link.
    async fn readlink(&self, req: Request, path: &OsStr) -> Result<ReplyData> {
        Err(libc::ENOSYS.into())
    }

    /// create a symbolic link.
    async fn symlink(
        &self,
        req: Request,
        parent: &OsStr,
        name: &OsStr,
        link_path: &OsStr,
    ) -> Result<ReplyEntry> {
        Err(libc::ENOSYS.into())
    }

    /// create file node. Create a regular file, character device, block device, fifo or socket
    /// node. When creating file, most cases user only need to implement
    /// [`create`][PathFilesystem::create].
    async fn mknod(
        &self,
        req: Request,
        parent: &OsStr,
        name: &OsStr,
        mode: u32,
        rdev: u32,
    ) -> Result<ReplyEntry> {
        Err(libc::ENOSYS.into())
    }

    /// create a directory.
    async fn mkdir(
        &self,
        req: Request,
        parent: &OsStr,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<ReplyEntry> {
        Err(libc::ENOSYS.into())
    }

    /// remove a file.
    async fn unlink(&self, req: Request, parent: &OsStr, name: &OsStr) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// remove a directory.
    async fn rmdir(&self, req: Request, parent: &OsStr, name: &OsStr) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// rename a file or directory.
    async fn rename(
        &self,
        req: Request,
        origin_parent: &OsStr,
        origin_name: &OsStr,
        parent: &OsStr,
        name: &OsStr,
    ) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// create a hard link.
    async fn link(
        &self,
        req: Request,
        path: &OsStr,
        new_parent: &OsStr,
        new_name: &OsStr,
    ) -> Result<ReplyEntry> {
        Err(libc::ENOSYS.into())
    }

    /// open a file. Open flags (with the exception of `O_CREAT`, `O_EXCL` and `O_NOCTTY`) are
    /// available in flags. Filesystem may store an arbitrary file handle (pointer, index, etc) in
    /// fh, and use this in other all other file operations (read, write, flush, release, fsync).
    /// Filesystem may also implement stateless file I/O and not store anything in fh. There are
    /// also some flags (`direct_io`, `keep_cache`) which the filesystem may set, to change the way
    /// the file is opened.  A file system need not implement this method if it
    /// sets [`MountOptions::no_open_support`][crate::MountOptions::no_open_support] and if the
    /// kernel supports `FUSE_NO_OPEN_SUPPORT`.
    ///
    /// # Notes:
    ///
    /// See `fuse_file_info` structure in
    /// [fuse_common.h](https://libfuse.github.io/doxygen/include_2fuse__common_8h_source.html) for
    /// more details.
    async fn open(&self, req: Request, path: &OsStr, flags: u32) -> Result<ReplyOpen> {
        Err(libc::ENOSYS.into())
    }

    /// read data. Read should send exactly the number of bytes requested except on EOF or error,
    /// otherwise the rest of the data will be substituted with zeroes. An exception to this is
    /// when the file has been opened in `direct_io` mode, in which case the return value of the
    /// read system call will reflect the return value of this operation. `fh` will contain the
    /// value set by the open method, or will be undefined if the open method didn't set any value.
    /// when `path` is None, it means the path may be deleted.
    async fn read(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        Err(libc::ENOSYS.into())
    }

    /// write data. Write should return exactly the number of bytes requested except on error. An
    /// exception to this is when the file has been opened in `direct_io` mode, in which case the
    /// return value of the write system call will reflect the return value of this operation. `fh`
    /// will contain the value set by the open method, or will be undefined if the open method
    /// didn't set any value. When `path` is None, it means the path may be deleted. When
    /// `write_flags` contains [`FUSE_WRITE_CACHE`](crate::raw::flags::FUSE_WRITE_CACHE), means the
    /// write operation is a delay write.
    #[allow(clippy::too_many_arguments)]
    async fn write(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: u64,
        offset: u64,
        data: &[u8],
        write_flags: u32,
        flags: u32,
    ) -> Result<ReplyWrite> {
        Err(libc::ENOSYS.into())
    }

    /// get filesystem statistics.
    async fn statfs(&self, req: Request, path: &OsStr) -> Result<ReplyStatFs> {
        Err(libc::ENOSYS.into())
    }

    /// release an open file. Release is called when there are no more references to an open file:
    /// all file descriptors are closed and all memory mappings are unmapped. For every open call
    /// there will be exactly one release call. The filesystem may reply with an error, but error
    /// values are not returned to `close()` or `munmap()` which triggered the release. `fh` will
    /// contain the value set by the open method, or will be undefined if the open method didn't
    /// set any value. `flags` will contain the same flags as for open. `flush` means flush the
    /// data or not when closing file. when `path` is None, it means the path may be deleted.
    async fn release(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: u64,
        flags: u32,
        lock_owner: u64,
        flush: bool,
    ) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// synchronize file contents. If the `datasync` is true, then only the user data should be
    /// flushed, not the metadata. when `path` is None, it means the path may be deleted.
    async fn fsync(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: u64,
        datasync: bool,
    ) -> Result<()> {
        Ok(())
    }

    /// set an extended attribute.
    async fn setxattr(
        &self,
        req: Request,
        path: &OsStr,
        name: &OsStr,
        value: &[u8],
        flags: u32,
        position: u32,
    ) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// get an extended attribute. If size is too small, use [`ReplyXAttr::Size`] to return correct
    /// size. If size is enough, use [`ReplyXAttr::Data`] to send it, or return error.
    async fn getxattr(
        &self,
        req: Request,
        path: &OsStr,
        name: &OsStr,
        size: u32,
    ) -> Result<ReplyXAttr> {
        Err(libc::ENOSYS.into())
    }

    /// list extended attribute names. If size is too small, use [`ReplyXAttr::Size`] to return
    /// correct size. If size is enough, use [`ReplyXAttr::Data`] to send it, or return error.
    async fn listxattr(&self, req: Request, path: &OsStr, size: u32) -> Result<ReplyXAttr> {
        Err(libc::ENOSYS.into())
    }

    /// remove an extended attribute.
    async fn removexattr(&self, req: Request, path: &OsStr, name: &OsStr) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// flush method. This is called on each `close()` of the opened file. Since file descriptors
    /// can be duplicated (`dup`, `dup2`, `fork`), for one open call there may be many flush calls.
    /// Filesystems shouldn't assume that flush will always be called after some writes, or that if
    /// will be called at all. `fh` will contain the value set by the open method, or will be
    /// undefined if the open method didn't set any value. when `path` is None, it means the path
    /// may be deleted.
    ///
    /// # Notes:
    ///
    /// the name of the method is misleading, since (unlike fsync) the filesystem is not forced to
    /// flush pending writes. One reason to flush data, is if the filesystem wants to return write
    /// errors. If the filesystem supports file locking operations (
    /// [`setlk`][PathFilesystem::setlk], [`getlk`][PathFilesystem::getlk]) it should remove all
    /// locks belonging to `lock_owner`.
    async fn flush(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: u64,
        lock_owner: u64,
    ) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// open a directory. Filesystem may store an arbitrary file handle (pointer, index, etc) in
    /// `fh`, and use this in other all other directory stream operations
    /// ([`readdir`][PathFilesystem::readdir], [`releasedir`][PathFilesystem::releasedir],
    /// [`fsyncdir`][PathFilesystem::fsyncdir]). Filesystem may also implement stateless directory
    /// I/O and not store anything in `fh`.  A file system need not implement this method if it
    /// sets [`MountOptions::no_open_dir_support`][crate::MountOptions::no_open_dir_support] and if
    /// the kernel supports `FUSE_NO_OPENDIR_SUPPORT`.
    async fn opendir(&self, req: Request, path: &OsStr, flags: u32) -> Result<ReplyOpen> {
        Err(libc::ENOSYS.into())
    }

    /// read directory. `offset` is used to track the offset of the directory entries. `fh` will
    /// contain the value set by the [`opendir`][PathFilesystem::opendir] method, or will be
    /// undefined if the [`opendir`][PathFilesystem::opendir] method didn't set any value.
    async fn readdir<'a>(
        &'a self,
        req: Request,
        path: &'a OsStr,
        fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<impl Stream<Item = Result<DirectoryEntry>> + Send + 'a>> {
        Err::<ReplyDirectory<Empty<_>>, _>(libc::ENOSYS.into())
    }

    /// release an open directory. For every [`opendir`][PathFilesystem::opendir] call there will
    /// be exactly one `releasedir` call. `fh` will contain the value set by the
    /// [`opendir`][PathFilesystem::opendir] method, or will be undefined if the
    /// [`opendir`][PathFilesystem::opendir] method didn't set any value.
    async fn releasedir(&self, req: Request, path: &OsStr, fh: u64, flags: u32) -> Result<()> {
        Ok(())
    }

    /// synchronize directory contents. If the `datasync` is true, then only the directory contents
    /// should be flushed, not the metadata. `fh` will contain the value set by the
    /// [`opendir`][PathFilesystem::opendir] method, or will be undefined if the
    /// [`opendir`][PathFilesystem::opendir] method didn't set any value.
    async fn fsyncdir(&self, req: Request, path: &OsStr, fh: u64, datasync: bool) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    #[cfg(feature = "file-lock")]
    /// test for a POSIX file lock.
    ///
    /// # Notes:
    ///
    /// this is supported on enable **`file-lock`** feature.
    #[allow(clippy::too_many_arguments)]
    async fn getlk(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        r#type: u32,
        pid: u32,
    ) -> Result<ReplyLock>;

    #[cfg(feature = "file-lock")]
    /// acquire, modify or release a POSIX file lock.
    ///
    /// # Notes:
    ///
    /// this is supported on enable **`file-lock`** feature.
    #[allow(clippy::too_many_arguments)]
    async fn setlk(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        r#type: u32,
        pid: u32,
        block: bool,
    ) -> Result<()>;

    /// check file access permissions. This will be called for the `access()` system call. If the
    /// `default_permissions` mount option is given, this method is not be called. This method is
    /// not called under Linux kernel versions 2.4.x.
    async fn access(&self, req: Request, path: &OsStr, mask: u32) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// create and open a file. If the file does not exist, first create it with the specified
    /// mode, and then open it. Open flags (with the exception of `O_NOCTTY`) are available in
    /// flags. Filesystem may store an arbitrary file handle (pointer, index, etc) in `fh`, and use
    /// this in other all other file operations ([`read`][PathFilesystem::read],
    /// [`write`][PathFilesystem::write], [`flush`][PathFilesystem::flush],
    /// [`release`][PathFilesystem::release], [`fsync`][PathFilesystem::fsync]). There are also
    /// some flags (`direct_io`, `keep_cache`) which the filesystem may set, to change the way the
    /// file is opened. If this method is not implemented or under Linux kernel versions earlier
    /// than 2.6.15, the [`mknod`][PathFilesystem::mknod] and [`open`][PathFilesystem::open]
    /// methods will be called instead.
    ///
    /// # Notes:
    ///
    /// See `fuse_file_info` structure in
    /// [fuse_common.h](https://libfuse.github.io/doxygen/include_2fuse__common_8h_source.html) for
    /// more details.
    async fn create(
        &self,
        req: Request,
        parent: &OsStr,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<ReplyCreated> {
        Err(libc::ENOSYS.into())
    }

    /// handle interrupt. When a operation is interrupted, an interrupt request will send to fuse
    /// server with the unique id of the operation.
    async fn interrupt(&self, req: Request, unique: u64) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// map block index within file to block index within device.
    ///
    /// # Notes:
    ///
    /// This may not works because currently this crate doesn't support fuseblk mode yet.
    async fn bmap(
        &self,
        req: Request,
        path: &OsStr,
        block_size: u32,
        idx: u64,
    ) -> Result<ReplyBmap> {
        Err(libc::ENOSYS.into())
    }

    /*async fn ioctl(
        &self,
        req: Request,
        inode: u64,
        fh: u64,
        flags: u32,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
    ) -> Result<ReplyIoctl> {
        Err(libc::ENOSYS.into())
    }*/

    /// poll for IO readiness events.
    #[allow(clippy::too_many_arguments)]
    async fn poll(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: u64,
        kn: Option<u64>,
        flags: u32,
        envents: u32,
        notify: &Notify,
    ) -> Result<ReplyPoll> {
        Err(libc::ENOSYS.into())
    }

    /// receive notify reply from kernel.
    async fn notify_reply(
        &self,
        req: Request,
        path: &OsStr,
        offset: u64,
        data: Bytes,
    ) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// forget more than one path. This is a batch version [`forget`][PathFilesystem::forget]
    async fn batch_forget(&self, req: Request, paths: &[&OsStr]) {}

    /// allocate space for an open file. This function ensures that required space is allocated for
    /// specified file.
    ///
    /// # Notes:
    ///
    /// more information about `fallocate`, please see **`man 2 fallocate`**
    async fn fallocate(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: u64,
        offset: u64,
        length: u64,
        mode: u32,
    ) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// read directory entries, but with their attribute, like [`readdir`][PathFilesystem::readdir]
    /// + [`lookup`][PathFilesystem::lookup] at the same time.
    async fn readdirplus<'a>(
        &'a self,
        req: Request,
        parent: &'a OsStr,
        fh: u64,
        offset: u64,
        lock_owner: u64,
    ) -> Result<ReplyDirectoryPlus<impl Stream<Item = Result<DirectoryEntryPlus>> + Send + 'a>>
    {
        Err::<ReplyDirectoryPlus<Empty<_>>, _>(libc::ENOSYS.into())
    }

    /// rename a file or directory with flags.
    async fn rename2(
        &self,
        req: Request,
        origin_parent: &OsStr,
        origin_name: &OsStr,
        parent: &OsStr,
        name: &OsStr,
        flags: u32,
    ) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    /// find next data or hole after the specified offset.
    async fn lseek(
        &self,
        req: Request,
        path: Option<&OsStr>,
        fh: u64,
        offset: u64,
        whence: u32,
    ) -> Result<ReplyLSeek> {
        Err(libc::ENOSYS.into())
    }

    /// copy a range of data from one file to another. This can improve performance because it
    /// reduce data copy: in normal, data will copy from FUSE server to kernel, then to user-space,
    /// then to kernel, finally send back to FUSE server. By implement this method, data will only
    /// copy in FUSE server internal.  when `from_path` or `to_path` is None, it means the path may
    /// be deleted.
    #[allow(clippy::too_many_arguments)]
    async fn copy_file_range(
        &self,
        req: Request,
        from_path: Option<&OsStr>,
        fh_in: u64,
        offset_in: u64,
        to_path: Option<&OsStr>,
        fh_out: u64,
        offset_out: u64,
        length: u64,
        flags: u64,
    ) -> Result<ReplyCopyFileRange> {
        Err(libc::ENOSYS.into())
    }
}
