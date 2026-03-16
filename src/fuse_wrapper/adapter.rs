// FuseAdapter :: A wrapper around FUSE that presents paths instead of inodes.
//
// Based on fuse_mt fusemt.rs by William R. Fraser.
// Simplified: no threadpool, all operations are synchronous.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use fuser::TimeOrNow;
use log::{debug, error};

use super::directory_cache::*;
use super::inode_table::*;
use super::types::*;

trait IntoRequestInfo {
    fn info(&self) -> RequestInfo;
}

impl IntoRequestInfo for fuser::Request {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            unique: self.unique().into(),
            uid: self.uid(),
            gid: self.gid(),
            pid: self.pid(),
        }
    }
}

fn with_ino(mut attr: FileAttr, ino: u64) -> FileAttr {
    attr.ino = INodeNo(ino);
    attr
}

fn errno(err: libc::c_int) -> fuser::Errno {
    fuser::Errno::from_i32(err)
}

trait TimeOrNowExt {
    fn time(self) -> SystemTime;
}

impl TimeOrNowExt for TimeOrNow {
    fn time(self) -> SystemTime {
        match self {
            TimeOrNow::SpecificTime(t) => t,
            TimeOrNow::Now => SystemTime::now(),
        }
    }
}

struct FuseAdapterInner {
    inodes: InodeTable,
    directory_cache: DirectoryCache,
}

impl FuseAdapterInner {
    fn new() -> Self {
        FuseAdapterInner {
            inodes: InodeTable::new(),
            directory_cache: DirectoryCache::new(),
        }
    }
}

pub struct FuseAdapter<T> {
    target: Arc<T>,
    inner: Mutex<FuseAdapterInner>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for FuseAdapter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuseAdapter")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl<T: FilesystemMT + Sync + Send + 'static> FuseAdapter<T> {
    pub fn new(target_fs: T) -> FuseAdapter<T> {
        FuseAdapter {
            target: Arc::new(target_fs),
            inner: Mutex::new(FuseAdapterInner::new()),
        }
    }
}

macro_rules! get_path {
    ($inner:expr, $ino:expr, $reply:expr) => {
        match $inner.inodes.get_path($ino) {
            Some(path) => path,
            None => {
                $reply.error(errno(libc::EINVAL));
                return;
            }
        }
    };
}

impl<T: FilesystemMT + Sync + Send + 'static> fuser::Filesystem for FuseAdapter<T> {
    fn init(
        &mut self,
        req: &fuser::Request,
        _config: &mut fuser::KernelConfig,
    ) -> io::Result<()> {
        debug!("init");
        self.target
            .init(req.info())
            .map_err(io::Error::from_raw_os_error)
    }

    fn destroy(&mut self) {
        debug!("destroy");
        self.target.destroy();
    }

    fn lookup(
        &self,
        req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let parent_raw: u64 = parent.into();
        let parent_path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, parent_raw, reply)
        };
        debug!("lookup: {:?}, {:?}", parent_path, name);
        let path = Arc::new((*parent_path).clone().join(name));
        match self.target.getattr(req.info(), &path, None) {
            Ok((ttl, attr)) => {
                let (ino, generation) = {
                    let mut inner = self.inner.lock().unwrap();
                    let (ino, generation) = inner.inodes.add_or_get(path.clone());
                    inner.inodes.lookup(ino);
                    (ino, generation)
                };
                reply.entry(
                    &ttl,
                    &with_ino(attr, ino),
                    fuser::Generation(generation),
                );
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn forget(&self, _req: &fuser::Request, ino: fuser::INodeNo, nlookup: u64) {
        let ino_raw: u64 = ino.into();
        let (path, lookups) = {
            let mut inner = self.inner.lock().unwrap();
            let path = inner
                .inodes
                .get_path(ino_raw)
                .unwrap_or_else(|| Arc::new(PathBuf::from("[unknown]")));
            let lookups = inner.inodes.forget(ino_raw, nlookup);
            (path, lookups)
        };
        debug!(
            "forget: inode {} ({:?}) now at {} lookups",
            ino_raw, path, lookups
        );
    }

    fn getattr(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: Option<fuser::FileHandle>,
        reply: fuser::ReplyAttr,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        debug!("getattr: {:?}", path);
        let fh_raw = fh.map(u64::from);
        match self.target.getattr(req.info(), &path, fh_raw) {
            Ok((ttl, attr)) => reply.attr(&ttl, &with_ino(attr, ino_raw)),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn setattr(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<fuser::FileHandle>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<fuser::BsdFileFlags>,
        reply: fuser::ReplyAttr,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        debug!("setattr: {:?}", path);

        let fh_raw = fh.map(u64::from);

        if let Some(mode) = mode
            && let Err(e) = self.target.chmod(req.info(), &path, fh_raw, mode)
        {
            reply.error(errno(e));
            return;
        }

        if (uid.is_some() || gid.is_some())
            && let Err(e) = self.target.chown(req.info(), &path, fh_raw, uid, gid)
        {
            reply.error(errno(e));
            return;
        }

        if let Some(size) = size
            && let Err(e) = self.target.truncate(req.info(), &path, fh_raw, size)
        {
            reply.error(errno(e));
            return;
        }

        if atime.is_some() || mtime.is_some() {
            let atime = atime.map(TimeOrNowExt::time);
            let mtime = mtime.map(TimeOrNowExt::time);
            if let Err(e) = self.target.utimens(req.info(), &path, fh_raw, atime, mtime) {
                reply.error(errno(e));
                return;
            }
        }

        let flags_raw = flags.map(|f| f.bits());
        if (crtime.is_some() || chgtime.is_some() || bkuptime.is_some() || flags_raw.is_some())
            && let Err(e) = self.target.utimens_macos(
                req.info(),
                &path,
                fh_raw,
                crtime,
                chgtime,
                bkuptime,
                flags_raw,
            )
        {
            reply.error(errno(e));
            return;
        }

        match self.target.getattr(req.info(), &path, fh_raw) {
            Ok((ttl, attr)) => reply.attr(&ttl, &with_ino(attr, ino_raw)),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn readlink(&self, req: &fuser::Request, ino: fuser::INodeNo, reply: fuser::ReplyData) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        debug!("readlink: {:?}", path);
        match self.target.readlink(req.info(), &path) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn mknod(
        &self,
        req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        rdev: u32,
        reply: fuser::ReplyEntry,
    ) {
        let parent_raw: u64 = parent.into();
        let parent_path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, parent_raw, reply)
        };
        debug!("mknod: {:?}/{:?}", parent_path, name);
        match self
            .target
            .mknod(req.info(), &parent_path, name, mode, rdev)
        {
            Ok((ttl, attr)) => {
                let (ino, generation) = self
                    .inner
                    .lock()
                    .unwrap()
                    .inodes
                    .add(Arc::new(parent_path.join(name)));
                reply.entry(
                    &ttl,
                    &with_ino(attr, ino),
                    fuser::Generation(generation),
                );
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn mkdir(
        &self,
        req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        let parent_raw: u64 = parent.into();
        let parent_path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, parent_raw, reply)
        };
        debug!("mkdir: {:?}/{:?}", parent_path, name);
        match self.target.mkdir(req.info(), &parent_path, name, mode) {
            Ok((ttl, attr)) => {
                let (ino, generation) = self
                    .inner
                    .lock()
                    .unwrap()
                    .inodes
                    .add(Arc::new(parent_path.join(name)));
                reply.entry(
                    &ttl,
                    &with_ino(attr, ino),
                    fuser::Generation(generation),
                );
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn unlink(
        &self,
        req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let parent_raw: u64 = parent.into();
        let parent_path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, parent_raw, reply)
        };
        debug!("unlink: {:?}/{:?}", parent_path, name);
        match self.target.unlink(req.info(), &parent_path, name) {
            Ok(()) => {
                self.inner
                    .lock()
                    .unwrap()
                    .inodes
                    .unlink(&parent_path.join(name));
                reply.ok()
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn rmdir(
        &self,
        req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let parent_raw: u64 = parent.into();
        let parent_path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, parent_raw, reply)
        };
        debug!("rmdir: {:?}/{:?}", parent_path, name);
        match self.target.rmdir(req.info(), &parent_path, name) {
            Ok(()) => {
                self.inner
                    .lock()
                    .unwrap()
                    .inodes
                    .unlink(&parent_path.join(name));
                reply.ok()
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn symlink(
        &self,
        req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        link: &Path,
        reply: fuser::ReplyEntry,
    ) {
        let parent_raw: u64 = parent.into();
        let parent_path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, parent_raw, reply)
        };
        debug!("symlink: {:?}/{:?} -> {:?}", parent_path, name, link);
        match self.target.symlink(req.info(), &parent_path, name, link) {
            Ok((ttl, attr)) => {
                let (ino, generation) = self
                    .inner
                    .lock()
                    .unwrap()
                    .inodes
                    .add(Arc::new(parent_path.join(name)));
                reply.entry(
                    &ttl,
                    &with_ino(attr, ino),
                    fuser::Generation(generation),
                );
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn rename(
        &self,
        req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        newparent: fuser::INodeNo,
        newname: &OsStr,
        _flags: fuser::RenameFlags,
        reply: fuser::ReplyEmpty,
    ) {
        let parent_raw: u64 = parent.into();
        let newparent_raw: u64 = newparent.into();
        let (parent_path, newparent_path) = {
            let inner = self.inner.lock().unwrap();
            let p = get_path!(inner, parent_raw, reply);
            let np = get_path!(inner, newparent_raw, reply);
            (p, np)
        };
        debug!(
            "rename: {:?}/{:?} -> {:?}/{:?}",
            parent_path, name, newparent_path, newname
        );
        match self
            .target
            .rename(req.info(), &parent_path, name, &newparent_path, newname)
        {
            Ok(()) => {
                self.inner.lock().unwrap().inodes.rename(
                    &parent_path.join(name),
                    Arc::new(newparent_path.join(newname)),
                );
                reply.ok()
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn link(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        newparent: fuser::INodeNo,
        newname: &OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let ino_raw: u64 = ino.into();
        let newparent_raw: u64 = newparent.into();
        let (path, newparent_path) = {
            let inner = self.inner.lock().unwrap();
            let p = get_path!(inner, ino_raw, reply);
            let np = get_path!(inner, newparent_raw, reply);
            (p, np)
        };
        debug!("link: {:?} -> {:?}/{:?}", path, newparent_path, newname);
        match self
            .target
            .link(req.info(), &path, &newparent_path, newname)
        {
            Ok((ttl, attr)) => {
                let (new_ino, generation) = self
                    .inner
                    .lock()
                    .unwrap()
                    .inodes
                    .add(Arc::new(newparent_path.join(newname)));
                reply.entry(
                    &ttl,
                    &with_ino(attr, new_ino),
                    fuser::Generation(generation),
                );
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn open(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        flags: fuser::OpenFlags,
        reply: fuser::ReplyOpen,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        debug!("open: {:?}", path);
        match self.target.open(req.info(), &path, flags.0 as u32) {
            Ok((fh, open_flags)) => reply.opened(
                fuser::FileHandle(fh),
                fuser::FopenFlags::from_bits_retain(open_flags),
            ),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn read(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: fuser::ReplyData,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        let fh_raw: u64 = fh.into();
        debug!("read: {:?} {:#x} @ {:#x}", path, size, offset);
        self.target
            .read(req.info(), &path, fh_raw, offset, size, |result| {
                match result {
                    Ok(data) => reply.data(data),
                    Err(e) => reply.error(errno(e)),
                }
                CallbackResult {
                    _private: std::marker::PhantomData {},
                }
            });
    }

    fn write(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: fuser::ReplyWrite,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        let fh_raw: u64 = fh.into();
        debug!("write: {:?} {:#x} @ {:#x}", path, data.len(), offset);

        // Copy the data because fuser reuses its buffer.
        let data_buf = Vec::from(data);

        match self
            .target
            .write(req.info(), &path, fh_raw, offset, data_buf, flags.0 as u32)
        {
            Ok(written) => reply.written(written),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn flush(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        lock_owner: fuser::LockOwner,
        reply: fuser::ReplyEmpty,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        let fh_raw: u64 = fh.into();
        debug!("flush: {:?}", path);
        match self.target.flush(req.info(), &path, fh_raw, lock_owner.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn release(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        flags: fuser::OpenFlags,
        lock_owner: Option<fuser::LockOwner>,
        flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        let fh_raw: u64 = fh.into();
        debug!("release: {:?}", path);
        match self.target.release(
            req.info(),
            &path,
            fh_raw,
            flags.0 as u32,
            lock_owner.map_or(0, |lo| lo.0),
            flush,
        ) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn fsync(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        let fh_raw: u64 = fh.into();
        debug!("fsync: {:?}", path);
        match self.target.fsync(req.info(), &path, fh_raw, datasync) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn opendir(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        flags: fuser::OpenFlags,
        reply: fuser::ReplyOpen,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        debug!("opendir: {:?}", path);
        match self.target.opendir(req.info(), &path, flags.0 as u32) {
            Ok((fh, open_flags)) => {
                let dcache_key = self.inner.lock().unwrap().directory_cache.new_entry(fh);
                reply.opened(
                    fuser::FileHandle(dcache_key),
                    fuser::FopenFlags::from_bits_retain(open_flags),
                );
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn readdir(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        mut reply: fuser::ReplyDirectory,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        let fh_raw: u64 = fh.into();
        debug!("readdir: {:?} @ {}", path, offset);

        let entries: Vec<DirectoryEntry> = {
            let mut inner = self.inner.lock().unwrap();
            let dcache_entry = inner.directory_cache.get_mut(fh_raw);
            if let Some(ref entries) = dcache_entry.entries {
                entries.clone()
            } else {
                debug!(
                    "entries not yet fetched; requesting with fh {}",
                    dcache_entry.fh
                );
                let real_fh = dcache_entry.fh;
                drop(inner);
                match self.target.readdir(req.info(), &path, real_fh) {
                    Ok(entries) => {
                        let mut inner = self.inner.lock().unwrap();
                        let dcache_entry = inner.directory_cache.get_mut(fh_raw);
                        dcache_entry.entries = Some(entries.clone());
                        entries
                    }
                    Err(e) => {
                        reply.error(errno(e));
                        return;
                    }
                }
            }
        };

        let parent_inode = if ino_raw == 1 {
            ino_raw
        } else {
            let parent_path: &Path = path.parent().unwrap();
            match self.inner.lock().unwrap().inodes.get_inode(parent_path) {
                Some(inode) => inode,
                None => {
                    error!("readdir: unable to get inode for parent of {:?}", path);
                    reply.error(errno(libc::EIO));
                    return;
                }
            }
        };

        debug!("directory has {} entries", entries.len());

        for (index, entry) in entries.iter().skip(offset as usize).enumerate() {
            let entry_inode = if entry.name == Path::new(".") {
                ino_raw
            } else if entry.name == Path::new("..") {
                parent_inode
            } else {
                !1
            };

            let buffer_full: bool = reply.add(
                fuser::INodeNo(entry_inode),
                offset + index as u64 + 1,
                entry.kind,
                entry.name.as_os_str(),
            );

            if buffer_full {
                debug!("readdir: reply buffer is full");
                break;
            }
        }

        reply.ok();
    }

    fn releasedir(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        flags: fuser::OpenFlags,
        reply: fuser::ReplyEmpty,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        let fh_raw: u64 = fh.into();
        debug!("releasedir: {:?}", path);
        let real_fh = self.inner.lock().unwrap().directory_cache.real_fh(fh_raw);
        match self
            .target
            .releasedir(req.info(), &path, real_fh, flags.0 as u32)
        {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
        self.inner.lock().unwrap().directory_cache.delete(fh_raw);
    }

    fn fsyncdir(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        let fh_raw: u64 = fh.into();
        debug!("fsyncdir: {:?} (datasync: {:?})", path, datasync);
        let real_fh = self.inner.lock().unwrap().directory_cache.real_fh(fh_raw);
        match self.target.fsyncdir(req.info(), &path, real_fh, datasync) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn statfs(&self, req: &fuser::Request, ino: fuser::INodeNo, reply: fuser::ReplyStatfs) {
        let ino_raw: u64 = ino.into();
        let path = if ino_raw == 1 {
            Arc::new(PathBuf::from("/"))
        } else {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };

        debug!("statfs: {:?}", path);
        match self.target.statfs(req.info(), &path) {
            Ok(statfs) => reply.statfs(
                statfs.blocks,
                statfs.bfree,
                statfs.bavail,
                statfs.files,
                statfs.ffree,
                statfs.bsize,
                statfs.namelen,
                statfs.frsize,
            ),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn setxattr(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: fuser::ReplyEmpty,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        debug!(
            "setxattr: {:?} {:?} ({} bytes, flags={:#x}, pos={:#x}",
            path,
            name,
            value.len(),
            flags,
            position
        );
        match self
            .target
            .setxattr(req.info(), &path, name, value, flags as u32, position)
        {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn getxattr(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        name: &OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        debug!("getxattr: {:?} {:?}", path, name);
        match self.target.getxattr(req.info(), &path, name, size) {
            Ok(Xattr::Size(size)) => {
                debug!("getxattr: sending size {}", size);
                reply.size(size)
            }
            Ok(Xattr::Data(vec)) => {
                debug!("getxattr: sending {} bytes", vec.len());
                reply.data(&vec)
            }
            Err(e) => {
                debug!("getxattr: error {}", e);
                reply.error(errno(e))
            }
        }
    }

    fn listxattr(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        debug!("listxattr: {:?}", path);
        match self.target.listxattr(req.info(), &path, size) {
            Ok(Xattr::Size(size)) => {
                debug!("listxattr: sending size {}", size);
                reply.size(size)
            }
            Ok(Xattr::Data(vec)) => {
                debug!("listxattr: sending {} bytes", vec.len());
                reply.data(&vec)
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn removexattr(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        debug!("removexattr: {:?}, {:?}", path, name);
        match self.target.removexattr(req.info(), &path, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn access(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        mask: fuser::AccessFlags,
        reply: fuser::ReplyEmpty,
    ) {
        let ino_raw: u64 = ino.into();
        let path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, ino_raw, reply)
        };
        debug!("access: {:?}, mask={:#o}", path, mask.bits());
        match self.target.access(req.info(), &path, mask.bits() as u32) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn create(
        &self,
        req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let parent_raw: u64 = parent.into();
        let parent_path = {
            let inner = self.inner.lock().unwrap();
            get_path!(inner, parent_raw, reply)
        };
        debug!(
            "create: {:?}/{:?} (mode={:#o}, flags={:#x})",
            parent_path, name, mode, flags
        );
        match self
            .target
            .create(req.info(), &parent_path, name, mode, flags as u32)
        {
            Ok(create) => {
                let (ino, generation) = self
                    .inner
                    .lock()
                    .unwrap()
                    .inodes
                    .add(Arc::new(parent_path.join(name)));
                let attr = with_ino(create.attr, ino);
                reply.created(
                    &create.ttl,
                    &attr,
                    fuser::Generation(generation),
                    fuser::FileHandle(create.fh),
                    fuser::FopenFlags::from_bits_retain(create.flags),
                );
            }
            Err(e) => reply.error(errno(e)),
        }
    }
}
