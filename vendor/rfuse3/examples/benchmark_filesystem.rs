use bytes::Bytes;
use clap::Parser;
use futures_util::Stream;
use rfuse3::{
    raw::{prelude::*, Filesystem, Session},
    Errno, MountOptions, Result,
};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::num::NonZeroU32;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(about = "rfuse3 benchmark filesystem", long_about = None)]
struct Args {
    /// Mount point directory
    mountpoint: PathBuf,

    /// Number of files to expose in the root directory
    #[arg(long, default_value_t = 1024)]
    file_count: usize,

    /// Size of each file in bytes
    #[arg(long, default_value_t = 4096)]
    file_size: usize,

    /// Max write size advertised to kernel
    #[arg(long, default_value_t = 1_048_576)]
    max_write: u32,

    /// Worker count (0 or 1 = legacy inline mode)
    #[arg(long, default_value_t = 4)]
    workers: usize,

    /// Max background in-flight requests
    #[arg(long, default_value_t = 128)]
    max_background: usize,

    /// Allow other users to access the mount
    #[arg(long, default_value_t = false)]
    allow_other: bool,

    /// Enable writeback cache
    #[arg(long, default_value_t = false)]
    write_back: bool,
}

#[derive(Debug)]
struct FileEntry {
    name: OsString,
    data: RwLock<Vec<u8>>,
}

#[derive(Debug)]
struct BenchmarkState {
    base_files: Vec<Arc<FileEntry>>,
    dynamic_files: HashMap<u64, Arc<FileEntry>>,
    name_to_inode: HashMap<OsString, u64>,
    next_inode: u64,
}

#[derive(Debug)]
struct BenchmarkFs {
    created_at: SystemTime,
    state: RwLock<BenchmarkState>,
    base_count: usize,
}

impl BenchmarkFs {
    fn new(file_count: usize, file_size: usize) -> Self {
        let created_at = SystemTime::now();
        let mut base_files = Vec::with_capacity(file_count);
        let name_to_inode = HashMap::new();
        let mut next_inode = 2u64;

        for idx in 0..file_count {
            let name = format!("file_{idx}.dat");
            let inode = next_inode;
            next_inode += 1;
            let name_os = OsString::from(name);
            base_files.push(Arc::new(FileEntry {
                name: name_os,
                data: RwLock::new(vec![idx as u8; file_size]),
            }));
            let _ = inode;
        }

        Self {
            created_at,
            state: RwLock::new(BenchmarkState {
                base_files,
                dynamic_files: HashMap::new(),
                name_to_inode,
                next_inode,
            }),
            base_count: file_count,
        }
    }

    fn root_attr(&self) -> FileAttr {
        FileAttr {
            ino: 1,
            size: 0,
            blocks: 0,
            atime: self.created_at.into(),
            mtime: self.created_at.into(),
            ctime: self.created_at.into(),
            #[cfg(target_os = "macos")]
            crtime: self.created_at.into(),
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            #[cfg(target_os = "macos")]
            flags: 0,
        }
    }

    async fn file_attr(&self, inode: u64) -> Result<FileAttr> {
        let entry = self.entry_by_inode(inode).await?;
        let data = entry.data.read().await;
        Ok(FileAttr {
            ino: inode,
            size: data.len() as u64,
            blocks: (data.len() as u64).div_ceil(512),
            atime: self.created_at.into(),
            mtime: self.created_at.into(),
            ctime: self.created_at.into(),
            #[cfg(target_os = "macos")]
            crtime: self.created_at.into(),
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            #[cfg(target_os = "macos")]
            flags: 0,
        })
    }

    fn base_inode_for_name(&self, name: &OsStr) -> Option<u64> {
        let bytes = name.as_bytes();
        if !bytes.starts_with(b"file_") || !bytes.ends_with(b".dat") {
            return None;
        }
        let num_bytes = &bytes[5..bytes.len() - 4];
        if num_bytes.is_empty() {
            return None;
        }
        let mut value: usize = 0;
        for &b in num_bytes {
            if !b.is_ascii_digit() {
                return None;
            }
            value = value.saturating_mul(10).saturating_add((b - b'0') as usize);
        }
        if value < self.base_count {
            Some((value as u64) + 2)
        } else {
            None
        }
    }

    async fn inode_for_name(&self, name: &OsStr) -> Option<u64> {
        if let Some(inode) = self.base_inode_for_name(name) {
            return Some(inode);
        }
        let state = self.state.read().await;
        state.name_to_inode.get(name).copied()
    }

    async fn entry_by_inode(&self, inode: u64) -> Result<Arc<FileEntry>> {
        if inode >= 2 {
            let base_idx = (inode - 2) as usize;
            if base_idx < self.base_count {
                let state = self.state.read().await;
                return Ok(state.base_files[base_idx].clone());
            }
        }
        let state = self.state.read().await;
        state
            .dynamic_files
            .get(&inode)
            .cloned()
            .ok_or_else(Errno::new_not_exist)
    }
}

impl Filesystem for BenchmarkFs {
    async fn init(&self, _req: Request) -> Result<ReplyInit> {
        info!("benchmark filesystem init");
        Ok(ReplyInit::default())
    }

    async fn destroy(&self, _req: Request) {
        info!("benchmark filesystem destroy");
    }

    async fn lookup(&self, _req: Request, parent: u64, name: &OsStr) -> Result<ReplyEntry> {
        if parent != 1 {
            return Err(libc::ENOENT.into());
        }
        debug!(?name, "lookup");
        let inode = self
            .inode_for_name(name)
            .await
            .ok_or_else(Errno::new_not_exist)?;
        let attr = self.file_attr(inode).await?;
        Ok(ReplyEntry {
            ttl: Duration::from_secs(1),
            attr,
            generation: 0,
        })
    }

    async fn getattr(
        &self,
        _req: Request,
        inode: u64,
        _fh: Option<u64>,
        _flags: u32,
    ) -> Result<ReplyAttr> {
        let attr = if inode == 1 {
            self.root_attr()
        } else {
            self.file_attr(inode).await?
        };
        Ok(ReplyAttr {
            ttl: Duration::from_secs(1),
            attr,
        })
    }

    async fn opendir(&self, _req: Request, inode: u64, _flags: u32) -> Result<ReplyOpen> {
        if inode != 1 {
            return Err(libc::ENOENT.into());
        }
        Ok(ReplyOpen { fh: 1, flags: 0 })
    }

    async fn readdir<'a>(
        &'a self,
        _req: Request,
        parent: u64,
        _fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<impl Stream<Item = Result<DirectoryEntry>> + Send + 'a>> {
        if parent != 1 {
            return Err(libc::ENOENT.into());
        }

        let state = self.state.read().await;
        let mut entries =
            Vec::with_capacity(state.base_files.len() + state.dynamic_files.len() + 2);
        entries.push(DirectoryEntry {
            inode: 1,
            offset: 1,
            kind: FileType::Directory,
            name: OsString::from("."),
        });
        entries.push(DirectoryEntry {
            inode: 1,
            offset: 2,
            kind: FileType::Directory,
            name: OsString::from(".."),
        });

        let mut idx_offset = 0usize;
        for (idx, entry) in state.base_files.iter().enumerate() {
            let inode = (idx as u64) + 2;
            entries.push(DirectoryEntry {
                inode,
                offset: (idx + 3) as i64,
                kind: FileType::RegularFile,
                name: entry.name.clone(),
            });
            idx_offset = idx + 1;
        }

        let mut dynamic_names: Vec<(u64, OsString)> = state
            .dynamic_files
            .iter()
            .map(|(inode, entry)| (*inode, entry.name.clone()))
            .collect();
        dynamic_names.sort_by(|a, b| a.1.cmp(&b.1));
        for (idx, (inode, name)) in dynamic_names.into_iter().enumerate() {
            entries.push(DirectoryEntry {
                inode,
                offset: (idx_offset + idx + 3) as i64,
                kind: FileType::RegularFile,
                name,
            });
        }

        let filtered: Vec<_> = entries
            .into_iter()
            .filter(|entry| entry.offset > offset)
            .map(Ok)
            .collect();

        Ok(ReplyDirectory {
            entries: futures_util::stream::iter(filtered),
        })
    }

    async fn open(&self, _req: Request, inode: u64, _flags: u32) -> Result<ReplyOpen> {
        if inode == 1 {
            return Err(libc::EISDIR.into());
        }
        debug!(inode, "open");
        let _ = self.entry_by_inode(inode).await?;
        Ok(ReplyOpen {
            fh: inode,
            flags: 0,
        })
    }

    async fn read(
        &self,
        _req: Request,
        inode: u64,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        debug!(inode, offset, size, "read");
        let entry = self.entry_by_inode(inode).await?;
        let data = entry.data.read().await;

        let start = offset as usize;
        if start >= data.len() {
            return Ok(ReplyData { data: Bytes::new() });
        }
        let end = (start + size as usize).min(data.len());
        let slice = &data[start..end];
        Ok(ReplyData {
            data: Bytes::copy_from_slice(slice),
        })
    }

    async fn write(
        &self,
        _req: Request,
        inode: u64,
        _fh: u64,
        offset: u64,
        data: &[u8],
        _write_flags: u32,
        _flags: u32,
    ) -> Result<ReplyWrite> {
        debug!(inode, offset, size = data.len(), "write");
        let entry = self.entry_by_inode(inode).await?;
        let mut file = entry.data.write().await;

        let start = offset as usize;
        let end = start + data.len();
        if end > file.len() {
            file.resize(end, 0);
        }
        file[start..end].copy_from_slice(data);

        Ok(ReplyWrite {
            written: data.len() as u32,
        })
    }

    async fn flush(&self, _req: Request, inode: u64, fh: u64, lock_owner: u64) -> Result<()> {
        debug!(inode, fh, lock_owner, "flush");
        Ok(())
    }

    async fn release(
        &self,
        _req: Request,
        inode: u64,
        fh: u64,
        _flags: u32,
        lock_owner: u64,
        flush: bool,
    ) -> Result<()> {
        debug!(inode, fh, lock_owner, flush, "release");
        Ok(())
    }

    async fn setattr(
        &self,
        _req: Request,
        inode: u64,
        _fh: Option<u64>,
        set_attr: SetAttr,
    ) -> Result<ReplyAttr> {
        if inode == 1 {
            return Err(libc::EISDIR.into());
        }
        debug!(inode, ?set_attr, "setattr");
        let entry = self.entry_by_inode(inode).await?;

        if let Some(size) = set_attr.size {
            let mut file = entry.data.write().await;
            file.resize(size as usize, 0);
        }

        let attr = self.file_attr(inode).await?;
        Ok(ReplyAttr {
            ttl: Duration::from_secs(1),
            attr,
        })
    }

    #[cfg(feature = "file-lock")]
    async fn getlk(
        &self,
        _req: Request,
        _inode: u64,
        _fh: u64,
        _lock_owner: u64,
        _start: u64,
        _end: u64,
        _type: u32,
        _pid: u32,
    ) -> Result<ReplyLock> {
        Err(libc::ENOSYS.into())
    }

    #[cfg(feature = "file-lock")]
    async fn setlk(
        &self,
        _req: Request,
        _inode: u64,
        _fh: u64,
        _lock_owner: u64,
        _start: u64,
        _end: u64,
        _type: u32,
        _pid: u32,
        _block: bool,
    ) -> Result<()> {
        Err(libc::ENOSYS.into())
    }

    async fn statfs(&self, _req: Request, _inode: u64) -> Result<ReplyStatFs> {
        let state = self.state.read().await;
        let files_len = self.base_count + state.dynamic_files.len();
        Ok(ReplyStatFs {
            blocks: 1024 * 1024,
            bfree: 1024 * 1024,
            bavail: 1024 * 1024,
            files: files_len as u64,
            ffree: 1024 * 1024,
            bsize: 4096,
            namelen: 255,
            frsize: 4096,
        })
    }

    async fn fallocate(
        &self,
        _req: Request,
        inode: u64,
        _fh: u64,
        offset: u64,
        length: u64,
        mode: u32,
    ) -> Result<()> {
        if mode != 0 {
            return Err(libc::EOPNOTSUPP.into());
        }
        let entry = self.entry_by_inode(inode).await?;
        let mut file = entry.data.write().await;
        let start = offset as usize;
        let end = start.saturating_add(length as usize);
        if end > file.len() {
            file.resize(end, 0);
        }
        Ok(())
    }

    async fn mknod(
        &self,
        _req: Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _rdev: u32,
    ) -> Result<ReplyEntry> {
        if parent != 1 {
            return Err(libc::ENOENT.into());
        }
        if self.base_inode_for_name(name).is_some() {
            return Err(libc::EEXIST.into());
        }
        let mut state = self.state.write().await;
        if state.name_to_inode.contains_key(name) {
            return Err(libc::EEXIST.into());
        }
        let inode = state.next_inode;
        state.next_inode += 1;
        let name_os = name.to_owned();
        let entry = Arc::new(FileEntry {
            name: name_os.clone(),
            data: RwLock::new(Vec::new()),
        });
        state.name_to_inode.insert(name_os, inode);
        state.dynamic_files.insert(inode, entry);

        let attr = self.file_attr(inode).await?;
        Ok(ReplyEntry {
            ttl: Duration::from_secs(1),
            attr,
            generation: 0,
        })
    }

    async fn create(
        &self,
        _req: Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        flags: u32,
    ) -> Result<ReplyCreated> {
        if parent != 1 {
            return Err(libc::ENOENT.into());
        }
        debug!(?name, flags, "create");
        if let Some(inode) = self.base_inode_for_name(name) {
            if flags & libc::O_EXCL as u32 != 0 {
                return Err(libc::EEXIST.into());
            }
            let attr = self.file_attr(inode).await?;
            return Ok(ReplyCreated {
                ttl: Duration::from_secs(1),
                attr,
                generation: 0,
                fh: inode,
                flags: 0,
            });
        }
        let mut state = self.state.write().await;
        if state.name_to_inode.contains_key(name) && flags & libc::O_EXCL as u32 != 0 {
            return Err(libc::EEXIST.into());
        }
        let inode = match state.name_to_inode.get(name).copied() {
            Some(existing) => existing,
            None => {
                let inode = state.next_inode;
                state.next_inode += 1;
                let name_os = name.to_owned();
                let entry = Arc::new(FileEntry {
                    name: name_os.clone(),
                    data: RwLock::new(Vec::new()),
                });
                state.name_to_inode.insert(name_os, inode);
                state.dynamic_files.insert(inode, entry);
                inode
            }
        };
        drop(state);

        let attr = self.file_attr(inode).await?;
        Ok(ReplyCreated {
            ttl: Duration::from_secs(1),
            attr,
            generation: 0,
            fh: inode,
            flags: 0,
        })
    }

    async fn unlink(&self, _req: Request, parent: u64, name: &OsStr) -> Result<()> {
        if parent != 1 {
            return Err(libc::ENOENT.into());
        }
        if self.base_inode_for_name(name).is_some() {
            return Err(libc::EPERM.into());
        }
        let mut state = self.state.write().await;
        if let Some(inode) = state.name_to_inode.remove(name) {
            state.dynamic_files.remove(&inode);
            Ok(())
        } else {
            Err(libc::ENOENT.into())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Only enable DEBUG if RUST_LOG is set and non-empty
    let max_level = match std::env::var("RUST_LOG") {
        Ok(val) if !val.is_empty() => tracing::Level::DEBUG,
        _ => tracing::Level::INFO,
    };
    tracing_subscriber::fmt().with_max_level(max_level).init();

    let args = Args::parse();
    let fs = BenchmarkFs::new(args.file_count, args.file_size);

    let mut mount_options = MountOptions::default();
    mount_options.fs_name("rfuse3-bench");
    mount_options.max_write(NonZeroU32::new(args.max_write.max(1_048_576)).unwrap());
    mount_options.direct_io(true);
    if args.allow_other {
        mount_options.allow_other(true);
    }
    if args.write_back {
        mount_options.write_back(true);
    }

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    mount_options.uid(uid).gid(gid);

    let mount_path = std::ffi::OsString::from(&args.mountpoint);

    info!(
        "Mounting benchmark filesystem at {} (files={}, size={}, workers={}, max_background={})",
        args.mountpoint.display(),
        args.file_count,
        args.file_size,
        args.workers,
        args.max_background
    );

    let mut session = Session::new(mount_options);
    if args.workers > 1 {
        session = session.with_workers(args.workers, args.max_background);
    }

    let mut mount_handle = {
        #[cfg(all(target_os = "linux", feature = "unprivileged"))]
        {
            session.mount_with_unprivileged(fs, mount_path).await
        }
        #[cfg(target_os = "macos")]
        {
            session.mount_with_unprivileged(fs, mount_path).await
        }
        #[cfg(target_os = "freebsd")]
        {
            session.mount_with_unprivileged(fs, mount_path).await
        }
        #[cfg(not(any(
            all(target_os = "linux", feature = "unprivileged"),
            target_os = "macos",
            target_os = "freebsd"
        )))]
        {
            session.mount(fs, mount_path).await
        }
    }
    .map_err(|e| {
        eprintln!("Mount failed: {e}");
        e
    })?;

    info!("Benchmark filesystem mounted. Press Ctrl+C to unmount.");

    let should_unmount = tokio::select! {
        res = &mut mount_handle => {
            match res {
                Ok(_) => info!("Filesystem exited normally"),
                Err(e) => {
                    warn!("Filesystem runtime error: {e}");
                    return Err(e.into());
                }
            }
            false
        },
        _ = signal::ctrl_c() => {
            info!("Received exit signal, unmounting filesystem...");
            true
        }
    };

    if should_unmount {
        mount_handle.unmount().await.map_err(|e| {
            eprintln!("Unmount failed: {e}");
            e
        })?;
        info!("Filesystem unmounted");
    }

    Ok(())
}
