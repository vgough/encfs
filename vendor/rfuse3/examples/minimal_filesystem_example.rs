use clap::Parser;
use futures_util::Stream;
use rfuse3::{
    raw::{prelude::*, Filesystem, Session},
    MountOptions, Result,
};
use std::ffi::OsStr;
use std::time::{Duration, SystemTime};
use tokio::signal;
use tracing::{debug, info, warn};

/// A minimal read-only filesystem implementation
#[derive(Debug)]
struct MinimalFileSystem {
    content: String,
}

impl MinimalFileSystem {
    fn new() -> Self {
        Self {
            content: "Hello, rfuse3! This is a minimal filesystem example.\n".to_string(),
        }
    }

    /// Create a FileAttr for the root directory
    fn root_attr(&self) -> FileAttr {
        FileAttr {
            ino: 1,
            size: 0,
            blocks: 0,
            atime: SystemTime::now().into(),
            mtime: SystemTime::now().into(),
            ctime: SystemTime::now().into(),
            #[cfg(target_os = "macos")]
            crtime: SystemTime::now().into(),
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

    /// Create a FileAttr for the hello.txt file
    fn file_attr(&self) -> FileAttr {
        FileAttr {
            ino: 2,
            size: self.content.len() as u64,
            blocks: 1,
            atime: SystemTime::now().into(),
            mtime: SystemTime::now().into(),
            ctime: SystemTime::now().into(),
            #[cfg(target_os = "macos")]
            crtime: SystemTime::now().into(),
            kind: FileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            #[cfg(target_os = "macos")]
            flags: 0,
        }
    }
}

impl Filesystem for MinimalFileSystem {
    async fn init(&self, _req: Request) -> Result<ReplyInit> {
        info!("Filesystem initialization");
        Ok(ReplyInit::default())
    }

    async fn destroy(&self, _req: Request) {
        info!("Filesystem destruction");
    }

    async fn lookup(&self, _req: Request, parent: u64, name: &OsStr) -> Result<ReplyEntry> {
        let name_str = name.to_string_lossy();
        debug!("Looking up file: parent={}, name={}", parent, name_str);

        if parent == 1 && name_str == "hello.txt" {
            Ok(ReplyEntry {
                ttl: Duration::from_secs(1),
                attr: self.file_attr(),
                generation: 0,
            })
        } else {
            Err(libc::ENOENT.into())
        }
    }

    async fn getattr(
        &self,
        _req: Request,
        inode: u64,
        _fh: Option<u64>,
        _flags: u32,
    ) -> Result<ReplyAttr> {
        debug!("Getting attributes: inode={}", inode);

        let attr = match inode {
            1 => self.root_attr(),
            2 => self.file_attr(),
            _ => return Err(libc::ENOENT.into()),
        };

        Ok(ReplyAttr {
            ttl: Duration::from_secs(1),
            attr,
        })
    }

    async fn opendir(&self, _req: Request, inode: u64, _flags: u32) -> Result<ReplyOpen> {
        debug!("Opening directory: inode={}", inode);

        if inode == 1 {
            Ok(ReplyOpen { fh: 1, flags: 0 })
        } else {
            Err(libc::ENOENT.into())
        }
    }

    async fn readdir<'a>(
        &'a self,
        _req: Request,
        parent: u64,
        _fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<impl Stream<Item = Result<DirectoryEntry>> + Send + 'a>> {
        debug!("Reading directory: parent={}, offset={}", parent, offset);

        if parent == 1 {
            let entries = vec![
                DirectoryEntry {
                    inode: 1,
                    offset: 1,
                    kind: FileType::Directory,
                    name: std::ffi::OsString::from("."),
                },
                DirectoryEntry {
                    inode: 1,
                    offset: 2,
                    kind: FileType::Directory,
                    name: std::ffi::OsString::from(".."),
                },
                DirectoryEntry {
                    inode: 2,
                    offset: 3,
                    kind: FileType::RegularFile,
                    name: std::ffi::OsString::from("hello.txt"),
                },
            ];

            let filtered: Vec<_> = entries
                .into_iter()
                .filter(|entry| entry.offset > offset)
                .map(Ok)
                .collect();

            Ok(ReplyDirectory {
                entries: futures_util::stream::iter(filtered),
            })
        } else {
            Err(libc::ENOENT.into())
        }
    }

    async fn readdirplus<'a>(
        &'a self,
        _req: Request,
        parent: u64,
        _fh: u64,
        offset: u64,
        _lock_owner: u64,
    ) -> Result<ReplyDirectoryPlus<impl Stream<Item = Result<DirectoryEntryPlus>> + Send + 'a>>
    {
        debug!(
            "Reading directory plus: parent={}, offset={}",
            parent, offset
        );

        if parent == 1 {
            let root_attr = self.root_attr();
            let file_attr = self.file_attr();

            let entries = vec![
                DirectoryEntryPlus {
                    inode: 1,
                    generation: 0,
                    kind: FileType::Directory,
                    name: std::ffi::OsString::from("."),
                    offset: 1,
                    attr: root_attr,
                    entry_ttl: Duration::from_secs(1),
                    attr_ttl: Duration::from_secs(1),
                },
                DirectoryEntryPlus {
                    inode: 1,
                    generation: 0,
                    kind: FileType::Directory,
                    name: std::ffi::OsString::from(".."),
                    offset: 2,
                    attr: root_attr,
                    entry_ttl: Duration::from_secs(1),
                    attr_ttl: Duration::from_secs(1),
                },
                DirectoryEntryPlus {
                    inode: 2,
                    generation: 0,
                    kind: FileType::RegularFile,
                    name: std::ffi::OsString::from("hello.txt"),
                    offset: 3,
                    attr: file_attr,
                    entry_ttl: Duration::from_secs(1),
                    attr_ttl: Duration::from_secs(1),
                },
            ];

            let filtered: Vec<_> = entries
                .into_iter()
                .filter(|entry| (entry.offset as u64) > offset)
                .map(Ok)
                .collect();

            Ok(ReplyDirectoryPlus {
                entries: futures_util::stream::iter(filtered),
            })
        } else {
            Err(libc::ENOENT.into())
        }
    }

    async fn open(&self, _req: Request, inode: u64, _flags: u32) -> Result<ReplyOpen> {
        debug!("Opening file: inode={}", inode);

        if inode == 2 {
            Ok(ReplyOpen { fh: 2, flags: 0 })
        } else {
            Err(libc::ENOENT.into())
        }
    }

    async fn read(
        &self,
        _req: Request,
        inode: u64,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        debug!(
            "Reading file: inode={}, offset={}, size={}",
            inode, offset, size
        );

        if inode == 2 {
            let start = offset as usize;
            let end = std::cmp::min(start + size as usize, self.content.len());

            let data = if start < self.content.len() {
                self.content.as_bytes()[start..end].to_vec()
            } else {
                Vec::new()
            };

            Ok(ReplyData { data: data.into() })
        } else {
            Err(libc::ENOENT.into())
        }
    }

    async fn statfs(&self, _req: Request, _inode: u64) -> Result<ReplyStatFs> {
        debug!("Getting filesystem statistics");

        Ok(ReplyStatFs {
            blocks: 1000, // Total blocks
            bfree: 800,   // Free blocks
            bavail: 800,  // Available blocks
            files: 100,   // Total files
            ffree: 50,    // Free files
            bsize: 4096,  // Block size
            namelen: 255, // Maximum filename length
            frsize: 4096, // Fragment size
        })
    }

    async fn access(&self, _req: Request, inode: u64, _mask: u32) -> Result<()> {
        debug!("Checking access permissions: inode={}", inode);

        if inode == 1 || inode == 2 {
            Ok(())
        } else {
            Err(libc::ENOENT.into())
        }
    }

    async fn getxattr(
        &self,
        _req: Request,
        inode: u64,
        name: &OsStr,
        _size: u32,
    ) -> Result<ReplyXAttr> {
        debug!(
            "Getting extended attributes: inode={}, name={:?}",
            inode, name
        );
        Err(libc::ENODATA.into())
    }

    async fn listxattr(&self, _req: Request, inode: u64, _size: u32) -> Result<ReplyXAttr> {
        debug!("Listing extended attributes: inode={}", inode);
        Ok(ReplyXAttr::Data(Vec::new().into()))
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about = "A minimal rfuse3 filesystem example")]
struct Args {
    /// Mount point path
    #[arg(long)]
    mountpoint: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let args = Args::parse();
    let fs = MinimalFileSystem::new();

    let mut mount_options = MountOptions::default();
    // Optional: enable force_readdir_plus for better performance
    // mount_options.force_readdir_plus(true);

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    mount_options.uid(uid).gid(gid);

    let mount_path = std::ffi::OsString::from(&args.mountpoint);

    info!(
        "Starting to mount minimal filesystem to: {}",
        args.mountpoint
    );

    let mut mount_handle = {
        #[cfg(all(target_os = "linux", feature = "unprivileged"))]
        {
            Session::new(mount_options)
                .mount_with_unprivileged(fs, mount_path)
                .await
        }
        #[cfg(target_os = "macos")]
        {
            Session::new(mount_options)
                .mount_with_unprivileged(fs, mount_path)
                .await
        }
        #[cfg(target_os = "freebsd")]
        {
            Session::new(mount_options)
                .mount_with_unprivileged(fs, mount_path)
                .await
        }
        #[cfg(not(any(
            all(target_os = "linux", feature = "unprivileged"),
            target_os = "macos",
            target_os = "freebsd"
        )))]
        {
            Session::new(mount_options).mount(fs, mount_path).await
        }
    }
    .map_err(|e| {
        eprintln!("Mount failed: {}", e);
        e
    })?;

    info!("Filesystem successfully mounted!");
    info!("You can try the following operations:");
    info!("  - ls {}  # List directory contents", args.mountpoint);
    info!("  - cat {}/hello.txt  # Read file", args.mountpoint);
    info!("Press Ctrl+C to unmount the filesystem");
    tokio::select! {
        res = &mut mount_handle => {
            match res {
                Ok(_) => info!("Filesystem exited normally"),
                Err(e) => {
                    warn!("Filesystem runtime error: {}", e);
                    return Err(e.into());
                }
            }
        },
        _ = signal::ctrl_c() => {
            info!("Received exit signal, unmounting filesystem...");
        }
    }

    // Unmount after the select completes to avoid overlapping borrows
    mount_handle.unmount().await.map_err(|e| {
        eprintln!("Unmount failed: {}", e);
        e
    })?;
    info!("Filesystem unmounted");

    Ok(())
}
