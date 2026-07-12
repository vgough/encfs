use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Debug, Formatter};
use std::path::PathBuf;
use std::sync::Mutex;

use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use futures_util::stream::{self, Stream, StreamExt};
use tracing::warn;

use super::inode_generator::InodeGenerator;
use super::path_filesystem::PathFilesystem;
use crate::helper::Apply;
use crate::notify::Notify;
use crate::raw::reply::*;
use crate::raw::{Filesystem, Request};
use crate::{Errno, SetAttr};
use crate::{Inode, Result};

const ROOT_INODE: Inode = 1;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct Name {
    parent: Inode,
    name: OsString,
}

impl Name {
    fn new(parent: Inode, name: OsString) -> Self {
        Self { parent, name }
    }
}

/// High-performance inode-name manager using DashMap for concurrent access.
/// This replaces the previous RwLock<HashMap> implementation to reduce lock contention.
#[derive(Debug)]
struct InodeNameManager {
    /// Maps inode -> set of names (supports hard links)
    inode_to_names: DashMap<Inode, HashSet<Name>>,
    /// Maps name -> inode for fast lookup
    name_to_inode: DashMap<Name, Inode>,
    /// Protected inode allocator
    inode_generator: Mutex<InodeGenerator>,
}

impl InodeNameManager {
    fn new() -> Self {
        let mut generator = InodeGenerator::new();
        let root_inode = generator.allocate_inode();
        assert_eq!(root_inode, ROOT_INODE);

        let inode_to_names = DashMap::new();
        inode_to_names.insert(
            root_inode,
            HashSet::from_iter(vec![Name::new(root_inode, OsString::from("/"))]),
        );

        Self {
            inode_to_names,
            name_to_inode: DashMap::new(),
            inode_generator: Mutex::new(generator),
        }
    }

    fn get_absolute_path(&self, inode: Inode) -> Option<PathBuf> {
        let names = self.inode_to_names.get(&inode)?;
        let name = names.iter().next().unwrap();

        if name.parent == ROOT_INODE {
            Some(PathBuf::from("/").apply(|path| path.push(&name.name)))
        } else {
            Some(
                self.get_absolute_path(name.parent)?
                    .apply(|path| path.push(&name.name)),
            )
        }
    }

    fn remove_name(&self, name: &Name) {
        if let Some((_, inode)) = self.name_to_inode.remove(name) {
            if let Entry::Occupied(mut entry) = self.inode_to_names.entry(inode) {
                let names = entry.get_mut();
                names.remove(name);
                if names.is_empty() {
                    entry.remove();
                    if let Ok(mut gen) = self.inode_generator.lock() {
                        gen.release_inode(inode);
                    }
                }
            }
        }
    }

    fn remove_inode(&self, inode: Inode) {
        if let Some((_, names)) = self.inode_to_names.remove(&inode) {
            for name in names {
                self.name_to_inode.remove(&name);
            }
        }

        if let Ok(mut gen) = self.inode_generator.lock() {
            gen.release_inode(inode);
        }
    }

    fn contains_name(&self, name: &Name) -> bool {
        self.name_to_inode.contains_key(name)
    }

    fn insert_name(&self, name: Name) -> Inode {
        let inode = self
            .inode_generator
            .lock()
            .unwrap_or_else(|poisoned| {
                warn!("inode_generator lock was poisoned, recovering");
                poisoned.into_inner()
            })
            .allocate_inode();

        self.name_to_inode.insert(name.clone(), inode);

        let mut names = HashSet::with_capacity(1);
        names.insert(name);

        self.inode_to_names.insert(inode, names);

        inode
    }

    /// Get or insert inode for a name atomically
    fn get_or_insert_inode(&self, name: Name) -> Inode {
        // Fast path: check if already exists
        if let Some(inode) = self.name_to_inode.get(&name).map(|r| *r) {
            return inode;
        }

        // Slow path: need to insert
        let inode = self
            .inode_generator
            .lock()
            .unwrap_or_else(|poisoned| {
                warn!("inode_generator lock was poisoned, recovering");
                poisoned.into_inner()
            })
            .allocate_inode();

        // Use entry API to handle race condition
        let actual_inode = *self.name_to_inode.entry(name.clone()).or_insert(inode);

        if actual_inode == inode {
            // We won the race, insert into inode_to_names
            let mut names = HashSet::with_capacity(1);
            names.insert(name);
            self.inode_to_names.insert(inode, names);
        } else {
            // Lost the race, release the allocated inode
            if let Ok(mut gen) = self.inode_generator.lock() {
                gen.release_inode(inode);
            }
        }

        actual_inode
    }

    /// Get parent inode for a given inode
    fn get_parent_inode(&self, inode: Inode) -> Option<Inode> {
        self.inode_to_names
            .get(&inode)
            .and_then(|names| names.iter().next().map(|n| n.parent))
    }
}

pub struct InodePathBridge<FS> {
    path_filesystem: FS,
    /// Concurrent inode-name manager using DashMap internally
    inode_name_manager: InodeNameManager,
}

impl<FS> InodePathBridge<FS> {
    pub fn new(path_filesystem: FS) -> Self {
        Self {
            path_filesystem,
            inode_name_manager: InodeNameManager::new(),
        }
    }
}

impl<FS> Debug for InodePathBridge<FS> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("InodePathBridge").finish_non_exhaustive()
    }
}

impl<FS> Filesystem for InodePathBridge<FS>
where
    FS: PathFilesystem + Send + Sync + 'static,
{
    async fn init(&self, req: Request) -> Result<ReplyInit> {
        self.path_filesystem.init(req).await?;
        Ok(ReplyInit::default())
    }

    async fn destroy(&self, req: Request) {
        self.path_filesystem.destroy(req).await
    }

    async fn lookup(&self, req: Request, parent: u64, name: &OsStr) -> Result<ReplyEntry> {
        let parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;

        match self
            .path_filesystem
            .lookup(req, parent_path.as_ref(), name)
            .await
        {
            Err(err) => {
                if err.is_not_exist() {
                    self.inode_name_manager
                        .remove_name(&Name::new(parent, name.to_owned()));
                }

                Err(err)
            }

            Ok(entry) => {
                let name = Name::new(parent, name.to_owned());
                let inode = self.inode_name_manager.get_or_insert_inode(name);

                Ok(ReplyEntry {
                    ttl: entry.ttl,
                    attr: (inode, entry.attr).into(),
                    generation: 0,
                })
            }
        }
    }

    async fn forget(&self, req: Request, inode: u64, nlookup: u64) {
        // TODO if kernel forget a dir which has children, it may break

        if let Some(path) = self.inode_name_manager.get_absolute_path(inode) {
            self.path_filesystem
                .forget(req, path.as_ref(), nlookup)
                .await;

            self.inode_name_manager.remove_inode(inode);
        }
    }

    async fn getattr(
        &self,
        req: Request,
        inode: u64,
        fh: Option<u64>,
        flags: u32,
    ) -> Result<ReplyAttr> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        let attr = self
            .path_filesystem
            .getattr(req, path.as_ref().map(|path| path.as_ref()), fh, flags)
            .await?;

        Ok(ReplyAttr {
            ttl: attr.ttl,
            attr: (inode, attr.attr).into(),
        })
    }

    async fn setattr(
        &self,
        req: Request,
        inode: u64,
        fh: Option<u64>,
        set_attr: SetAttr,
    ) -> Result<ReplyAttr> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        let attr = self
            .path_filesystem
            .setattr(req, path.as_ref().map(|path| path.as_ref()), fh, set_attr)
            .await?;

        Ok(ReplyAttr {
            ttl: attr.ttl,
            attr: (inode, attr.attr).into(),
        })
    }

    async fn readlink(&self, req: Request, inode: u64) -> Result<ReplyData> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem.readlink(req, path.as_ref()).await
    }

    async fn symlink(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        link: &OsStr,
    ) -> Result<ReplyEntry> {
        let parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;

        match self
            .path_filesystem
            .symlink(req, parent_path.as_ref(), name, link)
            .await
        {
            Err(err) => {
                if err.is_not_exist() {
                    let name = Name::new(parent, name.to_owned());
                    self.inode_name_manager.remove_name(&name);
                }

                Err(err)
            }

            Ok(entry) => {
                let name = Name::new(parent, name.to_owned());
                let inode = self.inode_name_manager.get_or_insert_inode(name);

                Ok(ReplyEntry {
                    ttl: entry.ttl,
                    attr: (inode, entry.attr).into(),
                    generation: 0,
                })
            }
        }
    }

    async fn mknod(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        rdev: u32,
    ) -> Result<ReplyEntry> {
        let parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;

        match self
            .path_filesystem
            .mknod(req, parent_path.as_ref(), name, mode, rdev)
            .await
        {
            Err(err) => {
                if err.is_exist() {
                    let name = Name::new(parent, name.to_owned());
                    self.inode_name_manager.remove_name(&name);
                }

                Err(err)
            }

            Ok(entry) => {
                let name = Name::new(parent, name.to_owned());
                let inode = self.inode_name_manager.get_or_insert_inode(name);

                Ok(ReplyEntry {
                    ttl: entry.ttl,
                    attr: (inode, entry.attr).into(),
                    generation: 0,
                })
            }
        }
    }

    async fn mkdir(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
    ) -> Result<ReplyEntry> {
        let parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;

        match self
            .path_filesystem
            .mkdir(req, parent_path.as_ref(), name, mode, umask)
            .await
        {
            Err(err) => {
                if err.is_exist() {
                    let name = Name::new(parent, name.to_owned());
                    self.inode_name_manager.remove_name(&name);
                }

                Err(err)
            }

            Ok(entry) => {
                let name = Name::new(parent, name.to_owned());
                let inode = self.inode_name_manager.get_or_insert_inode(name);

                Ok(ReplyEntry {
                    ttl: entry.ttl,
                    attr: (inode, entry.attr).into(),
                    generation: 0,
                })
            }
        }
    }

    async fn unlink(&self, req: Request, parent: u64, name: &OsStr) -> Result<()> {
        let parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;

        if let Err(err) = self
            .path_filesystem
            .unlink(req, parent_path.as_ref(), name)
            .await
        {
            if err.is_not_exist() {
                let name = Name::new(parent, name.to_owned());
                self.inode_name_manager.remove_name(&name);
            } else if err.is_dir() {
                let name = Name::new(parent, name.to_owned());

                if !self.inode_name_manager.contains_name(&name) {
                    self.inode_name_manager.insert_name(name);
                }
            }

            Err(err)
        } else {
            self.inode_name_manager
                .remove_name(&Name::new(parent, name.to_owned()));

            Ok(())
        }
    }

    async fn rmdir(&self, req: Request, parent: u64, name: &OsStr) -> Result<()> {
        let parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;

        if let Err(err) = self
            .path_filesystem
            .rmdir(req, parent_path.as_ref(), name)
            .await
        {
            if err.is_not_exist() {
                let name = Name::new(parent, name.to_owned());
                self.inode_name_manager.remove_name(&name);
            } else if err.is_not_dir() {
                let name = Name::new(parent, name.to_owned());

                if !self.inode_name_manager.contains_name(&name) {
                    self.inode_name_manager.insert_name(name);
                }
            }

            Err(err)
        } else {
            self.inode_name_manager
                .remove_name(&Name::new(parent, name.to_owned()));

            Ok(())
        }
    }

    async fn rename(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
    ) -> Result<()> {
        let origin_parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;
        let new_parent_path = self
            .inode_name_manager
            .get_absolute_path(new_parent)
            .ok_or_else(Errno::new_not_exist)?;

        // here is very complex so don't modify the inode_name_manager when error
        self.path_filesystem
            .rename(
                req,
                origin_parent_path.as_ref(),
                name,
                new_parent_path.as_ref(),
                new_name,
            )
            .await?;

        self.inode_name_manager
            .remove_name(&Name::new(parent, name.to_owned()));

        let new_name = Name::new(new_parent, new_name.to_owned());
        self.inode_name_manager.get_or_insert_inode(new_name);

        Ok(())
    }

    async fn link(
        &self,
        req: Request,
        inode: u64,
        new_parent: u64,
        new_name: &OsStr,
    ) -> Result<ReplyEntry> {
        let parent_path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;
        let new_parent_path = self
            .inode_name_manager
            .get_absolute_path(new_parent)
            .ok_or_else(Errno::new_not_exist)?;

        // here is very complex so don't modify the inode_name_manager when error
        let entry = self
            .path_filesystem
            .link(
                req,
                parent_path.as_ref(),
                new_parent_path.as_ref(),
                new_name,
            )
            .await?;

        let name = Name::new(new_parent, new_name.to_owned());
        let inode = self.inode_name_manager.get_or_insert_inode(name);

        Ok(ReplyEntry {
            ttl: entry.ttl,
            attr: (inode, entry.attr).into(),
            generation: 0,
        })
    }

    async fn open(&self, req: Request, inode: u64, flags: u32) -> Result<ReplyOpen> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem.open(req, path.as_ref(), flags).await
    }

    async fn read(
        &self,
        req: Request,
        inode: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReplyData> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        self.path_filesystem
            .read(
                req,
                path.as_ref().map(|path| path.as_ref()),
                fh,
                offset,
                size,
            )
            .await
    }

    async fn write(
        &self,
        req: Request,
        inode: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
        write_flags: u32,
        flags: u32,
    ) -> Result<ReplyWrite> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        self.path_filesystem
            .write(
                req,
                path.as_ref().map(|path| path.as_ref()),
                fh,
                offset,
                data,
                write_flags,
                flags,
            )
            .await
    }

    async fn statfs(&self, req: Request, inode: u64) -> Result<ReplyStatFs> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem.statfs(req, path.as_ref()).await
    }

    async fn release(
        &self,
        req: Request,
        inode: u64,
        fh: u64,
        flags: u32,
        lock_owner: u64,
        flush: bool,
    ) -> Result<()> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        self.path_filesystem
            .release(
                req,
                path.as_ref().map(|path| path.as_ref()),
                fh,
                flags,
                lock_owner,
                flush,
            )
            .await
    }

    async fn fsync(&self, req: Request, inode: u64, fh: u64, datasync: bool) -> Result<()> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        self.path_filesystem
            .fsync(req, path.as_ref().map(|path| path.as_ref()), fh, datasync)
            .await
    }

    async fn setxattr(
        &self,
        req: Request,
        inode: u64,
        name: &OsStr,
        value: &[u8],
        flags: u32,
        position: u32,
    ) -> Result<()> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem
            .setxattr(req, path.as_ref(), name, value, flags, position)
            .await
    }

    async fn getxattr(
        &self,
        req: Request,
        inode: u64,
        name: &OsStr,
        size: u32,
    ) -> Result<ReplyXAttr> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem
            .getxattr(req, path.as_ref(), name, size)
            .await
    }

    async fn listxattr(&self, req: Request, inode: u64, size: u32) -> Result<ReplyXAttr> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem
            .listxattr(req, path.as_ref(), size)
            .await
    }

    async fn removexattr(&self, req: Request, inode: u64, name: &OsStr) -> Result<()> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem
            .removexattr(req, path.as_ref(), name)
            .await
    }

    async fn flush(&self, req: Request, inode: u64, fh: u64, lock_owner: u64) -> Result<()> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        self.path_filesystem
            .flush(req, path.as_ref().map(|path| path.as_ref()), fh, lock_owner)
            .await
    }

    async fn opendir(&self, req: Request, inode: u64, flags: u32) -> Result<ReplyOpen> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem
            .opendir(req, path.as_ref(), flags)
            .await
    }

    async fn readdir(
        &self,
        req: Request,
        parent: u64,
        fh: u64,
        offset: i64,
    ) -> Result<ReplyDirectory<impl Stream<Item = Result<DirectoryEntry>> + Send + '_>> {
        let parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;

        let children = self
            .path_filesystem
            .readdir(req, parent_path.as_ref(), fh, offset)
            .await?;

        let entries = children.entries;
        futures_util::pin_mut!(entries);

        let entries_size = entries.size_hint().1.unwrap_or(0);
        let mut entry_list = Vec::with_capacity(entries_size);

        while let Some(entry) = entries.next().await {
            let entry = entry?;

            let inode = if entry.name == OsStr::new(".") {
                parent
            } else if entry.name == OsStr::new("..") {
                self.inode_name_manager
                    .get_parent_inode(parent)
                    .unwrap_or(ROOT_INODE)
            } else {
                let name = Name::new(parent, entry.name.clone());
                self.inode_name_manager.get_or_insert_inode(name)
            };

            entry_list.push(Ok(DirectoryEntry {
                inode,
                kind: entry.kind,
                name: entry.name,
                offset: entry.offset,
            }));
        }

        Ok(ReplyDirectory {
            entries: stream::iter(entry_list),
        })
    }

    async fn releasedir(&self, req: Request, inode: u64, fh: u64, flags: u32) -> Result<()> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem
            .releasedir(req, path.as_ref(), fh, flags)
            .await
    }

    async fn fsyncdir(&self, req: Request, inode: u64, fh: u64, datasync: bool) -> Result<()> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem
            .fsyncdir(req, path.as_ref(), fh, datasync)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "file-lock")]
    async fn getlk(
        &self,
        req: Request,
        inode: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        r#type: u32,
        pid: u32,
    ) -> Result<ReplyLock> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        self.path_filesystem
            .getlk(
                req,
                path.as_ref().map(|path| path.as_ref()),
                fh,
                lock_owner,
                start,
                end,
                r#type,
                pid,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "file-lock")]
    async fn setlk(
        &self,
        req: Request,
        inode: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        r#type: u32,
        pid: u32,
        block: bool,
    ) -> Result<()> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        self.path_filesystem
            .setlk(
                req,
                path.as_ref().map(|path| path.as_ref()),
                fh,
                lock_owner,
                start,
                end,
                r#type,
                pid,
                block,
            )
            .await
    }

    async fn access(&self, req: Request, inode: u64, mask: u32) -> Result<()> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem.access(req, path.as_ref(), mask).await
    }

    async fn create(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> Result<ReplyCreated> {
        let parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;

        match self
            .path_filesystem
            .create(req, parent_path.as_ref(), name, mode, flags)
            .await
        {
            Err(err) => {
                if err.is_exist() || err.is_dir() {
                    let name = Name::new(parent, name.to_owned());
                    self.inode_name_manager.get_or_insert_inode(name);
                }

                Err(err)
            }

            Ok(created) => {
                let name = Name::new(parent, name.to_owned());
                let inode = self.inode_name_manager.get_or_insert_inode(name);

                Ok(ReplyCreated {
                    ttl: created.ttl,
                    attr: (inode, created.attr).into(),
                    generation: 0,
                    fh: created.fh,
                    flags: created.flags,
                })
            }
        }
    }

    #[inline]
    async fn interrupt(&self, req: Request, unique: u64) -> Result<()> {
        self.path_filesystem.interrupt(req, unique).await
    }

    async fn bmap(&self, req: Request, inode: u64, block_size: u32, idx: u64) -> Result<ReplyBmap> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem
            .bmap(req, path.as_ref(), block_size, idx)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn poll(
        &self,
        req: Request,
        inode: u64,
        fh: u64,
        kh: Option<u64>,
        flags: u32,
        events: u32,
        notify: &Notify,
    ) -> Result<ReplyPoll> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        self.path_filesystem
            .poll(
                req,
                path.as_ref().map(|path| path.as_ref()),
                fh,
                kh,
                flags,
                events,
                notify,
            )
            .await
    }

    async fn notify_reply(&self, req: Request, inode: u64, offset: u64, data: Bytes) -> Result<()> {
        let path = self
            .inode_name_manager
            .get_absolute_path(inode)
            .ok_or_else(Errno::new_not_exist)?;

        self.path_filesystem
            .notify_reply(req, path.as_ref(), offset, data)
            .await
    }

    async fn batch_forget(&self, req: Request, inodes: &[(u64, u64)]) {
        // TODO if kernel forget a dir which has children, it may break

        let paths = inodes
            .iter()
            .copied()
            .filter_map(|inode| self.inode_name_manager.get_absolute_path(inode.0))
            .collect::<Vec<_>>();
        let paths = paths.iter().map(|path| path.as_ref()).collect::<Vec<_>>();

        self.path_filesystem.batch_forget(req, &paths).await;

        inodes
            .iter()
            .copied()
            .for_each(|inode| self.inode_name_manager.remove_inode(inode.0));
    }

    async fn fallocate(
        &self,
        req: Request,
        inode: u64,
        fh: u64,
        offset: u64,
        length: u64,
        mode: u32,
    ) -> Result<()> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        self.path_filesystem
            .fallocate(
                req,
                path.as_ref().map(|path| path.as_ref()),
                fh,
                offset,
                length,
                mode,
            )
            .await
    }

    async fn readdirplus(
        &self,
        req: Request,
        parent: u64,
        fh: u64,
        offset: u64,
        lock_owner: u64,
    ) -> Result<ReplyDirectoryPlus<impl Stream<Item = Result<DirectoryEntryPlus>> + Send + '_>>
    {
        let parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;

        let children = self
            .path_filesystem
            .readdirplus(req, parent_path.as_ref(), fh, offset, lock_owner)
            .await?;

        let entries = children.entries;
        futures_util::pin_mut!(entries);

        let entries_size = entries.size_hint().1.unwrap_or(0);
        let mut entry_list = Vec::with_capacity(entries_size);

        while let Some(entry) = entries.next().await {
            let entry = entry?;

            let inode = if entry.name == OsStr::new(".") {
                parent
            } else if entry.name == OsStr::new("..") {
                self.inode_name_manager
                    .get_parent_inode(parent)
                    .unwrap_or(ROOT_INODE)
            } else {
                let name = Name::new(parent, entry.name.clone());
                self.inode_name_manager.get_or_insert_inode(name)
            };

            entry_list.push(Ok(DirectoryEntryPlus {
                inode,
                generation: 0,
                kind: entry.kind,
                name: entry.name,
                offset: entry.offset,
                attr: (inode, entry.attr).into(),
                entry_ttl: entry.entry_ttl,
                attr_ttl: entry.attr_ttl,
            }));
        }

        Ok(ReplyDirectoryPlus {
            entries: stream::iter(entry_list),
        })
    }

    async fn rename2(
        &self,
        req: Request,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        flags: u32,
    ) -> Result<()> {
        let origin_parent_path = self
            .inode_name_manager
            .get_absolute_path(parent)
            .ok_or_else(Errno::new_not_exist)?;
        let new_parent_path = self
            .inode_name_manager
            .get_absolute_path(new_parent)
            .ok_or_else(Errno::new_not_exist)?;

        // here is very complex so don't modify the inode_name_manager when error
        self.path_filesystem
            .rename2(
                req,
                origin_parent_path.as_ref(),
                name,
                new_parent_path.as_ref(),
                new_name,
                flags,
            )
            .await?;

        self.inode_name_manager
            .remove_name(&Name::new(parent, name.to_owned()));

        let new_name = Name::new(new_parent, new_name.to_owned());
        self.inode_name_manager.get_or_insert_inode(new_name);

        Ok(())
    }

    async fn lseek(
        &self,
        req: Request,
        inode: u64,
        fh: u64,
        offset: u64,
        whence: u32,
    ) -> Result<ReplyLSeek> {
        let path = self.inode_name_manager.get_absolute_path(inode);

        self.path_filesystem
            .lseek(
                req,
                path.as_ref().map(|path| path.as_ref()),
                fh,
                offset,
                whence,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn copy_file_range(
        &self,
        req: Request,
        inode: u64,
        fh_in: u64,
        off_in: u64,
        inode_out: u64,
        fh_out: u64,
        off_out: u64,
        length: u64,
        flags: u64,
    ) -> Result<ReplyCopyFileRange> {
        let path_in = self.inode_name_manager.get_absolute_path(inode);
        let path_out = self.inode_name_manager.get_absolute_path(inode_out);

        self.path_filesystem
            .copy_file_range(
                req,
                path_in.as_ref().map(|path| path.as_ref()),
                fh_in,
                off_in,
                path_out.as_ref().map(|path| path.as_ref()),
                fh_out,
                off_out,
                length,
                flags,
            )
            .await
    }
}
