use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Debug, Formatter};
use std::path::PathBuf;
use std::sync::Mutex;

use bytes::Bytes;
use futures_util::stream::{Stream, StreamExt};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    use std::time::{Duration, SystemTime};

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    use crate::path::reply as path_reply;

    fn name(value: &str) -> Name {
        Name::new(ROOT_INODE, OsString::from(value))
    }

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    #[derive(Clone)]
    struct CountingPathFilesystem {
        fail_readdir: bool,
        readdir_calls: Arc<AtomicUsize>,
        readdir_polls: Arc<AtomicUsize>,
        readdirplus_calls: Arc<AtomicUsize>,
        readdirplus_polls: Arc<AtomicUsize>,
    }

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    impl CountingPathFilesystem {
        fn new() -> Self {
            Self {
                fail_readdir: false,
                readdir_calls: Arc::new(AtomicUsize::new(0)),
                readdir_polls: Arc::new(AtomicUsize::new(0)),
                readdirplus_calls: Arc::new(AtomicUsize::new(0)),
                readdirplus_polls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn with_failing_readdir() -> Self {
            Self {
                fail_readdir: true,
                ..Self::new()
            }
        }
    }

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    fn path_attr() -> path_reply::FileAttr {
        path_reply::FileAttr {
            size: 0,
            blocks: 0,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            #[cfg(target_os = "macos")]
            crtime: SystemTime::UNIX_EPOCH,
            kind: crate::FileType::Directory,
            perm: 0o755,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            #[cfg(target_os = "macos")]
            flags: 0,
            blksize: 4096,
        }
    }

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    impl PathFilesystem for CountingPathFilesystem {
        async fn init(&self, _req: Request) -> Result<path_reply::ReplyInit> {
            Ok(path_reply::ReplyInit::default())
        }

        async fn destroy(&self, _req: Request) {}

        async fn readdir<'a>(
            &'a self,
            _req: Request,
            _path: &'a OsStr,
            _fh: u64,
            _offset: i64,
        ) -> Result<
            path_reply::ReplyDirectory<
                impl Stream<Item = Result<path_reply::DirectoryEntry>> + Send + 'a,
            >,
        > {
            self.readdir_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_readdir {
                return Err(libc::EIO.into());
            }
            let poll_count = Arc::clone(&self.readdir_polls);
            let entries =
                ["first", "second", "third"]
                    .into_iter()
                    .enumerate()
                    .map(|(index, name)| {
                        Ok(path_reply::DirectoryEntry {
                            kind: crate::FileType::RegularFile,
                            name: OsString::from(name),
                            offset: (index + 1) as i64,
                        })
                    });

            Ok(path_reply::ReplyDirectory {
                entries: futures_util::stream::iter(entries).inspect(move |_| {
                    poll_count.fetch_add(1, Ordering::SeqCst);
                }),
            })
        }

        async fn readdirplus<'a>(
            &'a self,
            _req: Request,
            _path: &'a OsStr,
            _fh: u64,
            _offset: u64,
            _lock_owner: u64,
        ) -> Result<
            path_reply::ReplyDirectoryPlus<
                impl Stream<Item = Result<path_reply::DirectoryEntryPlus>> + Send + 'a,
            >,
        > {
            self.readdirplus_calls.fetch_add(1, Ordering::SeqCst);
            let poll_count = Arc::clone(&self.readdirplus_polls);
            let entries =
                ["first", "second", "third"]
                    .into_iter()
                    .enumerate()
                    .map(|(index, name)| {
                        Ok(path_reply::DirectoryEntryPlus {
                            kind: crate::FileType::RegularFile,
                            name: OsString::from(name),
                            offset: (index + 1) as i64,
                            attr: path_attr(),
                            entry_ttl: Duration::ZERO,
                            attr_ttl: Duration::ZERO,
                        })
                    });

            Ok(path_reply::ReplyDirectoryPlus {
                entries: futures_util::stream::iter(entries).inspect(move |_| {
                    poll_count.fetch_add(1, Ordering::SeqCst);
                }),
            })
        }
    }

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    #[tokio::test]
    async fn readdir_is_mapped_without_draining_the_path_stream() {
        let path_filesystem = CountingPathFilesystem::new();
        let bridge = InodePathBridge::new(path_filesystem.clone());
        let reply = Filesystem::readdir(&bridge, Request::default(), ROOT_INODE, 0, 0)
            .await
            .expect("root directory should exist");

        assert_eq!(path_filesystem.readdir_calls.load(Ordering::SeqCst), 0);
        assert_eq!(path_filesystem.readdir_polls.load(Ordering::SeqCst), 0);

        let mut entries = Box::pin(reply.entries);
        let first = entries
            .as_mut()
            .next()
            .await
            .expect("first entry")
            .expect("successful entry");
        assert_eq!(first.name, OsStr::new("first"));
        assert_eq!(path_filesystem.readdir_calls.load(Ordering::SeqCst), 1);
        assert_eq!(path_filesystem.readdir_polls.load(Ordering::SeqCst), 1);

        drop(entries);
        assert_eq!(path_filesystem.readdir_polls.load(Ordering::SeqCst), 1);
        assert_eq!(
            bridge
                .inode_name_manager
                .inode_for_name(&Name::new(ROOT_INODE, OsString::from("second"))),
            None
        );
    }

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    #[tokio::test]
    async fn readdirplus_is_mapped_without_draining_the_path_stream() {
        let path_filesystem = CountingPathFilesystem::new();
        let bridge = InodePathBridge::new(path_filesystem.clone());
        let reply = Filesystem::readdirplus(&bridge, Request::default(), ROOT_INODE, 0, 0, 0)
            .await
            .expect("root directory should exist");

        assert_eq!(path_filesystem.readdirplus_calls.load(Ordering::SeqCst), 0);
        assert_eq!(path_filesystem.readdirplus_polls.load(Ordering::SeqCst), 0);

        let mut entries = Box::pin(reply.entries);
        let first = entries
            .as_mut()
            .next()
            .await
            .expect("first entry")
            .expect("successful entry");
        assert_eq!(first.name, OsStr::new("first"));
        assert_eq!(first.attr.ino, first.inode);
        assert_eq!(path_filesystem.readdirplus_calls.load(Ordering::SeqCst), 1);
        assert_eq!(path_filesystem.readdirplus_polls.load(Ordering::SeqCst), 1);

        drop(entries);
        assert_eq!(path_filesystem.readdirplus_polls.load(Ordering::SeqCst), 1);
        assert_eq!(
            bridge
                .inode_name_manager
                .inode_for_name(&Name::new(ROOT_INODE, OsString::from("second"))),
            None
        );
    }

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    #[tokio::test]
    async fn readdir_errors_are_yielded_lazily() {
        let path_filesystem = CountingPathFilesystem::with_failing_readdir();
        let bridge = InodePathBridge::new(path_filesystem.clone());
        let reply = Filesystem::readdir(&bridge, Request::default(), ROOT_INODE, 0, 0)
            .await
            .expect("the lazy bridge stream is constructed before the path call");

        assert_eq!(path_filesystem.readdir_calls.load(Ordering::SeqCst), 0);
        let mut entries = Box::pin(reply.entries);
        assert!(entries.as_mut().next().await.expect("error item").is_err());
        assert_eq!(path_filesystem.readdir_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rename_preserves_inode_and_lookup_references() {
        let manager = InodeNameManager::new();
        let old_name = name("old");
        let new_name = name("new");
        let inode = manager.lookup_inode(old_name.clone());
        manager.get_or_insert_inode(name("unrelated"));

        assert_eq!(manager.rename(&old_name, new_name.clone()), inode);
        assert_eq!(manager.inode_for_name(&old_name), None);
        assert_eq!(manager.inode_for_name(&new_name), Some(inode));
        assert_eq!(manager.lookup_count(inode), Some(1));
        assert_eq!(
            manager.get_absolute_path(inode),
            Some(PathBuf::from("/new"))
        );
    }

    #[test]
    fn rename_overwrite_retires_destination_only_after_forget() {
        let manager = InodeNameManager::new();
        let source_name = name("source");
        let destination_name = name("destination");
        let source_inode = manager.lookup_inode(source_name.clone());
        let destination_inode = manager.lookup_inode(destination_name.clone());

        assert_eq!(
            manager.rename(&source_name, destination_name.clone()),
            source_inode
        );
        assert_eq!(
            manager.inode_for_name(&destination_name),
            Some(source_inode)
        );
        assert!(manager.has_inode(destination_inode));
        assert_eq!(manager.get_absolute_path(destination_inode), None);
        manager.forget(destination_inode, 1);
        assert!(!manager.has_inode(destination_inode));
    }

    #[test]
    fn hard_link_adds_a_name_to_the_existing_inode() {
        let manager = InodeNameManager::new();
        let source_name = name("source");
        let link_name = name("link");
        let inode = manager.lookup_inode(source_name);

        assert_eq!(manager.add_link(inode, link_name.clone()), Some(inode));
        assert_eq!(manager.inode_for_name(&link_name), Some(inode));
        assert_eq!(manager.lookup_count(inode), Some(2));
    }

    #[test]
    fn rename_between_hard_links_is_a_noop() {
        let manager = InodeNameManager::new();
        let source_name = name("source");
        let link_name = name("link");
        let inode = manager.lookup_inode(source_name.clone());
        manager.add_link(inode, link_name.clone());

        assert_eq!(manager.rename(&source_name, link_name.clone()), inode);
        assert_eq!(manager.inode_for_name(&source_name), Some(inode));
        assert_eq!(manager.inode_for_name(&link_name), Some(inode));
    }

    #[test]
    fn unlinked_inode_waits_for_all_forget_references() {
        let manager = InodeNameManager::new();
        let file_name = name("file");
        let inode = manager.lookup_inode(file_name.clone());
        assert_eq!(manager.lookup_inode(file_name.clone()), inode);
        assert_eq!(manager.lookup_count(inode), Some(2));

        manager.remove_name(&file_name);
        assert!(manager.has_inode(inode));
        assert_eq!(manager.get_absolute_path(inode), None);
        manager.forget(inode, 1);
        assert_eq!(manager.lookup_count(inode), Some(1));
        manager.forget(inode, 1);
        assert!(!manager.has_inode(inode));
    }

    #[test]
    fn forget_keeps_a_still_linked_name_stable() {
        let manager = InodeNameManager::new();
        let file_name = name("file");
        let inode = manager.lookup_inode(file_name.clone());

        manager.forget(inode, 1);
        assert_eq!(manager.lookup_count(inode), Some(0));
        assert_eq!(manager.inode_for_name(&file_name), Some(inode));
        assert_eq!(manager.lookup_inode(file_name), inode);
    }

    #[test]
    fn retired_inode_number_is_not_reused() {
        let manager = InodeNameManager::new();
        let old_name = name("old");
        let old_inode = manager.lookup_inode(old_name.clone());
        manager.remove_name(&old_name);
        manager.forget(old_inode, 1);

        let new_inode = manager.lookup_inode(name("new"));
        assert_ne!(new_inode, old_inode);
    }
}

#[derive(Debug)]
struct InodeRecord {
    names: HashSet<Name>,
    lookup_count: u64,
}

#[derive(Debug)]
struct InodeNameState {
    inode_to_record: HashMap<Inode, InodeRecord>,
    name_to_inode: HashMap<Name, Inode>,
    inode_generator: InodeGenerator,
}

/// Maintains the kernel-visible node ID namespace.
///
/// Both directions live under one mutex so rename/link updates are atomic. In
/// particular, a node ID must remain attached to the same object until all of
/// the kernel's lookup references have been forgotten.
#[derive(Debug)]
struct InodeNameManager {
    state: Mutex<InodeNameState>,
}

impl InodeNameManager {
    fn new() -> Self {
        let mut generator = InodeGenerator::new();
        let root_inode = generator.allocate_inode();
        assert_eq!(root_inode, ROOT_INODE);

        let mut inode_to_record = HashMap::new();
        inode_to_record.insert(
            root_inode,
            InodeRecord {
                names: HashSet::from_iter([Name::new(root_inode, OsString::from("/"))]),
                // The FUSE root is a permanent mount anchor, rather than a
                // reference-counted child node; model its lifetime as infinite.
                lookup_count: u64::MAX,
            },
        );

        Self {
            state: Mutex::new(InodeNameState {
                inode_to_record,
                name_to_inode: HashMap::new(),
                inode_generator: generator,
            }),
        }
    }

    fn get_absolute_path(&self, inode: Inode) -> Option<PathBuf> {
        let state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        Self::absolute_path_locked(&state, inode, &mut HashSet::new())
    }

    fn absolute_path_locked(
        state: &InodeNameState,
        inode: Inode,
        visited: &mut HashSet<Inode>,
    ) -> Option<PathBuf> {
        if !visited.insert(inode) {
            return None;
        }
        let record = state.inode_to_record.get(&inode)?;
        let name = record.names.iter().next()?;
        if name.parent == ROOT_INODE {
            Some(PathBuf::from("/").apply(|path| path.push(&name.name)))
        } else {
            Some(
                Self::absolute_path_locked(state, name.parent, visited)?
                    .apply(|path| path.push(&name.name)),
            )
        }
    }

    fn retire_if_unlinked_and_forgotten(state: &mut InodeNameState, inode: Inode) {
        let retire = state
            .inode_to_record
            .get(&inode)
            .is_some_and(|record| record.names.is_empty() && record.lookup_count == 0);
        if retire {
            state.inode_to_record.remove(&inode);
            state.inode_generator.release_inode(inode);
        }
    }

    fn remove_name_locked(state: &mut InodeNameState, name: &Name) -> Option<Inode> {
        let inode = state.name_to_inode.remove(name)?;
        if let Some(record) = state.inode_to_record.get_mut(&inode) {
            record.names.remove(name);
        }
        Self::retire_if_unlinked_and_forgotten(state, inode);
        Some(inode)
    }

    fn remove_name(&self, name: &Name) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        Self::remove_name_locked(&mut state, name);
    }

    fn allocate_name_locked(state: &mut InodeNameState, name: Name) -> Inode {
        let inode = state.inode_generator.allocate_inode();
        state.name_to_inode.insert(name.clone(), inode);
        state.inode_to_record.insert(
            inode,
            InodeRecord {
                names: HashSet::from_iter([name]),
                lookup_count: 0,
            },
        );
        inode
    }

    fn get_or_insert_inode_locked(state: &mut InodeNameState, name: Name) -> Inode {
        if let Some(inode) = state.name_to_inode.get(&name) {
            *inode
        } else {
            Self::allocate_name_locked(state, name)
        }
    }

    fn get_or_insert_inode(&self, name: Name) -> Inode {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        Self::get_or_insert_inode_locked(&mut state, name)
    }

    fn lookup_inode(&self, name: Name) -> Inode {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let inode = Self::get_or_insert_inode_locked(&mut state, name);
        if inode != ROOT_INODE {
            let record = state
                .inode_to_record
                .get_mut(&inode)
                .expect("name map points to missing inode record");
            record.lookup_count = record.lookup_count.saturating_add(1);
        }
        inode
    }

    fn forget(&self, inode: Inode, nlookup: u64) {
        if inode == ROOT_INODE {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(record) = state.inode_to_record.get_mut(&inode) {
            record.lookup_count = record.lookup_count.saturating_sub(nlookup);
        }
        Self::retire_if_unlinked_and_forgotten(&mut state, inode);
    }

    fn rename(&self, old_name: &Name, new_name: Name) -> Inode {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());

        let source_inode = state.name_to_inode.get(old_name).copied();
        if let Some(destination_inode) = state.name_to_inode.get(&new_name).copied() {
            if Some(destination_inode) == source_inode {
                return destination_inode;
            }
            Self::remove_name_locked(&mut state, &new_name);
        }

        let Some(inode) = source_inode else {
            return Self::get_or_insert_inode_locked(&mut state, new_name);
        };

        state.name_to_inode.remove(old_name);
        state.name_to_inode.insert(new_name.clone(), inode);
        if let Some(record) = state.inode_to_record.get_mut(&inode) {
            record.names.remove(old_name);
            record.names.insert(new_name);
        }
        inode
    }

    fn add_link(&self, inode: Inode, new_name: Name) -> Option<Inode> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if !state.inode_to_record.contains_key(&inode) {
            return None;
        }
        if let Some(destination_inode) = state.name_to_inode.get(&new_name).copied() {
            if destination_inode != inode {
                Self::remove_name_locked(&mut state, &new_name);
            }
        }
        state.name_to_inode.insert(new_name.clone(), inode);
        let record = state
            .inode_to_record
            .get_mut(&inode)
            .expect("checked inode record disappeared");
        record.names.insert(new_name);
        record.lookup_count = record.lookup_count.saturating_add(1);
        Some(inode)
    }

    fn contains_name(&self, name: &Name) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .name_to_inode
            .contains_key(name)
    }

    fn get_parent_inode(&self, inode: Inode) -> Option<Inode> {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .inode_to_record
            .get(&inode)
            .and_then(|record| record.names.iter().next().map(|name| name.parent))
    }

    #[cfg(test)]
    fn lookup_count(&self, inode: Inode) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .inode_to_record
            .get(&inode)
            .map(|record| record.lookup_count)
    }

    #[cfg(test)]
    fn inode_for_name(&self, name: &Name) -> Option<Inode> {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .name_to_inode
            .get(name)
            .copied()
    }

    #[cfg(test)]
    fn has_inode(&self, inode: Inode) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .inode_to_record
            .contains_key(&inode)
    }

    fn insert_name(&self, name: Name) -> Inode {
        self.get_or_insert_inode(name)
    }
}

pub struct InodePathBridge<FS> {
    path_filesystem: FS,
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
                let inode = self.inode_name_manager.lookup_inode(name);

                Ok(ReplyEntry {
                    ttl: entry.ttl,
                    attr: (inode, entry.attr).into(),
                    generation: 0,
                })
            }
        }
    }

    async fn forget(&self, req: Request, inode: u64, nlookup: u64) {
        if let Some(path) = self.inode_name_manager.get_absolute_path(inode) {
            self.path_filesystem
                .forget(req, path.as_ref(), nlookup)
                .await;
        }
        self.inode_name_manager.forget(inode, nlookup);
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
                let inode = self.inode_name_manager.lookup_inode(name);

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
                let inode = self.inode_name_manager.lookup_inode(name);

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
                let inode = self.inode_name_manager.lookup_inode(name);

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

        let old_name = Name::new(parent, name.to_owned());
        let new_name = Name::new(new_parent, new_name.to_owned());
        self.inode_name_manager.rename(&old_name, new_name);

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
        let inode = self
            .inode_name_manager
            .add_link(inode, name.clone())
            .unwrap_or_else(|| self.inode_name_manager.lookup_inode(name));

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

        // `PathFilesystem::readdir` may return a stream borrowing `parent_path`.
        // Keep that path in this generator so entries can be mapped lazily instead
        // of draining a stateful filesystem cursor before the session applies its
        // kernel response-size limit.
        Ok(ReplyDirectory {
            entries: async_stream::try_stream! {
                let children = self
                    .path_filesystem
                    .readdir(req, parent_path.as_ref(), fh, offset)
                    .await?;
                let entries = children.entries;
                futures_util::pin_mut!(entries);

                while let Some(entry) = entries.next().await {
                    let entry = entry?;
                    let inode = if entry.name == OsStr::new(".") {
                        parent
                    } else if entry.name == OsStr::new("..") {
                        self.inode_name_manager
                            .get_parent_inode(parent)
                            .unwrap_or(ROOT_INODE)
                    } else {
                        self.inode_name_manager
                            .get_or_insert_inode(Name::new(parent, entry.name.clone()))
                    };

                    yield DirectoryEntry {
                        inode,
                        kind: entry.kind,
                        name: entry.name,
                        offset: entry.offset,
                    };
                }
            },
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
                let inode = self.inode_name_manager.lookup_inode(name);

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
        let paths = inodes
            .iter()
            .copied()
            .filter_map(|inode| self.inode_name_manager.get_absolute_path(inode.0))
            .collect::<Vec<_>>();
        let paths = paths.iter().map(|path| path.as_ref()).collect::<Vec<_>>();

        self.path_filesystem.batch_forget(req, &paths).await;

        for &(inode, nlookup) in inodes {
            self.inode_name_manager.forget(inode, nlookup);
        }
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

        Ok(ReplyDirectoryPlus {
            entries: async_stream::try_stream! {
                let children = self
                    .path_filesystem
                    .readdirplus(req, parent_path.as_ref(), fh, offset, lock_owner)
                    .await?;
                let entries = children.entries;
                futures_util::pin_mut!(entries);

                while let Some(entry) = entries.next().await {
                    let entry = entry?;
                    let inode = if entry.name == OsStr::new(".") {
                        parent
                    } else if entry.name == OsStr::new("..") {
                        self.inode_name_manager
                            .get_parent_inode(parent)
                            .unwrap_or(ROOT_INODE)
                    } else {
                        self.inode_name_manager
                            .get_or_insert_inode(Name::new(parent, entry.name.clone()))
                    };

                    yield DirectoryEntryPlus {
                        inode,
                        generation: 0,
                        kind: entry.kind,
                        name: entry.name,
                        offset: entry.offset,
                        attr: (inode, entry.attr).into(),
                        entry_ttl: entry.entry_ttl,
                        attr_ttl: entry.attr_ttl,
                    };
                }
            },
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

        let old_name = Name::new(parent, name.to_owned());
        let new_name = Name::new(new_parent, new_name.to_owned());
        self.inode_name_manager.rename(&old_name, new_name);

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
