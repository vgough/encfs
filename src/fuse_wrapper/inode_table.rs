// InodeTable :: a bi-directional map of paths to inodes.
//
// Based on fuse_mt inode_table by William R. Fraser.

use std::borrow::Borrow;
use std::cmp::{Eq, PartialEq};
use std::collections::hash_map::Entry::*;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub type Inode = u64;
pub type Generation = u64;
pub type LookupCount = u64;

#[derive(Debug)]
struct InodeTableEntry {
    path: Option<Arc<PathBuf>>,
    lookups: LookupCount,
    generation: Generation,
}

/// A data structure for mapping paths to inodes and vice versa.
#[derive(Debug)]
pub struct InodeTable {
    table: Vec<InodeTableEntry>,
    free_list: VecDeque<usize>,
    by_path: HashMap<Arc<PathBuf>, usize>,
}

impl InodeTable {
    pub fn new() -> InodeTable {
        let mut inode_table = InodeTable {
            table: Vec::new(),
            free_list: VecDeque::new(),
            by_path: HashMap::new(),
        };
        let root = Arc::new(PathBuf::from("/"));
        inode_table.table.push(InodeTableEntry {
            path: Some(root.clone()),
            lookups: 0,
            generation: 0,
        });
        inode_table.by_path.insert(root, 0);
        inode_table
    }

    pub fn add(&mut self, path: Arc<PathBuf>) -> (Inode, Generation) {
        let (inode, generation) = {
            let (inode, entry) = Self::get_inode_entry(&mut self.free_list, &mut self.table);
            entry.path = Some(path.clone());
            entry.lookups = 1;
            (inode, entry.generation)
        };
        log::debug!("explicitly adding {} -> {:?} with 1 lookups", inode, path);
        let previous = self.by_path.insert(path, inode as usize - 1);
        if let Some(previous) = previous {
            panic!(
                "attempted to insert duplicate path into inode table: {:?}",
                previous
            );
        }
        (inode, generation)
    }

    pub fn add_or_get(&mut self, path: Arc<PathBuf>) -> (Inode, Generation) {
        match self.by_path.entry(path.clone()) {
            Vacant(path_entry) => {
                let (inode, entry) = Self::get_inode_entry(&mut self.free_list, &mut self.table);
                log::debug!("adding {} -> {:?} with 0 lookups", inode, path);
                entry.path = Some(path);
                path_entry.insert(inode as usize - 1);
                (inode, entry.generation)
            }
            Occupied(path_entry) => {
                let idx = path_entry.get();
                ((idx + 1) as Inode, self.table[*idx].generation)
            }
        }
    }

    pub fn get_path(&self, inode: Inode) -> Option<Arc<PathBuf>> {
        self.table[inode as usize - 1].path.clone()
    }

    pub fn get_inode(&mut self, path: &Path) -> Option<Inode> {
        self.by_path
            .get(Pathish::new(path))
            .map(|idx| (idx + 1) as Inode)
    }

    pub fn lookup(&mut self, inode: Inode) {
        if inode == 1 {
            return;
        }

        let entry = &mut self.table[inode as usize - 1];
        entry.lookups += 1;
        log::debug!(
            "lookups on {} -> {:?} now {}",
            inode,
            entry.path,
            entry.lookups
        );
    }

    pub fn forget(&mut self, inode: Inode, n: LookupCount) -> LookupCount {
        if inode == 1 {
            return 1;
        }

        let mut delete = false;
        let lookups: LookupCount;
        let idx = inode as usize - 1;

        {
            let entry = &mut self.table[idx];
            log::debug!("forget entry {:?}", entry);
            assert!(n <= entry.lookups);
            entry.lookups -= n;
            lookups = entry.lookups;
            if lookups == 0 {
                delete = true;
                self.by_path.remove(entry.path.as_ref().unwrap());
            }
        }

        if delete {
            self.table[idx].path = None;
            self.free_list.push_back(idx);
        }

        lookups
    }

    pub fn rename(&mut self, oldpath: &Path, newpath: Arc<PathBuf>) {
        let idx = self.by_path.remove(Pathish::new(oldpath)).unwrap();
        self.table[idx].path = Some(newpath.clone());
        self.by_path.insert(newpath, idx);
    }

    pub fn unlink(&mut self, path: &Path) {
        self.by_path.remove(Pathish::new(path));
    }

    fn get_inode_entry<'a>(
        free_list: &mut VecDeque<usize>,
        table: &'a mut Vec<InodeTableEntry>,
    ) -> (Inode, &'a mut InodeTableEntry) {
        let idx = match free_list.pop_front() {
            Some(idx) => {
                log::debug!("re-using inode {}", idx + 1);
                table[idx].generation += 1;
                idx
            }
            None => {
                table.push(InodeTableEntry {
                    path: None,
                    lookups: 0,
                    generation: 0,
                });
                table.len() - 1
            }
        };
        ((idx + 1) as Inode, &mut table[idx])
    }
}

/// Facilitates comparing Arc<PathBuf> and &Path
#[derive(Debug)]
struct Pathish {
    inner: Path,
}

impl Pathish {
    pub fn new(p: &Path) -> &Pathish {
        unsafe { &*(p as *const _ as *const Pathish) }
    }
}

impl Borrow<Pathish> for Arc<PathBuf> {
    fn borrow(&self) -> &Pathish {
        Pathish::new(self.as_path())
    }
}

impl Hash for Pathish {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl Eq for Pathish {}

impl PartialEq for Pathish {
    fn eq(&self, other: &Pathish) -> bool {
        self.inner.eq(&other.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inode_reuse() {
        let mut table = InodeTable::new();
        let path1 = Arc::new(PathBuf::from("/foo/a"));
        let path2 = Arc::new(PathBuf::from("/foo/b"));

        let inode1 = table.add(path1.clone()).0;
        assert!(inode1 != 1);
        assert_eq!(*path1, *table.get_path(inode1).unwrap());

        let inode2 = table.add(path2.clone()).0;
        assert!(inode2 != inode1);
        assert!(inode2 != 1);
        assert_eq!(*path2, *table.get_path(inode2).unwrap());

        assert_eq!(0, table.forget(inode1, 1));
        assert!(table.get_path(inode1).is_none());

        let (inode3, generation3) = table.add(Arc::new(PathBuf::from("/foo/c")));
        assert_eq!(inode1, inode3);
        assert_eq!(1, generation3);

        assert_eq!(Path::new("/foo/c"), *table.get_path(inode3).unwrap());
    }

    #[test]
    fn test_add_or_get() {
        let mut table = InodeTable::new();
        let path1 = Arc::new(PathBuf::from("/foo/a"));
        let path2 = Arc::new(PathBuf::from("/foo/b"));

        let inode1 = table.add_or_get(path1.clone()).0;
        assert_eq!(*path1, *table.get_path(inode1).unwrap());
        table.lookup(inode1);

        let inode2 = table.add(path2.clone()).0;
        assert_eq!(*path2, *table.get_path(inode2).unwrap());
        assert_eq!(inode2, table.add_or_get(path2).0);
        table.lookup(inode2);

        assert_eq!(0, table.forget(inode1, 1));
        assert_eq!(1, table.forget(inode2, 1));
    }

    #[test]
    fn test_inode_rename() {
        let mut table = InodeTable::new();
        let path1 = Arc::new(PathBuf::from("/foo/a"));
        let path2 = Arc::new(PathBuf::from("/foo/b"));

        let inode = table.add(path1.clone()).0;
        assert_eq!(*path1, *table.get_path(inode).unwrap());
        assert_eq!(inode, table.get_inode(&path1).unwrap());

        table.rename(&path1, path2.clone());
        assert!(table.get_inode(&path1).is_none());
        assert_eq!(inode, table.get_inode(&path2).unwrap());
        assert_eq!(*path2, *table.get_path(inode).unwrap());
    }

    #[test]
    fn test_unlink() {
        let mut table = InodeTable::new();
        let path = Arc::new(PathBuf::from("/foo/bar"));

        let inode = table.add(path.clone()).0;

        table.unlink(&path);
        assert!(table.get_inode(&path).is_none());

        assert_eq!(*path, *table.get_path(inode).unwrap());

        assert_eq!(0, table.forget(inode, 1));
        assert!(table.get_path(inode).is_none());
    }
}
