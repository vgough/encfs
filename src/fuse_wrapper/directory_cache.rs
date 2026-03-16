// DirectoryCache :: a cache for directory entries to simplify readdir calls.
//
// Based on fuse_mt directory_cache by William R. Fraser.

use std::collections::HashMap;
use std::num::Wrapping;

use super::DirectoryEntry;

/// Directory entry cache for readdir pagination.
#[derive(Debug)]
pub struct DirectoryCache {
    next_key: Wrapping<u64>,
    entries: HashMap<u64, DirectoryCacheEntry>,
}

impl DirectoryCache {
    pub fn new() -> DirectoryCache {
        DirectoryCache {
            next_key: Wrapping(1),
            entries: HashMap::new(),
        }
    }

    pub fn new_entry(&mut self, fh: u64) -> u64 {
        let key = self.next_key.0;
        self.entries.insert(key, DirectoryCacheEntry::new(fh));
        self.next_key += Wrapping(1);
        key
    }

    pub fn real_fh(&self, key: u64) -> u64 {
        self.entries
            .get(&key)
            .unwrap_or_else(|| {
                panic!("no such directory cache key {}", key);
            })
            .fh
    }

    pub fn get_mut(&mut self, key: u64) -> &mut DirectoryCacheEntry {
        self.entries.get_mut(&key).unwrap_or_else(|| {
            panic!("no such directory cache key {}", key);
        })
    }

    pub fn delete(&mut self, key: u64) {
        self.entries.remove(&key);
    }
}

#[derive(Debug)]
pub struct DirectoryCacheEntry {
    pub fh: u64,
    pub entries: Option<Vec<DirectoryEntry>>,
}

impl DirectoryCacheEntry {
    pub fn new(fh: u64) -> DirectoryCacheEntry {
        DirectoryCacheEntry { fh, entries: None }
    }
}
