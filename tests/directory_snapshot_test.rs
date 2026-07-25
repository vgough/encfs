use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use typed_fuse::{Caller, DirBuffer, FileKind, NodeAttr, PathDirSink, PathFilesystem, PathPlusDirSink};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn req() -> Caller {
    Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    }
}

fn setup_fs(test_name: &str) -> (PathBuf, EncFs) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "encfs_{test_name}_{}_{}",
        std::process::id(),
        nonce
    ));
    fs::create_dir(&root).expect("create test directory");
    let iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };
    let mut cipher = SslCipher::new(&iface, 192).expect("create cipher");
    cipher.set_key(&[1u8; 24], &[2u8; 16]);
    let config = encfs::config::EncfsConfig::test_default();
    (root.clone(), EncFs::new(root, Box::new(cipher), config))
}

fn create_file(encfs: &EncFs, name: &str) {
    encfs
        .mknod(
            Path::new(""),
            OsStr::new(name),
            u32::from(libc::S_IFREG | 0o600),
            0,
            0,
            &req(),
        )
        .unwrap_or_else(|e| panic!("create {name}: {e}"));
}

#[derive(Clone)]
struct Entry {
    name: OsString,
    offset: u64,
}

struct Entries {
    values: Vec<Entry>,
    limit: usize,
}
impl PathDirSink for Entries {
    fn add(&mut self, name: &OsStr, _kind: FileKind, next_offset: u64) -> bool {
        if self.values.len() >= self.limit {
            return false;
        }
        self.values.push(Entry {
            name: name.to_os_string(),
            offset: next_offset,
        });
        self.values.len() < self.limit
    }
}

#[derive(Clone)]
struct PlusEntry {
    name: OsString,
    attr: NodeAttr,
    offset: u64,
}

struct PlusEntries {
    values: Vec<PlusEntry>,
    limit: usize,
}
impl PathPlusDirSink for PlusEntries {
    fn add(&mut self, name: &OsStr, attr: NodeAttr, next_offset: u64) -> bool {
        if self.values.len() >= self.limit {
            return false;
        }
        self.values.push(PlusEntry {
            name: name.to_os_string(),
            attr,
            offset: next_offset,
        });
        self.values.len() < self.limit
    }
}

fn read_entries(encfs: &EncFs, handle: &DirBuffer, offset: u64) -> Vec<Entry> {
    let mut sink = Entries {
        values: Vec::new(),
        limit: usize::MAX,
    };
    encfs
        .readdir(Path::new(""), handle, offset, &mut sink, &req())
        .expect("readdir");
    sink.values
}

fn read_prefix(encfs: &EncFs, handle: &DirBuffer, count: usize) -> Vec<Entry> {
    let mut sink = Entries {
        values: Vec::new(),
        limit: count,
    };
    encfs
        .readdir(Path::new(""), handle, 0, &mut sink, &req())
        .expect("readdir prefix");
    sink.values
}

fn read_entries_plus(encfs: &EncFs, handle: &DirBuffer, offset: u64) -> Vec<PlusEntry> {
    let mut sink = PlusEntries {
        values: Vec::new(),
        limit: usize::MAX,
    };
    encfs
        .readdirplus(Path::new(""), handle, offset, &mut sink, &req())
        .expect("readdirplus");
    sink.values
}

fn read_prefix_plus(encfs: &EncFs, handle: &DirBuffer, count: usize) -> Vec<PlusEntry> {
    let mut sink = PlusEntries {
        values: Vec::new(),
        limit: count,
    };
    encfs
        .readdirplus(Path::new(""), handle, 0, &mut sink, &req())
        .expect("readdirplus prefix");
    sink.values
}

fn names<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> BTreeSet<String> {
    entries
        .into_iter()
        .map(|entry| entry.name.to_string_lossy().into_owned())
        .collect()
}

fn plus_names<'a>(entries: impl IntoIterator<Item = &'a PlusEntry>) -> BTreeSet<String> {
    entries
        .into_iter()
        .map(|entry| entry.name.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn readdir_resumes_from_an_opendir_snapshot() {
    let (root, encfs) = setup_fs("readdir_snapshot");
    for name in ["old-a", "old-b", "old-c"] {
        create_file(&encfs, name);
    }
    let handle = encfs
        .opendir(Path::new(""), 0, &req())
        .expect("opendir")
        .handle;
    let prefix = read_prefix(&encfs, &handle, 3);
    let resume_offset = prefix.last().expect("snapshot prefix").offset;
    encfs
        .unlink(Path::new(""), OsStr::new("old-b"), &req())
        .expect("remove old-b");
    create_file(&encfs, "new-entry");
    let resumed = read_entries(&encfs, &handle, resume_offset);
    let combined: Vec<_> = prefix.iter().chain(&resumed).cloned().collect();
    let expected_before = BTreeSet::from([
        ".".to_string(),
        "..".to_string(),
        "old-a".to_string(),
        "old-b".to_string(),
        "old-c".to_string(),
    ]);
    assert_eq!(names(&combined), expected_before);
    assert_eq!(combined.len(), expected_before.len(), "duplicate entries");
    let new_handle = encfs
        .opendir(Path::new(""), 0, &req())
        .expect("new opendir")
        .handle;
    let expected_after = BTreeSet::from([
        ".".to_string(),
        "..".to_string(),
        "old-a".to_string(),
        "old-c".to_string(),
        "new-entry".to_string(),
    ]);
    assert_eq!(names(&read_entries(&encfs, &new_handle, 0)), expected_after);
    encfs
        .releasedir(Some(Path::new("")), handle, &req())
        .expect("release old snapshot");
    encfs
        .releasedir(Some(Path::new("")), new_handle, &req())
        .expect("release new snapshot");
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn readdirplus_retains_snapshot_attributes_after_deletion() {
    let (root, encfs) = setup_fs("readdirplus_snapshot");
    create_file(&encfs, "kept");
    create_file(&encfs, "deleted");
    let handle = encfs
        .opendir(Path::new(""), 0, &req())
        .expect("opendir")
        .handle;
    let prefix = read_prefix_plus(&encfs, &handle, 2);
    let resume_offset = prefix.last().expect("snapshot prefix").offset;
    encfs
        .unlink(Path::new(""), OsStr::new("deleted"), &req())
        .expect("remove deleted entry");
    create_file(&encfs, "added");
    let resumed = read_entries_plus(&encfs, &handle, resume_offset);
    let combined: Vec<_> = prefix.iter().chain(&resumed).cloned().collect();
    let expected_before = BTreeSet::from([
        ".".to_string(),
        "..".to_string(),
        "kept".to_string(),
        "deleted".to_string(),
    ]);
    assert_eq!(plus_names(&combined), expected_before);
    assert_eq!(combined.len(), expected_before.len(), "duplicate entries");
    let deleted = combined
        .iter()
        .find(|entry| entry.name == OsStr::new("deleted"))
        .expect("deleted entry retained in snapshot");
    assert_eq!(deleted.attr.kind, FileKind::RegularFile);
    let new_handle = encfs
        .opendir(Path::new(""), 0, &req())
        .expect("new opendir")
        .handle;
    let expected_after = BTreeSet::from([
        ".".to_string(),
        "..".to_string(),
        "kept".to_string(),
        "added".to_string(),
    ]);
    assert_eq!(
        plus_names(&read_entries_plus(&encfs, &new_handle, 0)),
        expected_after
    );
    encfs
        .releasedir(Some(Path::new("")), handle, &req())
        .expect("release old snapshot");
    encfs
        .releasedir(Some(Path::new("")), new_handle, &req())
        .expect("release new snapshot");
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn directory_terminal_offsets_are_empty() {
    let (root, encfs) = setup_fs("directory_terminal_offsets");
    create_file(&encfs, "entry");
    let handle = encfs
        .opendir(Path::new(""), 0, &req())
        .expect("opendir")
        .handle;
    assert!(read_entries(&encfs, &handle, 3).is_empty());
    assert!(read_entries(&encfs, &handle, u64::MAX).is_empty());
    assert!(read_entries_plus(&encfs, &handle, 3).is_empty());
    assert!(read_entries_plus(&encfs, &handle, u64::MAX).is_empty());
    encfs
        .releasedir(Some(Path::new("")), handle, &req())
        .expect("releasedir");
    fs::remove_dir_all(root).expect("cleanup");
}
