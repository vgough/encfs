use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use encfs::fs::FileState;
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use typed_fuse::{
    Caller, DirBuffer, FileKind, NodeAttr, PathDirIdentity, PathDirSink, PathFilesystem,
    PathNodeRef, PathPlusDirSink,
};

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

fn create_file(encfs: &EncFs, root: &Arc<FileState>, name: &str) {
    encfs
        .mknod(
            PathNodeRef::new(Some(Path::new("")), root),
            OsStr::new(name),
            #[allow(clippy::useless_conversion)]
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
impl PathDirSink<FileState> for Entries {
    fn add(
        &mut self,
        name: &OsStr,
        _kind: FileKind,
        _identity: PathDirIdentity<FileState>,
        next_offset: u64,
    ) -> bool {
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
impl PathPlusDirSink<FileState> for PlusEntries {
    fn add(
        &mut self,
        name: &OsStr,
        attr: NodeAttr,
        _identity: PathDirIdentity<FileState>,
        next_offset: u64,
    ) -> bool {
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

fn read_entries(
    encfs: &EncFs,
    root: &Arc<FileState>,
    handle: &DirBuffer<FileState>,
    offset: u64,
) -> Vec<Entry> {
    let mut sink = Entries {
        values: Vec::new(),
        limit: usize::MAX,
    };
    encfs
        .readdir(
            PathNodeRef::new(Some(Path::new("")), root),
            handle,
            offset,
            &mut sink,
            &req(),
        )
        .expect("readdir");
    sink.values
}

fn read_prefix(
    encfs: &EncFs,
    root: &Arc<FileState>,
    handle: &DirBuffer<FileState>,
    count: usize,
) -> Vec<Entry> {
    let mut sink = Entries {
        values: Vec::new(),
        limit: count,
    };
    encfs
        .readdir(
            PathNodeRef::new(Some(Path::new("")), root),
            handle,
            0,
            &mut sink,
            &req(),
        )
        .expect("readdir prefix");
    sink.values
}

fn read_entries_plus(
    encfs: &EncFs,
    root: &Arc<FileState>,
    handle: &DirBuffer<FileState>,
    offset: u64,
) -> Vec<PlusEntry> {
    let mut sink = PlusEntries {
        values: Vec::new(),
        limit: usize::MAX,
    };
    encfs
        .readdirplus(
            PathNodeRef::new(Some(Path::new("")), root),
            handle,
            offset,
            &mut sink,
            &req(),
        )
        .expect("readdirplus");
    sink.values
}

fn read_prefix_plus(
    encfs: &EncFs,
    root: &Arc<FileState>,
    handle: &DirBuffer<FileState>,
    count: usize,
) -> Vec<PlusEntry> {
    let mut sink = PlusEntries {
        values: Vec::new(),
        limit: count,
    };
    encfs
        .readdirplus(
            PathNodeRef::new(Some(Path::new("")), root),
            handle,
            0,
            &mut sink,
            &req(),
        )
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
    let (dir, mut encfs) = setup_fs("readdir_snapshot");
    let root = encfs.root_state();
    for name in ["old-a", "old-b", "old-c"] {
        create_file(&encfs, &root, name);
    }
    let handle = encfs
        .opendir(PathNodeRef::new(Some(Path::new("")), &root), 0, &req())
        .expect("opendir")
        .handle;
    let prefix = read_prefix(&encfs, &root, &handle, 3);
    let resume_offset = prefix.last().expect("snapshot prefix").offset;
    encfs
        .unlink(
            PathNodeRef::new(Some(Path::new("")), &root),
            OsStr::new("old-b"),
            &req(),
        )
        .expect("remove old-b");
    create_file(&encfs, &root, "new-entry");
    let resumed = read_entries(&encfs, &root, &handle, resume_offset);
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
        .opendir(PathNodeRef::new(Some(Path::new("")), &root), 0, &req())
        .expect("new opendir")
        .handle;
    let expected_after = BTreeSet::from([
        ".".to_string(),
        "..".to_string(),
        "old-a".to_string(),
        "old-c".to_string(),
        "new-entry".to_string(),
    ]);
    assert_eq!(
        names(&read_entries(&encfs, &root, &new_handle, 0)),
        expected_after
    );
    encfs
        .releasedir(PathNodeRef::new(Some(Path::new("")), &root), handle, &req())
        .expect("release old snapshot");
    encfs
        .releasedir(
            PathNodeRef::new(Some(Path::new("")), &root),
            new_handle,
            &req(),
        )
        .expect("release new snapshot");
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn readdirplus_retains_snapshot_attributes_after_deletion() {
    let (dir, mut encfs) = setup_fs("readdirplus_snapshot");
    let root = encfs.root_state();
    create_file(&encfs, &root, "kept");
    create_file(&encfs, &root, "deleted");
    let handle = encfs
        .opendir(PathNodeRef::new(Some(Path::new("")), &root), 0, &req())
        .expect("opendir")
        .handle;
    let prefix = read_prefix_plus(&encfs, &root, &handle, 2);
    let resume_offset = prefix.last().expect("snapshot prefix").offset;
    encfs
        .unlink(
            PathNodeRef::new(Some(Path::new("")), &root),
            OsStr::new("deleted"),
            &req(),
        )
        .expect("remove deleted entry");
    create_file(&encfs, &root, "added");
    let resumed = read_entries_plus(&encfs, &root, &handle, resume_offset);
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
        .opendir(PathNodeRef::new(Some(Path::new("")), &root), 0, &req())
        .expect("new opendir")
        .handle;
    let expected_after = BTreeSet::from([
        ".".to_string(),
        "..".to_string(),
        "kept".to_string(),
        "added".to_string(),
    ]);
    assert_eq!(
        plus_names(&read_entries_plus(&encfs, &root, &new_handle, 0)),
        expected_after
    );
    encfs
        .releasedir(PathNodeRef::new(Some(Path::new("")), &root), handle, &req())
        .expect("release old snapshot");
    encfs
        .releasedir(
            PathNodeRef::new(Some(Path::new("")), &root),
            new_handle,
            &req(),
        )
        .expect("release new snapshot");
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn directory_terminal_offsets_are_empty() {
    let (dir, mut encfs) = setup_fs("directory_terminal_offsets");
    let root = encfs.root_state();
    create_file(&encfs, &root, "entry");
    let handle = encfs
        .opendir(PathNodeRef::new(Some(Path::new("")), &root), 0, &req())
        .expect("opendir")
        .handle;
    assert!(read_entries(&encfs, &root, &handle, 3).is_empty());
    assert!(read_entries(&encfs, &root, &handle, u64::MAX).is_empty());
    assert!(read_entries_plus(&encfs, &root, &handle, 3).is_empty());
    assert!(read_entries_plus(&encfs, &root, &handle, u64::MAX).is_empty());
    encfs
        .releasedir(PathNodeRef::new(Some(Path::new("")), &root), handle, &req())
        .expect("releasedir");
    fs::remove_dir_all(dir).expect("cleanup");
}
