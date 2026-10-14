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
    Caller, DirBuffer, Errno, FileKind, NodeAttr, PathDirIdentity, PathDirSink, PathFilesystem,
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

#[derive(Default)]
struct Entries(Vec<(OsString, FileKind)>);

impl PathDirSink<FileState> for Entries {
    fn add(
        &mut self,
        name: &OsStr,
        kind: FileKind,
        _identity: PathDirIdentity<FileState>,
        _next_offset: u64,
    ) -> bool {
        self.0.push((name.to_os_string(), kind));
        true
    }
}

#[derive(Default)]
struct PlusEntries(Vec<(OsString, Option<NodeAttr>)>);

impl PathPlusDirSink<FileState> for PlusEntries {
    fn add(
        &mut self,
        name: &OsStr,
        attr: Option<NodeAttr>,
        _identity: PathDirIdentity<FileState>,
        _next_offset: u64,
    ) -> bool {
        self.0.push((name.to_os_string(), attr));
        true
    }
}

fn list(encfs: &EncFs, root: &Arc<FileState>) -> DirBuffer<FileState> {
    let node = || PathNodeRef::new(Some(Path::new("")), root);
    encfs.opendir(node(), 0, &req()).expect("opendir");
    let listing = encfs.list_dir(node(), &(), &req()).expect("list_dir");
    encfs.releasedir(node(), (), &req()).expect("releasedir");
    listing
}

fn names(listing: &DirBuffer<FileState>) -> BTreeSet<String> {
    listing
        .iter()
        .map(|entry| entry.name.to_string_lossy().into_owned())
        .collect()
}

fn expected(list: &[&str]) -> BTreeSet<String> {
    [".", ".."]
        .iter()
        .chain(list)
        .map(|name| name.to_string())
        .collect()
}

/// `list_dir` reads the backing directory each time, so a listing (which
/// the adapter takes on the first read and on every read from offset 0)
/// shows its current contents.
#[test]
fn list_dir_reflects_current_contents() {
    let (dir, mut encfs) = setup_fs("list_dir_current");
    let root = encfs.root_state();
    create_file(&encfs, &root, "first");
    assert_eq!(names(&list(&encfs, &root)), expected(&["first"]));
    create_file(&encfs, &root, "second");
    assert_eq!(names(&list(&encfs, &root)), expected(&["first", "second"]));
    encfs
        .unlink(
            PathNodeRef::new(Some(Path::new("")), &root),
            OsStr::new("first"),
            &req(),
        )
        .expect("remove first");
    assert_eq!(names(&list(&encfs, &root)), expected(&["second"]));
    fs::remove_dir_all(dir).expect("cleanup");
}

/// Every entry carries its attributes, so `readdirplus` needs no lookups.
#[test]
fn list_dir_entries_carry_attributes() {
    let (dir, mut encfs) = setup_fs("list_dir_attrs");
    let root = encfs.root_state();
    create_file(&encfs, &root, "file");
    encfs
        .mkdir(
            PathNodeRef::new(Some(Path::new("")), &root),
            OsStr::new("subdir"),
            0o700,
            0,
            &req(),
        )
        .expect("mkdir");
    let listing = list(&encfs, &root);

    let mut plus = PlusEntries::default();
    listing.fill_plus(0, &mut plus);
    let kinds: Vec<_> = plus
        .0
        .iter()
        .map(|(name, attr)| {
            let attr = attr.unwrap_or_else(|| panic!("{name:?} has no attributes"));
            (name.to_string_lossy().into_owned(), attr.kind)
        })
        .collect();
    let mut sorted = kinds.clone();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        sorted,
        vec![
            (".".to_string(), FileKind::Directory),
            ("..".to_string(), FileKind::Directory),
            ("file".to_string(), FileKind::RegularFile),
            ("subdir".to_string(), FileKind::Directory),
        ]
    );

    let mut basic = Entries::default();
    listing.fill(0, &mut basic);
    let basic: Vec<_> = basic
        .0
        .into_iter()
        .map(|(name, kind)| (name.to_string_lossy().into_owned(), kind))
        .collect();
    assert_eq!(basic, kinds, "readdir and readdirplus kinds differ");
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn directory_terminal_offsets_are_empty() {
    let (dir, mut encfs) = setup_fs("directory_terminal_offsets");
    let root = encfs.root_state();
    create_file(&encfs, &root, "entry");
    let listing = list(&encfs, &root);
    assert_eq!(listing.len(), 3);
    for offset in [3, u64::MAX] {
        let mut basic = Entries::default();
        listing.fill(offset, &mut basic);
        assert!(basic.0.is_empty());
        let mut plus = PlusEntries::default();
        listing.fill_plus(offset, &mut plus);
        assert!(plus.0.is_empty());
    }
    fs::remove_dir_all(dir).expect("cleanup");
}

/// The listing is taken lazily, but `opendir` still fails where listing
/// would rather than succeeding and failing on the first read.
#[test]
fn opendir_fails_for_a_missing_directory() {
    let (dir, mut encfs) = setup_fs("opendir_missing");
    let root = encfs.root_state();
    let err = encfs
        .opendir(
            PathNodeRef::new(Some(Path::new("missing")), &root),
            0,
            &req(),
        )
        .expect_err("opendir of a missing directory succeeded");
    assert_eq!(err, Errno::ENOENT);
    fs::remove_dir_all(dir).expect("cleanup");
}
