//! Directory IV mode (ADR 0002): per-directory `.encfs.diriv` sidecars make
//! names depend only on their parent directory, so a directory rename is a
//! single backing rename(2).
use encfs::config::{EncfsConfig, Interface};
use encfs::crypto::ssl::SslCipher;
use encfs::diriv;
use encfs::fs::{EncFs, FileState};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use typed_fuse::{
    Caller, Errno, FileKind, PathDirIdentity, PathDirSink, PathFilesystem, PathNodeRef, XattrReply,
};

mod common;
use common::node;

fn req() -> Caller {
    Caller {
        pid: 1,
        gid: unsafe { libc::getgid() },
        uid: unsafe { libc::getuid() },
        umask: 0,
    }
}

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("encfs_diriv_{}_{}", name, std::process::id()));
    if root.exists() {
        // Earlier runs may have left read-only directories behind.
        make_writable(&root);
        fs::remove_dir_all(&root).unwrap();
    }
    fs::create_dir(&root).unwrap();
    root
}

fn make_writable(dir: &Path) {
    for entry in walk(dir) {
        if fs::symlink_metadata(&entry).is_ok_and(|m| m.is_dir()) {
            let _ = fs::set_permissions(&entry, fs::Permissions::from_mode(0o755));
        }
    }
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
}

/// Every path below `dir`, depth first.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            out.push(path.clone());
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                out.extend(walk(&path));
            }
        }
    }
    out
}

/// The descendants of `dir` relative to it, i.e. their ciphertext names.
fn relative_tree(dir: &Path) -> BTreeSet<PathBuf> {
    walk(dir)
        .into_iter()
        .map(|p| p.strip_prefix(dir).unwrap().to_path_buf())
        .collect()
}

fn directory_iv_config(external_iv_chaining: bool) -> EncfsConfig {
    let mut config = EncfsConfig::standard_v7();
    config.chained_name_iv = false;
    config.directory_iv = true;
    config.external_iv_chaining = external_iv_chaining;
    // The same shape `validate()` accepts in the config unit tests.
    config.minimum_reader_version = config.required_v7_reader_version();
    config
}

fn chained_v7_config() -> EncfsConfig {
    let mut config = EncfsConfig::standard_v7();
    config.use_chained_name_iv();
    config
}

struct Volume {
    root: PathBuf,
    config: EncfsConfig,
    fs: EncFs,
    root_state: Arc<FileState>,
    /// Remove the backing directory on drop.
    cleanup: bool,
}

impl Volume {
    fn new(name: &str, config: EncfsConfig) -> Self {
        let root = temp_root(name);
        if config.directory_iv {
            diriv::ensure_root(&root, true).unwrap();
        }
        Self::open(root, config)
    }

    /// A fresh filesystem instance on the same backing directory, as after a
    /// remount: nothing carries over in memory.
    fn open(root: PathBuf, config: EncfsConfig) -> Self {
        let iface = Interface {
            name: "ssl/aes".to_string(),
            major: 3,
            minor: 0,
            age: 0,
        };
        let mut cipher = SslCipher::new(&iface, config.key_size).unwrap();
        cipher.set_key(&[3u8; 32], &[4u8; 16]);
        cipher.set_name_encoding(&config.name_iface);
        cipher.set_wide_file_iv(config.wide_file_iv);
        cipher.set_name_mac_includes_iv(true);
        let mut fs = EncFs::new(root.clone(), Box::new(cipher), config.clone());
        let root_state = fs.root_state();
        Self {
            root,
            config,
            fs,
            root_state,
            cleanup: true,
        }
    }

    fn remount(mut self) -> Self {
        self.cleanup = false;
        Self::open(self.root.clone(), self.config.clone())
    }

    fn parent_and_name(path: &str) -> (&Path, &OsStr) {
        let path = Path::new(path);
        (path.parent().unwrap(), path.file_name().unwrap())
    }

    fn mkdir_mode(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let (parent, name) = Self::parent_and_name(path);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        self.fs
            .mkdir(parent.as_node(), name, mode, 0, &req())
            .map(|_| ())
    }

    fn mkdir(&self, path: &str) {
        self.mkdir_mode(path, 0o755)
            .unwrap_or_else(|e| panic!("mkdir {path}: {e}"));
    }

    fn rmdir(&self, path: &str) -> Result<(), Errno> {
        let (parent, name) = Self::parent_and_name(path);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        self.fs.rmdir(parent.as_node(), name, &req())
    }

    fn unlink(&self, path: &str) {
        let (parent, name) = Self::parent_and_name(path);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        self.fs.unlink(parent.as_node(), name, &req()).unwrap();
    }

    fn write_file(&self, path: &str, data: &[u8]) {
        let (parent, name) = Self::parent_and_name(path);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        let (entry, opened) = self
            .fs
            .create(
                parent.as_node(),
                name,
                0o644,
                0,
                libc::O_CREAT | libc::O_RDWR,
                &req(),
            )
            .unwrap_or_else(|e| panic!("create {path}: {e}"));
        let file = PathNodeRef::new(Some(Path::new(path)), &entry.state);
        assert_eq!(
            self.fs
                .write(file, &opened.handle, data, 0, &req())
                .unwrap(),
            data.len()
        );
        self.fs
            .release(
                PathNodeRef::new(Some(Path::new(path)), &entry.state),
                opened.handle,
                &req(),
            )
            .unwrap();
    }

    fn read_file(&self, path: &str) -> Vec<u8> {
        let file = node(&self.fs, &self.root_state, path, &req());
        let opened = self
            .fs
            .open(file.as_node(), libc::O_RDONLY, &req())
            .unwrap_or_else(|e| panic!("open {path}: {e}"));
        let data = self
            .fs
            .read(file.as_node(), &opened.handle, 0, 1 << 20, &req())
            .unwrap()
            .into_owned();
        self.fs
            .release(file.as_node(), opened.handle, &req())
            .unwrap();
        data
    }

    fn symlink(&self, path: &str, target: &str) {
        let (parent, name) = Self::parent_and_name(path);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        self.fs
            .symlink(parent.as_node(), name, Path::new(target), &req())
            .unwrap();
    }

    fn readlink(&self, path: &str) -> PathBuf {
        let link = node(&self.fs, &self.root_state, path, &req());
        self.fs.readlink(link.as_node(), &req()).unwrap()
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), Errno> {
        let (parent, name) = Self::parent_and_name(from);
        let (new_parent, new_name) = Self::parent_and_name(to);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        let new_parent = node(&self.fs, &self.root_state, new_parent, &req());
        self.fs.rename(
            parent.as_node(),
            name,
            new_parent.as_node(),
            new_name,
            &req(),
        )
    }

    fn setxattr(&self, path: &str, name: &str, value: &[u8]) {
        let target = node(&self.fs, &self.root_state, path, &req());
        self.fs
            .setxattr(target.as_node(), OsStr::new(name), value, 0, &req())
            .unwrap_or_else(|e| panic!("setxattr {path}: {e}"));
    }

    fn getxattr(&self, path: &str, name: &str) -> Vec<u8> {
        let target = node(&self.fs, &self.root_state, path, &req());
        match self
            .fs
            .getxattr(target.as_node(), OsStr::new(name), 65536, &req())
            .unwrap_or_else(|e| panic!("getxattr {path} {name}: {e}"))
        {
            XattrReply::Data(data) => data,
            other => panic!("unexpected reply {other:?}"),
        }
    }

    fn try_getxattr(&self, path: &str, name: &str) -> Result<Vec<u8>, Errno> {
        let target = node(&self.fs, &self.root_state, path, &req());
        match self
            .fs
            .getxattr(target.as_node(), OsStr::new(name), 65536, &req())?
        {
            XattrReply::Data(data) => Ok(data),
            other => panic!("unexpected reply {other:?}"),
        }
    }

    /// Attribute names listed for `path`, without those macOS adds itself.
    fn listxattr(&self, path: &str) -> BTreeSet<String> {
        let target = node(&self.fs, &self.root_state, path, &req());
        match self
            .fs
            .listxattr(target.as_node(), 65536, &req())
            .unwrap_or_else(|e| panic!("listxattr {path}: {e}"))
        {
            XattrReply::Data(data) => String::from_utf8(data)
                .unwrap()
                .split('\0')
                .filter(|n| !n.is_empty() && !n.starts_with("com.apple."))
                .map(str::to_string)
                .collect(),
            other => panic!("unexpected reply {other:?}"),
        }
    }

    fn link(&self, from: &str, to: &str) -> Result<(), Errno> {
        let (new_parent, new_name) = Self::parent_and_name(to);
        let target = node(&self.fs, &self.root_state, from, &req());
        let new_parent = node(&self.fs, &self.root_state, new_parent, &req());
        self.fs
            .link(target.as_node(), new_parent.as_node(), new_name, &req())
            .map(|_| ())
    }

    /// Opens `path` with `O_TRUNC`, as `> path` in a shell does.
    fn truncate_open(&self, path: &str) {
        let file = node(&self.fs, &self.root_state, path, &req());
        let opened = self
            .fs
            .open(file.as_node(), libc::O_WRONLY | libc::O_TRUNC, &req())
            .unwrap_or_else(|e| panic!("open {path}: {e}"));
        self.fs
            .release(file.as_node(), opened.handle, &req())
            .unwrap();
    }

    fn chmod_backing(&self, path: &str, mode: u32) {
        fs::set_permissions(self.backing(path), fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Plaintext names in `path`, without `.` and `..`.
    fn list(&self, path: &str) -> BTreeSet<OsString> {
        let dir = node(&self.fs, &self.root_state, path, &req());
        let opened = self.fs.opendir(dir.as_node(), 0, &req()).unwrap();
        let mut sink = Names::default();
        self.fs
            .readdir(dir.as_node(), &opened.handle, 0, &mut sink, &req())
            .unwrap();
        sink.0
            .into_iter()
            .filter(|n| n != "." && n != "..")
            .collect()
    }

    fn lookup(&self, path: &str) -> Result<bool, Errno> {
        let (parent, name) = Self::parent_and_name(path);
        let parent_state = common::resolve_state(&self.fs, &self.root_state, parent, &req());
        self.fs
            .lookup(PathNodeRef::new(Some(parent), &parent_state), name, &req())
            .map(|entry| entry.is_some())
    }

    /// The backing path of a plaintext path.
    fn backing(&self, path: &str) -> PathBuf {
        self.fs.encrypt_path(Path::new(path)).unwrap().0
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        if self.cleanup && !std::thread::panicking() {
            make_writable(&self.root);
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[derive(Default)]
struct Names(Vec<OsString>);

impl PathDirSink<FileState> for Names {
    fn add(
        &mut self,
        name: &OsStr,
        _kind: FileKind,
        _identity: PathDirIdentity<FileState>,
        _next_offset: u64,
    ) -> bool {
        self.0.push(name.to_os_string());
        true
    }
}

fn names(list: &[&str]) -> BTreeSet<OsString> {
    list.iter().map(OsString::from).collect()
}

#[test]
fn mkdir_creates_hidden_sidecar_and_rmdir_removes_it() {
    let vol = Volume::new("mkdir", directory_iv_config(true));
    vol.mkdir("/dir");

    let backing = vol.backing("/dir");
    let sidecar = diriv::sidecar_path(&backing);
    let meta = fs::symlink_metadata(&sidecar).unwrap();
    assert!(meta.is_file());
    assert_eq!(meta.len(), diriv::SIDECAR_LEN as u64);
    assert_eq!(meta.mode() & 0o777, 0o444);
    assert_ne!(
        diriv::read_sidecar(&backing).unwrap(),
        diriv::read_sidecar(&vol.root).unwrap(),
        "every directory gets its own random IV"
    );

    assert_eq!(vol.list("/"), names(&["dir"]));
    assert_eq!(vol.list("/dir"), names(&[]));

    vol.rmdir("/dir").unwrap();
    assert!(!backing.exists());
    assert_eq!(vol.list("/"), names(&[]));
}

#[test]
fn rmdir_of_non_empty_directory_keeps_sidecar() {
    let vol = Volume::new("rmdir_nonempty", directory_iv_config(true));
    vol.mkdir("/dir");
    vol.write_file("/dir/file", b"contents");
    let backing = vol.backing("/dir");
    let before = diriv::read_sidecar(&backing).unwrap();

    assert_eq!(vol.rmdir("/dir"), Err(Errno::ENOTEMPTY));
    assert_eq!(diriv::read_sidecar(&backing).unwrap(), before);
    assert_eq!(vol.read_file("/dir/file"), b"contents");

    vol.unlink("/dir/file");
    vol.rmdir("/dir").unwrap();
    assert!(!backing.exists());
}

/// A crash between unlinking the sidecar and removing the directory leaves
/// an empty directory with no sidecar; it can still be removed.
#[test]
fn rmdir_removes_directory_left_without_sidecar() {
    let vol = Volume::new("rmdir_leftover", directory_iv_config(true));
    vol.mkdir("/dir");
    let backing = vol.backing("/dir");
    fs::remove_file(diriv::sidecar_path(&backing)).unwrap();
    vol.rmdir("/dir").unwrap();
    assert!(!backing.exists());
}

#[test]
fn read_only_directories_get_sidecars_and_can_be_removed() {
    let vol = Volume::new("read_only_dir", directory_iv_config(true));
    vol.mkdir_mode("/ro", 0o555).unwrap();
    let backing = vol.backing("/ro");
    assert_eq!(fs::metadata(&backing).unwrap().mode() & 0o777, 0o555);
    diriv::read_sidecar(&backing).unwrap();
    assert_eq!(vol.list("/ro"), names(&[]));

    vol.rmdir("/ro").unwrap();
    assert!(!backing.exists());
}

#[test]
fn same_name_encrypts_differently_in_each_directory() {
    let vol = Volume::new("same_name", directory_iv_config(false));
    vol.mkdir("/a");
    vol.mkdir("/b");
    vol.write_file("/a/same.txt", b"a");
    vol.write_file("/b/same.txt", b"b");
    assert_ne!(
        vol.backing("/a/same.txt").file_name(),
        vol.backing("/b/same.txt").file_name()
    );
    assert_eq!(vol.read_file("/a/same.txt"), b"a");
    assert_eq!(vol.read_file("/b/same.txt"), b"b");
}

#[test]
fn damaged_sidecar_fails_closed_and_missing_parent_is_enoent() {
    let vol = Volume::new("damaged", directory_iv_config(true));
    vol.mkdir("/dir");
    vol.write_file("/dir/file", b"x");
    assert_eq!(vol.lookup("/dir/file"), Ok(true));
    assert_eq!(vol.lookup("/dir/absent"), Ok(false));

    // Damage only matters to a fresh mount: while mounted, the IVs are
    // cached and the backing directory is not modified behind the mount.
    let backing = vol.backing("/dir");
    let sidecar = diriv::sidecar_path(&backing);
    fs::remove_file(&sidecar).unwrap();
    let vol = vol.remount();
    assert_eq!(vol.lookup("/dir/file"), Err(Errno::EIO));

    fs::write(&sidecar, [0u8; 5]).unwrap();
    let vol = vol.remount();
    assert_eq!(vol.lookup("/dir/file"), Err(Errno::EIO));

    // A path through a directory that doesn't exist is just missing.
    let missing_parent = vol.fs.encrypt_path(Path::new("/nowhere/file")).unwrap_err();
    assert_eq!(missing_parent, libc::ENOENT);
}

fn deep_directory_rename(external_iv_chaining: bool, name: &str) {
    let vol = Volume::new(name, directory_iv_config(external_iv_chaining));
    vol.mkdir("/a");
    vol.mkdir("/a/b");
    vol.mkdir("/a/b/c");
    vol.mkdir("/z");
    vol.write_file("/a/b/c/file.txt", b"deep contents");
    vol.write_file("/a/top.txt", b"top contents");
    vol.symlink("/a/b/link", "c/file.txt");
    vol.setxattr("/a/b", "user.dir_attr", b"on a directory");
    vol.setxattr("/a/b/c/file.txt", "user.file_attr", b"on a file");
    vol.setxattr("/a", "user.moved_dir_attr", b"on the moved directory");

    let old_backing = vol.backing("/a");
    let inode = fs::metadata(&old_backing).unwrap().ino();
    let sidecar = diriv::read_sidecar(&old_backing).unwrap();
    let tree = relative_tree(&old_backing);
    // b, b/c, top.txt, b/link, b/c/file.txt and the sidecars of a, b and c.
    assert_eq!(tree.len(), 8, "unexpected tree {tree:?}");

    vol.rename("/a", "/z/moved").unwrap();

    let new_backing = vol.backing("/z/moved");
    assert!(!old_backing.exists());
    assert_eq!(
        fs::metadata(&new_backing).unwrap().ino(),
        inode,
        "the directory itself must move, not be copied"
    );
    assert_eq!(diriv::read_sidecar(&new_backing).unwrap(), sidecar);
    assert_eq!(
        relative_tree(&new_backing),
        tree,
        "no descendant may be renamed or rewritten"
    );

    let vol = vol.remount();
    assert_eq!(vol.read_file("/z/moved/b/c/file.txt"), b"deep contents");
    assert_eq!(vol.read_file("/z/moved/top.txt"), b"top contents");
    assert_eq!(vol.readlink("/z/moved/b/link"), PathBuf::from("c/file.txt"));
    assert_eq!(
        vol.getxattr("/z/moved/b", "user.dir_attr"),
        b"on a directory"
    );
    assert_eq!(
        vol.getxattr("/z/moved/b/c/file.txt", "user.file_attr"),
        b"on a file"
    );
    assert_eq!(
        vol.getxattr("/z/moved", "user.moved_dir_attr"),
        b"on the moved directory"
    );
    assert_eq!(vol.list("/z"), names(&["moved"]));
    assert_eq!(vol.list("/"), names(&["z"]));
}

#[test]
fn deep_directory_rename_is_one_backing_rename() {
    deep_directory_rename(false, "deep_rename");
}

#[test]
fn deep_directory_rename_is_one_backing_rename_with_external_iv() {
    deep_directory_rename(true, "deep_rename_external");
}

/// The IV cache is keyed by backing path and never rereads sidecars, so a
/// directory rename must not leave entries under its destination: here
/// `/a/x` and `/empty` each name different directories over time.
#[test]
fn renames_keep_cached_ivs_with_their_directories() {
    let vol = Volume::new("rename_cache", directory_iv_config(true));
    vol.mkdir("/a");
    vol.mkdir("/a/x");
    vol.write_file("/a/x/first", b"first");
    vol.rename("/a", "/b").unwrap();
    assert_eq!(vol.read_file("/b/x/first"), b"first");

    // A different directory now arrives at the vacated /a/x by rename.
    vol.mkdir("/c");
    vol.write_file("/c/second", b"second");
    vol.mkdir("/a");
    vol.rename("/c", "/a/x").unwrap();
    assert_eq!(vol.read_file("/a/x/second"), b"second");
    vol.write_file("/a/x/third", b"third");

    // Replacing an empty directory, then removing and recreating one.
    vol.mkdir("/empty");
    vol.rename("/b/x", "/empty").unwrap();
    assert_eq!(vol.read_file("/empty/first"), b"first");
    vol.unlink("/empty/first");
    vol.rmdir("/empty").unwrap();
    vol.mkdir("/empty");
    vol.write_file("/empty/fourth", b"fourth");

    let vol = vol.remount();
    assert_eq!(vol.list("/a/x"), names(&["second", "third"]));
    assert_eq!(vol.read_file("/a/x/third"), b"third");
    assert_eq!(vol.list("/empty"), names(&["fourth"]));
    assert_eq!(vol.read_file("/empty/fourth"), b"fourth");
    assert_eq!(vol.list("/b"), names(&[]));
}

#[test]
fn directory_rename_onto_empty_directory() {
    let vol = Volume::new("onto_empty", directory_iv_config(true));
    vol.mkdir("/src");
    vol.mkdir("/dst");
    vol.write_file("/src/file", b"payload");
    let src_sidecar = diriv::read_sidecar(&vol.backing("/src")).unwrap();

    vol.rename("/src", "/dst").unwrap();
    assert_eq!(vol.list("/"), names(&["dst"]));
    assert_eq!(
        diriv::read_sidecar(&vol.backing("/dst")).unwrap(),
        src_sidecar
    );
    assert_eq!(vol.read_file("/dst/file"), b"payload");
}

#[test]
fn directory_rename_onto_non_empty_directory_fails_and_keeps_both() {
    let vol = Volume::new("onto_nonempty", directory_iv_config(true));
    vol.mkdir("/src");
    vol.mkdir("/dst");
    vol.write_file("/src/a", b"from src");
    vol.write_file("/dst/b", b"from dst");
    let dst_sidecar = diriv::read_sidecar(&vol.backing("/dst")).unwrap();

    assert_eq!(vol.rename("/src", "/dst"), Err(Errno::ENOTEMPTY));
    assert_eq!(
        diriv::read_sidecar(&vol.backing("/dst")).unwrap(),
        dst_sidecar
    );
    assert_eq!(vol.read_file("/src/a"), b"from src");
    assert_eq!(vol.read_file("/dst/b"), b"from dst");

    // Onto a non-directory is refused as rename(2) would.
    vol.write_file("/plain", b"x");
    assert_eq!(vol.rename("/src", "/plain"), Err(Errno::ENOTDIR));
    assert_eq!(vol.read_file("/src/a"), b"from src");
}

fn file_and_symlink_moves(external_iv_chaining: bool, name: &str) {
    let vol = Volume::new(name, directory_iv_config(external_iv_chaining));
    vol.mkdir("/d1");
    vol.mkdir("/d2");
    vol.write_file("/d1/file", b"file contents");
    vol.setxattr("/d1/file", "user.tag", b"kept");
    vol.symlink("/d1/link", "../d2/elsewhere");

    vol.rename("/d1/file", "/d2/renamed").unwrap();
    vol.rename("/d1/link", "/d2/link2").unwrap();

    let vol = vol.remount();
    assert_eq!(vol.list("/d1"), names(&[]));
    assert_eq!(vol.list("/d2"), names(&["renamed", "link2"]));
    assert_eq!(vol.read_file("/d2/renamed"), b"file contents");
    assert_eq!(vol.getxattr("/d2/renamed", "user.tag"), b"kept");
    assert_eq!(vol.readlink("/d2/link2"), PathBuf::from("../d2/elsewhere"));
}

#[test]
fn file_and_symlink_moves_across_directories() {
    file_and_symlink_moves(false, "file_moves");
}

#[test]
fn file_and_symlink_moves_across_directories_with_external_iv() {
    file_and_symlink_moves(true, "file_moves_external");
}

#[test]
fn root_xattrs_survive_a_remount() {
    let vol = Volume::new("root_xattr", directory_iv_config(true));
    vol.setxattr("/", "user.root", b"root value");
    let vol = vol.remount();
    assert_eq!(vol.getxattr("/", "user.root"), b"root value");
}

/// Encrypted xattrs are keyed by a seed on the inode, so they come through
/// every way a rename can move an entry: rename(2) in place, or a copy where
/// the file header or the parent's name IV changes.
fn xattr_configs() -> Vec<(&'static str, EncfsConfig)> {
    let mut chained_internal = chained_v7_config();
    chained_internal.external_iv_chaining = false;
    vec![
        ("diriv", directory_iv_config(false)),
        ("diriv_external", directory_iv_config(true)),
        ("chained", chained_internal),
        ("chained_external", chained_v7_config()),
    ]
}

fn names_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| n.to_string()).collect()
}

/// The review case: a read-only file denies even its owner `setxattr`, so
/// nothing may need to write attributes after the mode is restored.
#[test]
fn read_only_file_keeps_xattrs_through_rename() {
    for (label, config) in xattr_configs() {
        let vol = Volume::new(&format!("ro_xattr_{label}"), config);
        vol.mkdir("/d1");
        vol.mkdir("/d2");
        vol.write_file("/d1/file", b"read only");
        vol.setxattr("/d1/file", "user.one", b"1");
        vol.setxattr("/d1/file", "user.two", b"2");
        vol.chmod_backing("/d1/file", 0o444);

        vol.rename("/d1/file", "/d2/moved")
            .unwrap_or_else(|e| panic!("{label}: rename: {e}"));

        let vol = vol.remount();
        assert_eq!(vol.read_file("/d2/moved"), b"read only", "{label}");
        assert_eq!(vol.getxattr("/d2/moved", "user.one"), b"1", "{label}");
        assert_eq!(vol.getxattr("/d2/moved", "user.two"), b"2", "{label}");
        assert_eq!(
            vol.listxattr("/d2/moved"),
            names_set(&["user.one", "user.two"]),
            "{label}"
        );
        let mode = fs::metadata(vol.backing("/d2/moved")).unwrap().mode();
        assert_eq!(mode & 0o777, 0o444, "{label}: mode restored");
        assert_eq!(vol.list("/d1"), names(&[]), "{label}");
    }
}

/// A destination's own attributes are keyed by its own seed; after the
/// rename only the source's remain, all readable.
#[test]
fn rename_over_a_file_replaces_its_xattrs() {
    for (label, config) in xattr_configs() {
        let vol = Volume::new(&format!("over_xattr_{label}"), config);
        vol.write_file("/src", b"source");
        vol.setxattr("/src", "user.src", b"from source");
        vol.write_file("/dst", b"destination");
        vol.setxattr("/dst", "user.dst", b"from destination");
        vol.setxattr("/dst", "user.both", b"destination's");
        vol.setxattr("/src", "user.both", b"source's");

        vol.rename("/src", "/dst")
            .unwrap_or_else(|e| panic!("{label}: rename: {e}"));

        let vol = vol.remount();
        assert_eq!(vol.read_file("/dst"), b"source", "{label}");
        assert_eq!(
            vol.listxattr("/dst"),
            names_set(&["user.src", "user.both"]),
            "{label}"
        );
        assert_eq!(vol.getxattr("/dst", "user.both"), b"source's", "{label}");
        assert_eq!(
            vol.try_getxattr("/dst", "user.dst"),
            Err(Errno::ENOATTR),
            "{label}"
        );
    }
}

/// A rename's copy can give an existing destination inode the source's
/// seed. A state for that inode kept alive elsewhere (an open handle, say)
/// must not go on using the IV it cached from the old seed.
#[test]
fn rename_over_a_file_whose_state_is_held_rereads_its_seed() {
    for (label, config) in xattr_configs() {
        let vol = Volume::new(&format!("held_xattr_{label}"), config);
        vol.write_file("/src", b"source");
        vol.setxattr("/src", "user.src", b"from source");
        vol.write_file("/dst", b"destination");
        vol.setxattr("/dst", "user.dst", b"from destination");

        let held = node(&vol.fs, &vol.root_state, "/dst", &req());
        // Caches the destination's IV in the held state.
        assert_eq!(vol.getxattr("/dst", "user.dst"), b"from destination");

        vol.rename("/src", "/dst")
            .unwrap_or_else(|e| panic!("{label}: rename: {e}"));
        assert_eq!(vol.getxattr("/dst", "user.src"), b"from source", "{label}");
        assert_eq!(vol.listxattr("/dst"), names_set(&["user.src"]), "{label}");
        drop(held);
    }
}

#[test]
fn directory_xattrs_survive_rename() {
    for (label, config) in xattr_configs() {
        let vol = Volume::new(&format!("dir_xattr_{label}"), config);
        vol.mkdir("/a");
        vol.mkdir("/a/sub");
        vol.write_file("/a/sub/file", b"inside");
        vol.setxattr("/a", "user.dir", b"on a");
        vol.setxattr("/a/sub", "user.sub", b"on sub");
        vol.setxattr("/a/sub/file", "user.file", b"on file");

        vol.rename("/a", "/b")
            .unwrap_or_else(|e| panic!("{label}: rename: {e}"));

        let vol = vol.remount();
        assert_eq!(vol.getxattr("/b", "user.dir"), b"on a", "{label}");
        assert_eq!(vol.getxattr("/b/sub", "user.sub"), b"on sub", "{label}");
        assert_eq!(
            vol.getxattr("/b/sub/file", "user.file"),
            b"on file",
            "{label}"
        );
    }
}

/// Opening with `O_TRUNC` writes a new file header; the attributes don't
/// depend on it.
#[test]
fn xattrs_survive_a_truncating_open() {
    for (label, config) in xattr_configs() {
        let vol = Volume::new(&format!("trunc_xattr_{label}"), config);
        vol.write_file("/file", b"before");
        vol.setxattr("/file", "user.kept", b"still here");
        vol.truncate_open("/file");
        assert_eq!(vol.read_file("/file"), b"", "{label}");
        assert_eq!(vol.getxattr("/file", "user.kept"), b"still here", "{label}");
    }
}

/// Hard links share an inode, and so its seed and attributes.
#[test]
fn hard_links_share_xattrs() {
    for (label, config) in xattr_configs() {
        if config.external_iv_chaining {
            continue; // link is refused there
        }
        let vol = Volume::new(&format!("link_xattr_{label}"), config);
        vol.mkdir("/d");
        vol.write_file("/file", b"linked");
        vol.setxattr("/file", "user.first", b"1");
        vol.link("/file", "/d/other")
            .unwrap_or_else(|e| panic!("{label}: link: {e}"));
        vol.setxattr("/d/other", "user.second", b"2");

        assert_eq!(vol.getxattr("/file", "user.second"), b"2", "{label}");
        assert_eq!(vol.getxattr("/d/other", "user.first"), b"1", "{label}");
        assert_eq!(
            vol.listxattr("/file"),
            names_set(&["user.first", "user.second"]),
            "{label}"
        );
    }
}

fn backing_xattr_names(path: &Path) -> Vec<Vec<u8>> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    typed_fuse::passthrough::listxattr_names_nofollow(&c_path).unwrap()
}

/// The seed is stored once per inode and never listed.
#[test]
fn the_xattr_seed_is_hidden() {
    let vol = Volume::new("seed_hidden", directory_iv_config(true));
    vol.write_file("/file", b"x");
    assert!(
        !backing_xattr_names(&vol.backing("/file"))
            .iter()
            .any(|n| n.starts_with(encfs::xattr_name::PREFIX.as_bytes())),
        "no seed before the first attribute"
    );
    vol.setxattr("/file", "user.a", b"1");
    vol.setxattr("/file", "user.b", b"2");

    let stored = backing_xattr_names(&vol.backing("/file"));
    let seed = encfs::xattr_name::IV_SEED_NAME.as_bytes();
    assert_eq!(stored.iter().filter(|n| *n == seed).count(), 1);
    assert_eq!(vol.listxattr("/file"), names_set(&["user.a", "user.b"]));
    assert_eq!(
        vol.try_getxattr("/file", encfs::xattr_name::IV_SEED_NAME),
        Err(Errno::ENOATTR),
        "the plaintext name doesn't reach the stored seed"
    );
}

/// On a volume whose config names the path-IV format of earlier versions,
/// extended attributes are unavailable: nothing is read, written or removed,
/// so going back to such a version finds its attributes as it left them,
/// and renames carry their stored bytes across.
#[test]
fn path_iv_volumes_leave_extended_attributes_alone() {
    let c = |s: &str| std::ffi::CString::new(s).unwrap();
    let raw_xattrs = |path: &Path| -> Vec<(Vec<u8>, Vec<u8>)> {
        let c_path = c(path.to_str().unwrap());
        let mut out: Vec<_> = backing_xattr_names(path)
            .into_iter()
            .filter(|n| n.starts_with(encfs::xattr_name::PREFIX.as_bytes()))
            .map(|n| {
                let name = std::ffi::CString::new(n.clone()).unwrap();
                let value =
                    typed_fuse::passthrough::getxattr_value_nofollow(&c_path, &name).unwrap();
                (n, value)
            })
            .collect();
        out.sort();
        out
    };
    for (label, mut config) in xattr_configs() {
        config.xattr_format = encfs::config::XattrFormat::EncryptedPathIv;
        let vol = Volume::new(&format!("path_iv_{label}"), config);
        vol.mkdir("/d");
        vol.write_file("/d/file", b"x");
        // What an earlier version stored: an encrypted name, no seed.
        let backing = vol.backing("/d/file");
        let old_name = c(&encfs::xattr_name::encode(&[7u8; 16]));
        let c_backing = c(backing.to_str().unwrap());
        typed_fuse::passthrough::setxattr_nofollow(&c_backing, &old_name, &[9u8; 16], 0).unwrap();
        let stored = raw_xattrs(&backing);

        let target = node(&vol.fs, &vol.root_state, "/d/file", &req());
        let enotsup = Errno::from(libc::ENOTSUP);
        assert_eq!(
            vol.fs
                .setxattr(target.as_node(), OsStr::new("user.a"), b"1", 0, &req()),
            Err(enotsup),
            "{label}"
        );
        assert_eq!(
            vol.try_getxattr("/d/file", "user.a"),
            Err(enotsup),
            "{label}"
        );
        assert_eq!(
            vol.fs
                .removexattr(target.as_node(), OsStr::new("user.a"), &req()),
            Err(enotsup),
            "{label}"
        );
        assert_eq!(vol.listxattr("/d/file"), names_set(&[]), "{label}");
        drop(target);
        assert_eq!(raw_xattrs(&backing), stored, "{label}: untouched");

        vol.rename("/d/file", "/moved")
            .unwrap_or_else(|e| panic!("{label}: rename: {e}"));
        vol.rename("/d", "/d2")
            .unwrap_or_else(|e| panic!("{label}: rename: {e}"));
        assert_eq!(
            raw_xattrs(&vol.backing("/moved")),
            stored,
            "{label}: carried by the rename"
        );
    }
}

/// Attributes stored under the retired path-IV format have no seed beside
/// them: they are not listed or returned, and new ones work alongside.
#[test]
fn attributes_without_a_seed_are_not_read() {
    let vol = Volume::new("seedless", chained_v7_config());
    vol.write_file("/file", b"x");
    let backing = vol.backing("/file");
    let c_path = std::ffi::CString::new(backing.as_os_str().as_encoded_bytes()).unwrap();
    let old_name = std::ffi::CString::new(encfs::xattr_name::encode(&[7u8; 16])).unwrap();
    typed_fuse::passthrough::setxattr_nofollow(&c_path, &old_name, &[9u8; 16], 0).unwrap();

    assert_eq!(vol.listxattr("/file"), names_set(&[]));
    vol.setxattr("/file", "user.new", b"current");
    assert_eq!(vol.listxattr("/file"), names_set(&["user.new"]));
    assert_eq!(vol.getxattr("/file", "user.new"), b"current");
    assert!(backing_xattr_names(&backing).contains(&old_name.into_bytes()));
}

/// Chained mode is untouched: no sidecars anywhere, and a directory rename
/// still re-creates the subtree under new names.
#[test]
fn chained_mode_creates_no_sidecars_and_still_copies_on_rename() {
    let vol = Volume::new("legacy", chained_v7_config());
    vol.mkdir("/a");
    vol.mkdir("/a/b");
    vol.write_file("/a/b/file", b"chained");
    assert!(
        walk(&vol.root)
            .iter()
            .all(|p| p.file_name() != Some(OsStr::new(diriv::SIDECAR_NAME))),
        "chained mode must not create sidecars"
    );

    let inode = fs::metadata(vol.backing("/a")).unwrap().ino();
    let old_child = vol.backing("/a/b");
    vol.rename("/a", "/moved").unwrap();
    let new_backing = vol.backing("/moved");
    assert_ne!(
        fs::metadata(&new_backing).unwrap().ino(),
        inode,
        "chained mode copies the subtree"
    );
    assert_ne!(
        vol.backing("/moved/b").file_name(),
        old_child.file_name(),
        "names below a renamed directory change"
    );
    assert_eq!(vol.read_file("/moved/b/file"), b"chained");
}

/// Names written before a remount stay readable, and the volume root keeps
/// one sidecar for its lifetime.
#[test]
fn remount_reuses_root_sidecar() {
    let vol = Volume::new("remount", directory_iv_config(false));
    let root_sidecar = diriv::read_sidecar(&vol.root).unwrap();
    vol.mkdir("/dir");
    vol.write_file("/dir/file", b"persisted");
    diriv::ensure_root(&vol.root, true).unwrap();
    let vol = vol.remount();
    assert_eq!(diriv::read_sidecar(&vol.root).unwrap(), root_sidecar);
    assert_eq!(vol.read_file("/dir/file"), b"persisted");
    assert_eq!(vol.list("/"), names(&["dir"]));
}

/// Changing the password re-saves the config; it must stay in directory IV
/// mode with its reader version, and the volume's names must still decode.
#[test]
fn password_change_keeps_directory_iv_mode() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let encfsctl = env!("CARGO_BIN_EXE_encfsctl");
    let root = temp_root("passwd");
    fs::remove_dir(&root).unwrap();
    let status = Command::new(encfsctl)
        .args(["new", "--extpass", "echo old-password"])
        .arg(&root)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let root_sidecar = diriv::read_sidecar(&root).unwrap();

    let config = EncfsConfig::load(&root.join(".encfs7")).unwrap();
    let mut efs = EncFs::new(
        root.clone(),
        config.get_cipher("old-password").unwrap(),
        config,
    );
    let root_state = efs.root_state();
    efs.mkdir(
        PathNodeRef::new(Some(Path::new("/")), &root_state),
        OsStr::new("kept"),
        0o755,
        0,
        &req(),
    )
    .unwrap();
    drop(efs);

    let mut child = Command::new(encfsctl)
        .arg("autopasswd")
        .arg(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"old-password\nnew-password\n")
        .unwrap();
    assert!(child.wait().unwrap().success());

    let config = EncfsConfig::load(&root.join(".encfs7")).unwrap();
    assert!(config.directory_iv);
    assert!(!config.chained_name_iv);
    assert_eq!(
        config.minimum_reader_version,
        encfs::constants::V7_INODE_XATTR_IV_CONFIG_VERSION
    );
    assert_eq!(diriv::read_sidecar(&root).unwrap(), root_sidecar);

    let mut efs = EncFs::new(
        root.clone(),
        config.get_cipher("new-password").unwrap(),
        config,
    );
    let root_state = efs.root_state();
    let entry = efs
        .lookup(
            PathNodeRef::new(Some(Path::new("/")), &root_state),
            OsStr::new("kept"),
            &req(),
        )
        .unwrap();
    assert!(
        entry.is_some(),
        "names must still decode after a password change"
    );

    let _ = fs::remove_dir_all(&root);
}
