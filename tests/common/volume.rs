//! A volume driven through `EncFs` directly, as the `encfsctl fsck` and
//! rename tests use it: paths are plaintext, from the volume root.
use super::node;
use encfs::config::EncfsConfig;
use encfs::crypto::cipher::Cipher;
use encfs::diriv;
use encfs::fs::{EncFs, FileState};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use typed_fuse::{
    Caller, FileKind, PathDirIdentity, PathDirSink, PathFilesystem, PathNodeRef, XattrReply,
};

pub fn req() -> Caller {
    Caller {
        pid: 1,
        gid: unsafe { libc::getgid() },
        uid: unsafe { libc::getuid() },
        umask: 0,
        correlation_id: None,
    }
}

pub fn cipher_for(config: &EncfsConfig) -> Box<dyn Cipher> {
    config.cipher_with_volume_key(&[3u8; 48]).unwrap()
}

pub fn v7(adjust: impl FnOnce(&mut EncfsConfig)) -> EncfsConfig {
    let mut config = EncfsConfig::standard_v7();
    adjust(&mut config);
    config.minimum_reader_version = config.required_v7_reader_version();
    config
}

pub struct Volume {
    _temp: tempfile::TempDir,
    pub root: PathBuf,
    pub config: EncfsConfig,
    pub fs: EncFs,
    pub root_state: Arc<FileState>,
}

impl Volume {
    pub fn new(config: EncfsConfig) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        if config.directory_iv {
            diriv::ensure_root(&root, true).unwrap();
        }
        let mut fs = EncFs::new(root.clone(), cipher_for(&config), config.clone());
        let root_state = fs.root_state();
        Self {
            _temp: temp,
            root,
            config,
            fs,
            root_state,
        }
    }

    /// A fresh filesystem on the same tree, as after a remount.
    pub fn remount(&mut self) {
        self.fs = EncFs::new(
            self.root.clone(),
            cipher_for(&self.config),
            self.config.clone(),
        );
        self.root_state = self.fs.root_state();
    }

    pub fn parent_and_name(path: &str) -> (&Path, &OsStr) {
        let path = Path::new(path);
        (path.parent().unwrap(), path.file_name().unwrap())
    }

    pub fn mkdir(&self, path: &str) {
        let (parent, name) = Self::parent_and_name(path);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        self.fs
            .mkdir(parent.as_node(), name, 0o755, 0, &req())
            .unwrap_or_else(|e| panic!("mkdir {path}: {e}"));
    }

    pub fn write_file(&self, path: &str, data: &[u8]) {
        self.write_at(path, &[(0, data)]);
    }

    /// Creates the file `path` and writes each `(offset, data)` piece to it
    /// in turn.
    pub fn write_at(&self, path: &str, pieces: &[(u64, &[u8])]) {
        let (parent, name) = Self::parent_and_name(path);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        let (entry, opened) = self
            .fs
            .create(
                parent.as_node(),
                name,
                0o640,
                0,
                libc::O_CREAT | libc::O_RDWR,
                &req(),
            )
            .unwrap_or_else(|e| panic!("create {path}: {e}"));
        let file = || PathNodeRef::new(Some(Path::new(path)), &entry.state);
        for (offset, data) in pieces {
            assert_eq!(
                self.fs
                    .write(file(), &opened.handle, data, *offset, &req())
                    .unwrap(),
                data.len()
            );
        }
        self.fs.release(file(), opened.handle, &req()).unwrap();
    }

    pub fn read_file(&self, path: &str) -> Vec<u8> {
        let file = node(&self.fs, &self.root_state, path, &req());
        let opened = self
            .fs
            .open(file.as_node(), libc::O_RDONLY, &req())
            .unwrap_or_else(|e| panic!("open {path}: {e}"));
        let data = self
            .fs
            .read(file.as_node(), &opened.handle, 0, 1 << 20, &req())
            .unwrap_or_else(|e| panic!("read {path}: {e}"))
            .into_owned();
        self.fs
            .release(file.as_node(), opened.handle, &req())
            .unwrap();
        data
    }

    pub fn symlink(&self, path: &str, target: &str) {
        let (parent, name) = Self::parent_and_name(path);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        self.fs
            .symlink(parent.as_node(), name, Path::new(target), &req())
            .unwrap();
    }

    pub fn readlink(&self, path: &str) -> PathBuf {
        let link = node(&self.fs, &self.root_state, path, &req());
        self.fs.readlink(link.as_node(), &req()).unwrap()
    }

    pub fn setxattr(&self, path: &str, name: &str, value: &[u8]) {
        let target = node(&self.fs, &self.root_state, path, &req());
        self.fs
            .setxattr(target.as_node(), OsStr::new(name), value, 0, &req())
            .unwrap_or_else(|e| panic!("setxattr {path}: {e}"));
    }

    pub fn getxattr(&self, path: &str, name: &str) -> Vec<u8> {
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

    pub fn list(&self, path: &str) -> BTreeSet<String> {
        let dir = node(&self.fs, &self.root_state, path, &req());
        let opened = self.fs.opendir(dir.as_node(), 0, &req()).unwrap();
        let mut sink = Names::default();
        self.fs
            .list_dir(dir.as_node(), &opened.handle, &req())
            .unwrap()
            .fill(0, &mut sink);
        sink.0
            .into_iter()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| n != "." && n != "..")
            .collect()
    }

    pub fn backing(&self, path: &str) -> PathBuf {
        self.fs.encrypt_path(Path::new(path)).unwrap().0
    }
    pub fn rename(&self, from: &str, to: &str) -> Result<(), typed_fuse::Errno> {
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
