//! Forward-mode rename where an entry's stored bytes depend on its path:
//! files without a header whose blocks are encrypted under the path IV,
//! extended attributes that pass through unencrypted, and backing entries
//! inside a renamed directory whose names don't decode. Everything is read
//! back through a fresh `EncFs`, as after a remount.
use encfs::config::EncfsConfig;
use encfs::crypto::cipher::Cipher;
use encfs::diriv;
use encfs::fs::{EncFs, FileState};
use encfs::fsck::{Action, Finding, Fsck, Handler, Outcome};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use typed_fuse::{Caller, PathFilesystem, PathNodeRef, XattrReply};

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

fn cipher_for(config: &EncfsConfig) -> Box<dyn Cipher> {
    config.cipher_with_volume_key(&[3u8; 48]).unwrap()
}

fn v7(adjust: impl FnOnce(&mut EncfsConfig)) -> EncfsConfig {
    let mut config = EncfsConfig::standard_v7();
    adjust(&mut config);
    config.minimum_reader_version = config.required_v7_reader_version();
    config
}

/// Headerless configs whose file IV is the path IV.
fn headerless_configs() -> Vec<(&'static str, EncfsConfig)> {
    vec![
        (
            // `encfsctl new --no-unique-iv`, what `encfsr` needs.
            "v7-no-unique-iv",
            v7(|c| {
                c.use_chained_name_iv();
                c.unique_iv = false;
                c.wide_file_iv = false;
            }),
        ),
        (
            "v7-headerless-diriv",
            v7(|c| {
                c.unique_iv = false;
                c.wide_file_iv = false;
            }),
        ),
        ("v6-headerless", {
            let mut c = EncfsConfig::test_default();
            c.unique_iv = false;
            c.external_iv_chaining = true;
            c.block_mac_bytes = 0;
            c
        }),
        ("v6-headerless-holes", {
            let mut c = EncfsConfig::test_default();
            c.unique_iv = false;
            c.external_iv_chaining = true;
            c.allow_holes = true;
            c
        }),
    ]
}

struct Volume {
    _temp: tempfile::TempDir,
    root: PathBuf,
    config: EncfsConfig,
    fs: EncFs,
    root_state: Arc<FileState>,
}

impl Volume {
    fn new(config: EncfsConfig) -> Self {
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

    fn remount(&mut self) {
        self.fs = EncFs::new(
            self.root.clone(),
            cipher_for(&self.config),
            self.config.clone(),
        );
        self.root_state = self.fs.root_state();
    }

    fn split(path: &str) -> (&Path, &OsStr) {
        let path = Path::new(path);
        (path.parent().unwrap(), path.file_name().unwrap())
    }

    fn mkdir(&self, path: &str) {
        let (parent, name) = Self::split(path);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        self.fs
            .mkdir(parent.as_node(), name, 0o755, 0, &req())
            .unwrap_or_else(|e| panic!("mkdir {path}: {e}"));
    }

    /// Writes each `(offset, data)` piece in turn to the new file `path`.
    fn write_file(&self, path: &str, pieces: &[(u64, &[u8])]) {
        let (parent, name) = Self::split(path);
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

    fn read_file(&self, path: &str) -> Vec<u8> {
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

    fn symlink(&self, path: &str, target: &str) {
        let (parent, name) = Self::split(path);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        self.fs
            .symlink(parent.as_node(), name, Path::new(target), &req())
            .unwrap();
    }

    fn readlink(&self, path: &str) -> PathBuf {
        let link = node(&self.fs, &self.root_state, path, &req());
        self.fs.readlink(link.as_node(), &req()).unwrap()
    }

    fn rename(&self, from: &str, to: &str) {
        let (parent, name) = Self::split(from);
        let (new_parent, new_name) = Self::split(to);
        let parent = node(&self.fs, &self.root_state, parent, &req());
        let new_parent = node(&self.fs, &self.root_state, new_parent, &req());
        self.fs
            .rename(
                parent.as_node(),
                name,
                new_parent.as_node(),
                new_name,
                &req(),
            )
            .unwrap_or_else(|e| panic!("rename {from} -> {to}: {e}"));
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

    fn backing(&self, path: &str) -> PathBuf {
        self.fs.encrypt_path(Path::new(path)).unwrap().0
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

/// Renaming a headerless file re-encrypts every block for its new path IV:
/// in place, into another directory, and inside a renamed directory. A
/// partial last block and a hole survive.
#[test]
fn headerless_files_are_re_encrypted_on_rename() {
    for (label, config) in headerless_configs() {
        let block = config.block_size as u64;
        let mut vol = Volume::new(config);
        let big = pattern(3 * block as usize + 100, 1);
        let tail = pattern(50, 2);
        vol.write_file("/a", &[(0, &big)]);
        // A hole between two written blocks.
        vol.write_file("/sparse", &[(0, &tail), (3 * block, &tail)]);
        vol.mkdir("/d");
        vol.mkdir("/d/sub");
        vol.write_file("/d/sub/x", &[(0, &tail)]);
        vol.symlink("/d/sub/link", "x");

        vol.rename("/a", "/b");
        vol.rename("/b", "/d/b");
        vol.rename("/sparse", "/d/sparse");
        vol.rename("/d", "/e");
        vol.remount();

        assert_eq!(vol.read_file("/e/b"), big, "{label}");
        let mut sparse = tail.clone();
        sparse.resize(3 * block as usize, 0);
        sparse.extend_from_slice(&tail);
        assert_eq!(vol.read_file("/e/sparse"), sparse, "{label}");
        assert_eq!(vol.read_file("/e/sub/x"), tail, "{label}");
        assert_eq!(vol.readlink("/e/sub/link"), Path::new("x"), "{label}");
    }
}

/// Where attributes pass through unencrypted, a rename that copies keeps
/// them: on the file itself, and on everything in a renamed directory.
#[test]
fn renames_that_copy_keep_plain_extended_attributes() {
    let mut paranoia = EncfsConfig::test_default();
    paranoia.external_iv_chaining = true;
    let mut vol = Volume::new(paranoia);
    vol.write_file("/f", &[(0, b"f")]);
    vol.setxattr("/f", "user.color", b"blue");
    vol.mkdir("/d");
    vol.setxattr("/d", "user.color", b"red");
    vol.write_file("/d/g", &[(0, b"g")]);
    vol.setxattr("/d/g", "user.color", b"green");

    vol.rename("/f", "/f2");
    vol.rename("/d", "/d2");
    vol.remount();
    assert_eq!(vol.getxattr("/f2", "user.color"), b"blue");
    assert_eq!(vol.getxattr("/d2", "user.color"), b"red");
    assert_eq!(vol.getxattr("/d2/g", "user.color"), b"green");
}

/// Entries in a renamed directory that the volume can't decode, such as a
/// sync tool's files, are carried along rather than deleted with the
/// source.
#[test]
fn renamed_directories_keep_entries_that_dont_decode() {
    let mut vol = Volume::new(v7(|c| c.use_chained_name_iv()));
    vol.mkdir("/d");
    vol.write_file("/d/f", &[(0, b"f")]);
    let dir = vol.backing("/d");
    fs::write(dir.join(".stignore"), b"state").unwrap();
    fs::write(dir.join("not ciphertext"), b"junk").unwrap();
    fs::create_dir(dir.join("junk dir")).unwrap();
    fs::write(dir.join("junk dir").join("inner"), b"inner").unwrap();

    vol.rename("/d", "/e");
    vol.remount();
    let moved = vol.backing("/e");
    assert_eq!(fs::read(moved.join(".stignore")).unwrap(), b"state");
    assert_eq!(fs::read(moved.join("not ciphertext")).unwrap(), b"junk");
    assert_eq!(
        fs::read(moved.join("junk dir").join("inner")).unwrap(),
        b"inner"
    );
    assert_eq!(vol.read_file("/e/f"), b"f");
}

struct TakeDefaults(Vec<Result<Outcome, String>>);

impl Handler for TakeDefaults {
    fn decide(&mut self, finding: &Finding) -> anyhow::Result<Action> {
        Ok(finding.default_action())
    }
    fn outcome(&mut self, _: &Finding, _: &Action, result: &anyhow::Result<Outcome>) {
        self.0.push(match result {
            Ok(outcome) => Ok(outcome.clone()),
            Err(e) => Err(e.to_string()),
        });
    }
    fn warning(&mut self, path: &Path, error: &anyhow::Error) {
        panic!("{}: {error:#}", path.display());
    }
}

/// A conflict copy in a directory renamed through the mount moves with it
/// under a re-encrypted base, so fsck can still recover it.
#[test]
fn conflict_copies_survive_a_directory_rename() {
    let mut vol = Volume::new(v7(|c| c.use_chained_name_iv()));
    vol.mkdir("/d");
    vol.write_file("/d/f", &[(0, b"the other version")]);
    let file = vol.backing("/d/f");
    let mut name = file.file_name().unwrap().to_os_string();
    name.push(".conflict1");
    fs::copy(&file, file.with_file_name(name)).unwrap();

    vol.rename("/d", "/e");
    vol.remount();
    let cipher = cipher_for(&vol.config);
    let mut handler = TakeDefaults(Vec::new());
    let mut fsck = Fsck::new(&vol.root, &vol.config, cipher.as_ref()).allow_changes(true);
    fsck.run(&mut handler).unwrap();
    assert_eq!(fsck.stats().fixed, 1, "{:?}", handler.0);
    vol.remount();
    assert_eq!(vol.read_file("/e/f (conflict1)"), b"the other version");
}

/// A rename onto a directory that isn't empty fails, as rename(2) does,
/// and leaves both directories as they were.
#[test]
fn renaming_onto_a_non_empty_directory_changes_nothing() {
    let mut vol = Volume::new(v7(|c| c.use_chained_name_iv()));
    vol.mkdir("/d");
    vol.write_file("/d/f", &[(0, b"f")]);
    vol.mkdir("/e");
    vol.write_file("/e/g", &[(0, b"g")]);

    let parent = node(&vol.fs, &vol.root_state, Path::new("/"), &req());
    let result = vol.fs.rename(
        parent.as_node(),
        OsStr::new("d"),
        parent.as_node(),
        OsStr::new("e"),
        &req(),
    );
    assert_eq!(result.unwrap_err(), typed_fuse::Errno::ENOTEMPTY);
    vol.remount();
    assert_eq!(vol.read_file("/d/f"), b"f");
    assert_eq!(vol.read_file("/e/g"), b"g");
}
