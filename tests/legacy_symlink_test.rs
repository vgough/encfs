//! Symlink targets on legacy (V4-V6) volumes must use the C++ EncFS encoding
//! (`DirNode::relativeCipherPath`), so links are readable by both
//! implementations. The golden values below are the output of the C++ EncFS
//! 1.9.5 sources (`NameIO::encodePath`, and `"+" + encodeName` for absolute
//! targets) for the `encfs6-std.xml` fixture (password "test").

use encfs::config::EncfsConfig;
use encfs::fs::EncFs;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use typed_fuse::{Caller, PathFilesystem, PathNodeRef};

mod common;
use common::Node;

const CPP_FOO: &str = "fLMCNPaioJgONaVVlbj3uVG4";
const CPP_DIR_FOO: &str = ",W3pS8-zxucfrK0JwBw6xBkX/POUujXpACk,r93Fj1IzawshB";
const CPP_ETC_HOSTS: &str = "+YODXynldyHaBQ1lpPE4BcFFZ";

fn caller() -> Caller {
    Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    }
}

#[test]
fn legacy_symlink_targets_match_cpp() -> anyhow::Result<()> {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let config = EncfsConfig::load(&fixtures.join("encfs6-std.xml"))?;
    let tmp = std::env::temp_dir().join(format!("encfs_legacy_symlink_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir(&tmp)?;

    let mut encfs = EncFs::new(tmp.clone(), config.get_cipher("test")?, config);
    let root = encfs.root_state();
    let r = caller();
    let parent = PathBuf::from("/");

    let cases = [
        ("l1", "foo", CPP_FOO),
        ("l2", "dir/foo", CPP_DIR_FOO),
        ("l3", "/etc/hosts", CPP_ETC_HOSTS),
    ];
    for (name, target, golden) in cases {
        let created = encfs
            .symlink(
                PathNodeRef::new(Some(&parent), &root),
                OsStr::new(name),
                Path::new(target),
                &r,
            )
            .map_err(|e| anyhow::anyhow!("symlink failed: {e:?}"))?;

        let (real, _) = encfs
            .encrypt_path(&parent.join(name))
            .map_err(|e| anyhow::anyhow!("encrypt_path failed: {e}"))?;
        assert_eq!(fs::read_link(&real)?, Path::new(golden), "{target}");

        let node = Node::at(parent.join(name), created.state);
        let read = encfs
            .readlink(node.as_node(), &r)
            .map_err(|e| anyhow::anyhow!("readlink failed: {e:?}"))?;
        assert_eq!(read, Path::new(target), "{target}");
    }

    fs::remove_dir_all(&tmp)?;
    Ok(())
}
