//! Forward-mode rename where an entry's stored bytes depend on its path:
//! files without a header whose blocks are encrypted under the path IV,
//! extended attributes that pass through unencrypted, and backing entries
//! inside a renamed directory whose names don't decode. Everything is read
//! back through a fresh `EncFs`, as after a remount.
use encfs::config::{ConfigType, EncfsConfig};
use encfs::crypto::block::BlockCodec;
use encfs::crypto::file_iv::FileIv;
use encfs::fsck::{Action, Finding, Fsck, Handler, Outcome};
use std::fs;
use std::path::Path;

mod common;
use common::volume::{Volume, cipher_for, v7};

/// Headerless configs: V7 ones, whose file IV is the path IV, and V6
/// ones, whose file IV is 0 whatever the path (see
/// [`legacy_headerless_files_use_iv_zero`]).
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
        vol.write_at("/a", &[(0, &big)]);
        // A hole between two written blocks.
        vol.write_at("/sparse", &[(0, &tail), (3 * block, &tail)]);
        vol.mkdir("/d");
        vol.mkdir("/d/sub");
        vol.write_at("/d/sub/x", &[(0, &tail)]);
        vol.symlink("/d/sub/link", "x");

        vol.rename("/a", "/b").unwrap();
        vol.rename("/b", "/d/b").unwrap();
        vol.rename("/sparse", "/d/sparse").unwrap();
        vol.rename("/d", "/e").unwrap();
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

/// V4-V6 files without a header are encrypted under IV 0, as C++ EncFS
/// writes them, even where the config asks for external IV chaining, which
/// C++ applies only to headers. Such a file reads wherever it is moved.
#[test]
fn legacy_headerless_files_use_iv_zero() {
    for (label, config) in headerless_configs() {
        if config.config_type == ConfigType::V7 {
            continue;
        }
        assert!(config.external_iv_chaining, "{label}");
        let mut vol = Volume::new(config);
        vol.mkdir("/d");
        vol.write_file("/d/f", b"placeholder");

        // Store the contents as C++ EncFS would, block by block under IV 0.
        let params = vol.config.file_codec_params();
        let layout = params.layout().unwrap();
        let cipher = cipher_for(&vol.config);
        let codec = BlockCodec::new(cipher.as_ref(), layout, false, false);
        let plain = pattern(2 * layout.data_size_per_block() as usize + 10, 5);
        let mut stored = Vec::new();
        for (n, chunk) in plain
            .chunks(layout.data_size_per_block() as usize)
            .enumerate()
        {
            stored.extend(
                codec
                    .encrypt_block(n as u64, FileIv::from_u64(0), chunk)
                    .unwrap(),
            );
        }
        fs::write(vol.backing("/d/f"), &stored).unwrap();
        vol.remount();
        assert_eq!(vol.read_file("/d/f"), plain, "{label}");

        vol.rename("/d/f", "/g").unwrap();
        vol.rename("/d", "/e").unwrap();
        vol.remount();
        assert_eq!(vol.read_file("/g"), plain, "{label}");
        assert_eq!(fs::read(vol.backing("/g")).unwrap(), stored, "{label}");
    }
}

/// Where attributes pass through unencrypted, a rename that copies keeps
/// them: on the file itself, and on everything in a renamed directory.
#[test]
fn renames_that_copy_keep_plain_extended_attributes() {
    let mut paranoia = EncfsConfig::test_default();
    paranoia.external_iv_chaining = true;
    let mut vol = Volume::new(paranoia);
    vol.write_at("/f", &[(0, b"f")]);
    vol.setxattr("/f", "user.color", b"blue");
    vol.mkdir("/d");
    vol.setxattr("/d", "user.color", b"red");
    vol.write_at("/d/g", &[(0, b"g")]);
    vol.setxattr("/d/g", "user.color", b"green");

    vol.rename("/f", "/f2").unwrap();
    vol.rename("/d", "/d2").unwrap();
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
    vol.write_at("/d/f", &[(0, b"f")]);
    let dir = vol.backing("/d");
    fs::write(dir.join(".stignore"), b"state").unwrap();
    fs::write(dir.join("not ciphertext"), b"junk").unwrap();
    fs::create_dir(dir.join("junk dir")).unwrap();
    fs::write(dir.join("junk dir").join("inner"), b"inner").unwrap();

    vol.rename("/d", "/e").unwrap();
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
    vol.write_at("/d/f", &[(0, b"the other version")]);
    let file = vol.backing("/d/f");
    let mut name = file.file_name().unwrap().to_os_string();
    name.push(".conflict1");
    fs::copy(&file, file.with_file_name(name)).unwrap();

    vol.rename("/d", "/e").unwrap();
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
    vol.write_at("/d/f", &[(0, b"f")]);
    vol.mkdir("/e");
    vol.write_at("/e/g", &[(0, b"g")]);

    let result = vol.rename("/d", "/e");
    assert_eq!(result.unwrap_err(), typed_fuse::Errno::ENOTEMPTY);
    vol.remount();
    assert_eq!(vol.read_file("/d/f"), b"f");
    assert_eq!(vol.read_file("/e/g"), b"g");
}
