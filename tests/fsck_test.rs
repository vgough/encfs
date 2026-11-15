//! `encfsctl fsck` (ADR 0007): conflict copies planted in the ciphertext tree
//! the way sync tools make them are classified, recovered under ordinary
//! names, and read back through a fresh `EncFs`.
use anyhow::Result;
use encfs::config::{EncfsConfig, Interface};
use encfs::diriv;
use encfs::fsck::{
    Action, Candidate, Class, Confidence, ConfigCopyStatus, Finding, Fsck, Handler, Outcome,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

mod common;
use common::volume::{Volume, cipher_for, req, v7};

const SYNCTHING: &str = ".sync-conflict-20230709-123456-ABCDEFG";
const NEXTCLOUD: &str = " (conflicted copy 2023-07-09 123456)";
const BISYNC: &str = ".conflict1";

fn stream_iface() -> Interface {
    Interface {
        name: "nameio/stream".to_string(),
        major: 2,
        minor: 1,
        age: 0,
    }
}

fn config_named(label: &str) -> EncfsConfig {
    configs().into_iter().find(|(l, ..)| *l == label).unwrap().1
}

/// Each config, and whether a file's contents bind it to its name there.
fn configs() -> Vec<(&'static str, EncfsConfig, bool)> {
    vec![
        ("v7-diriv", v7(|_| {}), true),
        ("v7-chained", v7(|c| c.use_chained_name_iv()), true),
        (
            "v7-chained-stream",
            v7(|c| {
                c.use_chained_name_iv();
                c.name_iface = stream_iface();
            }),
            true,
        ),
        (
            "v7-headerless",
            v7(|c| {
                c.use_chained_name_iv();
                c.unique_iv = false;
            }),
            true,
        ),
        (
            "v7-diriv-unchained-files",
            v7(|c| c.external_iv_chaining = false),
            false,
        ),
        (
            // The README's settings for syncing a mounted tree.
            "v7-no-chained-iv",
            v7(|c| {
                c.directory_iv = false;
                c.chained_name_iv = false;
                c.external_iv_chaining = false;
            }),
            false,
        ),
        ("v6-standard", EncfsConfig::test_default(), false),
        (
            "v6-paranoia",
            {
                let mut c = EncfsConfig::test_default();
                c.external_iv_chaining = true;
                c
            },
            true,
        ),
    ]
}

/// What these tests add to a [`Volume`].
trait FsckVolume {
    fn conflict_copy(&self, path: &str, suffix: &str) -> PathBuf;
    fn fsck(&self, modify: bool) -> (Recorder, encfs::fsck::Stats);
}

impl FsckVolume for Volume {
    /// Copies the backing entry of `path` to its ciphertext name plus
    /// `suffix`, byte for byte, as a sync tool keeping both versions does.
    fn conflict_copy(&self, path: &str, suffix: &str) -> PathBuf {
        let src = self.backing(path);
        let mut name = src.file_name().unwrap().to_os_string();
        name.push(suffix);
        let dst = src.with_file_name(name);
        copy_tree(&self.config, &src, &dst);
        dst
    }

    fn fsck(&self, modify: bool) -> (Recorder, encfs::fsck::Stats) {
        let cipher = cipher_for(&self.config);
        let mut recorder = Recorder::new(if modify { Mode::Yes } else { Mode::Report });
        let mut fsck = Fsck::new(&self.root, &self.config, cipher.as_ref()).allow_changes(modify);
        fsck.run(&mut recorder).unwrap();
        let stats = fsck.stats().clone();
        (recorder, stats)
    }
}

/// A byte-for-byte copy of a backing entry, stored attributes and
/// timestamps included.
fn copy_tree(config: &EncfsConfig, src: &Path, dst: &Path) {
    let meta = fs::symlink_metadata(src).unwrap();
    if meta.is_symlink() {
        std::os::unix::fs::symlink(fs::read_link(src).unwrap(), dst).unwrap();
    } else if meta.is_dir() {
        fs::create_dir(dst).unwrap();
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            copy_tree(config, &entry.path(), &dst.join(entry.file_name()));
        }
    } else {
        let output = encfs::recrypt::create_file(dst).unwrap();
        std::io::copy(&mut fs::File::open(src).unwrap(), &mut &output).unwrap();
    }
    encfs::recrypt::copy_metadata(config, src, dst, &meta).unwrap();
}

enum Mode {
    Report,
    Yes,
}

/// A handler that takes each finding's default (or skips, reporting only)
/// and records what happened.
struct Recorder {
    mode: Mode,
    findings: Vec<Finding>,
    outcomes: Vec<(OsString, Action, Result<Outcome, String>)>,
    warnings: Vec<String>,
}

impl Recorder {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            findings: Vec::new(),
            outcomes: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn finding(&self, name: &OsStr) -> &Finding {
        self.findings
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no finding for {name:?} in {:#?}", self.findings))
    }

    fn candidates(&self, name: &OsStr) -> &[Candidate] {
        match &self.finding(name).class {
            Class::ConflictCopy { candidates } => candidates,
            other => panic!("{name:?} is {other:?}, not a conflict copy"),
        }
    }
}

impl Handler for Recorder {
    fn decide(&mut self, finding: &Finding) -> Result<Action> {
        self.findings.push(finding.clone());
        Ok(match self.mode {
            Mode::Report => Action::Skip,
            Mode::Yes => finding.default_action(),
        })
    }

    fn outcome(&mut self, finding: &Finding, action: &Action, result: &Result<Outcome>) {
        self.outcomes.push((
            finding.name.clone(),
            action.clone(),
            match result {
                Ok(outcome) => Ok(outcome.clone()),
                Err(e) => Err(format!("{e:#}")),
            },
        ));
    }

    fn warning(&mut self, path: &Path, error: &anyhow::Error) {
        self.warnings.push(format!("{}: {error:#}", path.display()));
    }
}

fn names(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// Every file under `dir` with its bytes, and every symlink with its target.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            let data = if meta.is_dir() {
                stack.push(path.clone());
                Vec::new()
            } else if meta.is_symlink() {
                fs::read_link(&path)
                    .unwrap()
                    .as_os_str()
                    .as_bytes()
                    .to_vec()
            } else {
                fs::read(&path).unwrap()
            };
            out.insert(
                path.strip_prefix(dir).unwrap().to_path_buf(),
                (meta.mode(), data),
            );
        }
    }
    out
}

/// A populated `/dir` with a conflict copy of each kind of entry.
fn plant_conflicts(vol: &Volume) -> [PathBuf; 3] {
    vol.mkdir("/dir");
    vol.write_file("/dir/report.docx", b"version from this machine");
    vol.write_file("/dir/other", &vec![7u8; 10_000]);
    vol.mkdir("/dir/sub");
    vol.write_file("/dir/sub/inner.txt", b"inner contents");
    vol.mkdir("/dir/sub/deep");
    vol.write_file("/dir/sub/deep/leaf", b"leaf contents");
    vol.symlink("/dir/sub/deep/up", "../inner.txt");
    vol.symlink("/dir/link", "sub/inner.txt");
    [
        vol.conflict_copy("/dir/report.docx", SYNCTHING),
        vol.conflict_copy("/dir/sub", NEXTCLOUD),
        vol.conflict_copy("/dir/link", BISYNC),
    ]
}

#[test]
fn conflict_copies_are_recovered_in_every_config() {
    for (label, config, files_bound) in configs() {
        let mut vol = Volume::new(config.clone());
        let [file_copy, dir_copy, link_copy] = plant_conflicts(&vol);
        let mtime = fs::symlink_metadata(&file_copy).unwrap().mtime();

        let (recorder, stats) = vol.fsck(true);
        assert!(
            recorder.warnings.is_empty(),
            "{label}: {:?}",
            recorder.warnings
        );

        let file = &recorder.candidates(file_copy.file_name().unwrap())[0];
        assert_eq!(file.plain, b"report.docx", "{label}");
        assert_eq!(file.suffix, SYNCTHING, "{label}");
        let expected = if files_bound {
            Confidence::Verified
        } else {
            Confidence::Probable
        };
        assert_eq!(file.confidence, expected, "{label}: file");

        let dir = &recorder.candidates(dir_copy.file_name().unwrap())[0];
        let dirs_bound = config.chained_name_iv && !config.directory_iv;
        let expected = if dirs_bound {
            Confidence::Verified
        } else {
            Confidence::Probable
        };
        assert_eq!(dir.confidence, expected, "{label}: dir");

        let link = &recorder.candidates(link_copy.file_name().unwrap())[0];
        let expected = if config.symlink_target_depends_on_path() {
            Confidence::Verified
        } else {
            Confidence::Probable
        };
        assert_eq!(link.confidence, expected, "{label}: symlink");

        for (name, action, result) in &recorder.outcomes {
            assert!(result.is_ok(), "{label}: {name:?} {action:?}: {result:?}");
        }
        assert_eq!(stats.fixed, 3, "{label}");
        assert_eq!(stats.unresolved(), 0, "{label}");

        vol.remount();
        assert_eq!(
            vol.list("/dir"),
            names(&[
                "report.docx",
                "report (sync-conflict-20230709-123456-ABCDEFG).docx",
                "other",
                "sub",
                "sub (conflicted copy 2023-07-09 123456)",
                "link",
                "link (conflict1)",
            ]),
            "{label}"
        );
        assert_eq!(
            vol.read_file("/dir/report (sync-conflict-20230709-123456-ABCDEFG).docx"),
            b"version from this machine",
            "{label}"
        );
        let recovered_dir = "/dir/sub (conflicted copy 2023-07-09 123456)";
        assert_eq!(
            vol.read_file(&format!("{recovered_dir}/inner.txt")),
            b"inner contents",
            "{label}"
        );
        assert_eq!(
            vol.read_file(&format!("{recovered_dir}/deep/leaf")),
            b"leaf contents",
            "{label}"
        );
        assert_eq!(
            vol.readlink(&format!("{recovered_dir}/deep/up")),
            Path::new("../inner.txt"),
            "{label}"
        );
        assert_eq!(
            vol.readlink("/dir/link (conflict1)"),
            Path::new("sub/inner.txt"),
            "{label}"
        );

        let recovered = vol.backing("/dir/report (sync-conflict-20230709-123456-ABCDEFG).docx");
        let meta = fs::symlink_metadata(&recovered).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o640, "{label}");
        assert_eq!(meta.mtime(), mtime, "{label}");

        // Nothing is left for a second run.
        let (again, stats) = vol.fsck(true);
        assert!(again.findings.is_empty(), "{label}: {:#?}", again.findings);
        assert_eq!(stats.problems, 0, "{label}");
    }
}

#[test]
fn recovery_keeps_extended_attributes() {
    let mut vol = Volume::new(v7(|_| {}));
    vol.mkdir("/dir");
    vol.write_file("/dir/doc", b"text");
    vol.setxattr("/dir/doc", "user.color", b"blue");
    vol.conflict_copy("/dir/doc", BISYNC);

    let (_, stats) = vol.fsck(true);
    assert_eq!(stats.fixed, 1);
    vol.remount();
    assert_eq!(vol.read_file("/dir/doc (conflict1)"), b"text");
    assert_eq!(vol.getxattr("/dir/doc (conflict1)", "user.color"), b"blue");
}

/// A copy whose name has a decodable prefix but whose contents belong to
/// another file: rejected where contents are bound to names, probable (and
/// recovered by `--yes` only beside an existing sibling) where they aren't.
#[test]
fn contents_from_another_file_are_not_recovered_where_bound() {
    for (label, config, files_bound) in configs() {
        let vol = Volume::new(config);
        vol.write_file("/a", b"contents of a");
        vol.write_file("/b", b"contents of b");
        let base = vol.backing("/b");
        let mut name = base.file_name().unwrap().to_os_string();
        name.push(BISYNC);
        fs::copy(vol.backing("/a"), base.with_file_name(&name)).unwrap();

        let (recorder, _) = vol.fsck(false);
        let finding = recorder.finding(&name);
        if files_bound {
            assert!(
                matches!(finding.class, Class::Unknown),
                "{label}: {finding:?}"
            );
            assert_eq!(finding.default_action(), Action::Skip, "{label}");
        } else {
            let candidates = recorder.candidates(&name);
            assert_eq!(candidates[0].plain, b"b", "{label}");
            assert_eq!(candidates[0].confidence, Confidence::Probable, "{label}");
        }
    }
}

/// A bound file's base is verified by its first block alone: damage further
/// on doesn't rule the base out, since the rest isn't read.
#[test]
fn only_the_first_block_is_verified() {
    use std::os::unix::fs::FileExt;
    for (label, config, files_bound) in configs() {
        if !files_bound {
            continue;
        }
        let block_size = config.block_size as usize;
        let vol = Volume::new(config);
        vol.write_file("/big", &vec![7u8; 3 * block_size]);
        let copy = vol.conflict_copy("/big", BISYNC);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&copy)
            .unwrap();
        let last = file.metadata().unwrap().len() - 1;
        let mut byte = [0u8];
        file.read_exact_at(&mut byte, last).unwrap();
        file.write_at(&[byte[0] ^ 0xff], last).unwrap();

        let (recorder, _) = vol.fsck(false);
        let candidates = recorder.candidates(copy.file_name().unwrap());
        assert_eq!(candidates[0].plain, b"big", "{label}");
        assert_eq!(candidates[0].confidence, Confidence::Verified, "{label}");
    }
}

/// Without a sibling to be a copy of, an unbound candidate is only offered.
#[test]
fn probable_copies_without_a_sibling_are_not_recovered_by_default() {
    let config = config_named("v7-no-chained-iv");
    let vol = Volume::new(config);
    vol.write_file("/gone", b"data");
    let copy = vol.conflict_copy("/gone", SYNCTHING);
    fs::remove_file(vol.backing("/gone")).unwrap();

    let (recorder, _) = vol.fsck(false);
    let candidates = recorder.candidates(copy.file_name().unwrap());
    assert!(!candidates[0].sibling_exists);
    assert_eq!(
        recorder.finding(copy.file_name().unwrap()).default_action(),
        Action::Skip
    );
}

#[test]
fn report_only_changes_nothing() {
    let vol = Volume::new(v7(|c| c.use_chained_name_iv()));
    plant_conflicts(&vol);
    fs::write(vol.root.join("junk!"), b"junk").unwrap();
    let before = snapshot(&vol.root);

    let (recorder, stats) = vol.fsck(false);
    assert_eq!(stats.problems, 4);
    assert_eq!(stats.unresolved(), 4);
    assert!(recorder.outcomes.is_empty());
    assert_eq!(snapshot(&vol.root), before);

    // A report-only check refuses to apply anything, whatever it is asked.
    let cipher = cipher_for(&vol.config);
    let mut fsck = Fsck::new(&vol.root, &vol.config, cipher.as_ref());
    let finding = &recorder.findings[0];
    assert!(fsck.apply(finding, &finding.default_action()).is_err());
    assert_eq!(snapshot(&vol.root), before);
}

#[test]
fn yes_deletes_only_stale_temps_and_never_unknown_entries() {
    let vol = Volume::new(v7(|_| {}));
    vol.write_file("/file", b"data");
    let file = vol.backing("/file");
    let enc = file.file_name().unwrap().to_str().unwrap().to_string();

    let junk = vol.root.join("not ciphertext!");
    fs::write(&junk, b"junk").unwrap();
    fs::create_dir(vol.root.join("junk dir")).unwrap();
    let young = vol.root.join(format!(".syncthing.{enc}.tmp"));
    fs::write(&young, b"partial").unwrap();
    let old = vol.root.join(format!(".{enc}.~1a2b3c"));
    fs::write(&old, b"partial").unwrap();
    let two_days_ago = SystemTime::now() - Duration::from_secs(48 * 3600);
    typed_fuse::passthrough::utimens_path(&old, Some(two_days_ago), Some(two_days_ago)).unwrap();
    let ours = vol.root.join(".encfs.fsck-0011223344556677");
    fs::write(&ours, b"leftover").unwrap();
    let state = vol.root.join(".stfolder");
    fs::create_dir(&state).unwrap();
    let marker = vol.root.join("RCLONE_TEST");
    fs::write(&marker, b"").unwrap();
    let dotfile = vol.root.join(".DS_Store");
    fs::write(&dotfile, b"").unwrap();

    let (recorder, stats) = vol.fsck(true);
    assert!(matches!(
        recorder.finding(state.file_name().unwrap()).class,
        Class::ToolState
    ));
    assert!(matches!(
        recorder.finding(young.file_name().unwrap()).class,
        Class::Temp { stale: false, .. }
    ));
    assert!(
        !recorder
            .findings
            .iter()
            .any(|f| f.name == dotfile.file_name().unwrap()),
        "other dot names are passed over"
    );
    assert!(junk.exists() && vol.root.join("junk dir").exists());
    assert!(young.exists() && state.exists() && marker.exists());
    assert!(!old.exists() && !ours.exists());
    assert!(file.exists());
    assert_eq!(stats.fixed, 2);
    // The junk and the young temp remain.
    assert_eq!(stats.unresolved(), 3);
}

#[test]
fn bases_that_are_not_single_components_are_never_used() {
    let vol = Volume::new(v7(|c| c.use_chained_name_iv()));
    let cipher = cipher_for(&vol.config);
    for plain in [&b".."[..], b"/x", b"a/b"] {
        let (encrypted, _) = cipher.encrypt_filename(plain, 0).unwrap();
        fs::write(vol.root.join(format!("{encrypted}{BISYNC}")), b"x").unwrap();
    }
    let (recorder, _) = vol.fsck(true);
    assert_eq!(recorder.findings.len(), 3);
    for finding in &recorder.findings {
        assert!(matches!(finding.class, Class::Unknown), "{finding:?}");
    }
    assert!(recorder.outcomes.is_empty());
}

#[test]
fn recovered_names_avoid_collisions() {
    let mut vol = Volume::new(v7(|_| {}));
    vol.write_file("/notes.txt", b"one");
    vol.write_file("/notes (conflict1).txt", b"taken");
    vol.conflict_copy("/notes.txt", BISYNC);

    vol.fsck(true);
    vol.remount();
    assert_eq!(vol.read_file("/notes (conflict1) 2.txt"), b"one");
    assert_eq!(vol.read_file("/notes (conflict1).txt"), b"taken");
}

/// Two machines created the same directory, each with its own sidecar. The
/// names written under the losing sidecar are renamed under the live one,
/// and the copy is removed once nothing depends on it.
#[test]
fn entries_under_a_conflicting_sidecar_are_rehomed() {
    let mut vol = Volume::new(v7(|_| {}));
    vol.mkdir("/d");
    vol.write_file("/d/a", b"a from here");
    // The other machine's `/d`, with its own sidecar.
    vol.mkdir("/e");
    vol.write_file("/e/a", b"a from there");
    vol.write_file("/e/b", b"b from there");

    let dir = vol.backing("/d");
    let other = vol.backing("/e");
    for path in ["/e/a", "/e/b"] {
        let entry = vol.backing(path);
        fs::rename(&entry, dir.join(entry.file_name().unwrap())).unwrap();
    }
    let copy = dir.join(format!(".encfs{SYNCTHING}.diriv"));
    fs::copy(diriv::sidecar_path(&other), &copy).unwrap();
    let identical = dir.join(".encfs.diriv.conflict1");
    fs::copy(diriv::sidecar_path(&dir), &identical).unwrap();
    vol.remount();
    assert_eq!(vol.list("/d"), names(&["a"]));

    let (recorder, stats) = vol.fsck(true);
    assert!(matches!(
        recorder.finding(copy.file_name().unwrap()).class,
        Class::SidecarCopy {
            identical: false,
            dependents: 0,
            ..
        }
    ));
    assert_eq!(stats.unresolved(), 0, "{:#?}", recorder.outcomes);
    assert!(!copy.exists() && !identical.exists());

    vol.remount();
    assert_eq!(
        vol.list("/d"),
        names(&["a", "b", "a (sync-conflict-20230709-123456-ABCDEFG)"])
    );
    assert_eq!(vol.read_file("/d/a"), b"a from here");
    assert_eq!(vol.read_file("/d/b"), b"b from there");
    assert_eq!(
        vol.read_file("/d/a (sync-conflict-20230709-123456-ABCDEFG)"),
        b"a from there"
    );
}

/// While entries still depend on a differing sidecar copy, it isn't
/// offered for deletion.
#[test]
fn a_sidecar_copy_with_dependents_is_kept() {
    let vol = Volume::new(v7(|_| {}));
    vol.mkdir("/d");
    vol.mkdir("/e");
    vol.write_file("/e/b", b"b from there");
    let dir = vol.backing("/d");
    let entry = vol.backing("/e/b");
    fs::rename(&entry, dir.join(entry.file_name().unwrap())).unwrap();
    let copy = dir.join(".encfs.diriv (conflicted copy 2023-07-09 123456)");
    fs::copy(diriv::sidecar_path(&vol.backing("/e")), &copy).unwrap();

    let (recorder, _) = vol.fsck(false);
    let finding = recorder.finding(copy.file_name().unwrap());
    assert!(matches!(
        finding.class,
        Class::SidecarCopy { dependents: 1, .. }
    ));
    assert!(!finding.choices().delete);
}

fn cheap_v7(volume_key: u8) -> EncfsConfig {
    let mut config = v7(|_| {});
    config.argon2_memory_cost = Some(8);
    config.argon2_time_cost = Some(1);
    config.argon2_parallelism = Some(1);
    config.set_v7_key("password", &[volume_key; 48]).unwrap();
    config
}

#[test]
fn config_copies_are_deleted_only_when_equivalent() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    diriv::ensure_root(root, true).unwrap();
    let config = cheap_v7(1);
    config.save(&root.join(".encfs7")).unwrap();
    let duplicate = root.join(".encfs7 (conflicted copy 2023-07-09 123456)");
    fs::copy(root.join(".encfs7"), &duplicate).unwrap();
    let other_key = root.join(format!("{SYNCTHING}.encfs7"));
    cheap_v7(2).save(&other_key).unwrap();
    let wrong_password = root.join(".encfs7.conflict1");
    let mut changed = cheap_v7(1);
    changed.set_v7_key("another password", &[1; 48]).unwrap();
    changed.save(&wrong_password).unwrap();

    let loaded = EncfsConfig::load(&root.join(".encfs7")).unwrap();
    let cipher = loaded.get_cipher("password").unwrap();
    let mut recorder = Recorder::new(Mode::Yes);
    let mut fsck = Fsck::new(root, &loaded, cipher.as_ref())
        .allow_changes(true)
        .with_password("password");
    fsck.run(&mut recorder).unwrap();

    let status = |path: &Path| match &recorder.finding(path.file_name().unwrap()).class {
        Class::ConfigCopy { status, .. } => status.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(status(&duplicate), ConfigCopyStatus::Equivalent);
    assert_eq!(status(&other_key), ConfigCopyStatus::Different);
    assert!(matches!(
        status(&wrong_password),
        ConfigCopyStatus::Unreadable(_)
    ));
    assert!(!duplicate.exists());
    assert!(other_key.exists() && wrong_password.exists());
    assert!(root.join(".encfs7").exists());
}

/// A suffix that continues inside the name alphabet has no first split to
/// find, so only the shorter-prefix search finds the base.
#[test]
fn suffixes_inside_the_name_alphabet_are_found() {
    for (label, suffix, bound) in [
        ("v7-chained-stream", "-DEVICE", true),
        ("v7-chained", "COPY2", true),
        ("v6-standard", "-DEVICE", false),
    ] {
        let config = config_named(label);
        let mut vol = Volume::new(config);
        vol.write_file("/notes.txt", b"the other version");
        let copy = vol.conflict_copy("/notes.txt", suffix);

        let (recorder, _) = vol.fsck(true);
        let finding = recorder.finding(copy.file_name().unwrap());
        let Class::ConflictCopy { candidates } = &finding.class else {
            panic!("{label}: {finding:?}");
        };
        let found = candidates
            .iter()
            .find(|c| c.plain == b"notes.txt")
            .unwrap_or_else(|| panic!("{label}: {candidates:?}"));
        assert!(!found.first_split, "{label}");
        assert_eq!(found.suffix, suffix, "{label}");
        if bound {
            assert_eq!(found.confidence, Confidence::Verified, "{label}");
            vol.remount();
            assert_eq!(
                vol.read_file(&format!("/notes ({suffix}).txt")),
                b"the other version",
                "{label}"
            );
        } else {
            assert_eq!(found.confidence, Confidence::Probable, "{label}");
            assert_eq!(finding.default_action(), Action::Skip, "{label}");
            assert!(copy.exists(), "{label}");
        }
    }
}

/// PR #724's case, offline: a reverse view's remote holds a bisync
/// `.conflict2` copy. fsck on a mirror of the remote, given the reverse
/// config, recovers it under an ordinary name, and writing that entry back
/// through a writable reverse view (as `rclone --inplace` would) creates the
/// plaintext file in the source.
#[test]
fn a_conflict_copy_on_a_reverse_mirror_restores_through_the_view() {
    use encfs::reverse_fs::{ReverseFs, ReverseFsOptions};
    use typed_fuse::PathNodeFs;
    use typed_fuse_core::{LookupReply, Runtime};

    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let mirror = temp.path().join("mirror");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&mirror).unwrap();

    // `encfsctl new --no-unique-iv`: chained names, headerless files.
    let mut config = cheap_v7(5);
    config.use_chained_name_iv();
    config.unique_iv = false;
    config.wide_file_iv = false;
    config.minimum_reader_version = config.required_v7_reader_version();
    config.set_v7_key("password", &[5; 48]).unwrap();
    let config_path = source.join(".encfs7");
    config.save(&config_path).unwrap();
    let config = EncfsConfig::load(&config_path).unwrap();

    let caller = req();
    let view = || {
        Runtime::new(PathNodeFs::new(ReverseFs::new(
            source.clone(),
            config.get_cipher("password").unwrap(),
            config.clone(),
            fs::read(&config_path).unwrap(),
            fs::metadata(&config_path).unwrap(),
            ReverseFsOptions { writable: true },
        )))
    };
    let cipher = config.get_cipher("password").unwrap();
    let (name, _) = cipher.encrypt_filename(b"report.txt", 0).unwrap();
    let read_view = |runtime: &Runtime<_>| -> Vec<u8> {
        let LookupReply::Found(entry) = runtime.lookup(1, OsStr::new(&name), &caller).unwrap()
        else {
            panic!("report.txt is missing from the view");
        };
        let open = runtime.open(entry.ino, libc::O_RDONLY, &caller).unwrap();
        let data = runtime.read(entry.ino, open.fh, 0, 1 << 20, &caller, |r| {
            r.unwrap().into_owned()
        });
        runtime.release(entry.ino, open.fh, &caller).unwrap();
        data
    };

    // The remote has this machine's version, and the other machine's as
    // bisync's Path2 conflict copy.
    fs::write(source.join("report.txt"), b"version from here").unwrap();
    fs::write(mirror.join(&name), read_view(&view())).unwrap();
    fs::write(source.join("report.txt"), b"version from the other machine").unwrap();
    let copy = mirror.join(format!("{name}.conflict2"));
    fs::write(&copy, read_view(&view())).unwrap();
    fs::write(source.join("report.txt"), b"version from here").unwrap();

    let mut recorder = Recorder::new(Mode::Yes);
    let mut fsck = Fsck::new(&mirror, &config, cipher.as_ref()).allow_changes(true);
    fsck.run(&mut recorder).unwrap();
    assert_eq!(
        recorder.candidates(copy.file_name().unwrap())[0].confidence,
        Confidence::Verified
    );
    assert_eq!(fsck.stats().fixed, 1, "{:#?}", recorder.outcomes);

    // Sync the recovered entry down through the view.
    let (recovered, _) = cipher
        .encrypt_filename(b"report (conflict2).txt", 0)
        .unwrap();
    let ciphertext = fs::read(mirror.join(&recovered)).unwrap();
    let runtime = view();
    let (entry, open) = runtime
        .create(
            1,
            OsStr::new(&recovered),
            0o644,
            0,
            libc::O_RDWR | libc::O_CREAT,
            &caller,
        )
        .unwrap();
    assert_eq!(
        runtime
            .write(entry.ino, open.fh, &ciphertext, 0, &caller)
            .unwrap(),
        ciphertext.len()
    );
    runtime.flush(entry.ino, open.fh, &caller).unwrap();
    runtime.release(entry.ino, open.fh, &caller).unwrap();

    assert_eq!(
        fs::read(source.join("report (conflict2).txt")).unwrap(),
        b"version from the other machine"
    );
    assert_eq!(
        fs::read(source.join("report.txt")).unwrap(),
        b"version from here"
    );
}

fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// The config in use, kept in the root under a name of its own, is never
/// taken for a sync tool's copy of itself, while a real copy still is.
#[test]
fn the_config_in_use_is_never_touched_whatever_its_name() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    diriv::ensure_root(root, true).unwrap();
    let config_path = root.join("vol.encfs7");
    cheap_v7(1).save(&config_path).unwrap();
    let duplicate = root.join(format!("{SYNCTHING}.encfs7"));
    fs::copy(&config_path, &duplicate).unwrap();

    let loaded = EncfsConfig::load(&config_path).unwrap();
    let cipher = loaded.get_cipher("password").unwrap();
    let mut recorder = Recorder::new(Mode::Yes);
    let mut fsck = Fsck::new(root, &loaded, cipher.as_ref())
        .allow_changes(true)
        .with_password("password")
        .with_config_file(&config_path);
    fsck.run(&mut recorder).unwrap();

    assert!(
        !recorder
            .findings
            .iter()
            .any(|f| f.name == config_path.file_name().unwrap()),
        "{:#?}",
        recorder.findings
    );
    assert!(config_path.exists());
    assert!(!duplicate.exists(), "{:#?}", recorder.outcomes);
}

/// Where attributes pass through to the backing files unencrypted (V4-V6,
/// or V7 with plaintext attributes), recovery by copy keeps them.
#[test]
fn recovery_keeps_plain_extended_attributes() {
    for label in ["v6-paranoia", "v6-standard"] {
        let mut vol = Volume::new(config_named(label));
        vol.mkdir("/dir");
        vol.write_file("/dir/doc", b"text");
        vol.setxattr("/dir/doc", "user.color", b"blue");
        vol.mkdir("/tree");
        vol.write_file("/tree/leaf", b"leaf");
        vol.setxattr("/tree/leaf", "user.color", b"green");
        vol.setxattr("/tree", "user.color", b"red");
        vol.conflict_copy("/dir/doc", BISYNC);
        vol.conflict_copy("/tree", BISYNC);

        let (recorder, stats) = vol.fsck(true);
        assert_eq!(stats.fixed, 2, "{label}: {:#?}", recorder.outcomes);
        vol.remount();
        assert_eq!(vol.read_file("/dir/doc (conflict1)"), b"text", "{label}");
        assert_eq!(
            vol.getxattr("/dir/doc (conflict1)", "user.color"),
            b"blue",
            "{label}"
        );
        assert_eq!(vol.getxattr("/tree (conflict1)", "user.color"), b"red");
        assert_eq!(
            vol.getxattr("/tree (conflict1)/leaf", "user.color"),
            b"green",
            "{label}"
        );
    }
}

/// A handler that fails, as the interactive one does when a prompt can't
/// be answered.
struct Failing {
    decided: usize,
    warnings: usize,
}

impl Handler for Failing {
    fn decide(&mut self, _finding: &Finding) -> Result<Action> {
        self.decided += 1;
        anyhow::bail!("no answer")
    }
    fn outcome(&mut self, _: &Finding, _: &Action, _: &Result<Outcome>) {}
    fn warning(&mut self, _: &Path, _: &anyhow::Error) {
        self.warnings += 1;
    }
}

/// A handler's error ends the run where it happened; it isn't taken for a
/// directory that couldn't be read, skipping the rest of that directory
/// while the check goes on elsewhere.
#[test]
fn a_handler_error_ends_the_run() {
    let vol = Volume::new(v7(|_| {}));
    for dir in ["/a", "/b"] {
        vol.mkdir(dir);
        vol.write_file(&format!("{dir}/f"), b"data");
        vol.conflict_copy(&format!("{dir}/f"), BISYNC);
    }
    let cipher = cipher_for(&vol.config);
    let mut handler = Failing {
        decided: 0,
        warnings: 0,
    };
    let mut fsck = Fsck::new(&vol.root, &vol.config, cipher.as_ref()).allow_changes(true);
    assert!(fsck.run(&mut handler).is_err());
    assert_eq!(handler.decided, 1);
    assert_eq!(handler.warnings, 0);
}

/// A conflict copy that can't be read is still offered for recovery: its
/// base is merely unconfirmed, and the read error is reported.
#[test]
fn an_unreadable_conflict_copy_keeps_its_candidates() {
    if running_as_root() {
        return;
    }
    let vol = Volume::new(v7(|_| {}));
    vol.write_file("/doc", b"text");
    let copy = vol.conflict_copy("/doc", BISYNC);
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o000)).unwrap();

    let (recorder, stats) = vol.fsck(false);
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o644)).unwrap();
    let candidates = recorder.candidates(copy.file_name().unwrap());
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert_eq!(candidates[0].plain, b"doc");
    assert_eq!(candidates[0].confidence, Confidence::Probable);
    assert!(
        recorder
            .finding(copy.file_name().unwrap())
            .choices()
            .recover,
        "recovery stays on offer"
    );
    assert_eq!(recorder.warnings.len(), 1, "{:?}", recorder.warnings);
    assert_eq!(stats.errors, 1);
}

/// A recovered directory whose children's names depend on its own keeps
/// the conflict copies inside it recoverable: their bases are re-encrypted
/// with the directory, and fsck then recovers them in the new directory.
#[test]
fn conflict_copies_inside_a_recovered_directory_stay_recoverable() {
    for label in ["v7-chained", "v7-headerless", "v6-paranoia"] {
        let mut vol = Volume::new(config_named(label));
        vol.mkdir("/d");
        vol.write_file("/d/f", b"this machine's f");
        vol.mkdir("/d/sub");
        vol.write_file("/d/sub/g", b"g");
        vol.conflict_copy("/d/f", BISYNC);
        vol.conflict_copy("/d/sub", BISYNC);
        vol.conflict_copy("/d", SYNCTHING);

        let (recorder, stats) = vol.fsck(true);
        assert_eq!(stats.unresolved(), 0, "{label}: {:#?}", recorder.outcomes);
        assert!(
            recorder.warnings.is_empty(),
            "{label}: {:?}",
            recorder.warnings
        );
        vol.remount();
        let copy = "/d (sync-conflict-20230709-123456-ABCDEFG)";
        assert_eq!(
            vol.list(copy),
            names(&["f", "f (conflict1)", "sub", "sub (conflict1)"]),
            "{label}"
        );
        assert_eq!(
            vol.read_file(&format!("{copy}/f (conflict1)")),
            b"this machine's f",
            "{label}"
        );
        assert_eq!(
            vol.read_file(&format!("{copy}/sub (conflict1)/g")),
            b"g",
            "{label}"
        );
        assert_eq!(vol.read_file("/d/f (conflict1)"), b"this machine's f");
    }
}

/// The other machine's directory had its own sidecar, and its sync tool
/// left a conflict copy of one of its entries. That copy's base decodes
/// only under the sidecar copy, which is kept until the copy is recovered.
#[test]
fn conflict_copies_made_under_a_sidecar_copy_keep_it() {
    for modify in [false, true] {
        let mut vol = Volume::new(v7(|_| {}));
        vol.mkdir("/d");
        vol.mkdir("/e");
        vol.write_file("/e/b", b"b from there");
        let dir = vol.backing("/d");
        let other = vol.backing("/e");
        let conflict = vol.conflict_copy("/e/b", SYNCTHING);
        for entry in [vol.backing("/e/b"), conflict.clone()] {
            fs::rename(&entry, dir.join(entry.file_name().unwrap())).unwrap();
        }
        let sidecar_copy = dir.join(".encfs.diriv (conflicted copy 2023-07-09 123456)");
        fs::copy(diriv::sidecar_path(&other), &sidecar_copy).unwrap();

        let (recorder, stats) = vol.fsck(modify);
        let candidates = recorder.candidates(conflict.file_name().unwrap());
        assert_eq!(candidates[0].plain, b"b");
        assert_eq!(candidates[0].confidence, Confidence::Verified);
        assert_eq!(candidates[0].sidecar.as_deref(), sidecar_copy.file_name());
        if !modify {
            assert!(matches!(
                recorder.finding(sidecar_copy.file_name().unwrap()).class,
                Class::SidecarCopy { dependents: 2, .. }
            ));
            continue;
        }
        assert_eq!(stats.unresolved(), 0, "{:#?}", recorder.outcomes);
        assert!(!sidecar_copy.exists());
        vol.remount();
        assert_eq!(
            vol.list("/d"),
            names(&["b", "b (sync-conflict-20230709-123456-ABCDEFG)"])
        );
        assert_eq!(
            vol.read_file("/d/b (sync-conflict-20230709-123456-ABCDEFG)"),
            b"b from there"
        );
    }
}

/// Once the re-encrypted copy is in place the recovery has succeeded, even
/// if the original can't be removed: it is left under a temp name, which the
/// next run deletes rather than recovering the entry a second time.
#[test]
fn a_source_that_cannot_be_removed_is_left_as_a_stale_temp() {
    if running_as_root() {
        return;
    }
    let mut vol = Volume::new(config_named("v7-chained"));
    vol.mkdir("/d");
    vol.mkdir("/d/locked");
    vol.write_file("/d/locked/f", b"f");
    let copy = vol.conflict_copy("/d", BISYNC);
    let locked = copy.join(vol.backing("/d/locked").file_name().unwrap());
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();

    let (recorder, stats) = vol.fsck(true);
    assert!(
        matches!(
            recorder.outcomes[..],
            [(_, _, Ok(Outcome::Recovered { .. }))]
        ),
        "{:#?}",
        recorder.outcomes
    );
    assert_eq!(stats.fixed, 1);
    assert_eq!(recorder.warnings.len(), 1, "{:?}", recorder.warnings);
    assert!(!copy.exists());
    let leftovers: Vec<PathBuf> = fs::read_dir(&vol.root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().contains(".encfs.fsck-"))
        .collect();
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    for entry in fs::read_dir(&leftovers[0]).unwrap() {
        fs::set_permissions(entry.unwrap().path(), fs::Permissions::from_mode(0o755)).unwrap();
    }

    let (recorder, stats) = vol.fsck(true);
    assert!(
        matches!(
            recorder.finding(leftovers[0].file_name().unwrap()).class,
            Class::Temp { stale: true, .. }
        ),
        "{:#?}",
        recorder.findings
    );
    assert_eq!(stats.unresolved(), 0, "{:#?}", recorder.outcomes);
    assert!(!leftovers[0].exists());
    vol.remount();
    assert_eq!(vol.list("/"), names(&["d", "d (conflict1)"]));
    assert_eq!(vol.read_file("/d (conflict1)/locked/f"), b"f");
    // So the temp directory can be cleaned up.
    let recovered = vol.backing("/d (conflict1)/locked");
    fs::set_permissions(recovered, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Recovering a directory whose children's names depend on its own, where
/// files don't, renames the names and links the files: no file data is
/// copied.
#[test]
fn files_in_a_recovered_directory_are_linked() {
    for label in ["v6-standard", "v7-chained-names-only"] {
        let config = if label == "v6-standard" {
            config_named(label)
        } else {
            v7(|c| {
                c.use_chained_name_iv();
                c.external_iv_chaining = false;
            })
        };
        let mut vol = Volume::new(config);
        vol.mkdir("/d");
        vol.write_file("/d/big", &vec![1u8; 100_000]);
        let copy = vol.conflict_copy("/d", BISYNC);
        let inode = fs::metadata(copy.join(vol.backing("/d/big").file_name().unwrap()))
            .unwrap()
            .ino();

        let (recorder, stats) = vol.fsck(true);
        assert_eq!(stats.fixed, 1, "{label}: {:#?}", recorder.outcomes);
        let recovered = vol.backing("/d (conflict1)/big");
        assert_eq!(fs::metadata(&recovered).unwrap().ino(), inode, "{label}");
        vol.remount();
        assert_eq!(vol.read_file("/d (conflict1)/big"), vec![1u8; 100_000]);
    }
}

/// An entry that can't be read is a warning about that entry alone: the
/// rest of its directory and everything below it are still checked, and
/// the entry itself is left alone, even by `--fix --yes`.
#[test]
fn an_unreadable_entry_does_not_stop_its_directory() {
    if running_as_root() {
        return;
    }
    let vol = Volume::new(v7(|_| {}));
    vol.mkdir("/d");
    vol.mkdir("/d/sub");
    vol.write_file("/d/sub/report.docx", b"report");
    let conflict = vol.conflict_copy("/d/sub/report.docx", SYNCTHING);
    let dir = vol.backing("/d");
    let copy = dir.join(".encfs.sync-conflict-20230709-123456-ABCDEFG.diriv");
    fs::copy(diriv::sidecar_path(&dir), &copy).unwrap();
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o000)).unwrap();

    let (recorder, stats) = vol.fsck(true);
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o600)).unwrap();

    assert_eq!(stats.errors, 1, "{:#?}", recorder.warnings);
    assert!(
        recorder.warnings[0].contains(copy.file_name().unwrap().to_str().unwrap()),
        "{:#?}",
        recorder.warnings
    );
    assert!(
        recorder
            .findings
            .iter()
            .all(|f| f.name != copy.file_name().unwrap())
    );
    assert!(copy.exists());
    // The subdirectory was still checked, and its conflict copy recovered.
    recorder.candidates(conflict.file_name().unwrap());
    assert!(!conflict.exists());
}
