//! `encfsctl fsck` (ADR 0007): an offline check of a ciphertext tree. It
//! classifies every name the volume can't decrypt and recovers the conflict
//! copies that sync tools leave behind, by giving each one an ordinary
//! encrypted name.
//!
//! A scan changes nothing by itself. A [`Handler`] sees each [`Finding`] and
//! chooses an [`Action`]. Report-only mode, `--fix` and `--fix --yes` differ
//! only in their handlers.
//!
//! The tree must not be mounted or written to while fsck runs. Nothing here
//! takes the locks a mount would.

use crate::config::{CONFIG_FILES, ConfigType, EncfsConfig};
pub use crate::conflict::{Candidate, Confidence};
use crate::conflict::{Notes, Probe, default_candidate, sorted_entries};
use crate::crypto::cipher::Cipher;
use crate::crypto::file_iv::FileIv;
use crate::diriv;
use crate::recrypt::{Hooks, Recrypt, remove_entry, sync_dir};
use anyhow::{Context, Result, anyhow, bail};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use typed_fuse::passthrough;

/// How old a sync tool's temp file must be before fsck offers to delete it.
/// Syncthing keeps its temps for a day so it can resume a transfer.
pub const DEFAULT_OLDER_THAN: Duration = Duration::from_secs(24 * 60 * 60);

/// Prefix of the temporary names fsck builds a rewritten entry under before
/// renaming it into place. A leftover one is always stale, since fsck must
/// not run twice at once.
const TEMP_PREFIX: &str = ".encfs.fsck-";

/// How a copy of the volume config compares with the live one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigCopyStatus {
    /// It unlocks with the same password to the same key and settings.
    Equivalent,
    /// It unlocks, but to a different key or different settings.
    Different,
    /// It couldn't be loaded or unlocked with the password given.
    Unreadable(String),
    /// No password was available to check it.
    Unchecked,
}

/// What fsck found an entry to be.
#[derive(Debug, Clone)]
pub enum Class {
    /// A sync tool's copy of the directory's `.encfs.diriv`. When its bytes
    /// differ from the live sidecar's, entries created on the other side
    /// decode only under the copy (see [`Class::ForeignName`]).
    SidecarCopy {
        suffix: String,
        identical: bool,
        /// Entries that still decode only under this copy.
        dependents: usize,
    },
    /// A sync tool's copy of the volume config.
    ConfigCopy {
        suffix: String,
        status: ConfigCopyStatus,
    },
    /// A sync tool's own state, never touched.
    ToolState,
    /// A sync tool's temp file, or one fsck left behind.
    Temp {
        age: Option<Duration>,
        /// Old enough to delete.
        stale: bool,
    },
    /// A sync tool's conflict copy of an entry.
    ConflictCopy { candidates: Vec<Candidate> },
    /// An entry whose name decodes only under a conflicting sidecar copy.
    ForeignName {
        sidecar: OsString,
        plain: Vec<u8>,
        /// The sidecar copy's suffix, used to name it if `plain` is taken.
        suffix: String,
        proposed: Option<Vec<u8>>,
        path_iv: u64,
    },
    /// Anything else that doesn't decode.
    Unknown,
    /// The directory's own sidecar can't be read, so none of its names
    /// decode. The finding's name is the sidecar's.
    UnreadableDirectoryIv { error: String },
}

/// One entry that doesn't decrypt, and what fsck makes of it.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The backing directory holding the entry.
    pub dir: PathBuf,
    /// The directory's plaintext path, from the volume root (`/`).
    pub plain_dir: PathBuf,
    pub name: OsString,
    pub class: Class,
    names_iv: u64,
}

/// A sync tool's copy of a directory's sidecar, found while scanning it.
struct CopiedSidecar {
    name: OsString,
    suffix: String,
    identical: bool,
    /// The names IV the copy gives, when it differs from the live sidecar.
    names_iv: Option<u64>,
}

/// A subdirectory whose name decodes: its name, plaintext name, and the IV
/// decryption chained from it.
type Subdir = (OsString, Vec<u8>, u64);

/// What to do about a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Skip,
    Delete,
    /// Give the entry an ordinary name: the one fsck proposes, or `name`.
    /// `candidate` indexes [`Class::ConflictCopy`]'s candidates and is 0
    /// for [`Class::ForeignName`].
    Recover {
        candidate: usize,
        name: Option<Vec<u8>>,
    },
}

/// The actions a finding allows besides skipping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choices {
    pub recover: bool,
    pub delete: bool,
}

impl Finding {
    /// The sidecar copies this entry decodes only under, in whole or as a
    /// conflict copy's base.
    fn sidecars_used(&self) -> Vec<&OsString> {
        let mut used = Vec::new();
        match &self.class {
            Class::ForeignName { sidecar, .. } => used.push(sidecar),
            Class::ConflictCopy { candidates } => {
                for sidecar in candidates.iter().filter_map(|c| c.sidecar.as_ref()) {
                    if !used.contains(&sidecar) {
                        used.push(sidecar);
                    }
                }
            }
            _ => {}
        }
        used
    }

    /// The entry's backing path.
    pub fn path(&self) -> PathBuf {
        self.dir.join(&self.name)
    }

    /// Whether this counts against a clean result. Tool state doesn't.
    pub fn is_problem(&self) -> bool {
        !matches!(self.class, Class::ToolState)
    }

    /// How many bases recovery can choose between.
    pub fn candidate_count(&self) -> usize {
        match &self.class {
            Class::ConflictCopy { candidates } => candidates.len(),
            _ => 1,
        }
    }

    /// The plaintext name recovering with `candidate` would give the entry,
    /// as of the scan.
    pub fn proposed(&self, candidate: usize) -> Option<&[u8]> {
        match &self.class {
            Class::ConflictCopy { candidates } => candidates.get(candidate)?.proposed.as_deref(),
            Class::ForeignName { proposed, .. } => proposed.as_deref(),
            _ => None,
        }
    }

    pub fn choices(&self) -> Choices {
        let (recover, delete) = match &self.class {
            Class::SidecarCopy {
                identical,
                dependents,
                ..
            } => (false, *identical || *dependents == 0),
            Class::ConfigCopy { status, .. } => (false, *status == ConfigCopyStatus::Equivalent),
            Class::ToolState | Class::UnreadableDirectoryIv { .. } => (false, false),
            Class::Temp { stale, .. } => (false, *stale),
            Class::ConflictCopy { .. } | Class::ForeignName { .. } => (true, true),
            Class::Unknown => (false, true),
        };
        Choices { recover, delete }
    }

    /// The action `--fix --yes` takes.
    pub fn default_action(&self) -> Action {
        match &self.class {
            Class::SidecarCopy { .. } | Class::ConfigCopy { .. } | Class::Temp { .. }
                if self.choices().delete =>
            {
                Action::Delete
            }
            Class::ForeignName { .. } => Action::Recover {
                candidate: 0,
                name: None,
            },
            Class::ConflictCopy { candidates } => match default_candidate(candidates) {
                Some(candidate) => Action::Recover {
                    candidate,
                    name: None,
                },
                None => Action::Skip,
            },
            _ => Action::Skip,
        }
    }
}

/// What an applied action did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The entry now has the ordinary plaintext name `name` in its directory.
    Recovered {
        name: Vec<u8>,
    },
    Deleted,
}

/// Decides what to do about each finding and hears how it went.
pub trait Handler {
    /// Chooses the action for `finding`. Called once per finding, in scan
    /// order, directory by directory.
    fn decide(&mut self, finding: &Finding) -> Result<Action>;
    /// The result of an action other than [`Action::Skip`].
    fn outcome(&mut self, finding: &Finding, action: &Action, result: &Result<Outcome>);
    /// A problem that stopped fsck checking `path`.
    fn warning(&mut self, path: &Path, error: &anyhow::Error);
}

/// Counts for the summary and the exit status.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub dirs: usize,
    pub entries: usize,
    /// Entries whose names don't start with `.`, or aren't UTF-8: the ones
    /// `encfsctl showcruft` counts.
    pub unhidden: usize,
    /// Findings that count as problems (not tool state).
    pub problems: usize,
    /// Problems fixed by a recover or delete.
    pub fixed: usize,
    /// Directories or entries fsck couldn't check.
    pub errors: usize,
}

impl Stats {
    /// Problems left, including what couldn't be checked.
    pub fn unresolved(&self) -> usize {
        self.problems - self.fixed + self.errors
    }
}

/// An offline check of the ciphertext tree at `root`.
pub struct Fsck<'a> {
    root: PathBuf,
    config: &'a EncfsConfig,
    cipher: &'a dyn Cipher,
    password: Option<&'a str>,
    /// Identities (device, inode) of the config file in use, followed
    /// through a symlink and not, so it is never taken for a copy.
    config_ids: Vec<(u64, u64)>,
    older_than: Duration,
    now: SystemTime,
    modify: bool,
    /// Only tell undecodable names apart by name: no content checks,
    /// candidate search or sidecar copy reads (see [`Fsck::names_only`]).
    names_only: bool,
    stats: Stats,
    /// Problems found along the way that didn't stop the check, for the
    /// handler's [`Handler::warning`].
    notes: Notes,
}

/// Collects a copy's warnings as notes.
struct NoteHooks<'n>(&'n Notes);

impl Hooks for NoteHooks<'_> {
    fn warning(&mut self, path: &Path, error: &anyhow::Error) {
        self.0
            .borrow_mut()
            .push((path.to_path_buf(), anyhow!("{error:#}")));
    }
}

impl<'a> Fsck<'a> {
    /// A report-only check. See [`Fsck::allow_changes`].
    pub fn new(root: &Path, config: &'a EncfsConfig, cipher: &'a dyn Cipher) -> Self {
        Self {
            root: root.to_path_buf(),
            config,
            cipher,
            password: None,
            config_ids: Vec::new(),
            older_than: DEFAULT_OLDER_THAN,
            now: SystemTime::now(),
            modify: false,
            names_only: false,
            stats: Stats::default(),
            notes: RefCell::new(Vec::new()),
        }
    }

    /// Lets the handler's actions change the tree. Without it, any action
    /// but [`Action::Skip`] is refused.
    pub fn allow_changes(mut self, modify: bool) -> Self {
        self.modify = modify;
        self
    }

    /// The volume password, to check copies of the config with.
    pub fn with_password(mut self, password: &'a str) -> Self {
        self.password = Some(password);
        self
    }

    /// The config file the volume was opened with. fsck passes over it
    /// wherever it is in the tree and whatever it is named, so it is never
    /// taken for a sync tool's copy of itself.
    pub fn with_config_file(mut self, path: &Path) -> Self {
        for meta in [fs::metadata(path), fs::symlink_metadata(path)]
            .into_iter()
            .flatten()
        {
            self.config_ids.push((meta.dev(), meta.ino()));
        }
        self
    }

    /// Tells undecodable names apart by their names alone, without reading
    /// anything to find or check a conflict copy's base: what `showcruft`,
    /// which only lists them, needs. Conflict copies are then
    /// [`Class::Unknown`], and sidecar copies are never [`Class::ForeignName`]
    /// hosts.
    pub fn names_only(mut self) -> Self {
        self.names_only = true;
        self
    }

    /// The minimum age of a temp file fsck offers to delete.
    pub fn older_than(mut self, age: Duration) -> Self {
        self.older_than = age;
        self
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Checks the whole tree, passing each finding to `handler`. Parts of
    /// the tree that can't be read are passed to [`Handler::warning`] and
    /// counted in [`Stats::errors`]. An error returned is the handler's own,
    /// and ends the check there.
    pub fn run(&mut self, handler: &mut dyn Handler) -> Result<()> {
        let root = self.root.clone();
        let result = self.check_dir(&root, Path::new("/"), 0, handler);
        self.flush_notes(handler);
        result
    }

    /// Whether the entry at `path` (`meta` from `lstat`) is the config file
    /// in use.
    fn is_live_config(&self, path: &Path, meta: &fs::Metadata) -> bool {
        let is = |m: &fs::Metadata| self.config_ids.contains(&(m.dev(), m.ino()));
        is(meta) || (meta.file_type().is_symlink() && fs::metadata(path).is_ok_and(|m| is(&m)))
    }

    fn probe(&self) -> Probe<'_> {
        Probe::new(self.config, self.cipher, &self.notes)
    }

    /// Records a problem that didn't stop the check, once per path.
    fn note(&self, path: &Path, error: anyhow::Error) {
        self.probe().note(path, error);
    }

    /// Notes an entry of a directory being scanned that couldn't be read,
    /// so the rest of the directory is still checked. One that went away
    /// since it was listed is passed over.
    fn note_entry_error(&self, path: &Path, error: io::Error) {
        if error.kind() != io::ErrorKind::NotFound {
            self.note(path, anyhow::Error::new(error).context("reading the entry"));
        }
    }

    fn flush_notes(&mut self, handler: &mut dyn Handler) {
        for (path, error) in self.notes.take() {
            self.stats.errors += 1;
            handler.warning(&path, &error);
        }
    }

    fn check_dir(
        &mut self,
        dir: &Path,
        plain_dir: &Path,
        path_iv: u64,
        handler: &mut dyn Handler,
    ) -> Result<()> {
        self.stats.dirs += 1;
        let names_iv = match diriv::names_iv(self.config, self.cipher, dir, path_iv) {
            Ok(iv) => iv,
            Err(e) => {
                let finding = Finding {
                    dir: dir.to_path_buf(),
                    plain_dir: plain_dir.to_path_buf(),
                    name: OsString::from(diriv::SIDECAR_NAME),
                    class: Class::UnreadableDirectoryIv {
                        error: e.to_string(),
                    },
                    names_iv: 0,
                };
                self.stats.problems += 1;
                handler.decide(&finding)?;
                return Ok(());
            }
        };

        let scan = self.scan_dir(dir, plain_dir, names_iv);
        self.flush_notes(handler);
        let (mut findings, mut subdirs) = match scan {
            Ok(scan) => scan,
            Err(e) => {
                self.stats.errors += 1;
                handler.warning(dir, &e);
                return Ok(());
            }
        };

        // Entries that decode only under a sidecar copy, per copy.
        let mut dependents: HashMap<OsString, usize> = HashMap::new();
        for f in &findings {
            for sidecar in f.sidecars_used() {
                *dependents.entry(sidecar.clone()).or_default() += 1;
            }
        }

        let mut recovered = false;
        for finding in &mut findings {
            if let Class::SidecarCopy {
                dependents: count, ..
            } = &mut finding.class
            {
                *count = dependents.get(&finding.name).copied().unwrap_or(0);
            }
            if finding.is_problem() {
                self.stats.problems += 1;
            }
            let action = handler.decide(finding)?;
            if action == Action::Skip {
                continue;
            }
            let result = self.apply(finding, &action);
            if result.is_ok() {
                self.stats.fixed += 1;
                recovered |= matches!(action, Action::Recover { .. });
                for sidecar in finding.sidecars_used() {
                    if let Some(count) = dependents.get_mut(sidecar) {
                        *count -= 1;
                    }
                }
            }
            handler.outcome(finding, &action, &result);
            self.flush_notes(handler);
        }

        // Descend into every directory with a decodable name, including the
        // ones just recovered, which only a fresh listing has.
        if recovered {
            match self.decodable_subdirs(dir, names_iv) {
                Ok(listed) => subdirs = listed,
                Err(e) => {
                    self.stats.errors += 1;
                    handler.warning(dir, &e);
                    return Ok(());
                }
            }
        }
        for (name, plain, next_iv) in subdirs {
            let child = dir.join(&name);
            let child_plain = plain_dir.join(OsStr::from_bytes(&plain));
            let child_iv = diriv::child_path_iv(self.config, next_iv);
            self.check_dir(&child, &child_plain, child_iv, handler)?;
        }
        Ok(())
    }

    fn decodable_subdirs(&self, dir: &Path, names_iv: u64) -> Result<Vec<Subdir>> {
        let mut out = Vec::new();
        for entry in sorted_entries(dir)? {
            match entry.file_type() {
                Ok(t) if t.is_dir() => {}
                Ok(_) => continue,
                Err(e) => {
                    self.note_entry_error(&entry.path(), e);
                    continue;
                }
            }
            let name = entry.file_name();
            let Some(s) = name.to_str() else { continue };
            if let Ok((plain, next_iv)) = self.cipher.decrypt_entry_name(s, names_iv) {
                out.push((name, plain, next_iv));
            }
        }
        Ok(out)
    }

    /// Classifies every entry of `dir` that doesn't decode, and lists the
    /// subdirectories that do. Sidecar copies come last, so the entries that
    /// depend on them are handled first.
    fn scan_dir(
        &mut self,
        dir: &Path,
        plain_dir: &Path,
        names_iv: u64,
    ) -> Result<(Vec<Finding>, Vec<Subdir>)> {
        let entries = sorted_entries(dir)?;
        self.stats.entries += entries.len();

        let mut plain_names = HashSet::new();
        let mut subdirs = Vec::new();
        let mut undecodable = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            if !name.to_str().is_some_and(|s| s.starts_with('.')) {
                self.stats.unhidden += 1;
            }
            let decoded = name
                .to_str()
                .and_then(|s| self.cipher.decrypt_entry_name(s, names_iv).ok());
            match decoded {
                Some((plain, next_iv)) => {
                    match entry.file_type() {
                        Ok(t) if t.is_dir() => subdirs.push((name, plain.clone(), next_iv)),
                        Ok(_) => {}
                        Err(e) => self.note_entry_error(&entry.path(), e),
                    }
                    plain_names.insert(plain);
                }
                // Only undecodable entries need the full `lstat`.
                None => match entry.metadata() {
                    Ok(meta) => undecodable.push((name, meta)),
                    Err(e) => self.note_entry_error(&entry.path(), e),
                },
            }
        }

        let mut sidecar_copies = Vec::new();
        let mut unreadable = Vec::new();
        if self.config.directory_iv && !self.names_only {
            // The live sidecar, read only once a copy turns up.
            let mut live = None;
            for (name, meta) in &undecodable {
                let Some(suffix) = name
                    .to_str()
                    .and_then(|s| metadata_copy_suffix(s, diriv::SIDECAR_NAME))
                else {
                    continue;
                };
                if !meta.is_file() {
                    continue;
                }
                let bytes = match fs::read(dir.join(name)) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        // Not to be classified as anything else, or fixed.
                        self.note_entry_error(&dir.join(name), e);
                        unreadable.push(name.clone());
                        continue;
                    }
                };
                let live = live.get_or_insert_with(|| diriv::read_sidecar(dir).ok());
                let identical = live.is_some_and(|live| live[..] == bytes[..]);
                let alt_iv = if identical {
                    None
                } else {
                    <diriv::Sidecar>::try_from(bytes.as_slice())
                        .ok()
                        .and_then(|b| diriv::derive(self.cipher, &b).ok())
                        .map(|ivs| ivs.name_iv)
                };
                sidecar_copies.push(CopiedSidecar {
                    name: name.clone(),
                    suffix,
                    identical,
                    names_iv: alt_iv,
                });
            }
        }

        let mut findings = Vec::new();
        for (name, meta) in &undecodable {
            if unreadable.contains(name) {
                continue;
            }
            let class = match sidecar_copies.iter().find(|copy| copy.name == *name) {
                Some(copy) => Some(Class::SidecarCopy {
                    suffix: copy.suffix.clone(),
                    identical: copy.identical,
                    dependents: 0,
                }),
                None => self.classify(dir, names_iv, name, meta, &plain_names, &sidecar_copies),
            };
            if let Some(class) = class {
                findings.push(Finding {
                    dir: dir.to_path_buf(),
                    plain_dir: plain_dir.to_path_buf(),
                    name: name.clone(),
                    class,
                    names_iv,
                });
            }
        }
        findings.sort_by_key(|f| matches!(f.class, Class::SidecarCopy { .. }));
        Ok((findings, subdirs))
    }

    /// What an undecodable entry is, or `None` for names fsck passes over:
    /// the live metadata files (and the config in use, whatever its name),
    /// mkdir's staging directories, and other names starting with `.`, as
    /// `showcruft` does.
    fn classify(
        &self,
        dir: &Path,
        names_iv: u64,
        name: &OsStr,
        meta: &fs::Metadata,
        plain_names: &HashSet<Vec<u8>>,
        sidecar_copies: &[CopiedSidecar],
    ) -> Option<Class> {
        if self.is_live_config(&dir.join(name), meta) {
            return None;
        }
        let Some(s) = name.to_str() else {
            return Some(Class::Unknown);
        };
        if s == diriv::SIDECAR_NAME
            || CONFIG_FILES.iter().any(|(file, _)| *file == s)
            || diriv::is_staging_name(name)
        {
            return None;
        }
        if dir == self.root {
            for (live, config_type) in CONFIG_FILES {
                if let Some(suffix) = metadata_copy_suffix(s, live) {
                    let status = if meta.is_file() {
                        self.config_copy_status(&dir.join(name), *config_type)
                    } else {
                        ConfigCopyStatus::Unreadable("not a file".into())
                    };
                    return Some(Class::ConfigCopy { suffix, status });
                }
            }
        }
        if is_tool_state(s) {
            return Some(Class::ToolState);
        }
        if let Some(ours) = temp_kind(s) {
            let age = meta
                .modified()
                .ok()
                .and_then(|m| self.now.duration_since(m).ok());
            let stale = ours || age.is_some_and(|age| age >= self.older_than);
            return Some(Class::Temp { age, stale });
        }
        if s.starts_with('.') {
            return None;
        }
        if self.names_only {
            return Some(Class::Unknown);
        }

        let probe = self.probe();
        let mut ivs = vec![(names_iv, None)];
        for copy in sidecar_copies {
            let Some(alt_iv) = copy.names_iv else {
                continue;
            };
            if let Ok((plain, next_iv)) = self.cipher.decrypt_entry_name(s, alt_iv) {
                let proposed = probe
                    .choose_name(dir, names_iv, &plain, &copy.suffix, true, None)
                    .ok()
                    .map(|(n, _, _)| n);
                return Some(Class::ForeignName {
                    sidecar: copy.name.clone(),
                    plain,
                    suffix: copy.suffix.clone(),
                    proposed,
                    path_iv: diriv::child_path_iv(self.config, next_iv),
                });
            }
            ivs.push((alt_iv, Some(copy.name.as_os_str())));
        }

        // A conflict copy of an entry made under a sidecar copy has its base
        // encrypted under that copy's IV.
        let candidates = probe.candidates(dir, &ivs, s, meta, plain_names, Some(names_iv));
        if !candidates.is_empty() {
            return Some(Class::ConflictCopy { candidates });
        }
        Some(Class::Unknown)
    }

    /// Unlocks the config copy at `path`, a copy of a config file in the
    /// `config_type` format, with the volume password and compares it with
    /// the live config.
    fn config_copy_status(&self, path: &Path, config_type: ConfigType) -> ConfigCopyStatus {
        let Some(password) = self.password else {
            return ConfigCopyStatus::Unchecked;
        };
        let copy = match EncfsConfig::load_with_type(path, Some(config_type)) {
            Ok(copy) => copy,
            Err(e) => return ConfigCopyStatus::Unreadable(format!("{e:#}")),
        };
        let cipher = match copy.get_cipher(password) {
            Ok(cipher) => cipher,
            Err(e) => return ConfigCopyStatus::Unreadable(format!("{e:#}")),
        };
        if same_settings(self.config, &copy) && same_key(self.cipher, cipher.as_ref()) {
            ConfigCopyStatus::Equivalent
        } else {
            ConfigCopyStatus::Different
        }
    }

    /// Carries out `action` on `finding`.
    pub fn apply(&mut self, finding: &Finding, action: &Action) -> Result<Outcome> {
        if !self.modify {
            bail!("fsck is in report-only mode");
        }
        let path = finding.path();
        if self.is_live_config(&path, &fs::symlink_metadata(&path)?) {
            bail!("{} is the config file in use", path.display());
        }
        let choices = finding.choices();
        match action {
            Action::Skip => bail!("nothing to apply"),
            Action::Delete => {
                if !choices.delete {
                    bail!("this entry can't be deleted by fsck");
                }
                remove_entry(&path)?;
                self.sync_dir_noting(&finding.dir);
                Ok(Outcome::Deleted)
            }
            Action::Recover { candidate, name } => {
                if !choices.recover {
                    bail!("this entry can't be recovered");
                }
                let (plain, suffix, path_iv, prefer_plain) = match &finding.class {
                    Class::ConflictCopy { candidates } => {
                        let c = candidates
                            .get(*candidate)
                            .ok_or_else(|| anyhow!("no candidate {candidate}"))?;
                        (&c.plain, &c.suffix, c.path_iv, false)
                    }
                    Class::ForeignName {
                        plain,
                        suffix,
                        path_iv,
                        ..
                    } => (plain, suffix, *path_iv, true),
                    _ => bail!("this entry can't be recovered"),
                };
                let (new_plain, encrypted, new_path_iv) = self.probe().choose_name(
                    &finding.dir,
                    finding.names_iv,
                    plain,
                    suffix,
                    prefer_plain,
                    name.as_deref(),
                )?;
                self.move_entry(
                    &finding.dir,
                    &finding.name,
                    path_iv,
                    &encrypted,
                    new_path_iv,
                )?;
                Ok(Outcome::Recovered { name: new_plain })
            }
        }
    }

    /// Syncs `dir`, noting a failure: what was just done in it may not
    /// survive a crash.
    fn sync_dir_noting(&self, dir: &Path) {
        if let Err(e) = sync_dir(dir) {
            self.note(dir, e);
        }
    }

    /// Renames the entry `name` in `dir`, written under path IV `src_iv`, to
    /// `new_name` there under path IV `dst_iv`, never replacing anything.
    /// A rename where the contents don't depend on the path. Otherwise a
    /// re-encrypted copy ([`Recrypt::copy_tree`]) is built under a temp
    /// name and renamed into place, and only then is the source moved
    /// aside to a temp name and removed. Once the copy is in place the
    /// move has succeeded: a source that can't be removed is noted, and is
    /// left under a temp name the next run deletes, rather than as a
    /// conflict copy it would recover a second time.
    fn move_entry(
        &self,
        dir: &Path,
        name: &OsStr,
        src_iv: u64,
        new_name: &str,
        dst_iv: u64,
    ) -> Result<()> {
        let src = dir.join(name);
        let dst = dir.join(new_name);
        let meta = fs::symlink_metadata(&src)?;
        let recrypt = Recrypt::new(self.config, self.cipher);
        if src_iv == dst_iv || !recrypt.depends_on_path(&meta) {
            rename_noreplace(&src, &dst)?;
            self.sync_dir_noting(dir);
            return Ok(());
        }
        let temp = temp_path(dir)?;
        let built = recrypt
            .copy_tree(
                &src,
                src_iv,
                &temp,
                dst_iv,
                &meta,
                &mut NoteHooks(&self.notes),
            )
            .and_then(|()| rename_noreplace(&temp, &dst))
            .and_then(|()| sync_dir(dir));
        if let Err(e) = built {
            let _ = remove_entry(&temp);
            return Err(e);
        }

        let aside = temp_path(dir)?;
        let removed = rename_noreplace(&src, &aside)
            .with_context(|| format!("moving the source aside to {}", aside.display()))
            .and_then(|()| {
                remove_entry(&aside)
                    .with_context(|| format!("removing the source, now {}", aside.display()))
            });
        if let Err(e) = removed {
            self.note(
                &src,
                e.context("recovered, but the original couldn't be removed"),
            );
        }
        self.sync_dir_noting(dir);
        Ok(())
    }
}

/// `rename(2)` that fails rather than replace `dst`.
fn rename_noreplace(src: &Path, dst: &Path) -> Result<()> {
    let from = CString::new(src.as_os_str().as_bytes())?;
    let to = CString::new(dst.as_os_str().as_bytes())?;
    match passthrough::rename_noreplace_at(libc::AT_FDCWD, &from, libc::AT_FDCWD, &to) {
        Ok(true) => Ok(()),
        // No atomic form here. Nothing else writes the tree while fsck
        // runs, so a check first is enough.
        Ok(false) => {
            if fs::symlink_metadata(dst).is_ok() {
                bail!("{} already exists", dst.display());
            }
            fs::rename(src, dst)?;
            Ok(())
        }
        Err(e) => Err(anyhow!(io::Error::from_raw_os_error(e.raw())))
            .with_context(|| format!("renaming {} to {}", src.display(), dst.display())),
    }
}

/// A fresh temp path in `dir` (see [`TEMP_PREFIX`]).
fn temp_path(dir: &Path) -> Result<PathBuf> {
    Ok(dir.join(diriv::random_name(TEMP_PREFIX)?))
}

/// The suffix a sync tool added to the metadata file `live`, if `name` is a
/// conflict copy of it. Tools append their marker (`.encfs7 (conflicted
/// copy …)`) or put it before the extension. Syncthing takes the extension
/// as Go's `filepath.Ext` does, from the last dot, so `.encfs7` becomes
/// `.sync-conflict-….encfs7` and `.encfs.diriv` becomes
/// `.encfs.sync-conflict-….diriv`.
fn metadata_copy_suffix(name: &str, live: &str) -> Option<String> {
    if name == live {
        return None;
    }
    if let Some(rest) = name.strip_prefix(live) {
        return Some(rest.to_string());
    }
    let dot = live.rfind('.')?;
    let (stem, ext) = live.split_at(dot);
    let middle = name.strip_prefix(stem)?.strip_suffix(ext)?;
    (!middle.is_empty()).then(|| middle.to_string())
}

/// The format of a config file named `name`: what its name declares
/// ([`ConfigType::from_file_name`]), or that of the config file it is a sync
/// tool's conflict copy of. Only the name tells V4 from V5.
pub fn config_type_for_name(name: &str) -> Option<ConfigType> {
    ConfigType::from_file_name(name).or_else(|| {
        CONFIG_FILES
            .iter()
            .find(|(live, _)| metadata_copy_suffix(name, live).is_some())
            .map(|(_, config_type)| *config_type)
    })
}

/// Sync tools' own files, which fsck leaves alone.
fn is_tool_state(name: &str) -> bool {
    let sync_journal = |prefix: &str| {
        name.strip_prefix(prefix).is_some_and(|rest| {
            rest.ends_with(".db") || rest.ends_with(".db-wal") || rest.ends_with(".db-shm")
        })
    };
    matches!(
        name,
        ".stfolder"
            | ".stignore"
            | ".stversions"
            | ".dropbox"
            | ".dropbox.attr"
            | ".dropbox.cache"
            | ".nextcloudsync.log"
            | ".owncloudsync.log"
            | "RCLONE_TEST"
    ) || sync_journal(".sync_")
        || sync_journal("._sync_")
}

/// Whether `name` is a temp file: `Some(true)` for one fsck made, which is
/// always stale, `Some(false)` for a sync tool's.
fn temp_kind(name: &str) -> Option<bool> {
    if name.starts_with(TEMP_PREFIX) {
        return Some(true);
    }
    let syncthing = (name.starts_with(".syncthing.") || name.starts_with("~syncthing~"))
        && name.ends_with(".tmp");
    let nextcloud = name.starts_with('.')
        && name
            .rsplit_once(".~")
            .is_some_and(|(_, hex)| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    let rclone = name.ends_with(".partial");
    (syncthing || nextcloud || rclone).then_some(false)
}

/// Whether two configs encrypt the same way, apart from how the key is
/// stored. Every field but the key storage counts, so a new setting is
/// compared without being listed here.
fn same_settings(a: &EncfsConfig, b: &EncfsConfig) -> bool {
    let settings = |c: &EncfsConfig| EncfsConfig {
        creator: String::new(),
        version: 0,
        key_data: Vec::new(),
        salt: Vec::new(),
        kdf_iterations: 0,
        desired_kdf_duration: 0,
        kdf_algorithm: Default::default(),
        argon2_memory_cost: None,
        argon2_time_cost: None,
        argon2_parallelism: None,
        config_hash: None,
        ..c.clone()
    };
    settings(a) == settings(b)
}

/// Whether two ciphers hold the same volume key, judged by what they
/// produce for the same inputs.
fn same_key(a: &dyn Cipher, b: &dyn Cipher) -> bool {
    let probe = b"encfs fsck volume key probe";
    let same = |f: &dyn Fn(&dyn Cipher) -> Option<Vec<u8>>| {
        let ours = f(a);
        ours.is_some() && ours == f(b)
    };
    [0, 1, 0x0123_4567_89ab_cdef].into_iter().all(|iv| {
        same(&|c| {
            c.encrypt_filename(probe, iv)
                .ok()
                .map(|(n, _)| n.into_bytes())
        })
    }) && same(&|c| c.encrypt_header_with_iv(FileIv::from_u64(0x5a5a), 7).ok())
        && a.mac_64_no_iv(probe).ok() == b.mac_64_no_iv(probe).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config given by a sync tool's copy name keeps its format, which
    /// for V4 only the name tells.
    #[test]
    fn config_formats_are_known_by_copy_names() {
        let cases = [
            (".encfs4", Some(ConfigType::V4)),
            (".encfs4 (conflicted copy 2023-07-09)", Some(ConfigType::V4)),
            (
                ".encfs4.sync-conflict-20230709-123456-ABCDEFG",
                Some(ConfigType::V4),
            ),
            (".encfs5.conflict1", Some(ConfigType::V5)),
            (
                ".encfs6.sync-conflict-20230709-123456-ABCDEFG.xml",
                Some(ConfigType::V6),
            ),
            (
                ".sync-conflict-20230709-123456-ABCDEFG.encfs7",
                Some(ConfigType::V7),
            ),
            ("backup.encfs7", Some(ConfigType::V7)),
            ("config.xml", None),
        ];
        for (name, expected) in cases {
            assert_eq!(config_type_for_name(name), expected, "{name}");
        }
    }

    #[test]
    fn metadata_copies_are_recognized_in_every_tool_form() {
        let cases = [
            (".encfs7 (conflicted copy 2023-07-09 123456)", ".encfs7"),
            (".sync-conflict-20230709-123456-ABCDEFG.encfs7", ".encfs7"),
            (".encfs7.conflict1", ".encfs7"),
            (
                ".encfs6.sync-conflict-20230709-123456-ABCDEFG.xml",
                ".encfs6.xml",
            ),
            (
                ".encfs6 (alice's conflicted copy 2023-07-09).xml",
                ".encfs6.xml",
            ),
            (
                ".encfs.sync-conflict-20230709-123456-ABCDEFG.diriv",
                ".encfs.diriv",
            ),
            (
                ".encfs (conflicted copy 2023-07-09 123456).diriv",
                ".encfs.diriv",
            ),
            (".encfs.diriv.conflict2", ".encfs.diriv"),
        ];
        for (name, live) in cases {
            assert!(
                metadata_copy_suffix(name, live).is_some(),
                "{name} is a copy of {live}"
            );
        }
        assert_eq!(metadata_copy_suffix(".encfs7", ".encfs7"), None);
        assert_eq!(
            metadata_copy_suffix(".encfs.0123456789abcdef", ".encfs.diriv"),
            None,
            "mkdir staging names are not sidecar copies"
        );
        assert_eq!(
            metadata_copy_suffix(".encfs.fsck-0123456789abcdef", ".encfs.diriv"),
            None
        );
    }

    #[test]
    fn tool_state_and_temps() {
        for name in [
            ".stfolder",
            ".stversions",
            ".sync_0123456789ab.db",
            ".sync_0123456789ab.db-wal",
            "._sync_0123456789ab.db",
            ".dropbox.cache",
            "RCLONE_TEST",
        ] {
            assert!(is_tool_state(name), "{name}");
        }
        assert!(!is_tool_state(".sync_x.txt"));

        assert_eq!(temp_kind(".syncthing.ABCDEF.tmp"), Some(false));
        assert_eq!(temp_kind("~syncthing~ABCDEF.tmp"), Some(false));
        assert_eq!(temp_kind(".ABCDEF.~1a2b3c"), Some(false));
        assert_eq!(temp_kind("ABCDEF.1a2b3c4d.partial"), Some(false));
        assert_eq!(temp_kind(".encfs.fsck-0011223344556677"), Some(true));
        assert_eq!(temp_kind(".ABCDEF.~xyz"), None);
        assert_eq!(temp_kind("ABCDEF"), None);
    }
}
