//! Recognising a sync tool's conflict copy of an entry whose name no
//! longer decodes: the bases its name may split into, how sure each is,
//! and the name recovery would give it. Used by `encfsctl fsck`
//! ([`crate::fsck`]) to classify and recover such copies, and by
//! [`crate::recrypt`] to keep the ones inside a directory it re-encrypts
//! recoverable. It depends on neither.

use crate::config::{EncfsConfig, FileIvError};
use crate::crypto::block::{BlockCodec, BlockMode};
use crate::crypto::cipher::{Cipher, check_entry_name};
use crate::crypto::file::for_each_block;
use crate::crypto::ssl::NameEncoding;
use crate::diriv;
use crate::symlink_target;
use anyhow::{Context, Result, anyhow, bail};
use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::ops::ControlFlow;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The longest name most filesystems take, in bytes.
const NAME_MAX: usize = 255;

/// How many collision-avoiding numbers to try for a recovered name.
const MAX_NAME_ATTEMPTS: u32 = 1000;

/// What an entry is, from `lstat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

impl EntryKind {
    fn of(meta: &fs::Metadata) -> Self {
        let t = meta.file_type();
        if t.is_file() {
            Self::File
        } else if t.is_dir() {
            Self::Dir
        } else if t.is_symlink() {
            Self::Symlink
        } else {
            Self::Other
        }
    }
}

/// How sure fsck is that a conflict copy's base is right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// The entry's contents depend on the base's path IV, and they
    /// authenticate under it: a file's first block that isn't a hole, every
    /// child name of a directory, or a symlink's target.
    Verified,
    /// The base's name decrypts and is canonical, but nothing in the entry
    /// confirms it: the config doesn't bind contents to names, or there is
    /// nothing to check (an empty file or directory).
    Probable,
}

/// A way to read a conflict copy's name `V` as `base ‖ suffix`.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The plaintext name the base decrypts to.
    pub plain: Vec<u8>,
    /// What the sync tool appended to the base.
    pub suffix: String,
    /// Whether the split is at the first byte outside the name alphabet.
    pub first_split: bool,
    /// Whether `plain` names an existing entry in the same directory.
    pub sibling_exists: bool,
    pub confidence: Confidence,
    /// The plaintext name recovery would give the entry, as of the scan.
    pub proposed: Option<Vec<u8>>,
    /// The sidecar copy the base decodes under, when it isn't the live
    /// sidecar: the copy was made under that one.
    pub sidecar: Option<OsString>,
    /// The path IV the entry's contents were written under.
    pub(crate) path_iv: u64,
}

/// The candidate `--yes` recovers: the only verified one, or, when none is
/// verified, the only one that splits at the first byte outside the name
/// alphabet and names an existing sibling. Another prefix passing the name
/// checksum by chance (2⁻¹⁶ each) almost never names a sibling too, so it
/// doesn't cast doubt on that one.
pub(crate) fn default_candidate(candidates: &[Candidate]) -> Option<usize> {
    let only = |pred: &dyn Fn(&Candidate) -> bool| {
        let mut matching = candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| pred(c))
            .map(|(i, _)| i);
        match (matching.next(), matching.next()) {
            (Some(i), None) => Some(i),
            _ => None,
        }
    };
    if candidates
        .iter()
        .any(|c| c.confidence == Confidence::Verified)
    {
        return only(&|c| c.confidence == Confidence::Verified);
    }
    only(&|c| c.first_split && c.sibling_exists)
}

/// Problems that didn't stop the work, by path.
pub(crate) type Notes = RefCell<Vec<(PathBuf, anyhow::Error)>>;

/// How a file's first block that isn't a hole compares with a base.
enum FileCheck {
    Verified,
    /// No block to check: empty, or only holes.
    NothingChecked,
    Mismatch,
}

/// The searches behind classifying a conflict copy: the bases its name may
/// split into, what its contents say about each, and the names recovery
/// would give it. Problems reading entries are noted in `notes`. Shared by
/// [`crate::fsck::Fsck`] and [`crate::recrypt`], which keeps conflict
/// copies inside a directory it re-encrypts recoverable.
pub(crate) struct Probe<'a> {
    config: &'a EncfsConfig,
    cipher: &'a dyn Cipher,
    notes: &'a Notes,
}

impl<'a> Probe<'a> {
    pub(crate) fn new(config: &'a EncfsConfig, cipher: &'a dyn Cipher, notes: &'a Notes) -> Self {
        Self {
            config,
            cipher,
            notes,
        }
    }

    /// Records a problem that didn't stop the work, once per path.
    pub(crate) fn note(&self, path: &Path, error: anyhow::Error) {
        let mut notes = self.notes.borrow_mut();
        if !notes.iter().any(|(p, _)| p == path) {
            notes.push((path.to_path_buf(), error));
        }
    }

    /// The candidate `--fix --yes` would recover the conflict copy `name`
    /// in `dir` (names IV `names_iv`, whose decodable entries are
    /// `plain_names`) with. `None` when `name` has no candidate base; an
    /// error when it has more than one and none is the default.
    pub(crate) fn default_conflict_base(
        &self,
        dir: &Path,
        names_iv: u64,
        name: &str,
        meta: &fs::Metadata,
        plain_names: &HashSet<Vec<u8>>,
    ) -> Result<Option<Candidate>> {
        let mut candidates =
            self.candidates(dir, &[(names_iv, None)], name, meta, plain_names, None);
        if candidates.is_empty() {
            return Ok(None);
        }
        let Some(i) = default_candidate(&candidates) else {
            bail!(
                "{} could be a conflict copy of {} different names",
                dir.join(name).display(),
                candidates.len()
            );
        };
        Ok(Some(candidates.swap_remove(i)))
    }

    /// The ways to read `name` as a base plus a suffix that the entry's
    /// contents don't rule out, most likely first. A base may decode under
    /// any of `ivs`: the directory's names IV, then those of its sidecar
    /// copies, each with the copy's name. With `propose_under`, the
    /// directory's names IV, each candidate gets the name recovery would
    /// give it.
    pub(crate) fn candidates(
        &self,
        dir: &Path,
        ivs: &[(u64, Option<&OsStr>)],
        name: &str,
        meta: &fs::Metadata,
        plain_names: &HashSet<Vec<u8>>,
        propose_under: Option<u64>,
    ) -> Vec<Candidate> {
        let bytes = name.as_bytes();
        let encoding = NameEncoding::from_iface(&self.config.name_iface);
        let first = bytes.iter().position(|&b| !encoding.is_name_byte(b));
        let mut lens = Vec::new();
        if let Some(k) = first
            && k > 0
        {
            lens.push(k);
        }
        lens.extend((1..first.unwrap_or(bytes.len())).rev());

        let path = dir.join(name);
        let mut out = Vec::new();
        for &(iv, sidecar) in ivs {
            for &len in &lens {
                // Every byte before `first` is ASCII, so `len` is a boundary.
                let base = &name[..len];
                let Ok((plain, next_iv)) = self.cipher.decrypt_entry_name(base, iv) else {
                    continue;
                };
                // Canonical: the name the volume would write for `plain`.
                match self.cipher.encrypt_filename(&plain, iv) {
                    Ok((canonical, _)) if canonical == base => {}
                    _ => continue,
                }
                let path_iv = diriv::child_path_iv(self.config, next_iv);
                let Some(confidence) = self.verify(&path, meta, path_iv) else {
                    continue;
                };
                let suffix = name[len..].to_string();
                let proposed = propose_under.and_then(|names_iv| {
                    self.choose_name(dir, names_iv, &plain, &suffix, false, None)
                        .ok()
                        .map(|(n, _, _)| n)
                });
                out.push(Candidate {
                    sibling_exists: plain_names.contains(&plain),
                    plain,
                    suffix,
                    first_split: Some(len) == first,
                    confidence,
                    proposed,
                    sidecar: sidecar.map(OsStr::to_os_string),
                    path_iv,
                });
            }
        }
        // Stable: longer bases, and the live IV, stay ahead within each
        // group.
        out.sort_by_key(|c| {
            (
                c.confidence != Confidence::Verified,
                !c.sibling_exists,
                !c.first_split,
            )
        });
        out
    }

    /// Whether every block of a file is authenticated.
    fn blocks_authenticated(&self) -> bool {
        self.config.block_mode() == BlockMode::AesGcmSiv || self.config.block_mac_bytes > 0
    }

    /// Checks the entry at `path` against a base whose path IV is
    /// `path_iv`. `None` when the contents rule the base out. Contents that
    /// can't be read rule nothing out: the base stays probable, and the
    /// problem is noted.
    fn verify(&self, path: &Path, meta: &fs::Metadata, path_iv: u64) -> Option<Confidence> {
        let unreadable = |e: anyhow::Error| {
            self.note(path, e.context("couldn't read the entry to check its name"));
            Some(Confidence::Probable)
        };
        match EntryKind::of(meta) {
            EntryKind::File => {
                if !(self.config.file_contents_depend_on_path() && self.blocks_authenticated()) {
                    return Some(Confidence::Probable);
                }
                match self.verify_file(path, path_iv) {
                    Ok(FileCheck::Verified) => Some(Confidence::Verified),
                    Ok(FileCheck::NothingChecked) => Some(Confidence::Probable),
                    Ok(FileCheck::Mismatch) => None,
                    Err(e) => unreadable(e.into()),
                }
            }
            EntryKind::Dir => {
                if !self.config.children_depend_on_path() {
                    return Some(Confidence::Probable);
                }
                let children = match sorted_entries(path) {
                    Ok(children) => children,
                    Err(e) => return unreadable(e),
                };
                let names: Vec<_> = children
                    .iter()
                    .map(fs::DirEntry::file_name)
                    .filter(|n| !n.as_bytes().starts_with(b"."))
                    .collect();
                let decoded = names
                    .iter()
                    .filter(|n| {
                        n.to_str()
                            .is_some_and(|s| self.cipher.decrypt_entry_name(s, path_iv).is_ok())
                    })
                    .count();
                if names.is_empty() || (decoded > 0 && decoded < names.len()) {
                    Some(Confidence::Probable)
                } else if decoded == names.len() {
                    Some(Confidence::Verified)
                } else {
                    None
                }
            }
            EntryKind::Symlink => {
                if !self.config.symlink_target_depends_on_path() {
                    return Some(Confidence::Probable);
                }
                let target = match fs::read_link(path) {
                    Ok(target) => target,
                    Err(e) => return unreadable(e.into()),
                };
                symlink_target::decrypt(
                    self.cipher,
                    self.config,
                    target.as_os_str().as_bytes(),
                    path_iv,
                )
                .ok()
                .map(|_| Confidence::Verified)
            }
            EntryKind::Other => Some(Confidence::Probable),
        }
    }

    /// Authenticates the first block of the file at `path` that isn't a
    /// hole under the file IV a file with path IV `path_iv` has. A wrong
    /// base fails there, so the rest of the file isn't read. All-zero
    /// blocks, which a volume allowing holes reads as zeros, prove nothing
    /// and are passed over. An error means the file couldn't be read.
    fn verify_file(&self, path: &Path, path_iv: u64) -> io::Result<FileCheck> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let params = self.config.file_codec_params();
        if len <= params.header_size {
            return Ok(FileCheck::NothingChecked);
        }
        let file_iv = match self.config.read_file_iv(self.cipher, &file, path_iv) {
            Ok(iv) => iv,
            Err(FileIvError::Io(e)) => return Err(e),
            Err(FileIvError::ShortHeader | FileIvError::Header(_)) => {
                return Ok(FileCheck::Mismatch);
            }
        };
        let codec = BlockCodec::new(self.cipher, params.layout()?, false, false);
        let mut check = FileCheck::NothingChecked;
        for_each_block(&params, &file, len, |block_num, block, hole| {
            if hole {
                return Ok(ControlFlow::Continue(()));
            }
            check = match codec.decrypt_block(block_num, file_iv, block) {
                Ok(_) => FileCheck::Verified,
                Err(_) => FileCheck::Mismatch,
            };
            Ok(ControlFlow::Break(()))
        })?;
        Ok(check)
    }

    /// A free plaintext name for a recovered entry in `dir`, with its
    /// encrypted form and path IV. `requested` is the user's choice, used
    /// as given. Otherwise `plain` itself when `prefer_plain`, then
    /// `stem (suffix).ext`, numbered from 2 if that is taken, with the
    /// suffix shortened to fit the name length limit.
    pub(crate) fn choose_name(
        &self,
        dir: &Path,
        names_iv: u64,
        plain: &[u8],
        suffix: &str,
        prefer_plain: bool,
        requested: Option<&[u8]>,
    ) -> Result<(Vec<u8>, String, u64)> {
        let encrypt = |name: &[u8]| -> Result<Option<(String, u64)>> {
            check_entry_name(name)?;
            let (encrypted, next_iv) = self.cipher.encrypt_filename(name, names_iv)?;
            if encrypted.len() > NAME_MAX {
                return Ok(None);
            }
            Ok(Some((
                encrypted,
                diriv::child_path_iv(self.config, next_iv),
            )))
        };
        let free = |encrypted: &str| fs::symlink_metadata(dir.join(encrypted)).is_err();

        if let Some(name) = requested {
            let (encrypted, path_iv) =
                encrypt(name)?.ok_or_else(|| anyhow!("the name is too long"))?;
            if !free(&encrypted) {
                bail!("the name is taken");
            }
            return Ok((name.to_vec(), encrypted, path_iv));
        }
        if prefer_plain
            && let Some((encrypted, path_iv)) = encrypt(plain)?
            && free(&encrypted)
        {
            return Ok((plain.to_vec(), encrypted, path_iv));
        }

        let mut label: Vec<char> = clean_suffix(suffix).chars().collect();
        for number in 1..=MAX_NAME_ATTEMPTS {
            loop {
                let label_str: String = label.iter().collect();
                let name = recovery_name(plain, &label_str, number);
                match encrypt(&name)? {
                    Some((encrypted, path_iv)) => {
                        if free(&encrypted) {
                            return Ok((name, encrypted, path_iv));
                        }
                        break;
                    }
                    None if label.len() > 1 => {
                        label.pop();
                    }
                    None => bail!("no recovered name fits the name length limit"),
                }
            }
        }
        bail!("no free name for the recovered entry")
    }
}

/// A sync tool's suffix as the label inside a recovered name: leading
/// spaces, dots and underscores removed, and one pair of enclosing
/// parentheses.
fn clean_suffix(suffix: &str) -> String {
    let s = suffix.trim_start_matches([' ', '.', '_']).trim_end();
    let s = s
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(s)
        .trim();
    if s.is_empty() {
        "conflict".to_string()
    } else {
        s.to_string()
    }
}

/// `stem (label).ext`, or `stem (label) n.ext` from `number` 2 on. The
/// extension is a final `.` and 1 to 10 ASCII letters or digits, not at the
/// start of the name.
fn recovery_name(plain: &[u8], label: &str, number: u32) -> Vec<u8> {
    let ext_start = plain.iter().rposition(|&b| b == b'.').filter(|&i| {
        let ext = &plain[i + 1..];
        i > 0 && (1..=10).contains(&ext.len()) && ext.iter().all(u8::is_ascii_alphanumeric)
    });
    let (stem, ext) = plain.split_at(ext_start.unwrap_or(plain.len()));
    let mut name = stem.to_vec();
    name.extend_from_slice(format!(" ({label})").as_bytes());
    if number > 1 {
        name.extend_from_slice(format!(" {number}").as_bytes());
    }
    name.extend_from_slice(ext);
    name
}

/// Directory entries, sorted by name so runs are repeatable.
pub(crate) fn sorted_entries(dir: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut out = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<io::Result<Vec<_>>>()?;
    out.sort_by_cached_key(fs::DirEntry::file_name);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_names() {
        let name = |plain: &str, suffix: &str, n| {
            String::from_utf8(recovery_name(plain.as_bytes(), &clean_suffix(suffix), n)).unwrap()
        };
        assert_eq!(
            name("report.docx", ".sync-conflict-20230709-123456-ABCDEFG", 1),
            "report (sync-conflict-20230709-123456-ABCDEFG).docx"
        );
        assert_eq!(
            name(
                "report.docx",
                " (conflicted copy alice 2023-07-09 123456)",
                1
            ),
            "report (conflicted copy alice 2023-07-09 123456).docx"
        );
        assert_eq!(
            name("report.docx", ".conflict1", 1),
            "report (conflict1).docx"
        );
        assert_eq!(
            name("report.docx", ".conflict1", 3),
            "report (conflict1) 3.docx"
        );
        assert_eq!(name(".bashrc", "..path1", 1), ".bashrc (path1)");
        assert_eq!(name("archive.tar.gz", "_", 1), "archive.tar (conflict).gz");
        assert_eq!(
            name("notes", " (Case Conflict)", 1),
            "notes (Case Conflict)"
        );
        assert_eq!(
            name("a.verylongextension", ".x", 1),
            "a.verylongextension (x)"
        );
    }
}
