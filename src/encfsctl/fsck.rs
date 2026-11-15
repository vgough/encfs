//! `encfsctl fsck`: the command line around [`encfs::fsck`] (ADR 0007).

use anyhow::{Context, Result, bail};
use encfs::config::EncfsConfig;
use encfs::fsck::{
    Action, Candidate, Class, Confidence, ConfigCopyStatus, DEFAULT_OLDER_THAN, Finding, Fsck,
    Handler, Outcome,
};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(clap::Args)]
pub struct Options {
    #[arg(help = help_rootdir())]
    pub rootdir: PathBuf,
    #[arg(long, value_name = "FILE", help = help_config())]
    pub config: Option<PathBuf>,
    #[arg(long, help = help_fix())]
    pub fix: bool,
    #[arg(long, requires = "fix", help = help_yes())]
    pub yes: bool,
    #[arg(
        long = "older-than",
        value_name = "HOURS",
        default_value_t = DEFAULT_OLDER_THAN.as_secs() / 3600,
        help = help_older_than()
    )]
    pub older_than_hours: u64,
    #[arg(long, help = help_extpass())]
    pub extpass: Option<String>,
    #[arg(long, help = help_force())]
    pub force: bool,
    #[arg(short, long, help = help_verbose())]
    pub verbose: bool,
}

// Help text, translated at run time after the locale is set.
pub fn help_about() -> String {
    t!("help.encfsctl.fsck").to_string()
}

fn help_rootdir() -> String {
    t!("help.encfsctl.fsck_rootdir").to_string()
}

fn help_config() -> String {
    t!("help.encfsctl.fsck_config").to_string()
}

fn help_fix() -> String {
    t!("help.encfsctl.fsck_fix").to_string()
}

fn help_yes() -> String {
    t!("help.encfsctl.fsck_yes").to_string()
}

fn help_older_than() -> String {
    t!("help.encfsctl.fsck_older_than").to_string()
}

fn help_extpass() -> String {
    t!("help.encfsctl.fsck_extpass").to_string()
}

fn help_force() -> String {
    t!("help.encfsctl.fsck_force").to_string()
}

fn help_verbose() -> String {
    t!("help.encfsctl.fsck_verbose").to_string()
}

/// Runs the check. Returns whether problems are left, for the exit status.
pub fn run(opts: Options) -> Result<bool> {
    let root = super::canonical_root(&opts.rootdir);
    let config_path = match &opts.config {
        Some(path) => path.clone(),
        None => super::find_config_file(&root)?,
    };
    // A config given by name may be a sync tool's copy of one, whose name
    // still says which format it holds.
    let hint = config_path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(encfs::fsck::config_type_for_name);
    let config = EncfsConfig::load_with_type(&config_path, hint)
        .context(t!("ctl.error_failed_to_load_config"))?;

    if opts.fix {
        match mount_source_for(&root) {
            Ok(Some(source)) if !opts.force => {
                bail!(
                    "{}",
                    t!("ctl.fsck_mounted", root = root.display(), source = source)
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!("{}", t!("ctl.fsck_mount_check_failed", error = e)),
        }
        if !opts.yes && !io::stdin().is_terminal() {
            bail!("{}", t!("ctl.fsck_needs_terminal"));
        }
    }

    let password = Zeroizing::new(super::get_password(&config_path, opts.extpass)?);
    let cipher = config
        .get_cipher(&password)
        .context(t!("ctl.error_invalid_password"))?;

    if opts.fix {
        println!("{}", t!("ctl.fsck_fix_header", root = root.display()));
    } else {
        println!("{}", t!("ctl.fsck_report_header", root = root.display()));
    }

    let mode = match (opts.fix, opts.yes) {
        (false, _) => Mode::Report,
        (true, true) => Mode::Yes,
        (true, false) => Mode::Ask,
    };
    let mut handler = CliHandler {
        root: root.clone(),
        mode,
        verbose: opts.verbose,
        quit: false,
    };
    let mut fsck = Fsck::new(&root, &config, cipher.as_ref())
        .allow_changes(opts.fix)
        .with_password(&password)
        .with_config_file(&config_path)
        .older_than(Duration::from_secs(
            opts.older_than_hours.saturating_mul(3600),
        ));
    fsck.run(&mut handler)?;

    let stats = fsck.stats();
    println!();
    println!(
        "{}",
        t!(
            "ctl.fsck_summary",
            dirs = stats.dirs,
            entries = stats.entries,
            problems = stats.problems,
            fixed = stats.fixed,
            left = stats.unresolved()
        )
    );
    Ok(stats.unresolved() > 0)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Report,
    Yes,
    Ask,
}

struct CliHandler {
    root: PathBuf,
    mode: Mode,
    verbose: bool,
    /// The user chose to stop: skip everything else.
    quit: bool,
}

fn lossy(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

fn confidence(c: &Candidate) -> String {
    let level = match c.confidence {
        Confidence::Verified => t!("ctl.fsck_verified"),
        Confidence::Probable => t!("ctl.fsck_probable"),
    };
    if c.sibling_exists {
        level.into_owned()
    } else {
        format!("{level}, {}", t!("ctl.fsck_no_sibling"))
    }
}

fn format_age(age: Option<Duration>) -> String {
    let Some(age) = age else {
        return "?".into();
    };
    let hours = age.as_secs() / 3600;
    if hours >= 48 {
        format!("{}d", hours / 24)
    } else if hours > 0 {
        format!("{hours}h")
    } else {
        format!("{}m", age.as_secs() / 60)
    }
}

impl CliHandler {
    fn describe(&self, f: &Finding) {
        let path = f.path();
        let shown = path.strip_prefix(&self.root).unwrap_or(&path);
        println!();
        println!("{}", shown.display());
        println!(
            "    {}",
            t!("ctl.fsck_in_dir", path = f.plain_dir.display())
        );
        let line = match &f.class {
            Class::SidecarCopy {
                identical: true, ..
            } => t!("ctl.fsck_sidecar_copy_identical").into_owned(),
            Class::SidecarCopy { dependents, .. } => {
                t!("ctl.fsck_sidecar_copy_different", count = dependents).into_owned()
            }
            Class::ConfigCopy { status, .. } => match status {
                ConfigCopyStatus::Equivalent => t!("ctl.fsck_config_copy_equivalent"),
                ConfigCopyStatus::Different => t!("ctl.fsck_config_copy_different"),
                ConfigCopyStatus::Unreadable(error) => {
                    t!("ctl.fsck_config_copy_unreadable", error = error)
                }
                ConfigCopyStatus::Unchecked => t!("ctl.fsck_config_copy_unchecked"),
            }
            .into_owned(),
            Class::ToolState => t!("ctl.fsck_tool_state").into_owned(),
            Class::Temp { age, stale: true } => {
                t!("ctl.fsck_temp_stale", age = format_age(*age)).into_owned()
            }
            Class::Temp { age, stale: false } => {
                t!("ctl.fsck_temp_young", age = format_age(*age)).into_owned()
            }
            Class::ConflictCopy { candidates } => {
                let mut text = t!("ctl.fsck_conflict_copy").into_owned();
                for (i, c) in candidates.iter().enumerate() {
                    text.push_str("\n      ");
                    text.push_str(&t!(
                        "ctl.fsck_candidate",
                        index = i + 1,
                        name = lossy(&c.plain),
                        confidence = confidence(c),
                        suffix = c.suffix
                    ));
                }
                text
            }
            Class::ForeignName { plain, sidecar, .. } => t!(
                "ctl.fsck_foreign_name",
                name = lossy(plain),
                sidecar = sidecar.to_string_lossy()
            )
            .into_owned(),
            Class::Unknown => t!("ctl.fsck_unknown").into_owned(),
            Class::UnreadableDirectoryIv { error } => {
                t!("ctl.fsck_unreadable_diriv", error = error).into_owned()
            }
        };
        println!("    {line}");
        println!("    {}", self.default_text(f));
    }

    fn default_text(&self, f: &Finding) -> String {
        match f.default_action() {
            Action::Delete => t!("ctl.fsck_default_delete").into_owned(),
            Action::Recover { candidate, .. } => match f.proposed(candidate) {
                Some(name) => t!("ctl.fsck_default_recover", name = lossy(name)).into_owned(),
                None => t!("ctl.fsck_default_none").into_owned(),
            },
            Action::Skip => {
                let choices = f.choices();
                if choices.recover || choices.delete {
                    t!("ctl.fsck_default_none").into_owned()
                } else {
                    t!("ctl.fsck_default_leave").into_owned()
                }
            }
        }
    }

    fn ask(&mut self, f: &Finding) -> Result<Action> {
        let choices = f.choices();
        if !choices.recover && !choices.delete {
            return Ok(Action::Skip);
        }
        let default = f.default_action();
        let default_key = match default {
            Action::Recover { .. } => 'r',
            Action::Delete => 'd',
            Action::Skip => 's',
        };
        let mut options = Vec::new();
        if choices.recover {
            options.push(t!("ctl.fsck_option_recover").into_owned());
            options.push(t!("ctl.fsck_option_recover_as").into_owned());
        }
        if choices.delete {
            options.push(t!("ctl.fsck_option_delete").into_owned());
        }
        options.push(t!("ctl.fsck_option_skip").into_owned());
        options.push(t!("ctl.fsck_option_quit").into_owned());
        loop {
            let answer = prompt(&format!(
                "    {} ({}) ",
                options.join(", "),
                t!("ctl.fsck_default_key", key = default_key)
            ))?;
            let Some(answer) = answer else {
                return Ok(self.end_of_input());
            };
            let key = answer.trim().chars().next().unwrap_or(default_key);
            match key.to_ascii_lowercase() {
                'r' if choices.recover => {
                    if answer.trim().is_empty() && matches!(default, Action::Recover { .. }) {
                        return Ok(default);
                    }
                    let Some(candidate) = self.ask_candidate(f)? else {
                        return Ok(self.end_of_input());
                    };
                    return Ok(Action::Recover {
                        candidate,
                        name: None,
                    });
                }
                'a' if choices.recover => {
                    let Some(candidate) = self.ask_candidate(f)? else {
                        return Ok(self.end_of_input());
                    };
                    let Some(name) = prompt(&format!("    {} ", t!("ctl.fsck_prompt_name")))?
                    else {
                        return Ok(self.end_of_input());
                    };
                    let name = name.trim();
                    if name.is_empty() {
                        continue;
                    }
                    return Ok(Action::Recover {
                        candidate,
                        name: Some(name.as_bytes().to_vec()),
                    });
                }
                'd' if choices.delete => return Ok(Action::Delete),
                's' => return Ok(Action::Skip),
                'q' => {
                    self.quit = true;
                    return Ok(Action::Skip);
                }
                _ => println!("    {}", t!("ctl.fsck_invalid_choice")),
            }
        }
    }

    /// End of input at a prompt: skip this finding and stop asking, as
    /// quitting does, so the rest of the tree is still checked and counted.
    fn end_of_input(&mut self) -> Action {
        self.quit = true;
        Action::Skip
    }

    /// Which base to recover, when there is more than one. `None` at end
    /// of input.
    fn ask_candidate(&self, f: &Finding) -> Result<Option<usize>> {
        let count = f.candidate_count();
        if count == 1 {
            return Ok(Some(0));
        }
        loop {
            let Some(answer) = prompt(&format!(
                "    {} ",
                t!("ctl.fsck_prompt_candidate", count = count)
            ))?
            else {
                return Ok(None);
            };
            match answer.trim().parse::<usize>() {
                Ok(n) if (1..=count).contains(&n) => return Ok(Some(n - 1)),
                _ => println!("    {}", t!("ctl.fsck_invalid_choice")),
            }
        }
    }
}

/// Prints `text` and reads a line, or `None` at end of input.
fn prompt(text: &str) -> Result<Option<String>> {
    print!("{text}");
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        println!();
        return Ok(None);
    }
    Ok(Some(line))
}

impl Handler for CliHandler {
    fn decide(&mut self, f: &Finding) -> Result<Action> {
        if !f.is_problem() && !self.verbose {
            return Ok(Action::Skip);
        }
        self.describe(f);
        if self.quit {
            return Ok(Action::Skip);
        }
        match self.mode {
            Mode::Report => Ok(Action::Skip),
            Mode::Yes => Ok(f.default_action()),
            Mode::Ask => self.ask(f),
        }
    }

    fn outcome(&mut self, _f: &Finding, _action: &Action, result: &Result<Outcome>) {
        match result {
            Ok(Outcome::Recovered { name }) => {
                println!("    {}", t!("ctl.fsck_recovered", name = lossy(name)));
            }
            Ok(Outcome::Deleted) => println!("    {}", t!("ctl.fsck_deleted")),
            Err(e) => println!("    {}", t!("ctl.fsck_failed", error = format!("{e:#}"))),
        }
    }

    fn warning(&mut self, path: &Path, error: &anyhow::Error) {
        print_warning(path, error);
    }
}

/// Reports a path the scan couldn't check (also used by `showcruft`).
pub fn print_warning(path: &Path, error: &anyhow::Error) {
    eprintln!(
        "{}",
        t!(
            "ctl.fsck_warning",
            path = path.display(),
            error = format!("{error:#}")
        )
    );
}

/// The mount source naming `root` in the mount table, if a forward mount of
/// it is listed. `encfs` mounts as `encfs@<canonical root>` unless
/// `--fsname` overrides it.
fn mount_source_for(root: &Path) -> io::Result<Option<String>> {
    let mut wanted = vec![encfs::mount_source_name(&encfs::default_fsname(root))];
    if let Ok(absolute) = std::path::absolute(root) {
        wanted.push(encfs::mount_source_name(&encfs::default_fsname(&absolute)));
    }
    Ok(mount_sources()?
        .into_iter()
        .find(|source| wanted.contains(source)))
}

#[cfg(target_os = "linux")]
fn mount_sources() -> io::Result<Vec<String>> {
    let table = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(table
        .lines()
        .filter_map(|line| {
            let (_, rest) = line.split_once(" - ")?;
            let mut fields = rest.split(' ');
            fields.next()?; // filesystem type
            fields.next().map(unescape_mountinfo)
        })
        .collect())
}

/// Undoes the `\ooo` octal escapes `/proc/self/mountinfo` uses for spaces,
/// tabs, newlines and backslashes.
#[cfg(any(target_os = "linux", test))]
fn unescape_mountinfo(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = match bytes.get(i..i + 4) {
            Some([b'\\', digits @ ..]) if digits.iter().all(|b| (b'0'..=b'7').contains(b)) => {
                let value = digits
                    .iter()
                    .fold(0u32, |n, &b| n * 8 + u32::from(b - b'0'));
                u8::try_from(value).ok()
            }
            _ => None,
        };
        if let Some(value) = octal {
            out.push(value);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn mount_sources() -> io::Result<Vec<String>> {
    let mut mounts: *mut libc::statfs = std::ptr::null_mut();
    // SAFETY: getmntinfo points `mounts` at `count` entries in a buffer it
    // owns, valid until the next call; they are copied out before returning.
    let count = unsafe { libc::getmntinfo(&mut mounts, libc::MNT_NOWAIT) };
    if count <= 0 || mounts.is_null() {
        return Err(io::Error::last_os_error());
    }
    let entries = unsafe { std::slice::from_raw_parts(mounts, count as usize) };
    Ok(entries
        .iter()
        .map(|entry| {
            // SAFETY: the kernel NUL-terminates f_mntfromname.
            unsafe { std::ffi::CStr::from_ptr(entry.f_mntfromname.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        })
        .collect())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
fn mount_sources() -> io::Result<Vec<String>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_escapes_are_undone() {
        assert_eq!(unescape_mountinfo(r"encfs@/a\040b"), "encfs@/a b");
        assert_eq!(unescape_mountinfo(r"encfs@/a\134b"), r"encfs@/a\b");
        assert_eq!(unescape_mountinfo(r"x\04"), r"x\04");
        assert_eq!(unescape_mountinfo("plain"), "plain");
    }

    #[test]
    fn ages_are_short() {
        assert_eq!(format_age(Some(Duration::from_secs(90))), "1m");
        assert_eq!(format_age(Some(Duration::from_secs(5 * 3600))), "5h");
        assert_eq!(format_age(Some(Duration::from_secs(72 * 3600))), "3d");
        assert_eq!(format_age(None), "?");
    }
}
