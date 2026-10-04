//! Inactivity lock for on-demand mounts.
//!
//! An [`IdleLock`] sits in front of the FUSE operations of a mounted
//! filesystem. After `timeout` with no user activity it locks, and from then
//! on operations that would expose file contents or names are refused until
//! the [`Authenticator`] (Touch ID on macOS) succeeds again.
//!
//! Operations are classified with [`Access`]:
//!
//! - [`Access::Probe`]: metadata the OS polls constantly (statfs, getattr,
//!   lookup, access, and calls on handles that are already open such as fsync
//!   or flock). Always allowed and never counted as activity, so background
//!   polling neither keeps the mount unlocked nor triggers prompts.
//! - [`Access::XattrRead`]: getxattr/listxattr. Finder and Spotlight probe
//!   these constantly, so they never count as activity and never prompt, but
//!   values can hold user data, so they are refused while locked.
//! - [`Access::HandleWrite`]: write on a handle opened while unlocked. Always
//!   allowed, so data the kernel flushes after the lock engages is not lost;
//!   counts as activity while unlocked.
//! - [`Access::Data`]: everything else (open, read, readdir, readlink, create,
//!   and every namespace or attribute change). Counts as activity; while
//!   locked, blocks on a fresh authentication prompt.
//!
//! Requests from processes named in the ignore list (Spotlight, Time Machine
//! and similar background services) never count as activity and never
//! trigger a prompt: while locked they are simply refused.

use log::{info, warn};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// How long to refuse locked requests without prompting after a failed or
/// cancelled authentication, so a retrying application cannot stack prompts.
pub const FAILURE_COOLDOWN: Duration = Duration::from_secs(10);

/// Background services that probe or index volumes on macOS. Their requests
/// never count as activity and never trigger an authentication prompt.
pub const DEFAULT_IGNORED_PROCESSES: &[&str] = &[
    // Spotlight
    "mds",
    "mds_stores",
    "mdworker",
    "mdworker_shared",
    "mdsync",
    "mdbulkimport",
    "corespotlightd",
    // File system events, Time Machine, document versions
    "fseventsd",
    "backupd",
    "backupd-helper",
    "revisiond",
    // Quick Look thumbnail generation (not the user-driven space-bar preview)
    "QuickLookSatellite",
    "com.apple.quicklook.ThumbnailsAgent",
    // Malware and code-signing scans
    "XprotectService",
    "XProtect",
    "syspolicyd",
];

/// Longest process name the OS reports; longer configured names are compared
/// on this prefix.
#[cfg(target_os = "macos")]
const MAX_PROCESS_NAME: usize = 32; // 2 * MAXCOMLEN
#[cfg(not(target_os = "macos"))]
const MAX_PROCESS_NAME: usize = 15; // TASK_COMM_LEN - 1 on Linux

/// How an operation interacts with the lock. See the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Probe,
    XattrRead,
    HandleWrite,
    Data,
}

/// Interactive user authentication used to unlock.
pub trait Authenticator: Send + Sync {
    /// Prompt the user and block until they pass or fail. The error is a
    /// human-readable reason for logging.
    fn authenticate(&self) -> Result<(), String>;
}

type Clock = Box<dyn Fn() -> Duration + Send + Sync>;
type ProcessNamer = Box<dyn Fn(u32) -> Option<String> + Send + Sync>;

struct State {
    unlocked: bool,
    last_activity: Duration,
    prompting: bool,
    cooldown_until: Option<Duration>,
}

/// Locks data access after a period of inactivity. Starts unlocked; the
/// caller is expected to have authenticated the user before mounting.
pub struct IdleLock {
    timeout: Duration,
    authenticator: Box<dyn Authenticator>,
    ignored: Vec<String>,
    clock: Clock,
    process_name: ProcessNamer,
    state: Mutex<State>,
    prompt_done: Condvar,
}

impl IdleLock {
    pub fn new(
        timeout: Duration,
        authenticator: Box<dyn Authenticator>,
        ignored: impl IntoIterator<Item = String>,
    ) -> Self {
        Self::with_hooks(
            timeout,
            authenticator,
            ignored,
            Box::new(monotonic_now),
            Box::new(process_name),
        )
    }

    fn with_hooks(
        timeout: Duration,
        authenticator: Box<dyn Authenticator>,
        ignored: impl IntoIterator<Item = String>,
        clock: Clock,
        process_name: ProcessNamer,
    ) -> Self {
        let now = clock();
        Self {
            timeout,
            authenticator,
            ignored: ignored
                .into_iter()
                .map(|name| truncate_name(&name).to_string())
                .collect(),
            clock,
            process_name,
            state: Mutex::new(State {
                unlocked: true,
                last_activity: now,
                prompting: false,
                cooldown_until: None,
            }),
            prompt_done: Condvar::new(),
        }
    }

    /// Decide whether an operation from process `pid` may proceed, recording
    /// activity and prompting for authentication as needed. Returns `EACCES`
    /// when access is refused.
    pub fn check(&self, access: Access, pid: u32) -> Result<(), libc::c_int> {
        if access == Access::Probe {
            return Ok(());
        }
        // Only look up the caller when its identity matters.
        let background =
            matches!(access, Access::HandleWrite | Access::Data) && self.is_ignored(pid);

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let now = (self.clock)();
            if state.unlocked && now.saturating_sub(state.last_activity) >= self.timeout {
                state.unlocked = false;
                info!("Locked after {} s without activity", self.timeout.as_secs());
            }

            if state.unlocked {
                if !background && access != Access::XattrRead {
                    state.last_activity = now;
                }
                return Ok(());
            }

            match access {
                Access::Probe => unreachable!(),
                Access::HandleWrite => return Ok(()),
                Access::XattrRead => return Err(libc::EACCES),
                Access::Data => {}
            }
            if background {
                return Err(libc::EACCES);
            }
            if state.prompting {
                // Another request is already showing a prompt; share its
                // outcome instead of stacking a second one.
                state = self
                    .prompt_done
                    .wait_while(state, |s| s.prompting)
                    .unwrap_or_else(|e| e.into_inner());
                if !state.unlocked {
                    return Err(libc::EACCES);
                }
                continue;
            }
            if state.cooldown_until.is_some_and(|until| now < until) {
                return Err(libc::EACCES);
            }

            state.prompting = true;
            drop(state);
            let result = self.authenticator.authenticate();
            state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.prompting = false;
            let now = (self.clock)();
            match result {
                Ok(()) => {
                    info!("Unlocked");
                    state.unlocked = true;
                    state.last_activity = now;
                    state.cooldown_until = None;
                }
                Err(reason) => {
                    warn!("Unlock failed: {}", reason);
                    state.cooldown_until = Some(now + FAILURE_COOLDOWN);
                }
            }
            self.prompt_done.notify_all();
            return if state.unlocked {
                Ok(())
            } else {
                Err(libc::EACCES)
            };
        }
    }

    fn is_ignored(&self, pid: u32) -> bool {
        // pid 0 is the kernel itself (e.g. writeback), never the user.
        if pid == 0 {
            return true;
        }
        if self.ignored.is_empty() {
            return false;
        }
        (self.process_name)(pid)
            .is_some_and(|name| self.ignored.iter().any(|i| i == truncate_name(&name)))
    }
}

fn truncate_name(name: &str) -> &str {
    let mut end = name.len().min(MAX_PROCESS_NAME);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

/// A clock that keeps running while the machine sleeps, so the idle timeout
/// counts time spent with the lid closed.
fn monotonic_now() -> Duration {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;
    // CLOCK_MONOTONIC on macOS continues to advance during sleep, unlike
    // std::time::Instant (CLOCK_UPTIME_RAW).
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;

    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec.
    if unsafe { libc::clock_gettime(CLOCK, &mut ts) } != 0 {
        // Never fails for these clock ids; fall back to "now never moves",
        // which can only keep the lock engaged longer, not shorter.
        return Duration::ZERO;
    }
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

#[cfg(target_os = "macos")]
fn process_name(pid: u32) -> Option<String> {
    let mut buf = [0u8; 2 * MAX_PROCESS_NAME + 1];
    // SAFETY: the buffer is valid for `buf.len()` bytes.
    let len = unsafe {
        libc::proc_name(
            pid as libc::c_int,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    (len > 0).then(|| String::from_utf8_lossy(&buf[..len as usize]).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|name| name.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    const TIMEOUT: Duration = Duration::from_secs(60);
    const USER: u32 = 100;
    const SPOTLIGHT: u32 = 200;

    #[derive(Clone, Default)]
    struct Fake {
        now_ms: Arc<AtomicU64>,
        prompts: Arc<AtomicUsize>,
        succeed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Fake {
        fn advance(&self, d: Duration) {
            self.now_ms
                .fetch_add(d.as_millis() as u64, Ordering::SeqCst);
        }
        fn prompts(&self) -> usize {
            self.prompts.load(Ordering::SeqCst)
        }
    }

    impl Authenticator for Fake {
        fn authenticate(&self) -> Result<(), String> {
            self.prompts.fetch_add(1, Ordering::SeqCst);
            if self.succeed.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err("cancelled".into())
            }
        }
    }

    fn lock(fake: &Fake) -> IdleLock {
        fake.succeed.store(true, Ordering::SeqCst);
        let clock = fake.clone();
        IdleLock::with_hooks(
            TIMEOUT,
            Box::new(fake.clone()),
            DEFAULT_IGNORED_PROCESSES.iter().map(|s| s.to_string()),
            Box::new(move || Duration::from_millis(clock.now_ms.load(Ordering::SeqCst))),
            Box::new(|pid| match pid {
                SPOTLIGHT => Some("mdworker_shared".into()),
                _ => Some("zsh".into()),
            }),
        )
    }

    #[test]
    fn unlocked_until_idle_timeout() {
        let fake = Fake::default();
        let lock = lock(&fake);
        fake.advance(TIMEOUT / 2);
        assert_eq!(lock.check(Access::Data, USER), Ok(()));
        // The read above reset the timer.
        fake.advance(TIMEOUT / 2 + Duration::from_secs(1));
        assert_eq!(lock.check(Access::Data, USER), Ok(()));
        assert_eq!(fake.prompts(), 0);
    }

    #[test]
    fn locked_data_access_prompts_and_unlocks() {
        let fake = Fake::default();
        let lock = lock(&fake);
        fake.advance(TIMEOUT);
        assert_eq!(lock.check(Access::Data, USER), Ok(()));
        assert_eq!(fake.prompts(), 1);
        assert_eq!(lock.check(Access::Data, USER), Ok(()));
        assert_eq!(fake.prompts(), 1);
    }

    #[test]
    fn probes_do_not_count_as_activity_or_prompt() {
        let fake = Fake::default();
        let lock = lock(&fake);
        for _ in 0..3 {
            fake.advance(TIMEOUT / 4);
            assert_eq!(lock.check(Access::Probe, USER), Ok(()));
            assert_eq!(lock.check(Access::XattrRead, USER), Ok(()));
        }
        fake.advance(TIMEOUT / 4);
        // Now locked: probes still pass, xattr reads are refused quietly.
        assert_eq!(lock.check(Access::Probe, USER), Ok(()));
        assert_eq!(lock.check(Access::XattrRead, USER), Err(libc::EACCES));
        assert_eq!(fake.prompts(), 0);
    }

    #[test]
    fn background_processes_do_not_count_or_prompt() {
        let fake = Fake::default();
        let lock = lock(&fake);
        fake.advance(TIMEOUT / 2);
        assert_eq!(lock.check(Access::Data, SPOTLIGHT), Ok(()));
        fake.advance(TIMEOUT / 2);
        assert_eq!(lock.check(Access::Data, SPOTLIGHT), Err(libc::EACCES));
        assert_eq!(lock.check(Access::Data, 0), Err(libc::EACCES));
        assert_eq!(fake.prompts(), 0);
    }

    #[test]
    fn writes_on_open_handles_survive_the_lock() {
        let fake = Fake::default();
        let lock = lock(&fake);
        fake.advance(TIMEOUT);
        assert_eq!(lock.check(Access::HandleWrite, USER), Ok(()));
        // ...but do not unlock.
        assert_eq!(lock.check(Access::XattrRead, USER), Err(libc::EACCES));
        assert_eq!(fake.prompts(), 0);
    }

    #[test]
    fn failed_prompt_starts_cooldown() {
        let fake = Fake::default();
        let lock = lock(&fake);
        fake.succeed.store(false, Ordering::SeqCst);
        fake.advance(TIMEOUT);
        assert_eq!(lock.check(Access::Data, USER), Err(libc::EACCES));
        assert_eq!(lock.check(Access::Data, USER), Err(libc::EACCES));
        assert_eq!(fake.prompts(), 1);

        fake.succeed.store(true, Ordering::SeqCst);
        fake.advance(FAILURE_COOLDOWN);
        assert_eq!(lock.check(Access::Data, USER), Ok(()));
        assert_eq!(fake.prompts(), 2);
    }

    #[test]
    fn concurrent_requests_share_one_prompt() {
        struct Slow(Fake);
        impl Authenticator for Slow {
            fn authenticate(&self) -> Result<(), String> {
                std::thread::sleep(Duration::from_millis(50));
                self.0.authenticate()
            }
        }
        let fake = Fake::default();
        fake.succeed.store(true, Ordering::SeqCst);
        let clock = fake.clone();
        let threads = 4;
        let lock = Arc::new(IdleLock::with_hooks(
            TIMEOUT,
            Box::new(Slow(fake.clone())),
            Vec::new(),
            Box::new(move || Duration::from_millis(clock.now_ms.load(Ordering::SeqCst))),
            Box::new(|_| None),
        ));
        fake.advance(TIMEOUT);
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let lock = lock.clone();
                std::thread::spawn(move || lock.check(Access::Data, USER))
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), Ok(()));
        }
        assert_eq!(fake.prompts(), 1);
    }

    #[test]
    fn long_names_match_on_the_reported_prefix() {
        let long = "com.apple.quicklook.ThumbnailsAgent";
        let reported = &long[..MAX_PROCESS_NAME];
        assert_eq!(truncate_name(long), truncate_name(reported));
    }
}
