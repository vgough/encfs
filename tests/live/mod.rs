#![allow(dead_code)]
use anyhow::{anyhow, Context, Result};
use encfs::config::EncfsConfig;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

static LIVE_MUTEX: Mutex<()> = Mutex::new(());
static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub const LIVE_ENV: &str = "ENCFS_LIVE_TESTS";

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct LiveConfig {
    pub kind: LiveConfigKind,
    pub password: &'static str,
    pub block_size: u64,
    pub block_mac_bytes: u64,
    pub chained_name_iv: bool,
    pub external_iv_chaining: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum LiveConfigKind {
    Standard,
    Paranoia,
}

impl LiveConfigKind {
    pub fn fixture_filename(self) -> &'static str {
        match self {
            LiveConfigKind::Standard => "encfs6-std.xml",
            LiveConfigKind::Paranoia => "encfs6-paranoia.xml",
        }
    }
}

pub fn live_lock() -> MutexGuard<'static, ()> {
    // If a previous test panicked while holding the lock, allow subsequent tests to proceed.
    // The lock is purely for serialization (to avoid multiple FUSE mounts in parallel).
    LIVE_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn live_enabled() -> bool {
    match std::env::var(LIVE_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        Err(_) => false,
    }
}

pub fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn fixtures_dir() -> PathBuf {
    manifest_dir().join("tests/fixtures")
}

pub fn load_live_config(kind: LiveConfigKind) -> Result<LiveConfig> {
    let fixture_path = fixtures_dir().join(kind.fixture_filename());
    let cfg = EncfsConfig::load(&fixture_path)
        .with_context(|| format!("failed to load fixture config {:?}", fixture_path))?;

    Ok(LiveConfig {
        kind,
        password: "test",
        block_size: cfg.block_size as u64,
        block_mac_bytes: cfg.block_mac_bytes as u64,
        chained_name_iv: cfg.chained_name_iv,
        external_iv_chaining: cfg.external_iv_chaining,
    })
}

pub fn data_block_size(cfg: &LiveConfig) -> u64 {
    cfg.block_size - cfg.block_mac_bytes
}

pub fn unique_temp_dir(prefix: &str) -> Result<PathBuf> {
    let pid = std::process::id();
    let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{}_{}_{}_{}", prefix, pid, nanos, n));
    fs::create_dir_all(&dir).with_context(|| format!("failed to create temp dir {:?}", dir))?;
    Ok(dir)
}

pub fn path_has_tool(tool: &str) -> bool {
    if tool.contains('/') {
        return Path::new(tool).exists();
    }
    if let Ok(path) = std::env::var("PATH") {
        for p in std::env::split_paths(&path) {
            let cand = p.join(tool);
            if cand.exists() && cand.is_file() {
                return true;
            }
        }
    }
    false
}

fn run_quiet(cmd: &mut Command) -> io::Result<std::process::ExitStatus> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

fn mountinfo_has_mount(mount_point: &Path) -> io::Result<bool> {
    let mp = mount_point.to_string_lossy();
    let data = fs::read_to_string("/proc/self/mountinfo")?;
    for line in data.lines() {
        // Field 5 is mount point.
        // Avoid trying to fully unescape; our mountpoint paths contain no spaces.
        let mut parts = line.split_whitespace();
        let _id = parts.next();
        let _parent = parts.next();
        let _majmin = parts.next();
        let _root = parts.next();
        let mp_field = match parts.next() {
            Some(v) => v,
            None => continue,
        };
        if mp_field != mp {
            continue;
        }
        // Determine fstype after the " - " separator.
        if let Some((_pre, post)) = line.split_once(" - ") {
            let fstype = post.split_whitespace().next().unwrap_or("");
            if fstype.starts_with("fuse") {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[allow(dead_code)]
pub struct MountGuard {
    _lock: MutexGuard<'static, ()>,
    pub cfg: LiveConfig,
    pub backing_root: PathBuf,
    pub mount_point: PathBuf,
    child: Child,
    mounted: bool,
    cleanup_backing_root: bool,
}

impl MountGuard {
    pub fn mount(cfg: LiveConfig, read_only: bool) -> Result<Self> {
        ensure_live_ready()?;
        let lock = live_lock();

        let backing_root = init_backing_root(&cfg)?;
        let mount_point = unique_temp_dir("encfs_live_mount")?;

        Self::mount_at(lock, cfg, read_only, backing_root, mount_point, true)
    }

    pub fn mount_existing_backing_root(
        cfg: LiveConfig,
        read_only: bool,
        backing_root: PathBuf,
    ) -> Result<Self> {
        ensure_live_ready()?;
        let lock = live_lock();
        let mount_point = unique_temp_dir("encfs_live_mount")?;
        Self::mount_at(lock, cfg, read_only, backing_root, mount_point, false)
    }

    fn mount_at(
        lock: MutexGuard<'static, ()>,
        cfg: LiveConfig,
        read_only: bool,
        backing_root: PathBuf,
        mount_point: PathBuf,
        cleanup_backing_root: bool,
    ) -> Result<Self> {
        let encfs_bin = std::env::var("CARGO_BIN_EXE_encfs")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_encfs")));

        let mut cmd = Command::new(encfs_bin);
        cmd.arg("-f").arg("-S");
        if read_only {
            cmd.arg("-r");
        }
        cmd.arg(&backing_root).arg(&mount_point);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("failed to spawn encfs")?;
        let stdout_tail: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let stderr_tail: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        // Drain stdout/stderr so the child can't deadlock on a full pipe. Keep a small tail
        // for debugging mount failures/timeouts.
        const LOG_TAIL_MAX: usize = 64 * 1024;
        let spawn_drain = |mut r: std::process::ChildStdout,
                           tail: Arc<Mutex<Vec<u8>>>|
         -> std::thread::JoinHandle<()> {
            thread::spawn(move || {
                use std::io::Read;
                let mut buf = [0u8; 4096];
                loop {
                    match r.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut t = tail.lock().unwrap_or_else(|e| e.into_inner());
                            t.extend_from_slice(&buf[..n]);
                            if t.len() > LOG_TAIL_MAX {
                                let drop_n = t.len() - LOG_TAIL_MAX;
                                t.drain(0..drop_n);
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        if let Some(out) = child.stdout.take() {
            // ChildStdout and ChildStderr are distinct types; use separate closures.
            let tail = stdout_tail.clone();
            let _ = spawn_drain(out, tail);
        }
        if let Some(err) = child.stderr.take() {
            let tail = stderr_tail.clone();
            let _ = thread::spawn(move || {
                use std::io::Read;
                let mut r = err;
                let mut buf = [0u8; 4096];
                loop {
                    match r.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut t = tail.lock().unwrap_or_else(|e| e.into_inner());
                            t.extend_from_slice(&buf[..n]);
                            if t.len() > LOG_TAIL_MAX {
                                let drop_n = t.len() - LOG_TAIL_MAX;
                                t.drain(0..drop_n);
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        {
            let mut stdin = child.stdin.take().context("failed to open child stdin")?;
            stdin
                .write_all(format!("{}\n", cfg.password).as_bytes())
                .context("failed to write password to child stdin")?;
        }

        // Wait for mount to become active (or child to exit).
        let start = Instant::now();
        let timeout = std::env::var("ENCFS_LIVE_MOUNT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));
        let mut mounted = false;
        while start.elapsed() < timeout {
            if let Ok(true) = mountinfo_has_mount(&mount_point) {
                mounted = true;
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(anyhow!("encfs exited early with status {}", status));
            }
            thread::sleep(Duration::from_millis(50));
        }

        if !mounted {
            // Try to capture logs for debugging.
            let _ = child.kill();
            let _ = child.wait();
            let out =
                String::from_utf8_lossy(&stdout_tail.lock().unwrap_or_else(|e| e.into_inner()))
                    .to_string();
            let err =
                String::from_utf8_lossy(&stderr_tail.lock().unwrap_or_else(|e| e.into_inner()))
                    .to_string();
            return Err(anyhow!(
                "mount did not become ready in time; stdout tail:\n{}\nstderr tail:\n{}",
                out,
                err
            ));
        }

        Ok(Self {
            _lock: lock,
            cfg,
            backing_root,
            mount_point,
            child,
            mounted: true,
            cleanup_backing_root,
        })
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if self.mounted {
            let mp = self.mount_point.clone();
            // Best-effort unmount.
            let _ = if path_has_tool("fusermount3") {
                run_quiet(Command::new("fusermount3").arg("-u").arg(&mp))
            } else if path_has_tool("fusermount") {
                run_quiet(Command::new("fusermount").arg("-u").arg(&mp))
            } else {
                run_quiet(Command::new("umount").arg(&mp))
            };

            // Wait for child to exit; if it doesn't, kill it.
            let start = Instant::now();
            let timeout = Duration::from_secs(3);
            while start.elapsed() < timeout {
                if let Ok(Some(_)) = self.child.try_wait() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }

        // Cleanup temp dirs (best-effort).
        let _ = fs::remove_dir_all(&self.mount_point);
        if self.cleanup_backing_root {
            let _ = fs::remove_dir_all(&self.backing_root);
        }
    }
}

fn ensure_live_ready() -> Result<()> {
    if !live_enabled() {
        return Err(anyhow!(
            "{} not enabled; set {}=1 to run live mount tests",
            LIVE_ENV,
            LIVE_ENV
        ));
    }

    // Ensure we have an unmount tool to clean up.
    if !(path_has_tool("fusermount3") || path_has_tool("fusermount") || path_has_tool("umount")) {
        return Err(anyhow!(
            "missing unmount tool (need fusermount3/fusermount/umount in PATH)"
        ));
    }

    Ok(())
}

pub fn init_backing_root(cfg: &LiveConfig) -> Result<PathBuf> {
    let backing_root = unique_temp_dir("encfs_live_backing")?;

    // Copy fixture config into place.
    let fixture_path = fixtures_dir().join(cfg.kind.fixture_filename());
    fs::copy(&fixture_path, backing_root.join(".encfs6.xml")).with_context(|| {
        format!(
            "failed to copy fixture {:?} to backing root {:?}",
            fixture_path, backing_root
        )
    })?;

    Ok(backing_root)
}

pub fn list_non_dot_entries_recursive(root: &Path) -> Result<Vec<PathBuf>> {
    fn walk(acc: &mut Vec<PathBuf>, root: &Path) -> io::Result<()> {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') {
                continue;
            }
            let p = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                walk(acc, &p)?;
            } else {
                acc.push(p);
            }
        }
        Ok(())
    }

    let mut acc = Vec::new();
    walk(&mut acc, root).with_context(|| format!("failed to walk {:?}", root))?;
    Ok(acc)
}

pub fn backing_single_ciphertext_file(backing_root: &Path) -> Result<PathBuf> {
    let files = list_non_dot_entries_recursive(backing_root)?;
    let files: Vec<_> = files
        .into_iter()
        .filter(|p| p.is_file())
        .filter(|p| p.file_name() != Some(OsStr::new(".encfs6.xml")))
        .collect();
    if files.len() != 1 {
        return Err(anyhow!(
            "expected exactly 1 ciphertext file under {:?}, found {}: {:?}",
            backing_root,
            files.len(),
            files
        ));
    }
    Ok(files[0].clone())
}
