mod filesystem_support;

use anyhow::{Context, Result, anyhow, bail};
use filesystem_support::{
    BenchmarkResult, HostContext, SCHEMA_VERSION, Workload, calculate_deltas, ensure_compatible,
    load_result, parse_mdtest_output, save_result_atomic, workload_description,
};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const PASSWORD: &str = "encfs-filesystem-benchmark";
const LOG_TAIL_BYTES: usize = 64 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("filesystem benchmark failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let workload = Workload {
        ranks: env_value("BENCH_PROCS", 1)?,
        items_per_rank: env_value("BENCH_ITEMS", 1_000)?,
        iterations: env_value("BENCH_ITERATIONS", 5)?,
        bytes_per_file: env_value("BENCH_BYTES", 4_096)?,
    };
    validate_workload(&workload)?;

    let baseline_path = env::var_os("BENCH_BASELINE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".benchmarks/filesystem-baseline.json"));
    let save_baseline = env_flag("BENCH_SAVE_BASELINE");
    let baseline = if save_baseline {
        None
    } else {
        let result = load_result(&baseline_path).with_context(|| {
            format!(
                "a compatible baseline is required before running; create one with `task benchmark-save-baseline` (expected {})",
                baseline_path.display()
            )
        })?;
        ensure_compatible(&result, &workload)?;
        Some(result)
    };

    let mdtest_bin = env::var("MDTEST_BIN").unwrap_or_else(|_| "mdtest".to_string());
    require_tool(&mdtest_bin, "install IOR/mdtest or set MDTEST_BIN")?;
    let mpirun_bin = env::var("MPIRUN_BIN").unwrap_or_else(|_| "mpirun".to_string());
    if workload.ranks > 1 {
        require_tool(&mpirun_bin, "install MPI or set MPIRUN_BIN")?;
    }

    println!("Filesystem benchmark: {}", workload_description(&workload));
    let benchmark = run_filesystem_benchmark(&workload, &mdtest_bin, &mpirun_bin)?;
    let combined_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&benchmark.output.stdout),
        String::from_utf8_lossy(&benchmark.output.stderr)
    );
    let (mdtest_version, metrics) = parse_mdtest_output(&combined_output).with_context(|| {
        format!(
            "failed to parse mdtest output{}",
            benchmark.encfs_diagnostics
        )
    })?;
    let result = BenchmarkResult {
        schema_version: SCHEMA_VERSION,
        timestamp: chrono::Utc::now().to_rfc3339(),
        git_revision: git_revision(),
        mdtest_version,
        host: HostContext {
            os: sysinfo::System::name().unwrap_or_else(|| env::consts::OS.to_string()),
            os_version: sysinfo::System::os_version().unwrap_or_else(|| "unknown".to_string()),
            architecture: env::consts::ARCH.to_string(),
            cpu: cpu_brand(),
        },
        workload,
        metrics,
    };

    if save_baseline {
        save_result_atomic(&baseline_path, &result)?;
        println!(
            "Saved filesystem benchmark baseline to {}",
            baseline_path.display()
        );
    } else {
        print_comparison(baseline.as_ref().expect("baseline was loaded"), &result)?;
    }
    Ok(())
}

fn run_filesystem_benchmark(
    workload: &Workload,
    mdtest_bin: &str,
    mpirun_bin: &str,
) -> Result<CompletedBenchmark> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let release_dir = target_dir(&manifest_dir).join("release");
    let encfsctl = release_dir.join(executable_name("encfsctl"));
    let encfs = release_dir.join(executable_name("encfs"));
    for binary in [&encfsctl, &encfs] {
        if !binary.is_file() {
            bail!(
                "release binary {} is missing; run `cargo build --release` first",
                binary.display()
            );
        }
    }

    let temporary = tempfile::Builder::new()
        .prefix("encfs-filesystem-benchmark-")
        .tempdir()
        .context("failed to create benchmark temporary directory")?;
    let encrypted = temporary.path().join("encrypted");
    let mount_point = temporary.path().join("mount");
    fs::create_dir(&encrypted)?;
    fs::create_dir(&mount_point)?;

    let create_output = run_with_input(
        Command::new(&encfsctl)
            .arg("new")
            .arg("--stdinpass")
            .arg(&encrypted),
        format!("{PASSWORD}\n").as_bytes(),
    )
    .with_context(|| {
        format!(
            "failed to create fresh V7 filesystem in {}",
            encrypted.display()
        )
    })?;
    ensure_success("encfsctl new", &create_output)?;

    let timeout = Duration::from_secs(env_value("BENCH_MOUNT_TIMEOUT_SECS", 30)?);
    let mut mounted = MountedEncfs::start(&encfs, &encrypted, &mount_point, timeout)?;

    let benchmark = run_mdtest(workload, mdtest_bin, mpirun_bin, &mount_point);
    let cleanup = mounted.cleanup();
    let encfs_diagnostics = mounted.log_diagnostics();
    match (benchmark, cleanup) {
        (Ok(output), Ok(())) => {
            ensure_success("mdtest", &output)
                .map_err(|error| anyhow!("{error:#}{encfs_diagnostics}"))?;
            Ok(CompletedBenchmark {
                output,
                encfs_diagnostics,
            })
        }
        (Err(error), Ok(())) => Err(anyhow!("{error:#}{encfs_diagnostics}")),
        (Ok(_), Err(cleanup_error)) => Err(anyhow!("{cleanup_error:#}{encfs_diagnostics}")),
        (Err(error), Err(cleanup_error)) => Err(anyhow!(
            "{error:#}; cleanup also failed: {cleanup_error:#}{encfs_diagnostics}"
        )),
    }
}

struct CompletedBenchmark {
    output: Output,
    encfs_diagnostics: String,
}

fn run_mdtest(
    workload: &Workload,
    mdtest_bin: &str,
    mpirun_bin: &str,
    mount_point: &Path,
) -> Result<Output> {
    let mut command = if workload.ranks > 1 {
        let mut command = Command::new(mpirun_bin);
        command
            .arg("-n")
            .arg(workload.ranks.to_string())
            .arg(mdtest_bin);
        command
    } else {
        Command::new(mdtest_bin)
    };
    command
        .arg("-d")
        .arg(mount_point)
        .arg("-n")
        .arg(workload.items_per_rank.to_string())
        .arg("-i")
        .arg(workload.iterations.to_string())
        .arg("-w")
        .arg(workload.bytes_per_file.to_string())
        .arg("-e")
        .arg(workload.bytes_per_file.to_string())
        .stdin(Stdio::null());
    command.output().with_context(|| {
        format!(
            "failed to start mdtest using {}; install IOR/mdtest or set MDTEST_BIN",
            mdtest_bin
        )
    })
}

struct MountedEncfs {
    mount_point: PathBuf,
    child: Child,
    stdout_tail: Arc<Mutex<Vec<u8>>>,
    stderr_tail: Arc<Mutex<Vec<u8>>>,
    mounted: bool,
}

impl MountedEncfs {
    fn start(
        encfs: &Path,
        encrypted: &Path,
        mount_point: &Path,
        timeout: Duration,
    ) -> Result<Self> {
        let mut child = Command::new(encfs)
            .arg("-f")
            .arg("-S")
            .arg(encrypted)
            .arg(mount_point)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start release encfs binary {}", encfs.display()))?;

        let stdout_tail = Arc::new(Mutex::new(Vec::new()));
        let stderr_tail = Arc::new(Mutex::new(Vec::new()));
        if let Some(stdout) = child.stdout.take() {
            drain_logs(stdout, stdout_tail.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            drain_logs(stderr, stderr_tail.clone());
        }
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(format!("{PASSWORD}\n").as_bytes())?;
        }

        let mut mounted = Self {
            mount_point: mount_point.to_path_buf(),
            child,
            stdout_tail,
            stderr_tail,
            mounted: false,
        };
        let start = Instant::now();
        while start.elapsed() < timeout {
            if mount_is_visible(mount_point)? {
                mounted.mounted = true;
                return Ok(mounted);
            }
            if let Some(status) = mounted.child.try_wait()? {
                bail!(
                    "encfs exited before the mount became ready with status {}{}",
                    status,
                    mounted.log_diagnostics()
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
        bail!(
            "mount {} did not become ready within {:.1}s{}",
            mount_point.display(),
            timeout.as_secs_f64(),
            mounted.log_diagnostics()
        )
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.mounted {
            stop_child(&mut self.child);
            return Ok(());
        }

        let (tool, mut command) = unmount_command(&self.mount_point)?;
        let output = command
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("failed to start unmount command {tool}"))?;
        if !output.status.success() {
            bail!(
                "{tool} failed to unmount {} with status {}\nstdout:\n{}\nstderr:\n{}",
                self.mount_point.display(),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if !mount_is_visible(&self.mount_point)? {
                self.mounted = false;
                stop_child(&mut self.child);
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        bail!(
            "{tool} returned success but {} remained mounted",
            self.mount_point.display()
        )
    }

    fn log_diagnostics(&self) -> String {
        format!(
            "\nencfs stdout tail:\n{}\nencfs stderr tail:\n{}",
            log_tail(&self.stdout_tail),
            log_tail(&self.stderr_tail)
        )
    }
}

impl Drop for MountedEncfs {
    fn drop(&mut self) {
        if self.mounted {
            let _ = self.cleanup();
        }
        stop_child(&mut self.child);
    }
}

fn drain_logs<R: Read + Send + 'static>(mut reader: R, tail: Arc<Mutex<Vec<u8>>>) {
    thread::spawn(move || {
        let mut buffer = [0; 4096];
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0 {
                break;
            }
            let mut tail = tail.lock().unwrap_or_else(|error| error.into_inner());
            tail.extend_from_slice(&buffer[..count]);
            if tail.len() > LOG_TAIL_BYTES {
                let excess = tail.len() - LOG_TAIL_BYTES;
                tail.drain(..excess);
            }
        }
    });
}

fn log_tail(tail: &Mutex<Vec<u8>>) -> String {
    String::from_utf8_lossy(&tail.lock().unwrap_or_else(|error| error.into_inner())).to_string()
}

fn stop_child(child: &mut Child) {
    if matches!(child.try_wait(), Ok(None)) {
        #[cfg(unix)]
        {
            // Give EncFS's signal handler a chance to unmount before falling back to kill().
            // SAFETY: the child PID came directly from std::process::Child.
            let _ = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        }
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if !matches!(child.try_wait(), Ok(None)) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn mount_is_visible(mount_point: &Path) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let mount_point = mount_point
            .canonicalize()
            .unwrap_or_else(|_| mount_point.to_path_buf());
        let expected = mount_point.to_string_lossy();
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        Ok(mountinfo.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.get(4).is_some_and(|field| *field == expected)
                && line
                    .split_once(" - ")
                    .is_some_and(|(_, after)| after.starts_with("fuse"))
        }));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let output = Command::new("mount")
            .stdin(Stdio::null())
            .output()
            .context("failed to inspect mounted filesystems with `mount`")?;
        let listing = String::from_utf8_lossy(&output.stdout);
        let raw = format!(" on {} (", mount_point.display());
        let canonical = mount_point
            .canonicalize()
            .map(|path| format!(" on {} (", path.display()))
            .unwrap_or_else(|_| raw.clone());
        Ok(listing.lines().any(|line| {
            line.to_ascii_lowercase().contains("fuse")
                && (line.contains(&raw) || line.contains(&canonical))
        }))
    }
}

fn unmount_command(mount_point: &Path) -> Result<(&'static str, Command)> {
    for (tool, args) in [
        ("fusermount3", vec!["-u"]),
        ("fusermount", vec!["-u"]),
        ("umount", Vec::new()),
    ] {
        if tool_on_path(tool) {
            let mut command = Command::new(tool);
            command.args(args).arg(mount_point);
            return Ok((tool, command));
        }
    }
    bail!("no unmount tool found; install fusermount3/fusermount or make umount available")
}

fn run_with_input(command: &mut Command, input: &[u8]) -> Result<Output> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .context("child stdin was not available")?
        .write_all(input)?;
    Ok(child.wait_with_output()?)
}

fn ensure_success(name: &str, output: &Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "{name} failed with status {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn print_comparison(baseline: &BenchmarkResult, current: &BenchmarkResult) -> Result<()> {
    if baseline.host != current.host {
        eprintln!(
            "warning: baseline host {} {} / {} / {} differs from current host {} {} / {} / {}",
            baseline.host.os,
            baseline.host.os_version,
            baseline.host.architecture,
            baseline.host.cpu,
            current.host.os,
            current.host.os_version,
            current.host.architecture,
            current.host.cpu
        );
    }
    if baseline.mdtest_version != current.mdtest_version {
        eprintln!(
            "warning: baseline mdtest {} differs from current mdtest {}",
            baseline.mdtest_version, current.mdtest_version
        );
    }

    println!(
        "\nValues are operations per second (ops/sec); higher is better, so a positive delta is an improvement."
    );
    println!("Operation                         Baseline      Current        Delta");
    println!("-------------------------------- ------------ ------------ ----------");
    for delta in calculate_deltas(baseline, current)? {
        let percent = if delta.percent.is_infinite() {
            "+inf%".to_string()
        } else {
            format!("{:+.2}%", delta.percent)
        };
        println!(
            "{:<32} {:>12.2} {:>12.2} {:>10}",
            delta.name, delta.baseline, delta.current, percent
        );
    }
    println!("\nDeltas are informational and do not affect the command exit status.");
    Ok(())
}

fn validate_workload(workload: &Workload) -> Result<()> {
    if workload.ranks == 0
        || workload.items_per_rank == 0
        || workload.iterations == 0
        || workload.bytes_per_file == 0
    {
        bail!("BENCH_PROCS, BENCH_ITEMS, BENCH_ITERATIONS, and BENCH_BYTES must all be positive");
    }
    Ok(())
}

fn env_value<T>(name: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|error| anyhow!("invalid {name} value {value:?}: {error}")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn require_tool(tool: &str, hint: &str) -> Result<()> {
    if tool_on_path(tool) {
        Ok(())
    } else {
        bail!("required command {tool:?} was not found; {hint}")
    }
}

fn tool_on_path(tool: &str) -> bool {
    let path = Path::new(tool);
    if path.components().count() > 1 {
        return path.is_file();
    }
    env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths).any(|directory| directory.join(tool).is_file())
    })
}

fn target_dir(manifest_dir: &Path) -> PathBuf {
    env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                manifest_dir.join(path)
            }
        })
        .unwrap_or_else(|| manifest_dir.join("target"))
}

fn executable_name(name: &str) -> String {
    format!("{name}{}", env::consts::EXE_SUFFIX)
}

fn cpu_brand() -> String {
    use sysinfo::{CpuRefreshKind, RefreshKind, System};

    let system =
        System::new_with_specifics(RefreshKind::nothing().with_cpu(CpuRefreshKind::everything()));
    system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_string())
        .filter(|brand| !brand.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}
