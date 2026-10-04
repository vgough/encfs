use anyhow::{Context, Result};
use clap::Parser;
use daemonize::Daemonize;
use log::{error, info};
use rust_i18n::t;
use std::path::PathBuf;

use encfs::{config, fs::EncFs};
use typed_fuse::mount;

rust_i18n::i18n!("locales", fallback = "en");

// Helper functions for translated help text
fn help_main_about() -> String {
    t!("help.encfs.about").to_string()
}

fn help_main_foreground() -> String {
    t!("help.encfs.foreground").to_string()
}

fn help_main_verbose() -> String {
    t!("help.encfs.verbose").to_string()
}

fn help_main_debug() -> String {
    t!("help.encfs.debug").to_string()
}

fn help_main_single_thread() -> String {
    t!("help.encfs.single_thread").to_string()
}

fn help_main_public() -> String {
    t!("help.encfs.public").to_string()
}

fn help_main_extpass() -> String {
    t!("help.encfs.extpass").to_string()
}

fn help_main_stdinpass() -> String {
    t!("help.encfs.stdinpass").to_string()
}

fn help_main_read_only() -> String {
    t!("help.encfs.read_only").to_string()
}

fn help_main_no_default_permissions() -> String {
    t!("help.encfs.no_default_permissions").to_string()
}

fn help_main_root() -> String {
    t!("help.encfs.root").to_string()
}

fn help_main_mount_point() -> String {
    t!("help.encfs.mount_point").to_string()
}

#[cfg(target_os = "macos")]
fn help_main_touchid() -> String {
    t!("help.encfs.touchid").to_string()
}

#[cfg(target_os = "macos")]
fn help_main_idle_timeout() -> String {
    t!("help.encfs.idle_timeout").to_string()
}

#[cfg(target_os = "macos")]
fn help_main_idle_ignore() -> String {
    t!("help.encfs.idle_ignore").to_string()
}

#[derive(Parser, Debug)]
#[command(author, version, about = help_main_about(), long_about = None, arg_required_else_help = true)]
struct Args {
    #[arg(short, long, help = help_main_foreground())]
    foreground: bool,

    #[arg(short, long, help = help_main_verbose())]
    verbose: bool,

    #[arg(short, help = help_main_debug())]
    debug: bool,

    #[arg(short = 's', help = help_main_single_thread())]
    single_thread: bool,

    #[arg(long, help = help_main_public())]
    public: bool,

    #[arg(long, help = help_main_extpass())]
    extpass: Option<String>,

    #[arg(short = 'S', long = "stdinpass", help = help_main_stdinpass())]
    stdinpass: bool,

    #[arg(short = 'r', long, help = help_main_read_only())]
    read_only: bool,

    #[arg(long, help = help_main_no_default_permissions())]
    no_default_permissions: bool,

    #[cfg(target_os = "macos")]
    #[arg(long, help = help_main_touchid())]
    touchid: bool,

    #[cfg(target_os = "macos")]
    #[arg(
        long,
        value_name = "MINUTES",
        default_value_t = 10,
        value_parser = clap::value_parser!(u64).range(1..),
        requires = "touchid",
        help = help_main_idle_timeout()
    )]
    idle_timeout: u64,

    #[cfg(target_os = "macos")]
    #[arg(long, value_name = "PROCESS", requires = "touchid", help = help_main_idle_ignore())]
    idle_ignore: Vec<String>,

    #[arg(help = help_main_root())]
    root: PathBuf,

    #[arg(help = help_main_mount_point())]
    mount_point: PathBuf,
}

fn main() -> Result<()> {
    encfs::security::harden_process();
    encfs::init_locale();

    let args = Args::parse();

    let verbose = args.verbose || args.debug;
    let foreground = args.foreground || args.debug;

    let mut builder = env_logger::Builder::from_default_env();
    if verbose {
        builder.filter_level(log::LevelFilter::Debug);
    } else if std::env::var("RUST_LOG").is_err() {
        builder.filter_level(log::LevelFilter::Info);
    }
    builder.init();

    info!(
        "{}",
        t!(
            "main.mounting",
            root = args.root.display(),
            mount_point = args.mount_point.display()
        )
    );

    // Try to find config file - check .encfs7, .encfs6.xml, then legacy .encfs5
    let v7_config_path = args.root.join(".encfs7");
    let v6_config_path = args.root.join(".encfs6.xml");
    let legacy_config_path = args.root.join(".encfs5");

    let config_path = if v7_config_path.exists() {
        v7_config_path
    } else if v6_config_path.exists() {
        v6_config_path
    } else if legacy_config_path.exists() {
        info!("{}", t!("main.using_legacy_config"));
        legacy_config_path
    } else {
        error!(
            "{}",
            t!("main.no_config_file_found", root = args.root.display())
        );
        return Err(anyhow::anyhow!("{}", t!("main.no_config_file_found_short")));
    };

    let config =
        config::EncfsConfig::load(&config_path).context(t!("main.failed_to_load_config"))?;

    let mut password = if let Some(prog) = args.extpass {
        use std::process::Command;
        let output = Command::new("sh")
            .arg("-c")
            .arg(&prog)
            .env("RootDir", &args.root)
            .output()
            .context(t!("main.failed_to_run_extpass"))?;
        if !output.status.success() {
            return Err(anyhow::anyhow!("{}", t!("main.extpass_program_failed")));
        }
        String::from_utf8(output.stdout)?.trim_end().to_string()
    } else if args.stdinpass {
        use std::io::Read;
        let mut pw = String::new();
        std::io::stdin().read_to_string(&mut pw)?;
        pw.trim_end().to_string()
    } else {
        rpassword::prompt_password(&t!("main.password_prompt"))
            .context(t!("main.failed_to_read_password"))?
    };

    let cipher_result = config.get_cipher(&password);
    zeroize::Zeroize::zeroize(&mut password);

    match cipher_result {
        Ok(cipher) => {
            info!("{}", t!("main.successfully_decrypted"));

            // Resolve paths before daemonizing: Daemonize chdirs to "/", which
            // would break relative root/mount_point paths.
            let root = args
                .root
                .canonicalize()
                .with_context(|| format!("invalid root directory {}", args.root.display()))?;
            let mount_point = args
                .mount_point
                .canonicalize()
                .with_context(|| format!("invalid mount point {}", args.mount_point.display()))?;

            // On-demand mode: Touch ID once before the mount comes up, then
            // again whenever the idle lock engages.
            #[cfg(target_os = "macos")]
            let touchid = args.touchid.then(|| {
                encfs::touchid::TouchId::new(t!(
                    "main.touchid_reason",
                    mount_point = mount_point.display()
                ))
            });
            #[cfg(target_os = "macos")]
            let unlock = touchid.as_ref().map(|touchid| {
                move || -> Result<()> {
                    use encfs::idle_lock::Authenticator;
                    touchid.authenticate().map_err(|error| {
                        anyhow::anyhow!("{}", t!("main.touchid_failed", error = error))
                    })
                }
            });
            #[cfg(not(target_os = "macos"))]
            let unlock: Option<fn() -> Result<()>> = None;

            // Daemonize unless foreground mode is requested. This must happen
            // before the FUSE session is created (forking after libfuse has
            // initialized process state is unsafe). The initial unlock runs in
            // the daemon so LocalAuthentication is never used across a fork.
            if foreground {
                if let Some(unlock) = &unlock {
                    unlock()?;
                }
            } else {
                daemonize(
                    unlock
                        .as_ref()
                        .map(|unlock| unlock as &dyn Fn() -> Result<()>),
                )?;
            }

            let fs = EncFs::new(root, cipher, config).with_read_only(args.read_only);
            #[cfg(target_os = "macos")]
            let fs = match touchid {
                Some(touchid) => {
                    use encfs::idle_lock::{DEFAULT_IGNORED_PROCESSES, IdleLock};
                    info!(
                        "{}",
                        t!("main.touchid_unlocked", minutes = args.idle_timeout)
                    );
                    let ignored = DEFAULT_IGNORED_PROCESSES
                        .iter()
                        .map(|name| name.to_string())
                        .chain(args.idle_ignore);
                    fs.with_idle_lock(IdleLock::new(
                        std::time::Duration::from_secs(args.idle_timeout * 60),
                        Box::new(touchid),
                        ignored,
                    ))
                }
                None => fs,
            };

            let mount_config = mount::MountConfig {
                allow_other: args.public,
                default_permissions: !args.no_default_permissions,
                read_only: args.read_only,
                ..mount::MountConfig::new("encfs")
            };

            mount::mount_blocking(fs, &mount_point, &mount_config, args.single_thread)?;
        }
        Err(e) => {
            error!("{}", t!("main.failed_to_decrypt_key", error = e));

            return Err(e);
        }
    }

    Ok(())
}

/// Detach into the background. With `ready`, the parent waits for the daemon
/// to run it and exits non-zero (with the error on the terminal) if it fails,
/// instead of exiting successfully before the daemon has been checked.
fn daemonize(ready: Option<&dyn Fn() -> Result<()>>) -> Result<()> {
    use daemonize::Outcome;
    use std::io::{Read, Write};

    let daemon_error = |e: &dyn std::fmt::Display| {
        let error_msg = t!("main.failed_to_daemonize", error = e);
        error!("{}", error_msg);
        anyhow::anyhow!("{}", error_msg)
    };

    let Some(ready) = ready else {
        Daemonize::new().start().map_err(|e| daemon_error(&e))?;
        info!("{}", t!("main.daemonized_successfully"));
        return Ok(());
    };

    let (mut reader, mut writer) = std::io::pipe()?;
    match Daemonize::new().execute() {
        Outcome::Parent(Ok(_)) => {
            drop(writer);
            // EOF arrives once the daemon reports or exits.
            let mut status = String::new();
            reader.read_to_string(&mut status)?;
            match status.strip_prefix("ok") {
                Some("") => std::process::exit(0),
                _ if status.is_empty() => Err(daemon_error(&"daemon exited during startup")),
                _ => {
                    let message = status.strip_prefix("error: ").unwrap_or(&status);
                    error!("{}", message);
                    Err(anyhow::anyhow!("{}", message))
                }
            }
        }
        Outcome::Parent(Err(e)) => Err(daemon_error(&e)),
        Outcome::Child(Ok(_)) => {
            drop(reader);
            info!("{}", t!("main.daemonized_successfully"));
            let result = ready();
            let _ = match &result {
                Ok(()) => writer.write_all(b"ok"),
                Err(e) => writer.write_all(format!("error: {e}").as_bytes()),
            };
            drop(writer);
            result
        }
        Outcome::Child(Err(e)) => Err(daemon_error(&e)),
    }
}
