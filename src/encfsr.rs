#[macro_use]
extern crate rust_i18n;

use anyhow::{Context, Result};
use clap::Parser;
use encfs::config;
use log::info;
use std::path::PathBuf;

i18n!("locales", fallback = "en");

// Helper functions for translated help text (matches pattern from encfsctl.rs)
fn help_encfsr_about() -> String {
    t!("help.encfsr.about").to_string()
}

fn help_encfsr_source() -> String {
    t!("help.encfsr.source").to_string()
}

fn help_encfsr_mount_point() -> String {
    t!("help.encfsr.mount_point").to_string()
}

fn help_encfsr_stdinpass() -> String {
    t!("help.encfsr.stdinpass").to_string()
}

fn help_encfsr_extpass() -> String {
    t!("help.encfsr.extpass").to_string()
}

fn help_encfsr_foreground() -> String {
    t!("help.encfsr.foreground").to_string()
}

fn help_encfsr_fuse_opts() -> String {
    t!("help.encfsr.fuse_opts").to_string()
}

#[derive(Parser, Debug)]
#[command(author, version, about = help_encfsr_about(), long_about = None)]
struct Args {
    /// Source directory containing plaintext files and encfs config
    #[arg(help = help_encfsr_source())]
    source: PathBuf,

    /// Directory where the virtual encrypted filesystem will be mounted
    #[arg(help = help_encfsr_mount_point())]
    mount_point: PathBuf,

    /// Read password from stdin instead of prompting (for scripted backup pipelines)
    #[arg(short = 'S', long = "stdinpass", help = help_encfsr_stdinpass())]
    stdinpass: bool,

    /// External program to provide the password
    #[arg(long, help = help_encfsr_extpass())]
    extpass: Option<String>,

    /// Run in foreground (do not daemonize after mounting)
    #[arg(short = 'f', long, help = help_encfsr_foreground())]
    foreground: bool,

    /// FUSE options passed directly to the FUSE layer (e.g. -o allow_other).
    /// Place these after -- or use trailing arguments directly.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, help = help_encfsr_fuse_opts())]
    fuse_opts: Vec<String>,
}

fn main() -> Result<()> {
    encfs::init_locale();

    let args = Args::parse();

    // Initialize logging (match main.rs pattern, no verbose flag in Phase 1)
    let mut builder = env_logger::Builder::from_default_env();
    if std::env::var("RUST_LOG").is_err() {
        builder.filter_level(log::LevelFilter::Info);
    }
    builder.init();

    // --- Source directory validation (QUAL-01) ---

    if !args.source.exists() {
        eprintln!(
            "{}",
            t!("encfsr.source_not_found", source = args.source.display())
        );
        std::process::exit(1);
    }

    if !args.source.is_dir() {
        eprintln!(
            "{}",
            t!("encfsr.source_not_dir", source = args.source.display())
        );
        std::process::exit(1);
    }

    // --- Locate config file (QUAL-01) ---
    // Search order matches main.rs: .encfs7, .encfs6.xml, .encfs5
    let config_path = {
        let candidates = [".encfs7", ".encfs6.xml", ".encfs5"];
        candidates
            .iter()
            .map(|name| args.source.join(name))
            .find(|p| p.exists())
            .unwrap_or_else(|| {
                eprintln!(
                    "{}",
                    t!("encfsr.no_config_found", source = args.source.display())
                );
                std::process::exit(1);
            })
    };

    // --- Load config ---
    let config = config::EncfsConfig::load(&config_path).unwrap_or_else(|e| {
        eprintln!(
            "{}",
            t!(
                "encfsr.config_load_failed",
                path = config_path.display(),
                error = e
            )
        );
        std::process::exit(1);
    });

    // --- Password acquisition (matches main.rs pattern) ---
    let password = if let Some(prog) = args.extpass {
        use std::process::Command;
        let output = Command::new("sh")
            .arg("-c")
            .arg(&prog)
            .env("RootDir", &args.source)
            .output()
            .context("failed to run extpass program")?;
        if !output.status.success() {
            eprintln!("error: extpass program exited with failure");
            std::process::exit(1);
        }
        String::from_utf8(output.stdout)?.trim_end().to_string()
    } else if args.stdinpass {
        use std::io::Read;
        let mut pw = String::new();
        std::io::stdin().read_to_string(&mut pw)?;
        pw.trim_end().to_string()
    } else {
        rpassword::prompt_password("EncFS Password: ").context("failed to read password")?
    };

    // --- Decrypt config and derive cipher ---
    // get_cipher() calls the library's internal validate() first, then we do the encfsr-specific check.
    // IMPORTANT: validate() inside get_cipher() rejects unique_iv=false (normal encfs requires it).
    // encfsr needs the OPPOSITE: reject unique_iv=true (deterministic output requires it to be false).
    // We check config.unique_iv directly after get_cipher() succeeds (per CONTEXT.md locked decision).
    let _cipher = config.get_cipher(&password).unwrap_or_else(|e| {
        eprintln!("{}", t!("encfsr.decrypt_failed", error = e));
        std::process::exit(1);
    });

    // --- encfsr-specific config validation (CONF-01, CONF-02) ---
    // CONF-01: reject unique_iv = true (produces non-deterministic output)
    if config.unique_iv {
        eprintln!("{}", t!("encfsr.unique_iv_rejected"));
        std::process::exit(1);
    }

    // CONF-02: chained_name_iv = true is explicitly allowed — no check here

    // --- Phase 1 boundary: config is validated, mount is not yet implemented ---
    info!("{}", t!("encfsr.mount_not_implemented"));

    // Future phases: build ReverseFilesystemMT and call fuse_mt::mount here.
    // fuse_opts are captured in args.fuse_opts for use in Phase 2.

    Ok(())
}
