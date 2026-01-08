use anyhow::{Context, Result};
use clap::Parser;
use daemonize::Daemonize;
use log::{error, info};
use rust_i18n::t;
use std::ffi::OsStr;
use std::path::PathBuf;

use encfs::{config, fs::EncFs};

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

fn help_main_root() -> String {
    t!("help.encfs.root").to_string()
}

fn help_main_mount_point() -> String {
    t!("help.encfs.mount_point").to_string()
}

#[derive(Parser, Debug)]
#[command(author, version, about = help_main_about(), long_about = None)]
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

    #[arg(help = help_main_root())]
    root: PathBuf,

    #[arg(help = help_main_mount_point())]
    mount_point: PathBuf,
}

fn main() -> Result<()> {
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

    // Try to find config file - check for .encfs6.xml first, then legacy .encfs5
    let config_path = args.root.join(".encfs6.xml");
    let legacy_config_path = args.root.join(".encfs5");

    let config_path = if config_path.exists() {
        config_path
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

    let password = if let Some(prog) = args.extpass {
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

    match config.get_cipher(&password) {
        Ok(cipher) => {
            info!("{}", t!("main.successfully_decrypted"));

            // Daemonize unless foreground mode is requested
            if !foreground {
                let daemonize = Daemonize::new();
                match daemonize.start() {
                    Ok(_) => info!("{}", t!("main.daemonized_successfully")),
                    Err(e) => {
                        let error_msg = t!("main.failed_to_daemonize", error = e);
                        error!("{}", error_msg);
                        return Err(anyhow::anyhow!("{}", error_msg));
                    }
                }
            }

            let fs = EncFs::new(args.root, cipher, config);

            let mut check_opts = vec![];
            if args.public {
                check_opts.push(OsStr::new("-o"));
                check_opts.push(OsStr::new("allow_other"));
            }

            if args.read_only {
                check_opts.push(OsStr::new("-o"));
                check_opts.push(OsStr::new("ro"));
            }

            // If we want to support full FUSE args, checking clap's handling of unknown args would be better,
            // but for now we construct what we support.

            // fuse-mt default threads logic:
            // 0 means default (usually num_cpus). 1 means single threaded.
            let threads = if args.single_thread { 1 } else { 0 };

            fuse_mt::mount(
                fuse_mt::FuseMT::new(fs, threads),
                &args.mount_point,
                &check_opts,
            )?;
        }
        Err(e) => {
            error!("{}", t!("main.failed_to_decrypt_key", error = e));

            return Err(e);
        }
    }

    Ok(())
}
