use std::io::Result;
use std::process::Command;

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn build_info() {
    // These also cover source archives without Git metadata and new files.
    for path in [
        "src",
        "locales",
        "proto",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    // Watch tracked sources and Git state so incremental builds refresh the
    // revision and dirty marker, including when the last edit is reverted.
    if let Some(files) = command_output("git", &["ls-files"]) {
        for file in files.lines() {
            println!("cargo:rerun-if-changed={file}");
        }
    }
    for name in ["HEAD", "index", "packed-refs"] {
        if let Some(path) = command_output("git", &["rev-parse", "--git-path", name])
            && std::path::Path::new(&path).exists()
        {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(reference) = command_output("git", &["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = command_output("git", &["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }

    let revision = command_output("git", &["describe", "--tags", "--always", "--dirty"])
        .unwrap_or_else(|| "unknown revision".into());
    println!("cargo:rerun-if-env-changed=RUSTC");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let compiler =
        command_output(&rustc, &["--version"]).unwrap_or_else(|| "unknown compiler".into());

    // Respect reproducible-build timestamps when supplied by the packager.
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let date = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(epoch) => chrono::DateTime::from_timestamp(
            epoch.parse().expect("SOURCE_DATE_EPOCH must be an integer"),
            0,
        )
        .expect("SOURCE_DATE_EPOCH is out of range"),
        Err(_) => chrono::Utc::now(),
    };
    let target = std::env::var("TARGET").expect("Cargo sets TARGET");
    let profile = std::env::var("PROFILE").expect("Cargo sets PROFILE");
    println!(
        "cargo:rustc-env=ENCFS_BUILD_INFO=({revision}); {} {compiler}; {target} ({profile})",
        date.format("%Y-%m-%d")
    );
}

fn main() -> Result<()> {
    build_info();
    // protoc-bin-vendored only ships binaries for Linux, macOS and Windows,
    // so on other platforms (FreeBSD) there is nothing to point PROTOC at.
    // Leaving PROTOC unset makes prost-build search PATH for protoc instead.
    if let Ok(protoc_path) = protoc_bin_vendored::protoc_bin_path() {
        // SAFETY: build script runs in isolated build environment; no other threads rely on PROTOC.
        unsafe {
            std::env::set_var("PROTOC", protoc_path);
        }
    }

    prost_build::Config::new()
        .compile_protos(&["proto/encfs_config.proto"], &["proto"])
        .expect("Failed to compile protos");
    Ok(())
}
