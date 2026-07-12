//! Shared FUSE mount plumbing for the encfs and encfsr binaries.
//!
//! Builds rfuse3 MountOptions from our CLI-level settings (with per-platform
//! handling of options rfuse3 drops on macOS) and runs a mounted session until
//! unmount or a termination signal.

use anyhow::{Context, Result};
use log::info;
use rfuse3::MountOptions;
use rfuse3::path::{PathFilesystem, Session};
use std::path::Path;

/// Mount settings shared by both binaries.
pub struct MountConfig {
    pub fs_name: String,
    pub allow_other: bool,
    pub allow_root: bool,
    pub default_permissions: bool,
    pub read_only: bool,
    pub nonempty: bool,
    /// macOS Finder volume name.
    pub volname: Option<String>,
    /// Additional raw mount option words (e.g. from encfsr's FUSE passthrough
    /// args), without any "-o" prefix.
    pub extra_options: Vec<String>,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            fs_name: "encfs".to_string(),
            allow_other: false,
            allow_root: false,
            default_permissions: true,
            read_only: false,
            nonempty: false,
            volname: None,
            extra_options: Vec::new(),
        }
    }
}

pub fn build_mount_options(cfg: &MountConfig) -> MountOptions {
    let mut opts = MountOptions::default();
    opts.uid(unsafe { libc::getuid() })
        .gid(unsafe { libc::getgid() })
        .fs_name(&cfg.fs_name)
        .allow_other(cfg.allow_other)
        .allow_root(cfg.allow_root)
        .default_permissions(cfg.default_permissions)
        .read_only(cfg.read_only)
        .nonempty(cfg.nonempty);

    #[cfg(target_os = "macos")]
    {
        // rfuse3's macOS option builder only emits fsname/allow_root/allow_other;
        // read_only, default_permissions, and volname must ride in custom_options
        // as explicit "-o key" tokens for mount_macfuse.
        let mut tokens: Vec<String> = Vec::new();
        if cfg.read_only {
            tokens.push("rdonly".to_string());
        }
        if cfg.default_permissions {
            tokens.push("default_permissions".to_string());
        }
        if let Some(volname) = &cfg.volname {
            tokens.push(format!("volname={volname}"));
        }
        tokens.extend(cfg.extra_options.iter().cloned());
        if !tokens.is_empty() {
            let joined = tokens
                .iter()
                .map(|t| format!("-o {t}"))
                .collect::<Vec<_>>()
                .join(" ");
            opts.custom_options(joined);
        }
    }

    #[cfg(not(target_os = "macos"))]
    if !cfg.extra_options.is_empty() {
        opts.custom_options(cfg.extra_options.join(","));
    }

    opts
}

/// Mount `fs` at `mount_point` and run until externally unmounted or a
/// SIGINT/SIGTERM arrives (which triggers a clean unmount).
pub async fn mount_and_run<FS>(fs: FS, mount_point: &Path, options: MountOptions) -> Result<()>
where
    FS: PathFilesystem + Send + Sync + 'static,
{
    let session = Session::new(options);

    // macOS: Session::mount is already the mount_macfuse path (works unprivileged).
    // Linux: always mount via fusermount3 so fsname/ro/default_permissions are
    // honored regardless of privilege (rfuse3's privileged option builder drops them).
    #[cfg(target_os = "macos")]
    let mut handle = session.mount(fs, mount_point).await.with_context(|| {
        format!(
            "failed to mount FUSE filesystem at {}",
            mount_point.display()
        )
    })?;
    #[cfg(not(target_os = "macos"))]
    let mut handle = session
        .mount_with_unprivileged(fs, mount_point)
        .await
        .with_context(|| {
            format!(
                "failed to mount FUSE filesystem at {}",
                mount_point.display()
            )
        })?;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;

    tokio::select! {
        res = &mut handle => {
            res.context("FUSE session ended with error")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, unmounting");
            handle.unmount().await.context("unmount failed")?;
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, unmounting");
            handle.unmount().await.context("unmount failed")?;
        }
    }

    Ok(())
}

/// Build a tokio runtime (single-threaded if requested) and run the mount to
/// completion. Must be called after any daemonize fork.
pub fn mount_blocking<FS>(
    fs: FS,
    mount_point: &Path,
    cfg: &MountConfig,
    single_thread: bool,
) -> Result<()>
where
    FS: PathFilesystem + Send + Sync + 'static,
{
    let runtime = if single_thread {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
    }
    .context("failed to build tokio runtime")?;

    runtime.block_on(mount_and_run(fs, mount_point, build_mount_options(cfg)))
}
