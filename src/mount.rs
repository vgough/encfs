//! Shared synchronous FUSE mount plumbing for the encfs and encfsr binaries.

use anyhow::{Context, Result};
use fuse3::{
    MountOption, PathFilesystem, PathNodeFs, Session, SessionConfig, ThreadPoolConfig,
    ThreadingMode,
};
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
    /// Additional raw mount option words, without any `-o` prefix.
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

pub fn build_mount_options(cfg: &MountConfig) -> Vec<MountOption> {
    let mut options = vec![MountOption::FsName(cfg.fs_name.clone())];
    // macFUSE rejects the Linux `uid`/`gid` mount options. It already mounts
    // as the calling user, matching the behavior of the previous macOS
    // option builder.
    #[cfg(not(target_os = "macos"))]
    {
        options.push(MountOption::Custom(format!("uid={}", unsafe {
            libc::getuid()
        })));
        options.push(MountOption::Custom(format!("gid={}", unsafe {
            libc::getgid()
        })));
    }
    if cfg.allow_other {
        options.push(MountOption::AllowOther);
    }
    if cfg.allow_root {
        options.push(MountOption::Custom("allow_root".to_string()));
    }
    if cfg.default_permissions {
        options.push(MountOption::DefaultPermissions);
    }
    if cfg.read_only {
        options.push(MountOption::ReadOnly);
    }
    if cfg.nonempty {
        options.push(MountOption::Custom("nonempty".to_string()));
    }
    if let Some(volname) = &cfg.volname {
        options.push(MountOption::Custom(format!("volname={volname}")));
    }
    options.extend(cfg.extra_options.iter().cloned().map(MountOption::Custom));
    options
}

/// Mount synchronously and let libfuse install signal handlers and run its
/// single- or multi-threaded request loop. This is called after daemonization.
pub fn mount_blocking<FS>(
    fs: FS,
    mount_point: &Path,
    cfg: &MountConfig,
    single_thread: bool,
) -> Result<()>
where
    FS: PathFilesystem + 'static,
{
    let adapter = PathNodeFs::new(fs);
    let session_config = SessionConfig {
        threading: if single_thread {
            ThreadingMode::SingleThreaded
        } else {
            ThreadingMode::MultiThreaded(ThreadPoolConfig::default())
        },
    };
    let options = build_mount_options(cfg);
    let mut session = Session::new_with_config(adapter, &options, session_config)
        .context("failed to create FUSE session")?;
    session.mount(mount_point).with_context(|| {
        format!(
            "failed to mount FUSE filesystem at {}",
            mount_point.display()
        )
    })?;
    session.run().context("FUSE session ended with error")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_mount_policy_and_passthrough_options() {
        let config = MountConfig {
            fs_name: "encfs-test".to_string(),
            allow_other: true,
            allow_root: true,
            default_permissions: true,
            read_only: true,
            nonempty: true,
            volname: Some("Encrypted Files".to_string()),
            extra_options: vec!["noatime".to_string()],
        };

        let options = build_mount_options(&config);
        assert!(options.contains(&MountOption::FsName("encfs-test".to_string())));
        assert!(options.contains(&MountOption::AllowOther));
        assert!(options.contains(&MountOption::DefaultPermissions));
        assert!(options.contains(&MountOption::ReadOnly));
        assert!(options.contains(&MountOption::Custom("allow_root".to_string())));
        assert!(options.contains(&MountOption::Custom("nonempty".to_string())));
        assert!(options.contains(&MountOption::Custom("volname=Encrypted Files".to_string())));
        assert!(options.contains(&MountOption::Custom("noatime".to_string())));
        #[cfg(target_os = "macos")]
        assert!(!options.iter().any(|option| matches!(
            option,
            MountOption::Custom(value) if value.starts_with("uid=") || value.starts_with("gid=")
        )));
    }
}
