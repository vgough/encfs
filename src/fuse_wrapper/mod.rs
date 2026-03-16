// Fuse wrapper module - provides path-based filesystem interface on top of fuser.
//
// Based on fuse_mt by William R. Fraser.
// Simplified: no threadpool, all operations are synchronous.

mod adapter;
mod directory_cache;
mod inode_table;
mod types;

pub use adapter::*;
pub use types::*;

use std::ffi::OsStr;
use std::io;
use std::path::Path;

/// Build a [`fuser::Config`] from a traditional `&[&OsStr]` options slice.
fn config_from_legacy_options(options: &[&OsStr]) -> fuser::Config {
    use fuser::{MountOption, SessionACL};

    let mut config = fuser::Config::default();

    let mut i = 0;
    while i < options.len() {
        let opt = options[i];
        if opt == OsStr::new("-o") {
            i += 1;
            if i >= options.len() {
                break;
            }
            let val = options[i].to_string_lossy();
            for part in val.split(',') {
                let part = part.trim();
                if let Some(name) = part.strip_prefix("fsname=") {
                    config
                        .mount_options
                        .push(MountOption::FSName(name.to_owned()));
                } else {
                    match part {
                        "allow_other" => {
                            config.acl = SessionACL::All;
                        }
                        "allow_root" => {
                            config.acl = SessionACL::RootAndOwner;
                        }
                        "auto_unmount" => {
                            config.mount_options.push(MountOption::AutoUnmount);
                        }
                        "default_permissions" => {
                            config.mount_options.push(MountOption::DefaultPermissions);
                        }
                        "dev" => {
                            config.mount_options.push(MountOption::Dev);
                        }
                        "nodev" => {
                            config.mount_options.push(MountOption::NoDev);
                        }
                        "suid" => {
                            config.mount_options.push(MountOption::Suid);
                        }
                        "nosuid" => {
                            config.mount_options.push(MountOption::NoSuid);
                        }
                        "ro" => {
                            config.mount_options.push(MountOption::RO);
                        }
                        "rw" => {
                            config.mount_options.push(MountOption::RW);
                        }
                        "exec" => {
                            config.mount_options.push(MountOption::Exec);
                        }
                        "noexec" => {
                            config.mount_options.push(MountOption::NoExec);
                        }
                        "atime" => {
                            config.mount_options.push(MountOption::Atime);
                        }
                        "noatime" => {
                            config.mount_options.push(MountOption::NoAtime);
                        }
                        "dirsync" => {
                            config.mount_options.push(MountOption::DirSync);
                        }
                        "sync" => {
                            config.mount_options.push(MountOption::Sync);
                        }
                        _ => {}
                    }
                }
            }
        }
        i += 1;
    }

    config
}

/// Mount the given filesystem to the given mountpoint. This function will not return until the
/// filesystem is unmounted.
pub fn mount<FS: fuser::Filesystem, P: AsRef<Path>>(
    fs: FS,
    mountpoint: P,
    options: &[&OsStr],
) -> io::Result<()> {
    let config = config_from_legacy_options(options);
    fuser::mount2(fs, mountpoint, &config)
}

/// Mount the given filesystem in the background, returning a session handle.
pub fn spawn_mount<FS: fuser::Filesystem + Send + 'static, P: AsRef<Path>>(
    fs: FS,
    mountpoint: P,
    options: &[&OsStr],
) -> io::Result<fuser::BackgroundSession> {
    let config = config_from_legacy_options(options);
    fuser::spawn_mount2(fs, mountpoint, &config)
}
