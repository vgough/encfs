//! Live FUSE-mount coverage for the 96-bit wide file IV (V7/AES-GCM-SIV,
//! `wide_file_iv = true`), the config `encfsctl new` produces by default.
//!
//! `tests/wide_file_iv_test.rs` drives `EncFs` directly (no FUSE) and
//! `tests/live_mount.rs` only mounts V6 fixtures (`LiveConfigKind::Standard`
//! / `Paranoia`). Every wide-file-IV volume actually reachable in practice —
//! via `encfsctl new` with default flags, then `encfs` — goes through a real
//! FUSE mount, which neither existing suite exercised before this file. It
//! uses the same `MountGuard` harness as `live_mount.rs`, generating the V7
//! config on the fly via `live::init_wide_v7_backing_root()` (there is no
//! `.encfs7` fixture checked in), exactly as `encfsctl new` does.
//!
//! The config-independent "cp between two paths on the same mount silently
//! drops data" bug (see `tests/live_mount.rs::live_internal_copy_same_mount_*`)
//! is *not* re-tested here: it reproduces identically under a plain V6
//! config, so it isn't specific to wide file IVs and doesn't belong in this
//! file. What belongs here is proof that the wide-IV read/write/header path
//! itself is sound end-to-end through a real mount.

mod live;

use anyhow::{Context, Result};
use live::{MountGuard, live_enabled};
use std::fs;
use std::process::Command;

fn require_live() {
    if !live_enabled() {
        eprintln!("skipping live mount test (set ENCFS_LIVE_TESTS=1 to enable)");
    }
}

fn ciphertext_files_total_len(backing_root: &std::path::Path) -> Result<u64> {
    let files = live::list_non_dot_entries_recursive(backing_root)?;
    let mut total = 0u64;
    for f in files {
        if f.is_file() {
            total += fs::metadata(&f)?.len();
        }
    }
    Ok(total)
}

/// Plain write-then-read through a fresh wide-IV mount, checking the backing
/// ciphertext's *physical* size (not the mounted logical size, which reads
/// back as 0 for a missing, empty, and header-only file alike and so can't
/// distinguish "no data persisted" from "no file").
#[test]
#[ignore]
fn live_wide_file_iv_basic_write_readback() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }

    let (backing_root, cfg) = live::init_wide_v7_backing_root()?;
    let mount = MountGuard::mount_existing_backing_root(cfg, false, backing_root)?;

    let p = mount.mount_point.join("hello.txt");
    let payload = b"hello wide-iv encfs, written through a real FUSE mount\n";
    fs::write(&p, payload).context("write through mount")?;

    let got = fs::read(&p).context("read back through mount")?;
    assert_eq!(got, payload);

    let physical = ciphertext_files_total_len(&mount.backing_root)?;
    // Header alone is 12 bytes; a real write must push this well past that.
    assert!(
        physical > 12,
        "backing ciphertext is only {physical} bytes; file data was not persisted \
         (this is the reported wide-file-IV bug: header-only backing file, no data)"
    );

    Ok(())
}

/// Copies a multi-block file *from outside the mount* into a fresh wide-IV
/// mount via the real `cp` binary, matching a realistic `cp src dest-inside-mount`.
/// (This is the external-source case; see `live_mount.rs` for the same-mount
/// case, which fails for reasons unrelated to wide IVs.)
#[test]
#[ignore]
fn live_wide_file_iv_multi_block_copy() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }

    let (backing_root, cfg) = live::init_wide_v7_backing_root()?;
    let mount = MountGuard::mount_existing_backing_root(cfg, false, backing_root)?;

    let src_dir = live::unique_temp_dir("encfs_live_wide_v7_src")?;
    let src = src_dir.join("payload.bin");
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(&src, &payload).context("write source payload")?;

    let dst = mount.mount_point.join("payload.bin");
    let status = Command::new("cp")
        .arg(&src)
        .arg(&dst)
        .status()
        .context("spawn cp")?;
    anyhow::ensure!(status.success(), "cp exited with {status}");

    let got = fs::read(&dst).context("read back copied file")?;
    assert_eq!(got.len(), payload.len(), "copied file size mismatch");
    assert_eq!(got, payload, "copied file content mismatch");

    Ok(())
}
