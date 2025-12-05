mod live;

use anyhow::{Context, Result};
use encfs::crypto::file::FileEncoder;
use live::{data_block_size, live_enabled, load_live_config, MountGuard};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

fn require_live() {
    if !live_enabled() {
        // If the test is run without `--ignored`, treat it as a no-op.
        eprintln!("skipping live mount test (set ENCFS_LIVE_TESTS=1 to enable)");
    }
}

fn pattern_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(17))
        .collect()
}

fn read_all(path: &Path) -> Result<Vec<u8>> {
    let mut f = fs::File::open(path).with_context(|| format!("open {:?}", path))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

fn read_range(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn libc_truncate(path: &Path, size: u64) -> Result<()> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())?;
    let rc = unsafe { libc::truncate(c.as_ptr(), size as libc::off_t) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).context("libc::truncate failed")
    }
}

fn expected_physical_size(logical: u64, cfg: &live::LiveConfig) -> u64 {
    FileEncoder::<fs::File>::calculate_physical_size(
        logical,
        8,
        cfg.block_size,
        cfg.block_mac_bytes,
    )
}

fn ciphertext_single_file_size(backing_root: &Path) -> Result<u64> {
    let p = live::backing_single_ciphertext_file(backing_root)?;
    Ok(fs::metadata(p)?.len())
}

#[test]
#[ignore]
fn live_smoke_mount_unmount_standard() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    let cfg = load_live_config(live::LiveConfigKind::Standard)?;
    let mount = MountGuard::mount(cfg, false)?;

    // Root listing should be empty (no user files) and must not expose `.encfs6.xml`.
    let entries: Vec<_> = fs::read_dir(&mount.mount_point)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::result::Result<_, _>>()?;
    for n in &entries {
        assert_ne!(n.to_string_lossy(), ".encfs6.xml");
    }

    Ok(())
}

fn run_basic_io(cfg_kind: live::LiveConfigKind) -> Result<()> {
    let cfg = load_live_config(cfg_kind)?;
    let mount = MountGuard::mount(cfg.clone(), false)?;

    let p = mount.mount_point.join("basic.txt");
    let payload = b"hello live encfs\n";
    fs::write(&p, payload)?;
    let got = fs::read(&p)?;
    assert_eq!(got, payload);

    // Offset write (forces RMW logic through kernel).
    let dbs = data_block_size(&cfg);
    let mut f = fs::OpenOptions::new().read(true).write(true).open(&p)?;
    f.seek(SeekFrom::Start(dbs + 5))?;
    f.write_all(b"Z")?;
    drop(f);

    let got2 = read_range(&p, dbs + 5, 1)?;
    assert_eq!(got2, b"Z");

    // Backing store should not contain plaintext filename (sanity check).
    let names = live::list_non_dot_entries_recursive(&mount.backing_root)?;
    for n in names {
        let s = n.file_name().unwrap_or_default().to_string_lossy();
        assert!(!s.contains("basic.txt"));
    }

    Ok(())
}

#[test]
#[ignore]
fn live_basic_io_standard() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    run_basic_io(live::LiveConfigKind::Standard)
}

#[test]
#[ignore]
fn live_basic_io_paranoia() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    run_basic_io(live::LiveConfigKind::Paranoia)
}

fn run_truncate_matrix(cfg_kind: live::LiveConfigKind) -> Result<()> {
    let cfg = load_live_config(cfg_kind)?;
    let mount = MountGuard::mount(cfg.clone(), false).context("mount failed")?;

    let dbs = data_block_size(&cfg);
    let p = mount.mount_point.join("t.bin");

    eprintln!("truncate_matrix: initial write");
    // Create initial content spanning >2 blocks.
    let initial_len = (2 * dbs + 100) as usize;
    let initial = pattern_bytes(initial_len);
    fs::write(&p, &initial).with_context(|| format!("write initial {:?}", p))?;
    assert_eq!(
        fs::metadata(&p)
            .with_context(|| format!("metadata after initial write {:?}", p))?
            .len(),
        initial_len as u64
    );

    // Same-size truncate (path-based)
    eprintln!("truncate_matrix: same-size truncate");
    libc_truncate(&p, initial_len as u64).context("same-size libc::truncate failed")?;
    assert_eq!(
        read_all(&p).context("read_all after same-size truncate")?,
        initial
    );
    assert_eq!(
        ciphertext_single_file_size(&mount.backing_root).context("ciphertext size read failed")?,
        expected_physical_size(initial_len as u64, &cfg)
    );

    // Shrink inside a block: 2*dbs + 20
    eprintln!("truncate_matrix: shrink inside block");
    let s1 = 2 * dbs + 20;
    {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .with_context(|| format!("open for ftruncate {:?}", p))?;
        f.set_len(s1)
            .with_context(|| format!("ftruncate {:?} to {}", p, s1))?;
    }
    let got = read_all(&p).context("read_all after shrink inside block")?;
    assert_eq!(got.len(), s1 as usize);
    assert_eq!(&got[..], &initial[..s1 as usize]);
    assert_eq!(
        ciphertext_single_file_size(&mount.backing_root).context("ciphertext size after shrink")?,
        expected_physical_size(s1, &cfg)
    );
    // Read past EOF should yield nothing.
    assert!(read_range(&p, s1, 10)
        .with_context(|| format!("read_range past EOF {:?}", p))?
        .is_empty());

    // Shrink at exact block boundary: 2*dbs
    eprintln!("truncate_matrix: shrink at boundary");
    let s2 = 2 * dbs;
    libc_truncate(&p, s2).context("libc::truncate to block boundary failed")?;
    let got2 = read_all(&p).context("read_all after boundary shrink")?;
    assert_eq!(got2.len(), s2 as usize);
    assert_eq!(&got2[..], &initial[..s2 as usize]);
    assert_eq!(
        ciphertext_single_file_size(&mount.backing_root)
            .context("ciphertext size after boundary")?,
        expected_physical_size(s2, &cfg)
    );

    // Full-block to partial-block transition: 2*dbs - 1
    eprintln!("truncate_matrix: full->partial shrink");
    let s3 = 2 * dbs - 1;
    {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .with_context(|| format!("open for ftruncate {:?}", p))?;
        f.set_len(s3)
            .with_context(|| format!("ftruncate {:?} to {}", p, s3))?;
    }
    let got3 = read_all(&p).context("read_all after full->partial shrink")?;
    assert_eq!(got3.len(), s3 as usize);
    assert_eq!(&got3[..], &initial[..s3 as usize]);
    assert_eq!(
        ciphertext_single_file_size(&mount.backing_root).context("ciphertext size after s3")?,
        expected_physical_size(s3, &cfg)
    );

    // Shrink to zero.
    eprintln!("truncate_matrix: shrink to zero");
    libc_truncate(&p, 0).context("libc::truncate to zero failed")?;
    assert_eq!(
        fs::metadata(&p)
            .with_context(|| format!("metadata after truncate-to-zero {:?}", p))?
            .len(),
        0
    );
    assert!(read_all(&p)
        .context("read_all after truncate-to-zero")?
        .is_empty());
    assert_eq!(
        ciphertext_single_file_size(&mount.backing_root).context("ciphertext size after zero")?,
        expected_physical_size(0, &cfg)
    );

    // Extend within same block: 100 -> 500
    eprintln!("truncate_matrix: extend within block");
    let old = 100u64;
    let new = 500u64;
    fs::write(&p, pattern_bytes(old as usize))
        .with_context(|| format!("rewrite {:?} to {} bytes for extend-within-block", p, old))?;
    libc_truncate(&p, new)
        .with_context(|| format!("truncate {:?} to {} (extend-within-block)", p, new))?;
    assert_eq!(
        fs::metadata(&p)
            .with_context(|| format!("metadata after extend-within-block {:?}", p))?
            .len(),
        new
    );
    let prefix = read_range(&p, 0, old as usize)
        .with_context(|| format!("read prefix after extend-within-block {:?}", p))?;
    assert_eq!(prefix, pattern_bytes(old as usize));
    let grown = read_range(&p, old, (new - old) as usize)
        .with_context(|| format!("read grown range after extend-within-block {:?}", p))?;
    assert!(grown.iter().all(|b| *b == 0));
    assert_eq!(
        ciphertext_single_file_size(&mount.backing_root)?,
        expected_physical_size(new, &cfg)
    );

    // Extend across boundary: (dbs-10) -> (dbs+10)
    eprintln!("truncate_matrix: extend across boundary");
    let old2 = dbs - 10;
    let new2 = dbs + 10;
    fs::write(&p, pattern_bytes(old2 as usize))?;
    {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .with_context(|| format!("open for ftruncate (extend across boundary) {:?}", p))?;
        f.set_len(new2)
            .with_context(|| format!("ftruncate {:?} to {}", p, new2))?;
    }
    let grown2 = read_range(&p, old2, (new2 - old2) as usize)?;
    assert!(grown2.iter().all(|b| *b == 0));

    // Extend from exact boundary: dbs -> dbs+20
    eprintln!("truncate_matrix: extend from boundary");
    let old3 = dbs;
    let new3 = dbs + 20;
    fs::write(&p, pattern_bytes(old3 as usize))?;
    libc_truncate(&p, new3)?;
    let grown3 = read_range(&p, old3, (new3 - old3) as usize)?;
    assert!(grown3.iter().all(|b| *b == 0));

    // Mixed sequence: write, shrink mid-block, then extend beyond old size.
    eprintln!("truncate_matrix: mixed shrink/extend");
    let base = (dbs + 50) as u64;
    fs::write(&p, pattern_bytes(base as usize))?;
    let shrink = dbs + 5;
    libc_truncate(&p, shrink)?;
    let extend = dbs + 200;
    libc_truncate(&p, extend)?;
    let gotm = read_all(&p)?;
    assert_eq!(gotm.len(), extend as usize);
    assert_eq!(
        &gotm[..shrink as usize],
        &pattern_bytes(base as usize)[..shrink as usize]
    );
    assert!(gotm[shrink as usize..].iter().all(|b| *b == 0));

    Ok(())
}

#[test]
#[ignore]
fn live_truncate_matrix_standard() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    match run_truncate_matrix(live::LiveConfigKind::Standard) {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("{:#?}", e);
            Err(e)
        }
    }
}

#[test]
#[ignore]
fn live_truncate_matrix_paranoia() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    match run_truncate_matrix(live::LiveConfigKind::Paranoia) {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("{:#?}", e);
            Err(e)
        }
    }
}

fn run_rename_tests(cfg_kind: live::LiveConfigKind) -> Result<()> {
    let cfg = load_live_config(cfg_kind)?;
    // Use a persistent backing root so we can remount and verify readability (especially paranoia rename).
    let backing = live::init_backing_root(&cfg)?;
    {
        let mount = MountGuard::mount_existing_backing_root(cfg.clone(), false, backing.clone())
            .context("mount (phase1) failed")?;
        let root = &mount.mount_point;

        fs::create_dir(root.join("dirA")).context("mkdir dirA failed")?;
        fs::create_dir(root.join("dirB")).context("mkdir dirB failed")?;
        let a = root.join("dirA/file.txt");
        fs::write(&a, b"rename payload").context("write dirA/file.txt failed")?;

        // Rename within directory.
        let a2 = root.join("dirA/file2.txt");
        fs::rename(&a, &a2).context("rename dirA/file.txt -> dirA/file2.txt failed")?;
        assert!(!a.exists(), "old name still exists after rename");
        assert_eq!(
            fs::read(&a2).context("read dirA/file2.txt failed")?,
            b"rename payload"
        );

        // Rename across directories.
        let b = root.join("dirB/file2.txt");
        fs::rename(&a2, &b).context("rename dirA/file2.txt -> dirB/file2.txt failed")?;
        assert!(!a2.exists(), "old name still exists after cross-dir rename");
        assert_eq!(
            fs::read(&b).context("read dirB/file2.txt failed")?,
            b"rename payload"
        );

        // Directory rename with children.
        fs::create_dir(root.join("dirOld")).context("mkdir dirOld failed")?;
        fs::create_dir_all(root.join("dirOld/sub")).context("mkdir dirOld/sub failed")?;
        let nested = root.join("dirOld/sub/n.txt");
        fs::write(&nested, b"nested").context("write dirOld/sub/n.txt failed")?;
        fs::rename(root.join("dirOld"), root.join("dirNew"))
            .context("rename dirOld -> dirNew failed")?;

        // In this implementation, directory rename may be implemented as copy+delete to accommodate
        // IV-chaining behavior. Some kernels/FUSE layers can temporarily expose stale lookup state
        // immediately after rename; the stronger end-to-end check is performed after remount below.
        assert!(root.join("dirNew").exists(), "dirNew missing after rename");
        assert!(
            !root.join("dirOld").exists(),
            "dirOld still exists after rename"
        );

        // Ensure data is flushed to backing store before unmount/remount.
        thread::sleep(Duration::from_millis(100));
    }

    // Remount and verify data is still readable.
    {
        let mount = MountGuard::mount_existing_backing_root(cfg.clone(), false, backing.clone())
            .context("mount (phase2) failed")?;
        let root = &mount.mount_point;
        assert_eq!(
            fs::read(root.join("dirB/file2.txt"))
                .context("read after remount dirB/file2.txt failed")?,
            b"rename payload"
        );
        assert_eq!(
            fs::read(root.join("dirNew/sub/n.txt"))
                .context("read after remount dirNew/sub/n.txt failed")?,
            b"nested"
        );
    }

    // Cleanup backing root (best-effort)
    let _ = fs::remove_dir_all(&backing);
    Ok(())
}

#[test]
#[ignore]
fn live_rename_standard() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    run_rename_tests(live::LiveConfigKind::Standard)
}

#[test]
#[ignore]
fn live_rename_paranoia() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    run_rename_tests(live::LiveConfigKind::Paranoia)
}

fn run_symlink_tests_standard() -> Result<()> {
    let cfg = load_live_config(live::LiveConfigKind::Standard)?;
    let mount = MountGuard::mount(cfg, false)?;
    let root = &mount.mount_point;

    // Create target file and symlink to it.
    fs::write(root.join("target.txt"), b"t")?;
    std::os::unix::fs::symlink("target.txt", root.join("lnk"))?;
    let target = fs::read_link(root.join("lnk"))?;
    assert_eq!(target, PathBuf::from("target.txt"));

    // Rename the symlink; readlink should still return the original target.
    fs::rename(root.join("lnk"), root.join("lnk2"))?;
    let target2 = fs::read_link(root.join("lnk2"))?;
    assert_eq!(target2, PathBuf::from("target.txt"));

    Ok(())
}

#[test]
#[ignore]
fn live_symlink_standard() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    run_symlink_tests_standard()
}

#[test]
#[ignore]
fn live_symlink_rename_paranoia_is_enosys() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    let cfg = load_live_config(live::LiveConfigKind::Paranoia)?;
    let mount = MountGuard::mount(cfg, false)?;
    let root = &mount.mount_point;

    fs::write(root.join("target.txt"), b"t")?;
    std::os::unix::fs::symlink("target.txt", root.join("lnk"))?;
    let err = fs::rename(root.join("lnk"), root.join("lnk2")).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOSYS));
    Ok(())
}

#[test]
#[ignore]
fn live_unlink_while_open() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    let cfg = load_live_config(live::LiveConfigKind::Standard)?;
    let mount = MountGuard::mount(cfg, false)?;
    let p = mount.mount_point.join("u.txt");
    fs::write(&p, b"unlink-open")?;

    let mut f = fs::OpenOptions::new().read(true).write(true).open(&p)?;
    fs::remove_file(&p)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    assert_eq!(buf, b"unlink-open");
    drop(f);

    // After close, the ciphertext entry should be gone (since only one file existed).
    let files = live::list_non_dot_entries_recursive(&mount.backing_root)?;
    assert!(
        files.is_empty(),
        "expected ciphertext file removed after close"
    );
    Ok(())
}

#[test]
#[ignore]
fn live_chmod_utimens_statfs() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    let cfg = load_live_config(live::LiveConfigKind::Standard)?;
    let mount = MountGuard::mount(cfg, false)?;
    let p = mount.mount_point.join("m.txt");
    fs::write(&p, b"meta")?;

    // chmod
    let mut perms = fs::metadata(&p)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&p, perms)?;
    let mode = fs::metadata(&p)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // utimens (set atime/mtime explicitly).
    let at = 1_700_000_000i64;
    let mt = 1_700_000_123i64;
    let ts = [
        libc::timespec {
            tv_sec: at,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: mt,
            tv_nsec: 0,
        },
    ];
    let c_path = CString::new(p.as_os_str().as_encoded_bytes())?;
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), ts.as_ptr(), 0) };
    assert_eq!(
        rc,
        0,
        "utimensat failed: {:?}",
        std::io::Error::last_os_error()
    );

    let mtime = fs::metadata(&p)?.modified()?;
    let mtime_secs = mtime
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64;
    assert_eq!(mtime_secs, mt);

    // statfs via statvfs
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let c_mp = CString::new(mount.mount_point.as_os_str().as_encoded_bytes())?;
    let rc = unsafe { libc::statvfs(c_mp.as_ptr(), &mut vfs as *mut _) };
    assert_eq!(
        rc,
        0,
        "statvfs failed: {:?}",
        std::io::Error::last_os_error()
    );
    assert!(vfs.f_blocks > 0);

    Ok(())
}

#[test]
#[ignore]
fn live_read_only_mount_is_ero_fs() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }
    let cfg = load_live_config(live::LiveConfigKind::Standard)?;
    let mount = MountGuard::mount(cfg, true)?;
    let p = mount.mount_point.join("ro.txt");
    let err = fs::write(&p, b"nope").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EROFS));
    Ok(())
}

#[test]
#[ignore]
fn live_wrong_password_fails_to_mount() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }

    let mut cfg = load_live_config(live::LiveConfigKind::Standard)?;
    cfg.password = "wrong";
    let res = MountGuard::mount(cfg, false);
    assert!(res.is_err(), "expected mount to fail with wrong password");
    Ok(())
}

#[test]
#[ignore]
fn live_backing_invalid_filename_is_ignored_in_readdir() -> Result<()> {
    require_live();
    if !live_enabled() {
        return Ok(());
    }

    let cfg = load_live_config(live::LiveConfigKind::Standard)?;
    let mount = MountGuard::mount(cfg, false)?;

    // Create an invalid ciphertext filename directly in the backing store.
    // `readdir` should attempt to decrypt, fail, warn, and skip it (not crash / not expose).
    fs::write(mount.backing_root.join("not_a_valid_encfs_name!"), b"x")?;

    let entries: Vec<_> = fs::read_dir(&mount.mount_point)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::result::Result<_, _>>()?;
    assert!(
        entries.is_empty(),
        "expected invalid backing entry to be ignored, got {:?}",
        entries
    );

    Ok(())
}
