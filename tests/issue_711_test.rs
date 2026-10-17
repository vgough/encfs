//! Issue #711: errors from corrupted file contents must say which file is
//! corrupted. They name it by its backing (encrypted) path, never the
//! plaintext one; `encfsctl decode` recovers the plaintext name.

use encfs::config::EncfsConfig;
use encfs::fs::EncFs;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use typed_fuse::{Caller, PathFilesystem, PathNodeRef};

const PASSWORD_CMD: &str = "echo issue-711";
const PLAINTEXT_DIR: &str = "secret-dir";
const PLAINTEXT_NAME: &str = "secret-name";

fn req() -> Caller {
    Caller {
        pid: 1,
        gid: unsafe { libc::getgid() },
        uid: unsafe { libc::getuid() },
        umask: 0,
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("encfs_issue711_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn encfsctl(args: &[&OsStr]) -> Output {
    encfsctl_in(Path::new("."), args)
}

fn encfsctl_in(cwd: &Path, args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_encfsctl"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

fn decode(cwd: &Path, root: &Path, encoded: &Path) -> String {
    let out = encfsctl_in(
        cwd,
        &[
            "decode".as_ref(),
            "--extpass".as_ref(),
            PASSWORD_CMD.as_ref(),
            root.as_os_str(),
            encoded.as_os_str(),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Creates a volume holding one file, in a subdirectory, with a corrupted
/// first block, and returns the file's backing path.
fn corrupted_volume(root: &Path) -> PathBuf {
    let out = encfsctl(&[
        "new".as_ref(),
        "--extpass".as_ref(),
        PASSWORD_CMD.as_ref(),
        root.as_os_str(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let config = EncfsConfig::load(&root.join(".encfs7")).unwrap();
    let header_size = config.header_size() as usize;
    let cipher = config.get_cipher("issue-711").unwrap();
    let mut efs = EncFs::new(root.to_path_buf(), cipher, config);
    let root_state = efs.root_state();
    let dir_path = format!("/{PLAINTEXT_DIR}");
    let dir = efs
        .mkdir(
            PathNodeRef::new(Some(Path::new("/")), &root_state),
            OsStr::new(PLAINTEXT_DIR),
            0o755,
            0,
            &req(),
        )
        .unwrap();
    let (entry, opened) = efs
        .create(
            PathNodeRef::new(Some(Path::new(&dir_path)), &dir.state),
            OsStr::new(PLAINTEXT_NAME),
            0o644,
            0,
            libc::O_CREAT | libc::O_RDWR,
            &req(),
        )
        .unwrap();
    let path = format!("{dir_path}/{PLAINTEXT_NAME}");
    let file = || PathNodeRef::new(Some(Path::new(&path)), &entry.state);
    efs.write(file(), &opened.handle, &[7u8; 100], 0, &req())
        .unwrap();
    efs.release(file(), opened.handle, &req()).unwrap();

    let (backing, _) = efs.encrypt_path(Path::new(&path)).unwrap();
    let mut data = fs::read(&backing).unwrap();
    data[header_size + 20] ^= 0x01;
    fs::write(&backing, data).unwrap();
    backing
}

/// Errors name backing files under the canonical root, however it was given.
fn assert_names_backing_file(stderr: &[u8], backing: &Path) {
    let stderr = String::from_utf8_lossy(stderr);
    let backing = backing.canonicalize().unwrap();
    assert!(
        stderr.contains(&backing.display().to_string()),
        "error does not name {}: {stderr}",
        backing.display()
    );
    assert!(
        !stderr.contains(PLAINTEXT_DIR) && !stderr.contains(PLAINTEXT_NAME),
        "error leaks a plaintext name: {stderr}"
    );
}

/// The path an error prints decodes back to the plaintext one as is.
#[test]
fn decode_accepts_the_printed_backing_path() {
    let root = temp_dir("decode");
    let backing = corrupted_volume(&root);

    let plaintext = format!("{PLAINTEXT_DIR}/{PLAINTEXT_NAME}");
    let parent = root.parent().unwrap();
    let relative_root = Path::new(root.file_name().unwrap());
    let in_root = backing.strip_prefix(&root).unwrap();

    assert_eq!(decode(parent, &root, &backing), plaintext);
    // Under the canonical root, as a mount logs it.
    assert_eq!(
        decode(parent, &root, &backing.canonicalize().unwrap()),
        plaintext
    );
    // With the root given as a relative path, under the working directory,
    // as encfsctl prints it (getcwd reports the canonical directory).
    assert_eq!(
        decode(parent, relative_root, &backing.canonicalize().unwrap()),
        plaintext
    );
    // Relative to the root, as before, with or without a leading `/`.
    assert_eq!(decode(parent, &root, in_root), plaintext);
    assert_eq!(decode(parent, relative_root, in_root), plaintext);
    assert_eq!(
        decode(parent, &root, &Path::new("/").join(in_root)),
        plaintext
    );

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn cat_names_the_corrupted_file() {
    let root = temp_dir("cat");
    let backing = corrupted_volume(&root);

    let out = encfsctl(&[
        "cat".as_ref(),
        "--extpass".as_ref(),
        PASSWORD_CMD.as_ref(),
        backing.as_os_str(),
    ]);
    assert!(!out.status.success());
    assert_names_backing_file(&out.stderr, &backing);

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn export_names_the_corrupted_file() {
    let root = temp_dir("export");
    let backing = corrupted_volume(&root);
    // Given relative to the working directory, and through `..`, the root is
    // still printed as the canonical path, which `decode` accepts with the
    // root given any other way.
    let parent = root.parent().unwrap();
    let name = root.file_name().unwrap();
    let relative_root = Path::new(name).join("..").join(name);

    for fail_on_error in [false, true] {
        let dest = temp_dir(&format!("export_dest_{fail_on_error}"));
        let mut args: Vec<&OsStr> = vec![
            "export".as_ref(),
            "--extpass".as_ref(),
            PASSWORD_CMD.as_ref(),
            relative_root.as_os_str(),
            dest.as_os_str(),
        ];
        if fail_on_error {
            args.push("--fail-on-error".as_ref());
        }
        let out = encfsctl_in(parent, &args);
        assert_eq!(out.status.success(), !fail_on_error);
        assert_names_backing_file(&out.stderr, &backing);
        // Reported as corruption, naming the file once.
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("Undecryptable file contents"), "{stderr}");
        assert!(!stderr.contains("/../"), "{stderr}");
        let name = backing.file_name().unwrap().to_string_lossy();
        assert_eq!(stderr.matches(&*name).count(), 1, "{stderr}");
        // No partial copy is left behind.
        assert!(!dest.join(PLAINTEXT_DIR).join(PLAINTEXT_NAME).exists());
        let _ = fs::remove_dir_all(&dest);
    }

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn cat_names_a_file_with_an_incomplete_header() {
    let root = temp_dir("cat_header");
    let backing = corrupted_volume(&root);
    fs::OpenOptions::new()
        .write(true)
        .open(&backing)
        .unwrap()
        .set_len(2)
        .unwrap();

    let out = encfsctl(&[
        "cat".as_ref(),
        "--extpass".as_ref(),
        PASSWORD_CMD.as_ref(),
        backing.as_os_str(),
    ]);
    assert!(!out.status.success());
    assert_names_backing_file(&out.stderr, &backing);

    fs::remove_dir_all(&root).unwrap();
}

/// With `--fail-on-error`, export names the file whatever the error is.
#[test]
fn export_fail_on_error_names_an_unreadable_file() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_dir("export_unreadable");
    let backing = corrupted_volume(&root);
    fs::set_permissions(&backing, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&backing).is_ok() {
        // Running as root: permissions don't stop the read.
        fs::remove_dir_all(&root).unwrap();
        return;
    }

    let dest = temp_dir("export_unreadable_dest");
    let out = encfsctl(&[
        "export".as_ref(),
        "--extpass".as_ref(),
        PASSWORD_CMD.as_ref(),
        "--fail-on-error".as_ref(),
        root.as_os_str(),
        dest.as_os_str(),
    ]);
    assert!(!out.status.success());
    assert_names_backing_file(&out.stderr, &backing);
    // Named once, not again for each directory the error passes through.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let dir = backing.parent().unwrap().canonicalize().unwrap();
    let dir = dir.display().to_string();
    assert_eq!(stderr.matches(&dir).count(), 1, "{stderr}");

    let _ = fs::remove_dir_all(&dest);
    fs::remove_dir_all(&root).unwrap();
}

/// With `--fail-on-error`, an undecryptable name is reported once, by its
/// backing path.
#[test]
fn export_fail_on_error_names_an_undecryptable_entry_once() {
    let root = temp_dir("export_bad_name");
    let backing = corrupted_volume(&root);
    // Keep the invalid name as the only export failure, regardless of
    // directory iteration order.
    fs::remove_file(backing).unwrap();
    let bad = root.join("AAAAAAAAAAAAAAAAAAAAAAAA");
    fs::write(&bad, b"").unwrap();

    let dest = temp_dir("export_bad_name_dest");
    let out = encfsctl(&[
        "export".as_ref(),
        "--extpass".as_ref(),
        PASSWORD_CMD.as_ref(),
        "--fail-on-error".as_ref(),
        root.as_os_str(),
        dest.as_os_str(),
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let name = bad.file_name().unwrap().to_string_lossy();
    assert_eq!(stderr.matches(&*name).count(), 1, "{stderr}");
    let bad = bad.canonicalize().unwrap();
    assert!(stderr.contains(&bad.display().to_string()), "{stderr}");

    let _ = fs::remove_dir_all(&dest);
    fs::remove_dir_all(&root).unwrap();
}

/// Without `--fail-on-error`, export warns about an undecryptable entry by
/// its full backing path, so it can be found in a subdirectory, and goes on.
#[test]
fn export_warning_names_a_nested_undecryptable_entry() {
    let root = temp_dir("export_nested_bad_name");
    let backing = corrupted_volume(&root);
    let dir = backing.parent().unwrap().to_path_buf();
    fs::remove_file(backing).unwrap();
    let bad = dir.join("AAAAAAAAAAAAAAAAAAAAAAAA");
    fs::write(&bad, b"").unwrap();

    let dest = temp_dir("export_nested_bad_name_dest");
    let out = encfsctl(&[
        "export".as_ref(),
        "--extpass".as_ref(),
        PASSWORD_CMD.as_ref(),
        root.as_os_str(),
        dest.as_os_str(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let bad = bad.canonicalize().unwrap();
    assert!(stderr.contains(&bad.display().to_string()), "{stderr}");
    assert!(dest.join(PLAINTEXT_DIR).is_dir());

    let _ = fs::remove_dir_all(&dest);
    fs::remove_dir_all(&root).unwrap();
}

/// `cat ROOT PATH` accepts the backing path an error prints.
#[test]
fn cat_accepts_the_printed_backing_path() {
    let root = temp_dir("cat_backing");
    let backing = corrupted_volume(&root);
    let parent = root.parent().unwrap();
    let relative_root = Path::new(root.file_name().unwrap());

    // A relative root prints under the working directory, which getcwd
    // reports canonical.
    let canonical_backing = backing.canonicalize().unwrap();
    for (root_arg, printed) in [
        (root.as_path(), &backing),
        (relative_root, &canonical_backing),
    ] {
        let out = encfsctl_in(
            parent,
            &[
                "cat".as_ref(),
                "--extpass".as_ref(),
                PASSWORD_CMD.as_ref(),
                root_arg.as_os_str(),
                printed.as_os_str(),
            ],
        );
        // It finds the file, and fails on its corrupted block.
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("Undecryptable file contents"), "{stderr}");
        assert_names_backing_file(&out.stderr, &backing);
    }

    fs::remove_dir_all(&root).unwrap();
}
