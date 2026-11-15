//! Backward compatibility with C++ EncFS: files it wrote read back through
//! `EncFs`'s open/read path, `encfsctl cat` and `encfsctl export`. The
//! procedure, and the results to expect, are in
//! `docs/testing/cpp-compatibility.md`.
//!
//! Ignored by default, as `cat` derives the key once per file:
//!
//! ```text
//! ENCFS_CPP_VOLUMES=<dir> cargo test --test cpp_compat_test -- --ignored --nocapture
//! ```
//!
//! Always checks the C++ fixtures in `tests/fixtures`. With
//! `ENCFS_CPP_VOLUMES`, also checks every `<dir>/<name>/cipher` volume
//! (config inside, password "test") against `<dir>/<name>/manifest`, as
//! `tests/cpp_compat/make-volumes.sh` writes them. Prints one `ok`/`FAIL`
//! line per volume and reader.
use encfs::config::EncfsConfig;
use encfs::fs::EncFs;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use typed_fuse::PathFilesystem;

mod common;
use common::node;
use common::volume::req;

const PASSWORD: &str = "test";

fn sha1(data: &[u8]) -> String {
    Sha1::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for e in fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let t = e.file_type().unwrap();
        let to = dst.join(e.file_name());
        if t.is_dir() {
            copy_tree(&e.path(), &to);
        } else if t.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(e.path()).unwrap(), &to).unwrap();
        } else {
            fs::copy(e.path(), &to).unwrap();
        }
    }
}

/// What each plaintext path holds: `file <sha1>` or `link <target>`.
type Listing = BTreeMap<String, String>;

fn is_config(name: &[u8]) -> bool {
    name.starts_with(b".encfs")
}

/// Reads the tree at `root` through `EncFs`: names by `decrypt_path`,
/// contents by open/read, targets by readlink.
fn read_through_encfs(root: &Path, config: &EncfsConfig) -> Result<Listing, String> {
    let cipher = config.get_cipher(PASSWORD).map_err(|e| format!("{e:#}"))?;
    let mut efs = EncFs::new(root.to_path_buf(), cipher, config.clone());
    let root_state = efs.root_state();
    let mut out = Listing::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for e in fs::read_dir(root.join(&rel)).unwrap() {
            let e = e.unwrap();
            if is_config(e.file_name().as_bytes()) {
                continue;
            }
            let rel = rel.join(e.file_name());
            let (plain, _) = efs
                .decrypt_path(&rel)
                .map_err(|e| format!("decrypt_path {rel:?}: errno {e}"))?;
            let plain_s = format!("/{}", plain.to_string_lossy());
            let t = e.file_type().unwrap();
            if t.is_dir() {
                stack.push(rel);
            } else if t.is_symlink() {
                let n = node(&efs, &root_state, &plain_s, &req());
                let target = efs
                    .readlink(n.as_node(), &req())
                    .map_err(|e| format!("readlink {plain_s}: errno {e}"))?;
                out.insert(plain_s, format!("link {}", target.display()));
            } else {
                let n = node(&efs, &root_state, &plain_s, &req());
                let opened = efs
                    .open(n.as_node(), libc::O_RDONLY, &req())
                    .map_err(|e| format!("open {plain_s}: errno {e}"))?;
                let mut data = Vec::new();
                loop {
                    let chunk = efs
                        .read(
                            n.as_node(),
                            &opened.handle,
                            data.len() as u64,
                            1 << 17,
                            &req(),
                        )
                        .map_err(|e| format!("read {plain_s}: errno {e}"))?
                        .into_owned();
                    if chunk.is_empty() {
                        break;
                    }
                    data.extend_from_slice(&chunk);
                }
                efs.release(n.as_node(), opened.handle, &req()).unwrap();
                out.insert(plain_s, format!("file {}", sha1(&data)));
            }
        }
    }
    Ok(out)
}

fn encfsctl(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_encfsctl"))
        .args(args)
        .output()
        .unwrap()
}

/// `encfsctl cat` of each file, by backing path.
fn read_with_cat(root: &Path) -> Result<Listing, String> {
    let cipher_names = {
        let mut v = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                if is_config(e.file_name().as_bytes()) {
                    continue;
                }
                let t = e.file_type().unwrap();
                if t.is_dir() {
                    stack.push(e.path());
                } else if t.is_file() {
                    v.push(e.path());
                }
            }
        }
        v
    };
    let mut out = Listing::new();
    for path in cipher_names {
        let rel = path.strip_prefix(root).unwrap();
        let decoded = encfsctl(&[
            "decode".as_ref(),
            "--extpass".as_ref(),
            "echo test".as_ref(),
            "--".as_ref(),
            root.as_os_str(),
            rel.as_os_str(),
        ]);
        let plain = String::from_utf8_lossy(&decoded.stdout).trim().to_string();
        let o = encfsctl(&[
            "cat".as_ref(),
            "--extpass".as_ref(),
            "echo test".as_ref(),
            // An encrypted name can start with `-`.
            "--".as_ref(),
            root.as_os_str(),
            rel.as_os_str(),
        ]);
        if !o.status.success() {
            return Err(format!(
                "cat {plain}: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        let plain = if plain.starts_with('/') {
            plain
        } else {
            format!("/{plain}")
        };
        out.insert(plain, format!("file {}", sha1(&o.stdout)));
    }
    Ok(out)
}

/// `encfsctl export --fail-on-error` of the whole tree.
fn read_with_export(root: &Path) -> Result<Listing, String> {
    let dest = tempfile::tempdir().unwrap();
    let dest = dest.path().join("out");
    let o = encfsctl(&[
        "export".as_ref(),
        "--extpass".as_ref(),
        "echo test".as_ref(),
        "--fail-on-error".as_ref(),
        root.as_os_str(),
        dest.as_os_str(),
    ]);
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).trim().to_string());
    }
    let mut out = Listing::new();
    let mut stack = vec![dest.clone()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let t = e.file_type().unwrap();
            let plain = format!("/{}", e.path().strip_prefix(&dest).unwrap().display());
            if t.is_dir() {
                stack.push(e.path());
            } else if t.is_symlink() {
                out.insert(
                    plain,
                    format!("link {}", fs::read_link(e.path()).unwrap().display()),
                );
            } else {
                out.insert(
                    plain,
                    format!("file {}", sha1(&fs::read(e.path()).unwrap())),
                );
            }
        }
    }
    Ok(out)
}

fn compare(label: &str, how: &str, got: Result<Listing, String>, want: &Listing) -> bool {
    match got {
        Err(e) => {
            println!("FAIL {label:<28} {how:<7} {e}");
            false
        }
        Ok(got) => {
            let want: Listing = if how == "cat" {
                want.iter()
                    .filter(|(_, v)| v.starts_with("file"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            } else {
                want.clone()
            };
            if got == want {
                println!("ok   {label:<28} {how:<7} {} entries", got.len());
                true
            } else {
                println!("FAIL {label:<28} {how:<7} mismatch");
                for (k, v) in &want {
                    if got.get(k) != Some(v) {
                        println!("       want {k}: {v}, got {:?}", got.get(k));
                    }
                }
                for k in got.keys().filter(|k| !want.contains_key(*k)) {
                    println!("       extra {k}: {}", got[k]);
                }
                false
            }
        }
    }
}

/// A volume in a temp dir, config inside, ready for every reader.
fn check(label: &str, root: &Path, want: Option<Listing>) -> bool {
    let config_path = fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| is_config(p.file_name().unwrap().as_bytes()))
        .unwrap();
    let config = match EncfsConfig::load(&config_path) {
        Ok(config) => config,
        Err(e) => {
            println!("FAIL {label:<28} load    {e:#}");
            return false;
        }
    };
    println!(
        "--   {label}: {:?} v{} uniqueIV={} chainedIV={} externalIV={} mac={} holes={} block={}",
        config.config_type,
        config.version,
        config.unique_iv,
        config.chained_name_iv,
        config.external_iv_chaining,
        config.block_mac_bytes,
        config.allow_holes,
        config.block_size
    );
    let mount = read_through_encfs(root, &config);
    // Without a manifest, the mount's view is the reference for the tools,
    // and only that it reads at all is checked here.
    let want = match (want, &mount) {
        (Some(w), _) => w,
        (None, Ok(m)) => m.clone(),
        (None, Err(_)) => Listing::new(),
    };
    let mut ok = compare(label, "mount", mount, &want);
    ok &= compare(label, "cat", read_with_cat(root), &want);
    ok &= compare(label, "export", read_with_export(root), &want);
    ok
}

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

#[test]
#[ignore = "slow; see docs/testing/cpp-compatibility.md"]
fn cpp_written_files_read_back() {
    let mut ok = true;
    let temp = tempfile::tempdir().unwrap();

    // C++ fixtures already in the repo.
    let std_root = temp.path().join("v6-std");
    fs::create_dir(&std_root).unwrap();
    fs::copy(fixture("encfs6-std.xml"), std_root.join(".encfs6.xml")).unwrap();
    fs::copy(
        fixture("MhAO8Ckgt67m1cSrFU9HHiNT"),
        std_root.join("MhAO8Ckgt67m1cSrFU9HHiNT"),
    )
    .unwrap();
    // The same file through the legacy FileDecoder path the existing
    // tests use: DESIGN.md.
    ok &= check("fixture v6 standard", &std_root, None);

    let par_root = temp.path().join("v6-paranoia");
    fs::create_dir(&par_root).unwrap();
    fs::copy(fixture("encfs6-paranoia.xml"), par_root.join(".encfs6.xml")).unwrap();
    copy_tree(
        &fixture("U,-Aj0Ha7VZMhbnuv-vx1DZu"),
        &par_root.join("U,-Aj0Ha7VZMhbnuv-vx1DZu"),
    );
    ok &= check("fixture v6 paranoia", &par_root, None);

    let v5_root = temp.path().join("v5");
    copy_tree(&fixture("encfs142"), &v5_root);
    ok &= check("fixture v5 (encfs 1.4.2)", &v5_root, None);

    // Volumes written by a C++ mount, with manifests.
    if let Ok(dir) = std::env::var("ENCFS_CPP_VOLUMES") {
        let mut names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.join("manifest").exists())
            .collect();
        names.sort();
        for vol in names {
            let label = vol.file_name().unwrap().to_string_lossy().into_owned();
            let root = temp.path().join(format!("cpp-{label}"));
            copy_tree(&vol.join("cipher"), &root);
            let mut want = Listing::new();
            for line in fs::read_to_string(vol.join("manifest")).unwrap().lines() {
                let mut parts = line.splitn(3, ' ');
                let (hash, kind, rest) = (
                    parts.next().unwrap(),
                    parts.next().unwrap(),
                    parts.next().unwrap(),
                );
                let rest = rest.trim_start_matches('.');
                match kind {
                    "f" => {
                        want.insert(rest.to_string(), format!("file {hash}"));
                    }
                    "l" => {
                        let (path, target) = rest.split_once(" -> ").unwrap();
                        want.insert(path.to_string(), format!("link {target}"));
                    }
                    _ => panic!("{line}"),
                }
            }
            ok &= check(&format!("C++ {label}"), &root, Some(want));
        }
    }
    assert!(ok, "see FAIL lines above");
}
