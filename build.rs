use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Skip compilation when using system gettext
    if env::var_os("CARGO_FEATURE_GETTEXT_SYSTEM").is_some() {
        println!("cargo:warning=Using system gettext translations");
        return;
    }

    let locale_dir = env::var("ENCFS_LOCALE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env::var("OUT_DIR").unwrap()).join("i18n"));

    println!("cargo:rerun-if-changed=po");
    println!("cargo:rerun-if-changed=po/LINGUAS");

    // watch out for this var because it influences installation folder settings, see mod i18n in lib.rs for details
    println!("cargo:rustc-env=ENCFS_LOCALE_DIR={}", locale_dir.display());

    let languages = read_linguas("po/LINGUAS");

    for lang in languages {
        let po_file = Path::new("po").join(format!("{lang}.po"));
        let mo_file = locale_dir.join(&lang).join("LC_MESSAGES").join("encfs.mo");
        compile_po(&po_file, &mo_file);
    }
}

fn read_linguas(path: &str) -> Vec<String> {
    let contents = fs::read_to_string(path)
        .expect("failed to read po/LINGUAS");

    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

fn compile_po(po_path: &Path, mo_path: &Path) {
    if let Some(parent) = mo_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }

    let status = Command::new("msgfmt")
        .arg("--check")
        .arg(po_path)
        .arg("-o")
        .arg(mo_path)
        .arg("--statistics")
        .status()
        .expect("failed to execute msgfmt");

    if !status.success() {
        panic!("msgfmt failed for {:?}", po_path);
    }
}