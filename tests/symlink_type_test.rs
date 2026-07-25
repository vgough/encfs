use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use typed_fuse::{Caller, FileKind as FileType, PathDirSink, PathFilesystem};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

struct Entries(Vec<(OsString, FileType)>);
impl PathDirSink for Entries {
    fn add(&mut self, name: &OsStr, kind: FileType, _next_offset: u64) -> bool {
        self.0.push((name.to_os_string(), kind));
        true
    }
}

#[test]
fn test_symlink_type() {
    let _ = env_logger::builder().is_test(true).try_init();
    let tmp = std::env::temp_dir().join("encfs_symlink_test");
    if tmp.exists() {
        fs::remove_dir_all(&tmp).unwrap();
    }
    fs::create_dir(&tmp).unwrap();

    let root = tmp.clone();

    // Setup Cipher
    let iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };
    let cipher = SslCipher::new(&iface, 192).unwrap();
    let mut cipher = cipher;
    let user_key = vec![1u8; 24];
    let user_iv = vec![2u8; 16];
    cipher.set_key(&user_key, &user_iv);

    let config = encfs::config::EncfsConfig::test_default();
    let fs = EncFs::new(root.clone(), Box::new(cipher), config);

    let req = Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    };

    let parent = PathBuf::from("");
    let name = OsStr::new("mysymlink");
    let target = Path::new("target_file");

    // Create Symlink
    let _ = fs
        .symlink(&parent, name, target, &req)
        .expect("symlink creation failed");

    // Check getattr
    let path = parent.join(name);
    let attr = fs.getattr(Some(&path), None, &req).expect("getattr failed");

    // Logic: attr.kind should be Symlink, but currently it is RegularFile (bug)
    println!("File kind: {:?}", attr.kind);
    assert_eq!(
        attr.kind,
        FileType::Symlink,
        "getattr: Expected Symlink, got {:?}",
        attr.kind
    );

    // Check readdir
    let handle = fs.opendir(&parent, 0, &req).expect("opendir failed").handle;
    let mut entries = Entries(Vec::new());
    fs.readdir(&parent, &handle, 0, &mut entries, &req)
        .expect("readdir failed");
    let entry = entries
        .0
        .iter()
        .find(|e| e.0 == OsStr::new("mysymlink"))
        .expect("symlink not found in readdir");
    println!("Readdir entry kind: {:?}", entry.1);
    assert_eq!(
        entry.1,
        FileType::Symlink,
        "readdir: Expected Symlink, got {:?}",
        entry.1
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
