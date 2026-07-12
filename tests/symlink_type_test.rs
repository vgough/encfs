use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use futures_util::StreamExt;
use rfuse3::FileType;
use rfuse3::path::PathFilesystem;
use rfuse3::path::Request;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

#[tokio::test]
async fn test_symlink_type() {
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

    let req = Request {
        unique: 1,
        pid: 1,
        gid: 0,
        uid: 0,
    };

    let parent = PathBuf::from("");
    let name = OsStr::new("mysymlink");
    let target = Path::new("target_file");

    // Create Symlink
    let _ = fs
        .symlink(req, parent.as_os_str(), name, target.as_os_str())
        .await
        .expect("symlink creation failed");

    // Check getattr
    let path = parent.join(name);
    let attr = fs
        .getattr(req, Some(path.as_os_str()), None, 0)
        .await
        .expect("getattr failed")
        .attr;

    // Logic: attr.kind should be Symlink, but currently it is RegularFile (bug)
    println!("File kind: {:?}", attr.kind);
    assert_eq!(
        attr.kind,
        FileType::Symlink,
        "getattr: Expected Symlink, got {:?}",
        attr.kind
    );

    // Check readdir
    let fh = fs
        .opendir(req, parent.as_os_str(), 0)
        .await
        .expect("opendir failed")
        .fh;
    let reply = fs
        .readdir(req, parent.as_os_str(), fh, 0)
        .await
        .expect("readdir failed");
    let entries_stream = reply.entries;
    futures_util::pin_mut!(entries_stream);
    let mut entries = Vec::new();
    while let Some(entry) = entries_stream.next().await {
        entries.push(entry.expect("readdir entry error"));
    }
    let entry = entries
        .iter()
        .find(|e| e.name.to_str() == Some("mysymlink"))
        .expect("symlink not found in readdir");
    println!("Readdir entry kind: {:?}", entry.kind);
    assert_eq!(
        entry.kind,
        FileType::Symlink,
        "readdir: Expected Symlink, got {:?}",
        entry.kind
    );

    // Cleanup
    fs::remove_dir_all(&tmp).unwrap();
}
