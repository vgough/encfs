use encfs::config::Interface;
use encfs::crypto::ssl::SslCipher;
use encfs::fs::EncFs;
use futures_util::StreamExt;
use rfuse3::FileType;
use rfuse3::path::PathFilesystem;
use rfuse3::path::Request;
use rfuse3::path::reply::{DirectoryEntry, DirectoryEntryPlus};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn req() -> Request {
    Request {
        unique: 1,
        pid: 1,
        gid: 0,
        uid: 0,
    }
}

fn setup_fs(test_name: &str) -> (PathBuf, EncFs) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "encfs_{test_name}_{}_{}",
        std::process::id(),
        nonce
    ));
    fs::create_dir(&root).expect("create test directory");

    let iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };
    let mut cipher = SslCipher::new(&iface, 192).expect("create cipher");
    cipher.set_key(&[1u8; 24], &[2u8; 16]);

    let config = encfs::config::EncfsConfig::test_default();
    let encfs = EncFs::new(root.clone(), Box::new(cipher), config);
    (root, encfs)
}

async fn create_file(encfs: &EncFs, name: &str) {
    encfs
        .mknod(
            req(),
            OsStr::new(""),
            OsStr::new(name),
            u32::from(libc::S_IFREG | 0o600),
            0,
        )
        .await
        .unwrap_or_else(|e| panic!("create {name}: {e}"));
}

async fn read_entries(encfs: &EncFs, fh: u64, offset: i64) -> Vec<DirectoryEntry> {
    let reply = encfs
        .readdir(req(), OsStr::new(""), fh, offset)
        .await
        .expect("readdir");
    let entries = reply.entries;
    futures_util::pin_mut!(entries);
    let mut result = Vec::new();
    while let Some(entry) = entries.next().await {
        result.push(entry.expect("directory entry"));
    }
    result
}

async fn read_prefix(encfs: &EncFs, fh: u64, count: usize) -> Vec<DirectoryEntry> {
    let reply = encfs
        .readdir(req(), OsStr::new(""), fh, 0)
        .await
        .expect("readdir prefix");
    let entries = reply.entries;
    futures_util::pin_mut!(entries);
    let mut result = Vec::new();
    while result.len() < count {
        let Some(entry) = entries.next().await else {
            break;
        };
        result.push(entry.expect("directory prefix entry"));
    }
    result
}

async fn read_entries_plus(encfs: &EncFs, fh: u64, offset: u64) -> Vec<DirectoryEntryPlus> {
    let reply = encfs
        .readdirplus(req(), OsStr::new(""), fh, offset, 0)
        .await
        .expect("readdirplus");
    let entries = reply.entries;
    futures_util::pin_mut!(entries);
    let mut result = Vec::new();
    while let Some(entry) = entries.next().await {
        result.push(entry.expect("directory entry plus"));
    }
    result
}

async fn read_prefix_plus(encfs: &EncFs, fh: u64, count: usize) -> Vec<DirectoryEntryPlus> {
    let reply = encfs
        .readdirplus(req(), OsStr::new(""), fh, 0, 0)
        .await
        .expect("readdirplus prefix");
    let entries = reply.entries;
    futures_util::pin_mut!(entries);
    let mut result = Vec::new();
    while result.len() < count {
        let Some(entry) = entries.next().await else {
            break;
        };
        result.push(entry.expect("directory plus prefix entry"));
    }
    result
}

fn names<'a>(entries: impl IntoIterator<Item = &'a DirectoryEntry>) -> BTreeSet<String> {
    entries
        .into_iter()
        .map(|entry| entry.name.to_string_lossy().into_owned())
        .collect()
}

fn plus_names<'a>(entries: impl IntoIterator<Item = &'a DirectoryEntryPlus>) -> BTreeSet<String> {
    entries
        .into_iter()
        .map(|entry| entry.name.to_string_lossy().into_owned())
        .collect()
}

#[tokio::test]
async fn readdir_resumes_from_an_opendir_snapshot() {
    let (root, encfs) = setup_fs("readdir_snapshot");
    for name in ["old-a", "old-b", "old-c"] {
        create_file(&encfs, name).await;
    }

    let fh = encfs
        .opendir(req(), OsStr::new(""), 0)
        .await
        .expect("opendir")
        .fh;
    let prefix = read_prefix(&encfs, fh, 3).await;
    let resume_offset = prefix.last().expect("snapshot prefix").offset;

    encfs
        .unlink(req(), OsStr::new(""), OsStr::new("old-b"))
        .await
        .expect("remove old-b");
    create_file(&encfs, "new-entry").await;

    let resumed = read_entries(&encfs, fh, resume_offset).await;
    let combined: Vec<_> = prefix.iter().chain(&resumed).cloned().collect();
    let expected_before = BTreeSet::from([
        ".".to_string(),
        "..".to_string(),
        "old-a".to_string(),
        "old-b".to_string(),
        "old-c".to_string(),
    ]);
    assert_eq!(names(&combined), expected_before);
    assert_eq!(combined.len(), expected_before.len(), "duplicate entries");

    let new_fh = encfs
        .opendir(req(), OsStr::new(""), 0)
        .await
        .expect("new opendir")
        .fh;
    let expected_after = BTreeSet::from([
        ".".to_string(),
        "..".to_string(),
        "old-a".to_string(),
        "old-c".to_string(),
        "new-entry".to_string(),
    ]);
    assert_eq!(
        names(&read_entries(&encfs, new_fh, 0).await),
        expected_after
    );

    encfs
        .releasedir(req(), OsStr::new(""), fh, 0)
        .await
        .expect("release old snapshot");
    encfs
        .releasedir(req(), OsStr::new(""), new_fh, 0)
        .await
        .expect("release new snapshot");
    fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn readdirplus_retains_snapshot_attributes_after_deletion() {
    let (root, encfs) = setup_fs("readdirplus_snapshot");
    create_file(&encfs, "kept").await;
    create_file(&encfs, "deleted").await;

    let fh = encfs
        .opendir(req(), OsStr::new(""), 0)
        .await
        .expect("opendir")
        .fh;
    // Consume only dot entries so every named entry, including the one deleted
    // below, must be returned from the retained snapshot after the mutation.
    let prefix = read_prefix_plus(&encfs, fh, 2).await;
    let resume_offset = prefix.last().expect("snapshot prefix").offset as u64;

    encfs
        .unlink(req(), OsStr::new(""), OsStr::new("deleted"))
        .await
        .expect("remove deleted entry");
    create_file(&encfs, "added").await;

    let resumed = read_entries_plus(&encfs, fh, resume_offset).await;
    let combined: Vec<_> = prefix.iter().chain(&resumed).cloned().collect();
    let expected_before = BTreeSet::from([
        ".".to_string(),
        "..".to_string(),
        "kept".to_string(),
        "deleted".to_string(),
    ]);
    assert_eq!(plus_names(&combined), expected_before);
    assert_eq!(combined.len(), expected_before.len(), "duplicate entries");
    let deleted = combined
        .iter()
        .find(|entry| entry.name == OsStr::new("deleted"))
        .expect("deleted entry retained in snapshot");
    assert_eq!(deleted.kind, FileType::RegularFile);
    assert_eq!(deleted.attr.kind, FileType::RegularFile);

    let new_fh = encfs
        .opendir(req(), OsStr::new(""), 0)
        .await
        .expect("new opendir")
        .fh;
    let expected_after = BTreeSet::from([
        ".".to_string(),
        "..".to_string(),
        "kept".to_string(),
        "added".to_string(),
    ]);
    assert_eq!(
        plus_names(&read_entries_plus(&encfs, new_fh, 0).await),
        expected_after
    );

    encfs
        .releasedir(req(), OsStr::new(""), fh, 0)
        .await
        .expect("release old snapshot");
    encfs
        .releasedir(req(), OsStr::new(""), new_fh, 0)
        .await
        .expect("release new snapshot");
    fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn directory_handle_validation_and_terminal_offsets() {
    let (root, encfs) = setup_fs("directory_handle_validation");
    create_file(&encfs, "entry").await;

    let invalid = 999_999;
    let error = match encfs.readdir(req(), OsStr::new(""), invalid, 0).await {
        Err(error) => error,
        Ok(_) => panic!("unknown readdir handle should fail"),
    };
    assert_eq!(error, rfuse3::Errno::from(libc::EBADF));
    let error = match encfs
        .readdirplus(req(), OsStr::new(""), invalid, 0, 0)
        .await
    {
        Err(error) => error,
        Ok(_) => panic!("unknown readdirplus handle should fail"),
    };
    assert_eq!(error, rfuse3::Errno::from(libc::EBADF));

    let fh = encfs
        .opendir(req(), OsStr::new(""), 0)
        .await
        .expect("opendir")
        .fh;
    assert!(read_entries(&encfs, fh, 3).await.is_empty());
    assert!(read_entries(&encfs, fh, i64::MAX).await.is_empty());
    assert!(read_entries_plus(&encfs, fh, 3).await.is_empty());
    assert!(read_entries_plus(&encfs, fh, u64::MAX).await.is_empty());

    encfs
        .releasedir(req(), OsStr::new(""), fh, 0)
        .await
        .expect("releasedir");
    encfs
        .releasedir(req(), OsStr::new(""), fh, 0)
        .await
        .expect("releasedir is idempotent");

    let error = match encfs.readdir(req(), OsStr::new(""), fh, 0).await {
        Err(error) => error,
        Ok(_) => panic!("released readdir handle should fail"),
    };
    assert_eq!(error, rfuse3::Errno::from(libc::EBADF));
    let error = match encfs.readdirplus(req(), OsStr::new(""), fh, 0, 0).await {
        Err(error) => error,
        Ok(_) => panic!("released readdirplus handle should fail"),
    };
    assert_eq!(error, rfuse3::Errno::from(libc::EBADF));

    fs::remove_dir_all(root).expect("cleanup");
}
