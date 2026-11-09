/// Tests for: control requests over extended attributes on the mount root
///
/// A getxattr of a `user.encfs.rpc.*` name on the root is answered by the
/// filesystem itself with a JSON reply, never stored or listed, and refused to
/// other users (see `encfs::rpc`).
use encfs::config::{ConfigType, Interface, XattrFormat};
use encfs::crypto::ssl::SslCipher;
use encfs::fs::{EncFs, FileState};
use encfs::idle_lock::{Authenticator, IdleLock};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use typed_fuse::{Caller, Errno, PathFilesystem, PathNodeRef, XattrReply as ReplyXAttr};

mod common;
use common::Node;

const XATTR_BUF_SIZE: usize = 65536;
const INFO: &str = "user.encfs.rpc.info";

fn setup_fs(root: &Path, config_type: ConfigType, xattr_format: XattrFormat) -> EncFs {
    let iface = Interface {
        name: "ssl/aes".to_string(),
        major: 3,
        minor: 0,
        age: 0,
    };
    let mut cipher = SslCipher::new(&iface, 192).unwrap();
    cipher.set_key(&[1u8; 24], &[2u8; 16]);
    let mut config = encfs::config::EncfsConfig::test_default();
    config.config_type = config_type;
    config.xattr_format = xattr_format;
    EncFs::new(root.to_path_buf(), Box::new(cipher), config)
}

fn v7_fs(root: &Path) -> EncFs {
    setup_fs(root, ConfigType::V7, XattrFormat::default())
}

fn req() -> Caller {
    Caller {
        pid: 1,
        gid: 0,
        uid: 0,
        umask: 0,
    }
}

fn root_node(encfs: &mut EncFs) -> Node<FileState> {
    Node::at("/", encfs.root_state())
}

/// A V7 filesystem over a fresh directory, with its root node.
fn mounted() -> (tempfile::TempDir, EncFs, Node<FileState>) {
    let tmp = tempfile::tempdir().unwrap();
    let mut encfs = v7_fs(tmp.path());
    let root = root_node(&mut encfs);
    (tmp, encfs, root)
}

struct Refuse;

impl Authenticator for Refuse {
    fn authenticate(&self) -> Result<(), String> {
        Err("refused".into())
    }
}

/// `encfs` with an idle lock that stays unlocked for the test's duration.
fn with_idle_lock(encfs: EncFs) -> EncFs {
    encfs.with_idle_lock(IdleLock::new(
        Duration::from_secs(3600),
        Box::new(Refuse),
        Vec::new(),
    ))
}

/// A caller who is neither root nor the user running the tests.
fn other_user() -> Caller {
    let euid = unsafe { libc::geteuid() };
    Caller {
        uid: if euid == 4242 { 4243 } else { 4242 },
        ..req()
    }
}

fn get(encfs: &EncFs, node: &Node<FileState>, name: &str) -> Result<Vec<u8>, Errno> {
    match encfs.getxattr(node.as_node(), OsStr::new(name), XATTR_BUF_SIZE, &req())? {
        ReplyXAttr::Data(data) => Ok(data),
        ReplyXAttr::Size(_) => panic!("getxattr returned Size instead of Data"),
    }
}

fn rpc(encfs: &EncFs, node: &Node<FileState>, name: &str) -> serde_json::Value {
    let reply = get(encfs, node, name).expect("rpc getxattr failed");
    serde_json::from_slice(&reply).expect("reply is JSON")
}

fn list_names(encfs: &EncFs, node: &Node<FileState>) -> Vec<String> {
    match encfs
        .listxattr(node.as_node(), XATTR_BUF_SIZE, &req())
        .expect("listxattr failed")
    {
        ReplyXAttr::Data(data) => String::from_utf8_lossy(&data)
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
        ReplyXAttr::Size(_) => panic!("listxattr returned Size instead of Data"),
    }
}

#[test]
fn info_reports_the_mount() {
    let tmp = tempfile::tempdir().unwrap();
    let mut encfs = v7_fs(tmp.path()).with_mount_point(PathBuf::from("/mnt/plain"));
    let root = root_node(&mut encfs);

    let reply = rpc(&encfs, &root, INFO);
    assert_eq!(reply["protocol"], encfs::rpc::PROTOCOL);
    assert_eq!(reply["ok"], true, "{reply}");
    let result = &reply["result"];
    assert_eq!(result["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(result["root"], tmp.path().to_str().unwrap());
    assert_eq!(result["mount_point"], "/mnt/plain");
    assert_eq!(result["read_only"], false);
    assert_eq!(result["pid"], std::process::id());
    assert_eq!(result["config"]["format"], "V7");
    assert_eq!(result["config"]["xattrs_available"], true);
    assert!(result["idle_lock"].is_null());
    assert_eq!(result["commands"], serde_json::json!(["info", "lock"]));
}

#[test]
fn errors_are_reported_in_the_reply() {
    let (_tmp, encfs, root) = mounted();

    let reply = rpc(&encfs, &root, "user.encfs.rpc.frobnicate");
    assert_eq!(reply["protocol"], encfs::rpc::PROTOCOL);
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"]["code"], "unknown_command");

    let reply = rpc(&encfs, &root, "user.encfs.rpc.info?x=1");
    assert_eq!(reply["error"]["code"], "invalid_params");
}

/// The usual size probe reports the length the read then returns.
#[test]
fn the_size_probe_matches_the_reply() {
    let (_tmp, encfs, root) = mounted();

    let probed = match encfs
        .getxattr(root.as_node(), OsStr::new(INFO), 0, &req())
        .unwrap()
    {
        ReplyXAttr::Size(size) => size,
        ReplyXAttr::Data(_) => panic!("size probe returned data"),
    };
    assert_eq!(probed, get(&encfs, &root, INFO).unwrap().len());
}

#[test]
fn requests_are_not_attributes() {
    let (_tmp, encfs, root) = mounted();
    let r = req();

    assert_eq!(
        encfs.setxattr(root.as_node(), OsStr::new(INFO), b"x", 0, &r),
        Err(Errno::EPERM)
    );
    assert_eq!(
        encfs.removexattr(root.as_node(), OsStr::new(INFO), &r),
        Err(Errno::EPERM)
    );
    encfs
        .setxattr(root.as_node(), OsStr::new("user.color"), b"red", 0, &r)
        .unwrap();
    assert_eq!(list_names(&encfs, &root), ["user.color"]);
}

/// Below the root, a request name is an ordinary attribute.
#[test]
fn only_the_root_answers() {
    let (tmp, encfs, root) = mounted();
    let r = req();
    let entry = encfs
        .mkdir(
            PathNodeRef::new(Some(Path::new("/")), root.state()),
            OsStr::new("sub"),
            0o755,
            0,
            &r,
        )
        .unwrap();
    let sub = Node::at("/sub", entry.state);

    assert!(get(&encfs, &sub, INFO).is_err());
    encfs
        .setxattr(sub.as_node(), OsStr::new(INFO), b"stored", 0, &r)
        .unwrap();
    assert_eq!(get(&encfs, &sub, INFO).unwrap(), b"stored");
    assert_eq!(list_names(&encfs, &sub), [INFO]);

    // Mounted at that directory, the stored attribute is shadowed by the
    // request and left out of the list.
    let backing = std::fs::read_dir(tmp.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut inner = v7_fs(&backing);
    let inner_root = root_node(&mut inner);
    assert_eq!(rpc(&inner, &inner_root, INFO)["ok"], true);
    assert!(list_names(&inner, &inner_root).is_empty());
}

/// Volumes without usable extended attributes still answer requests.
#[test]
fn volumes_without_xattrs_answer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut encfs = setup_fs(tmp.path(), ConfigType::V7, XattrFormat::EncryptedPathIv);
    let root = root_node(&mut encfs);
    assert!(get(&encfs, &root, "user.color").is_err());
    let reply = rpc(&encfs, &root, INFO);
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["result"]["config"]["xattrs_available"], false);

    let mut legacy = setup_fs(tmp.path(), ConfigType::V6, XattrFormat::default());
    let root = root_node(&mut legacy);
    assert_eq!(
        rpc(&legacy, &root, INFO)["result"]["config"]["format"],
        "V6"
    );
}

/// Only the mount's owner (or root) may make requests, so other users can
/// neither read `info` nor lock the mount.
#[test]
fn other_users_are_refused() {
    let (_tmp, encfs, root) = mounted();
    let encfs = with_idle_lock(encfs);
    for name in [INFO, "user.encfs.rpc.lock"] {
        assert!(matches!(
            encfs.getxattr(
                root.as_node(),
                OsStr::new(name),
                XATTR_BUF_SIZE,
                &other_user()
            ),
            Err(Errno::EACCES)
        ));
    }
    let owner = Caller {
        uid: unsafe { libc::geteuid() },
        ..req()
    };
    assert!(
        encfs
            .getxattr(root.as_node(), OsStr::new(INFO), XATTR_BUF_SIZE, &owner)
            .is_ok()
    );
    assert_eq!(
        rpc(&encfs, &root, INFO)["result"]["idle_lock"]["locked"],
        false
    );
}

#[test]
fn lock_needs_an_idle_lock() {
    let (_tmp, encfs, root) = mounted();
    let reply = rpc(&encfs, &root, "user.encfs.rpc.lock");
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"]["code"], "unavailable");
}
