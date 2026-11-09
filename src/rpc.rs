//! Control requests to a mounted filesystem, carried over extended attributes
//! on the mount root (see `docs/adr/0004-xattr-rpc-channel.md`).
//!
//! A client calls `getxattr(<mountpoint>, "user.encfs.rpc.<command>[?k=v&...]")`
//! and reads a JSON reply from the value. The name is the whole request, so a
//! call is stateless, needs no write access, and works on read-only mounts.
//!
//! - `<command>` and parameter keys use `[a-z0-9_-]`; parameter values are
//!   percent-encoded. FreeBSD refuses a `/` in an attribute name, and values
//!   such as paths would otherwise contain one.
//! - Every reply carries `"protocol"` and `"ok"`, plus either `"result"` or an
//!   `"error"` with a stable `"code"`. A request encfs doesn't understand is
//!   answered with an error reply rather than `ENOATTR`, which is what a
//!   filesystem that isn't encfs returns.
//! - Names are limited to 127 bytes on macOS (255 on Linux); [`PREFIX`] takes
//!   15 of them.
//!
//! A filesystem answers through [`is_request`], [`respond`],
//! [`refuse_write`] and [`without_requests`], which hold the whole policy:
//! only the root answers, only the mount's owner may ask, and requests are
//! never stored or listed. With an idle lock, [`is_request_admission`] picks
//! out the requests that skip it.

use crate::config::{ConfigType, EncfsConfig};
use crate::idle_lock::IdleLock;
use log::{debug, warn};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use typed_fuse::Admission;

/// Attribute name prefix of a request.
pub const PREFIX: &str = "user.encfs.rpc.";

/// Version of the reply format, reported in every reply.
pub const PROTOCOL: u32 = 1;

/// Largest reply a client needs to accept (`XATTR_SIZE_MAX` on Linux).
const MAX_REPLY: usize = 64 * 1024;

fn is_rpc_name(name: &[u8]) -> bool {
    name.starts_with(PREFIX.as_bytes())
}

/// Whether attribute `name` on the node at `path` (as the mount sees both)
/// is a request. Only the root answers; elsewhere the name is an ordinary
/// attribute.
pub fn is_request(path: &Path, name: &OsStr) -> bool {
    is_rpc_name(name.as_bytes()) && path.as_os_str() == "/"
}

/// Whether an admitted FUSE request is a getxattr, setxattr or removexattr
/// of a request name on the root: one [`is_request`] will pick out once it
/// runs, known before the filesystem takes any lock.
pub fn is_request_admission(request: &Admission<'_>) -> bool {
    request
        .xattr_name()
        .is_some_and(|n| is_rpc_name(n.as_bytes()))
        && request.targets_root()
}

/// Refuses a setxattr or removexattr of attribute `name` on the node at
/// `path` if it is a request: requests are not attributes, and the prefix is
/// reserved for commands.
pub fn refuse_write(path: &Path, name: &OsStr) -> Result<(), libc::c_int> {
    if is_request(path, name) {
        debug!(
            "{:?} on the root is a control request, not an attribute",
            name
        );
        return Err(libc::EPERM);
    }
    Ok(())
}

/// The NUL-separated attribute list of the node at `path` without request
/// names: requests are not attributes, and an attribute stored under one of
/// their names on the root can't be read back.
pub fn without_requests(path: &Path, list: Vec<u8>) -> Vec<u8> {
    let names = || list.split_inclusive(|&b| b == 0);
    if path != Path::new("/") || !names().any(is_rpc_name) {
        return list;
    }
    names()
        .filter(|name| !is_rpc_name(name))
        .flatten()
        .copied()
        .collect()
}

/// A decoded request.
#[derive(Debug)]
struct Request {
    command: String,
    params: BTreeMap<String, String>,
}

/// Machine-readable reason a request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorCode {
    /// The name could not be decoded.
    InvalidRequest,
    /// No such command.
    UnknownCommand,
    /// The command does not take the parameters given.
    InvalidParams,
    /// The mount lacks what the command acts on (such as an idle lock).
    Unavailable,
}

/// A request that could not be answered, reported in the reply.
#[derive(Debug, Serialize)]
struct RpcError {
    code: ErrorCode,
    message: String,
}

impl RpcError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Whether `b` is an RFC 3986 unreserved character, left as-is when encoding.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn percent_encode_into(out: &mut String, s: &str) {
    for b in s.bytes() {
        if is_unreserved(b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

/// Decode a request from its attribute name.
fn parse(name: &[u8]) -> Result<Request, RpcError> {
    let invalid = |message: &str| RpcError::new(ErrorCode::InvalidRequest, message);
    let name = std::str::from_utf8(name).map_err(|_| invalid("name is not UTF-8"))?;
    let rest = name
        .strip_prefix(PREFIX)
        .ok_or_else(|| invalid("missing request prefix"))?;
    let (command, query) = match rest.split_once('?') {
        Some((command, query)) => (command, Some(query)),
        None => (rest, None),
    };
    if !is_token(command) {
        return Err(invalid("malformed command name"));
    }

    let mut params = BTreeMap::new();
    for pair in query.into_iter().flat_map(|q| q.split('&')) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if !is_token(key) {
            return Err(invalid("malformed parameter name"));
        }
        let value = percent_decode(value).ok_or_else(|| invalid("malformed parameter value"))?;
        if params.insert(key.to_string(), value).is_some() {
            return Err(invalid("duplicate parameter"));
        }
    }
    Ok(Request {
        command: command.to_string(),
        params,
    })
}

/// The attribute name for a request, the inverse of [`parse`].
fn encode_request<'a>(
    command: &str,
    params: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> String {
    let mut name = format!("{PREFIX}{command}");
    for (i, (key, value)) in params.into_iter().enumerate() {
        name.push(if i == 0 { '?' } else { '&' });
        name.push_str(key);
        name.push('=');
        percent_encode_into(&mut name, value);
    }
    name
}

/// The volume settings `info` reports.
#[derive(Debug, Serialize)]
pub struct ConfigInfo {
    pub format: &'static str,
    pub cipher: String,
    pub name_encoding: String,
    pub key_size: i32,
    pub block_size: i32,
    pub block_mac_bytes: i32,
    pub unique_iv: bool,
    pub chained_name_iv: bool,
    pub external_iv_chaining: bool,
    pub directory_iv: bool,
    pub xattrs_available: bool,
}

/// The name `info` reports for a config format, kept apart from its
/// `Debug` form since replies are a contract.
fn format_name(config_type: ConfigType) -> &'static str {
    match config_type {
        ConfigType::None => "none",
        ConfigType::Prehistoric => "prehistoric",
        ConfigType::V3 => "V3",
        ConfigType::V4 => "V4",
        ConfigType::V5 => "V5",
        ConfigType::V6 => "V6",
        ConfigType::V7 => "V7",
    }
}

impl From<&EncfsConfig> for ConfigInfo {
    fn from(config: &EncfsConfig) -> Self {
        Self {
            format: format_name(config.config_type),
            cipher: config.cipher_iface.name.clone(),
            name_encoding: config.name_iface.name.clone(),
            key_size: config.key_size,
            block_size: config.block_size,
            block_mac_bytes: config.block_mac_bytes,
            unique_iv: config.unique_iv,
            chained_name_iv: config.chained_name_iv,
            external_iv_chaining: config.external_iv_chaining,
            directory_iv: config.directory_iv,
            xattrs_available: config.xattrs_available(),
        }
    }
}

/// State of the inactivity lock, for `info`.
#[derive(Debug, Serialize)]
pub struct IdleLockInfo {
    pub timeout_secs: u64,
    pub locked: bool,
}

impl From<&IdleLock> for IdleLockInfo {
    fn from(lock: &IdleLock) -> Self {
        Self {
            timeout_secs: lock.timeout().as_secs(),
            locked: lock.is_locked(),
        }
    }
}

/// The result of `info`. `root` and `mount_point` are lossy for paths that
/// aren't valid UTF-8, which JSON can't carry: each invalid sequence becomes
/// U+FFFD (see ADR 0004).
#[derive(Debug, Serialize)]
pub struct Info {
    pub version: &'static str,
    pub build: &'static str,
    pub pid: u32,
    pub root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<String>,
    pub read_only: bool,
    pub config: ConfigInfo,
    pub idle_lock: Option<IdleLockInfo>,
    /// The commands this build understands (see [`HANDLERS`]).
    pub commands: Vec<&'static str>,
}

impl Info {
    /// `info` for the running process, mounting `root`.
    pub fn new(
        root: &Path,
        mount_point: Option<&Path>,
        read_only: bool,
        config: &EncfsConfig,
        idle_lock: Option<&IdleLock>,
    ) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            build: crate::build_info::VERSION,
            pid: std::process::id(),
            root: root.to_string_lossy().into_owned(),
            mount_point: mount_point.map(|p| p.to_string_lossy().into_owned()),
            read_only,
            config: ConfigInfo::from(config),
            idle_lock: idle_lock.map(IdleLockInfo::from),
            commands: HANDLERS.iter().map(|(name, _)| *name).collect(),
        }
    }
}

fn no_params(request: &Request) -> Result<(), RpcError> {
    match request.params.keys().next() {
        None => Ok(()),
        Some(key) => Err(RpcError::new(
            ErrorCode::InvalidParams,
            format!("{} takes no parameter {key}", request.command),
        )),
    }
}

/// What a mounted filesystem does for the commands.
pub trait Mount {
    /// The result of `info`.
    fn info(&self) -> Info;
    /// Engage the idle lock now, returning its new state, or `None` when the
    /// mount has no idle lock.
    fn lock(&self) -> Option<IdleLockInfo>;
}

// Results are plain structs with string keys, which always serialize, so
// `json!` (which unwraps `to_value`) cannot panic on them.
type Handler = fn(&Request, &dyn Mount) -> Result<Value, RpcError>;

/// Every command, by name. `info` lists them from here, so the list can't
/// drift from what is answered. A listed command can still fail on a mount
/// that lacks what it acts on (`lock` without an idle lock).
const HANDLERS: &[(&str, Handler)] = &[("info", info), ("lock", lock)];

fn info(request: &Request, mount: &dyn Mount) -> Result<Value, RpcError> {
    no_params(request)?;
    Ok(json!(mount.info()))
}

/// Locking only ever takes access away and is idempotent, so a getxattr
/// (which a size probe repeats) may carry it.
fn lock(request: &Request, mount: &dyn Mount) -> Result<Value, RpcError> {
    no_params(request)?;
    let state = mount
        .lock()
        .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "this mount has no idle lock"))?;
    Ok(json!(state))
}

fn run(name: &[u8], mount: &dyn Mount) -> Result<Value, RpcError> {
    let request = parse(name)?;
    let (_, handler) = HANDLERS
        .iter()
        .find(|(command, _)| *command == request.command)
        .ok_or_else(|| {
            RpcError::new(
                ErrorCode::UnknownCommand,
                format!("unknown command {}", request.command),
            )
        })?;
    handler(&request, mount)
}

/// The JSON reply to the request named `name` from user `caller_uid`,
/// carried out on `mount`. Fails with `EACCES` unless the caller is the user
/// running the mount, or root: with `--public` other users reach the root
/// too, and the reply names the encrypted directory even where `--fsname`
/// keeps it out of the mount table. Every other failure is in the reply.
pub fn respond(name: &OsStr, caller_uid: u32, mount: &dyn Mount) -> Result<Vec<u8>, libc::c_int> {
    let owner = unsafe { libc::geteuid() };
    if caller_uid != 0 && caller_uid != owner {
        warn!(
            "Refused control request {:?} from uid {} (mount owner {})",
            name, caller_uid, owner
        );
        return Err(libc::EACCES);
    }
    let reply = match run(name.as_bytes(), mount) {
        Ok(result) => json!({"protocol": PROTOCOL, "ok": true, "result": result}),
        Err(error) => json!({"protocol": PROTOCOL, "ok": false, "error": error}),
    };
    Ok(reply.to_string().into_bytes())
}

/// Send a request to the filesystem mounted at `mount_point` and return the
/// raw JSON reply. A filesystem that doesn't answer requests fails with
/// `ENOATTR` (`ENODATA` on Linux).
pub fn call<'a>(
    mount_point: &Path,
    command: &str,
    params: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> std::io::Result<Vec<u8>> {
    use typed_fuse::passthrough::{c_name, c_path, getxattr_nofollow};
    let name = encode_request(command, params);
    // One call with room for any reply, rather than probing the size first:
    // the reply could change between the probe and the read.
    let mut reply = vec![0u8; MAX_REPLY];
    let len = c_path(mount_point)
        .and_then(|path| getxattr_nofollow(&path, &c_name(OsStr::new(&name))?, &mut reply))
        .map_err(|e| std::io::Error::from_raw_os_error(e.raw()))?;
    reply.truncate(len);
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mount that records what it was asked to do.
    #[derive(Default)]
    struct FakeMount {
        idle_lock: bool,
        infos: std::cell::Cell<usize>,
        locks: std::cell::Cell<usize>,
    }

    impl Mount for FakeMount {
        fn info(&self) -> Info {
            self.infos.set(self.infos.get() + 1);
            Info::new(
                Path::new("/data/enc"),
                None,
                false,
                &EncfsConfig::test_default(),
                None,
            )
        }

        fn lock(&self) -> Option<IdleLockInfo> {
            self.locks.set(self.locks.get() + 1);
            self.idle_lock.then_some(IdleLockInfo {
                timeout_secs: 600,
                locked: true,
            })
        }
    }

    fn reply_from(mount: &FakeMount, name: &str) -> serde_json::Value {
        serde_json::from_slice(&respond(OsStr::new(name), 0, mount).unwrap()).unwrap()
    }

    fn reply(name: &str) -> serde_json::Value {
        reply_from(&FakeMount::default(), name)
    }

    /// Only attribute requests on the root with a request name bypass the
    /// idle lock.
    #[test]
    fn request_admissions_are_root_attribute_requests() {
        use typed_fuse::{Caller, PathOp};
        let caller = Caller::default();
        let getxattr = |root, name| {
            Admission::new(PathOp::Getxattr, &caller)
                .with_root(root)
                .with_xattr_name(OsStr::new(name))
        };
        assert!(is_request_admission(&getxattr(true, "user.encfs.rpc.info")));
        assert!(!is_request_admission(&getxattr(
            false,
            "user.encfs.rpc.info"
        )));
        assert!(!is_request_admission(&getxattr(true, "user.color")));
        let listing = Admission::new(PathOp::Listxattr, &caller).with_root(true);
        assert!(!is_request_admission(&listing));
    }

    #[test]
    fn parses_a_bare_command() {
        let request = parse(b"user.encfs.rpc.info").unwrap();
        assert_eq!(request.command, "info");
        assert!(request.params.is_empty());
    }

    #[test]
    fn parameters_round_trip() {
        let values = ["/a/b c", "100%", "x&y=z?", "ünï", "", "plain-._~"];
        for value in values {
            let name = encode_request("cmd", [("key", value), ("other_2", "v")]);
            assert!(!name.contains('/'), "{name}");
            let request = parse(name.as_bytes()).unwrap();
            assert_eq!(request.command, "cmd");
            assert_eq!(request.params["key"], value, "{name}");
            assert_eq!(request.params["other_2"], "v");
        }
    }

    #[test]
    fn a_bare_key_has_an_empty_value() {
        let request = parse(b"user.encfs.rpc.cmd?flag").unwrap();
        assert_eq!(request.params["flag"], "");
    }

    #[test]
    fn rejects_malformed_requests() {
        for name in [
            &b"user.encfs.rpc."[..],
            b"user.encfs.rpc.Info",
            b"user.encfs.rpc.in fo",
            b"user.encfs.rpc.cmd?",
            b"user.encfs.rpc.cmd?K=v",
            b"user.encfs.rpc.cmd?k=%2",
            b"user.encfs.rpc.cmd?k=%zz",
            b"user.encfs.rpc.cmd?k=%+1",
            b"user.encfs.rpc.cmd?k=%ff",
            b"user.encfs.rpc.cmd?k=1&k=2",
            b"user.encfs.rpc.cmd\xff",
            b"user.other",
        ] {
            let error = parse(name).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidRequest, "{name:?}");
        }
    }

    #[test]
    fn info_reports_the_volume() {
        let reply = reply("user.encfs.rpc.info");
        assert_eq!(reply["protocol"], PROTOCOL);
        assert_eq!(reply["ok"], true);
        assert!(reply.get("error").is_none());
        let result = &reply["result"];
        assert_eq!(result["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(result["root"], "/data/enc");
        assert_eq!(result["pid"], std::process::id());
        assert!(result.get("mount_point").is_none());
        assert!(result["idle_lock"].is_null());
        assert_eq!(result["config"]["format"], "V6");
        assert_eq!(result["commands"], serde_json::json!(["info", "lock"]));
    }

    #[test]
    fn info_takes_no_parameters() {
        let reply = reply("user.encfs.rpc.info?x=1");
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"]["code"], "invalid_params");
        assert!(reply.get("result").is_none());
    }

    #[test]
    fn unknown_commands_get_an_error_reply() {
        let reply = reply("user.encfs.rpc.frobnicate");
        assert_eq!(reply["protocol"], PROTOCOL);
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"]["code"], "unknown_command");
    }

    #[test]
    fn malformed_requests_get_an_error_reply() {
        let reply = reply("user.encfs.rpc.info?k=%");
        assert_eq!(reply["error"]["code"], "invalid_request");
    }

    #[test]
    fn the_mount_is_only_asked_for_what_the_command_needs() {
        let mount = FakeMount::default();
        reply_from(&mount, "user.encfs.rpc.other");
        reply_from(&mount, "user.encfs.rpc.lock?x=1");
        assert_eq!((mount.infos.get(), mount.locks.get()), (0, 0));
        reply_from(&mount, "user.encfs.rpc.info");
        assert_eq!((mount.infos.get(), mount.locks.get()), (1, 0));
    }

    #[test]
    fn lock_engages_the_idle_lock() {
        let mount = FakeMount {
            idle_lock: true,
            ..Default::default()
        };
        let reply = reply_from(&mount, "user.encfs.rpc.lock");
        assert_eq!(reply["ok"], true, "{reply}");
        assert_eq!(reply["result"]["locked"], true);
        assert_eq!(reply["result"]["timeout_secs"], 600);
        assert_eq!(mount.locks.get(), 1);
    }

    #[test]
    fn lock_needs_an_idle_lock() {
        let mount = FakeMount::default();
        let reply = reply_from(&mount, "user.encfs.rpc.lock");
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"]["code"], "unavailable");
        assert!(reply.get("result").is_none());
    }

    #[test]
    fn lock_takes_no_parameters() {
        let mount = FakeMount {
            idle_lock: true,
            ..Default::default()
        };
        let reply = reply_from(&mount, "user.encfs.rpc.lock?now=1");
        assert_eq!(reply["error"]["code"], "invalid_params");
    }
}
