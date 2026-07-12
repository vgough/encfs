use std::io;
#[cfg(target_os = "macos")]
use std::time::Duration;
#[cfg(any(target_os = "macos", test))]
use std::{ffi::OsStr, path::Path};

#[cfg(target_os = "macos")]
use std::{io::IoSliceMut, os::unix::io::RawFd, process::Output};

#[cfg(target_os = "macos")]
use nix::sys::socket::{self, ControlMessageOwned, MsgFlags};

#[cfg(all(not(feature = "tokio-runtime"), feature = "async-io-runtime"))]
pub use async_io::FuseConnection;
#[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
pub use tokio::FuseConnection;

#[cfg(feature = "async-io-runtime")]
mod async_io;
#[cfg(feature = "tokio-runtime")]
mod tokio;

pub(crate) type CompleteIoResult<T, U> = (T, io::Result<U>);

#[cfg(target_os = "macos")]
pub(super) const MACFUSE_COMMFD_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(any(target_os = "macos", test))]
const MAX_CAPTURED_OUTPUT_LEN: usize = 4096;

#[cfg(any(target_os = "macos", test))]
fn display_process_stream(bytes: &[u8]) -> String {
    let mut output = String::from_utf8_lossy(bytes).trim().to_owned();
    if output.is_empty() {
        return "<empty>".to_owned();
    }

    if output.len() > MAX_CAPTURED_OUTPUT_LEN {
        let mut truncate_at = MAX_CAPTURED_OUTPUT_LEN;
        while !output.is_char_boundary(truncate_at) {
            truncate_at -= 1;
        }
        output.truncate(truncate_at);
        output.push_str("...<truncated>");
    }

    output
}

#[cfg(any(target_os = "macos", test))]
fn macfuse_command_failure_message(
    binary_path: &Path,
    mount_path: &OsStr,
    status: impl std::fmt::Display,
    stdout: &[u8],
    stderr: &[u8],
) -> String {
    format!(
        "mount_macfuse exited before sending FUSE fd: binary={}, mount={}, status={}, stderr={}, stdout={}",
        binary_path.display(),
        mount_path.to_string_lossy(),
        status,
        display_process_stream(stderr),
        display_process_stream(stdout)
    )
}

#[cfg(target_os = "macos")]
pub(super) fn macfuse_command_failure_error(
    binary_path: &Path,
    mount_path: &OsStr,
    output: &Output,
) -> io::Error {
    io::Error::other(macfuse_command_failure_message(
        binary_path,
        mount_path,
        output.status,
        &output.stdout,
        &output.stderr,
    ))
}

#[cfg(target_os = "macos")]
pub(super) fn recv_fuse_fd_blocking(fd: RawFd) -> io::Result<RawFd> {
    let mut buf = [0_u8; 1];
    let mut bufs = [IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);

    let msg = socket::recvmsg::<()>(fd, &mut bufs, Some(&mut cmsg_buf), MsgFlags::empty())?;
    let mut cmsgs = msg.cmsgs()?;
    match cmsgs.next() {
        Some(ControlMessageOwned::ScmRights(fds)) if !fds.is_empty() => Ok(fds[0]),
        Some(ControlMessageOwned::ScmRights(_)) => {
            Err(io::Error::other("mount_macfuse sent an empty FUSE fd list"))
        }
        _ => Err(io::Error::other(
            "mount_macfuse did not send FUSE fd on _FUSE_COMMFD",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, path::Path};

    use super::{display_process_stream, macfuse_command_failure_message, MAX_CAPTURED_OUTPUT_LEN};

    #[test]
    fn macfuse_command_failure_message_includes_child_output() {
        let message = macfuse_command_failure_message(
            Path::new("/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse"),
            OsStr::new("/tmp/libra-task-worktree-fuse/workspace"),
            "exit status: 1",
            b"",
            b"mount_macfuse: permission denied\n",
        );

        assert!(message.contains("mount_macfuse exited before sending FUSE fd"));
        assert!(message.contains("status=exit status: 1"));
        assert!(message.contains("stderr=mount_macfuse: permission denied"));
        assert!(message.contains("stdout=<empty>"));
        assert!(message.contains("/tmp/libra-task-worktree-fuse/workspace"));
    }

    #[test]
    fn display_process_stream_truncates_on_utf8_boundary() {
        let input = format!(
            "{}é{}",
            "a".repeat(MAX_CAPTURED_OUTPUT_LEN - 1),
            "b".repeat(16)
        );

        let output = display_process_stream(input.as_bytes());

        assert_eq!(
            output,
            format!("{}...<truncated>", "a".repeat(MAX_CAPTURED_OUTPUT_LEN - 1))
        );
    }
}
