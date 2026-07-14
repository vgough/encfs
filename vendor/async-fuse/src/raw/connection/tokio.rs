#[cfg(target_os = "macos")]
use std::env;
#[cfg(target_os = "macos")]
use std::ffi::OsStr;
#[cfg(all(target_os = "linux", feature = "unprivileged"))]
use std::ffi::OsString;
#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::fs::OpenOptions;
use std::io;
#[cfg(all(target_os = "linux", feature = "unprivileged"))]
use std::io::IoSliceMut;
use std::ops::{Deref, DerefMut};
#[cfg(not(target_os = "macos"))]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::os::fd::OwnedFd;
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", feature = "unprivileged")
))]
use std::os::unix::io::RawFd;
#[cfg(target_os = "macos")]
use std::os::unix::io::{AsRawFd, FromRawFd};
#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "macos"
))]
use std::path::Path;
use std::pin::pin;
#[cfg(target_os = "macos")]
use std::process::Stdio;
use std::sync::Arc;

use async_notify::Notify;
use futures_util::lock::Mutex;
use futures_util::{select, FutureExt};
#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "macos"
))]
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};
#[cfg(all(target_os = "linux", feature = "unprivileged"))]
use nix::sys::socket::{ControlMessageOwned, MsgFlags};
#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "macos"
))]
use tokio::process::Command;
#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "macos"
))]
use tokio::task;
#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "macos"
))]
use tracing::debug;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use tracing::warn;

use super::CompleteIoResult;
#[cfg(target_os = "macos")]
use super::{macfuse_command_failure_error, recv_fuse_fd_blocking, MACFUSE_COMMFD_TIMEOUT};
#[cfg(all(target_os = "linux", feature = "unprivileged"))]
use crate::find_fusermount3;
#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "macos"
))]
use crate::MountOptions;

#[cfg(target_os = "macos")]
fn macfuse_fd_receive_error(binary_path: &Path, mount_path: &OsStr, err: io::Error) -> io::Error {
    io::Error::new(
        err.kind(),
        format!(
            "failed to receive FUSE fd from mount_macfuse: binary={}, mount={}: {}",
            binary_path.display(),
            mount_path.to_string_lossy(),
            err
        ),
    )
}

#[cfg(target_os = "macos")]
fn macfuse_fd_timeout_error(binary_path: &Path, mount_path: &OsStr) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "timed out after {:?} waiting for mount_macfuse to send FUSE fd: binary={}, mount={}",
            MACFUSE_COMMFD_TIMEOUT,
            binary_path.display(),
            mount_path.to_string_lossy()
        ),
    )
}

#[cfg(target_os = "macos")]
async fn wait_for_macfuse_fd_task(
    fd_task: &mut task::JoinHandle<io::Result<RawFd>>,
    binary_path: &Path,
    mount_path: &OsStr,
) -> io::Result<RawFd> {
    fd_task
        .await
        .map_err(|err| {
            io::Error::other(format!("wait for mount_macfuse FUSE fd task failed: {err}"))
        })?
        .map_err(|err| macfuse_fd_receive_error(binary_path, mount_path, err))
}

#[cfg(target_os = "macos")]
async fn wait_for_macfuse_fd_task_until_timeout(
    fd_task: &mut task::JoinHandle<io::Result<RawFd>>,
    binary_path: &Path,
    mount_path: &OsStr,
) -> io::Result<RawFd> {
    match tokio::time::timeout(
        MACFUSE_COMMFD_TIMEOUT,
        wait_for_macfuse_fd_task(fd_task, binary_path, mount_path),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            fd_task.abort();
            Err(macfuse_fd_timeout_error(binary_path, mount_path))
        }
    }
}

#[derive(Debug)]
pub struct FuseConnection {
    unmount_notify: Arc<Notify>,
    mode: ConnectionMode,
}

impl FuseConnection {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn new(unmount_notify: Arc<Notify>) -> io::Result<Self> {
        #[cfg(target_os = "freebsd")]
        {
            let connection = BlockingFuseConnection::new()?;

            Ok(Self {
                unmount_notify,
                mode: ConnectionMode::Blocking(connection),
            })
        }

        #[cfg(target_os = "linux")]
        {
            let connection = BlockingFuseConnection::new()?;

            Ok(Self {
                unmount_notify,
                mode: ConnectionMode::Blocking(connection),
            })
        }
    }

    #[cfg(all(target_os = "linux", feature = "unprivileged"))]
    pub async fn new_with_unprivileged(
        mount_options: MountOptions,
        mount_path: impl AsRef<Path>,
        unmount_notify: Arc<Notify>,
    ) -> io::Result<Self> {
        let connection =
            BlockingFuseConnection::new_with_unprivileged(mount_options, mount_path).await?;

        Ok(Self {
            unmount_notify,
            mode: ConnectionMode::Blocking(connection),
        })
    }

    #[cfg(target_os = "macos")]
    pub async fn new_with_unprivileged(
        mount_options: MountOptions,
        mount_path: impl AsRef<Path>,
        unmount_notify: Arc<Notify>,
    ) -> io::Result<Self> {
        let connection =
            BlockFuseConnection::new_with_unprivileged(mount_options, mount_path).await?;

        Ok(Self {
            unmount_notify,
            mode: ConnectionMode::Block(connection),
        })
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            unmount_notify: self.unmount_notify.clone(),
            mode: match &self.mode {
                #[cfg(target_os = "macos")]
                ConnectionMode::Block(connection) => ConnectionMode::Block(connection.try_clone()?),
                #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                ConnectionMode::Blocking(connection) => {
                    ConnectionMode::Blocking(connection.try_clone()?)
                }
            },
        })
    }

    pub async fn read_vectored<T: DerefMut<Target = [u8]> + Send + 'static>(
        &self,
        header_buf: Vec<u8>,
        data_buf: T,
    ) -> Option<CompleteIoResult<(Vec<u8>, T), usize>> {
        let mut unmount_fut = pin!(self.unmount_notify.notified().fuse());
        let mut read_fut = pin!(self.inner_read_vectored(header_buf, data_buf).fuse());

        select! {
            _ = unmount_fut => None,
            res = read_fut => Some(res)
        }
    }

    async fn inner_read_vectored<T: DerefMut<Target = [u8]> + Send + 'static>(
        &self,
        header_buf: Vec<u8>,
        data_buf: T,
    ) -> CompleteIoResult<(Vec<u8>, T), usize> {
        match &self.mode {
            #[cfg(target_os = "macos")]
            ConnectionMode::Block(connection) => {
                connection.read_vectored(header_buf, data_buf).await
            }
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            ConnectionMode::Blocking(connection) => {
                connection.read_vectored(header_buf, data_buf).await
            }
        }
    }

    pub async fn write_vectored<
        T: Deref<Target = [u8]> + Send + 'static,
        U: Deref<Target = [u8]> + Send + 'static,
    >(
        &self,
        data: T,
        body_extend_data: Option<U>,
    ) -> CompleteIoResult<(T, Option<U>), usize> {
        match &self.mode {
            #[cfg(target_os = "macos")]
            ConnectionMode::Block(connection) => {
                connection.write_vectored(data, body_extend_data).await
            }
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            ConnectionMode::Blocking(connection) => {
                connection.write_vectored(data, body_extend_data).await
            }
        }
    }
}

#[derive(Debug)]
enum ConnectionMode {
    #[cfg(target_os = "macos")]
    Block(BlockFuseConnection),
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    Blocking(BlockingFuseConnection),
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct BlockFuseConnection {
    file: File,
    read: Mutex<()>,
    write: Mutex<()>,
}

#[cfg(target_os = "macos")]
impl BlockFuseConnection {
    #[cfg(target_os = "macos")]
    async fn new_with_unprivileged(
        mount_options: MountOptions,
        mount_path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        use tokio::time::sleep;

        use crate::find_macfuse_mount;

        let (sock0, sock1) = match socket::socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        ) {
            Err(err) => return Err(err.into()),

            Ok((sock0, sock1)) => (sock0, sock1),
        };

        let binary_path = find_macfuse_mount()?;

        const ENV: &str = "_FUSE_COMMFD";

        let options = mount_options.build();

        debug!("mount options {:?}", options);

        let exec_path = match env::current_exe() {
            Ok(path) => path,
            Err(err) => return Err(err),
        };

        let mount_path = mount_path.as_ref().as_os_str().to_os_string();
        let mount_path_for_error = mount_path.clone();
        let binary_path_for_error = binary_path.clone();

        let fd0 = sock0.as_raw_fd();
        let mut binding = Command::new(&binary_path);
        let child = binding
            .env(ENV, fd0.to_string())
            .env("_FUSE_CALL_BY_LIB", "1")
            .env("_FUSE_COMMVERS", "2")
            .env("_FUSE_DAEMON_PATH", exec_path)
            .args(vec![options, mount_path])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!(
                        "spawn mount_macfuse failed: binary={}, mount={}: {}",
                        binary_path_for_error.display(),
                        mount_path_for_error.to_string_lossy(),
                        err
                    ),
                )
            })?;
        drop(sock0);

        let (child_result_tx, mut child_result_rx) = tokio::sync::oneshot::channel();
        let child_task = tokio::spawn(async move {
            let output = child.wait_with_output().await;
            let _ = child_result_tx.send(output);
        });

        let mut fd_task = task::spawn_blocking(move || {
            debug!("wait_thread start");
            recv_fuse_fd_blocking(sock1.as_raw_fd())
        });

        let fd_result = tokio::select! {
            fd_result = wait_for_macfuse_fd_task(
                &mut fd_task,
                &binary_path_for_error,
                mount_path_for_error.as_os_str(),
            ) => {
                fd_result
            }
            child_result = &mut child_result_rx => {
                match child_result {
                    Ok(Ok(output)) if output.status.success() => {
                        wait_for_macfuse_fd_task_until_timeout(
                            &mut fd_task,
                            &binary_path_for_error,
                            mount_path_for_error.as_os_str(),
                        ).await
                    }
                    Ok(Ok(output)) => {
                        Err(macfuse_command_failure_error(
                            &binary_path_for_error,
                            mount_path_for_error.as_os_str(),
                            &output,
                        ))
                    }
                    Ok(Err(err)) => {
                        Err(io::Error::new(
                            err.kind(),
                            format!(
                                "wait for mount_macfuse failed: binary={}, mount={}: {}",
                                binary_path_for_error.display(),
                                mount_path_for_error.to_string_lossy(),
                                err
                            ),
                        ))
                    }
                    Err(_) => {
                        Err(io::Error::other(format!(
                            "mount_macfuse monitor task dropped before sending FUSE fd: binary={}, mount={}",
                            binary_path_for_error.display(),
                            mount_path_for_error.to_string_lossy()
                        )))
                    }
                }
            }
            _ = sleep(MACFUSE_COMMFD_TIMEOUT) => {
                fd_task.abort();
                Err(macfuse_fd_timeout_error(
                    &binary_path_for_error,
                    mount_path_for_error.as_os_str(),
                ))
            }
        };

        let fd = match fd_result {
            Ok(fd) => fd,
            Err(err) => {
                child_task.abort();
                return Err(err);
            }
        };

        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Self {
            file,
            read: Mutex::new(()),
            write: Mutex::new(()),
        })
    }

    fn try_clone(&self) -> io::Result<Self> {
        let fd = self.file.as_raw_fd();
        let new_fd = unsafe { libc::dup(fd) };
        if new_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(new_fd) };
        Ok(Self {
            file,
            read: Mutex::new(()),
            write: Mutex::new(()),
        })
    }

    async fn read_vectored<T: DerefMut<Target = [u8]> + Send + 'static>(
        &self,
        header_buf: Vec<u8>,
        data_buf: T,
    ) -> CompleteIoResult<(Vec<u8>, T), usize> {
        let _guard = self.read.lock().await;
        let fd = self.file.as_raw_fd();

        task::spawn_blocking(move || {
            let mut iov = [
                libc::iovec {
                    iov_base: header_buf.as_ptr() as *mut libc::c_void,
                    iov_len: header_buf.len(),
                },
                libc::iovec {
                    iov_base: data_buf.as_ptr() as *mut libc::c_void,
                    iov_len: data_buf.len(),
                },
            ];
            let n = unsafe { libc::readv(fd, iov.as_mut_ptr(), 2) };
            if n < 0 {
                ((header_buf, data_buf), Err(io::Error::last_os_error()))
            } else {
                ((header_buf, data_buf), Ok(n as usize))
            }
        })
        .await
        .unwrap()
    }

    async fn write_vectored<
        T: Deref<Target = [u8]> + Send + 'static,
        U: Deref<Target = [u8]> + Send + 'static,
    >(
        &self,
        data: T,
        body_extend_data: Option<U>,
    ) -> CompleteIoResult<(T, Option<U>), usize> {
        let _guard = self.write.lock().await;
        let fd = self.file.as_raw_fd();

        task::spawn_blocking(move || {
            let body = body_extend_data.as_deref();
            match body {
                None => {
                    let iov = [libc::iovec {
                        iov_base: data.deref().as_ptr() as *mut libc::c_void,
                        iov_len: data.deref().len(),
                    }];
                    let n = unsafe { libc::writev(fd, iov.as_ptr(), 1) };
                    if n < 0 {
                        ((data, body_extend_data), Err(io::Error::last_os_error()))
                    } else {
                        ((data, body_extend_data), Ok(n as usize))
                    }
                }
                Some(body_data) => {
                    let iov = [
                        libc::iovec {
                            iov_base: data.deref().as_ptr() as *mut libc::c_void,
                            iov_len: data.deref().len(),
                        },
                        libc::iovec {
                            iov_base: body_data.as_ptr() as *mut libc::c_void,
                            iov_len: body_data.len(),
                        },
                    ];
                    let n = unsafe { libc::writev(fd, iov.as_ptr(), 2) };
                    if n < 0 {
                        ((data, body_extend_data), Err(io::Error::last_os_error()))
                    } else {
                        ((data, body_extend_data), Ok(n as usize))
                    }
                }
            }
        })
        .await
        .unwrap()
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
#[derive(Debug)]
struct BlockingFuseConnection {
    fd: Arc<OwnedFd>,
    read: Mutex<()>,
    write: Mutex<()>,
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
impl BlockingFuseConnection {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    fn new() -> io::Result<Self> {
        use std::io::ErrorKind;

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        const DEV_FUSE: &str = "/dev/fuse";

        match OpenOptions::new().write(true).read(true).open(DEV_FUSE) {
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    warn!("Cannot open {}.  Is the module loaded?", DEV_FUSE);
                }
                warn!("Cannot open {}.  err: {:?}", DEV_FUSE, e);
                Err(e)
            }
            Ok(file) => Ok(Self {
                fd: Arc::new(file.into()),
                read: Mutex::new(()),
                write: Mutex::new(()),
            }),
        }
    }

    #[cfg(all(target_os = "linux", feature = "unprivileged"))]
    async fn new_with_unprivileged(
        mount_options: MountOptions,
        mount_path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd};

        let (sock0, sock1) = match socket::socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::empty(),
        ) {
            Err(err) => return Err(err.into()),

            Ok((sock0, sock1)) => (sock0, sock1),
        };

        let binary_path = find_fusermount3()?;

        const ENV: &str = "_FUSE_COMMFD";

        let options = mount_options.build_with_unprivileged();

        debug!("mount options {:?}", options);

        let mount_path = mount_path.as_ref().as_os_str().to_os_string();

        let fd0 = sock0.as_raw_fd();
        let mut child = Command::new(binary_path)
            .env(ENV, fd0.to_string())
            .args(vec![OsString::from("-o"), options, mount_path])
            .spawn()?;

        if !child.wait().await?.success() {
            return Err(io::Error::other("fusermount run failed"));
        }

        let fd1 = sock1.as_raw_fd();
        let fd = task::spawn_blocking(move || {
            // let mut buf = vec![0; 10000]; // buf should large enough
            let mut buf = vec![]; // it seems 0 len still works well

            let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);

            let mut bufs = [IoSliceMut::new(&mut buf)];

            let msg = match socket::recvmsg::<()>(
                fd1,
                &mut bufs[..],
                Some(&mut cmsg_buf),
                MsgFlags::empty(),
            ) {
                Err(err) => return Err(err.into()),

                Ok(msg) => msg,
            };

            let fd = if let Some(ControlMessageOwned::ScmRights(fds)) = msg.cmsgs()?.next() {
                if fds.is_empty() {
                    return Err(io::Error::other("no fuse fd"));
                }

                fds[0]
            } else {
                return Err(io::Error::other("get fuse fd failed"));
            };

            Ok(fd)
        })
        .await
        .unwrap()?;

        // Safety: fd is valid
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        Ok(Self {
            fd: Arc::new(fd),
            read: Mutex::new(()),
            write: Mutex::new(()),
        })
    }

    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            fd: self.fd.clone(),
            read: Mutex::new(()),
            write: Mutex::new(()),
        })
    }

    async fn read_vectored<T: DerefMut<Target = [u8]> + Send + 'static>(
        &self,
        mut header_buf: Vec<u8>,
        mut data_buf: T,
    ) -> CompleteIoResult<(Vec<u8>, T), usize> {
        let _guard = self.read.lock().await;
        let fd = self.fd.clone();

        tokio::task::spawn_blocking(move || {
            let mut iov = [
                libc::iovec {
                    iov_base: header_buf.as_mut_ptr().cast(),
                    iov_len: header_buf.len(),
                },
                libc::iovec {
                    iov_base: data_buf.deref_mut().as_mut_ptr().cast(),
                    iov_len: data_buf.deref().len(),
                },
            ];
            let n = unsafe { libc::readv(fd.as_raw_fd(), iov.as_mut_ptr(), iov.len() as i32) };
            if n < 0 {
                ((header_buf, data_buf), Err(io::Error::last_os_error()))
            } else {
                ((header_buf, data_buf), Ok(n as usize))
            }
        })
        .await
        .unwrap()
    }

    async fn write_vectored<
        T: Deref<Target = [u8]> + Send + 'static,
        U: Deref<Target = [u8]> + Send + 'static,
    >(
        &self,
        data: T,
        body_extend_data: Option<U>,
    ) -> CompleteIoResult<(T, Option<U>), usize> {
        let _guard = self.write.lock().await;
        let fd = self.fd.clone();

        tokio::task::spawn_blocking(move || {
            let body = body_extend_data.as_deref();
            let n = match body {
                None => {
                    let iov = [libc::iovec {
                        iov_base: data.deref().as_ptr() as *mut libc::c_void,
                        iov_len: data.deref().len(),
                    }];
                    unsafe { libc::writev(fd.as_raw_fd(), iov.as_ptr(), iov.len() as i32) }
                }
                Some(body_data) => {
                    let iov = [
                        libc::iovec {
                            iov_base: data.deref().as_ptr() as *mut libc::c_void,
                            iov_len: data.deref().len(),
                        },
                        libc::iovec {
                            iov_base: body_data.as_ptr() as *mut libc::c_void,
                            iov_len: body_data.len(),
                        },
                    ];
                    unsafe { libc::writev(fd.as_raw_fd(), iov.as_ptr(), iov.len() as i32) }
                }
            };
            if n < 0 {
                ((data, body_extend_data), Err(io::Error::last_os_error()))
            } else {
                ((data, body_extend_data), Ok(n as usize))
            }
        })
        .await
        .unwrap()
    }
}

impl AsFd for FuseConnection {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match &self.mode {
            #[cfg(target_os = "macos")]
            ConnectionMode::Block(connection) => connection.file.as_fd(),

            #[cfg(any(target_os = "linux", target_os = "freebsd",))]
            ConnectionMode::Blocking(connection) => connection.fd.as_ref().as_fd(),
        }
    }
}
