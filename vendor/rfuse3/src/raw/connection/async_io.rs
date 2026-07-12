#[cfg(target_os = "macos")]
use std::env;
#[cfg(target_os = "macos")]
use std::ffi::OsStr;
#[cfg(all(target_os = "linux", feature = "unprivileged"))]
use std::ffi::OsString;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs::File;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::fs::OpenOptions;
use std::io;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Write;
use std::io::{IoSlice, IoSliceMut};
use std::ops::{Deref, DerefMut};
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "freebsd"
))]
use std::os::fd::OwnedFd;
#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", feature = "unprivileged")
))]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(all(target_os = "linux", feature = "unprivileged"))]
use std::os::unix::io::RawFd;
#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "macos"
))]
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;

#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "freebsd"
))]
use async_io::Async;
use async_lock::Mutex;
use async_notify::Notify;
#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "macos"
))]
use async_process::Command;
#[cfg(target_os = "macos")]
use async_process::Stdio;
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
    target_os = "freebsd",
))]
use nix::sys::uio;
#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "macos"
))]
use tracing::debug;

#[cfg(all(target_os = "linux", feature = "unprivileged"))]
use crate::find_fusermount3;
use crate::raw::connection::CompleteIoResult;
#[cfg(target_os = "macos")]
use crate::raw::connection::{
    macfuse_command_failure_error, recv_fuse_fd_blocking, MACFUSE_COMMFD_TIMEOUT,
};
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
            let connection = NonBlockFuseConnection::new()?;

            Ok(Self {
                unmount_notify,
                mode: ConnectionMode::NonBlock(connection),
            })
        }

        #[cfg(target_os = "linux")]
        {
            let connection = BlockFuseConnection::new()?;

            Ok(Self {
                unmount_notify,
                mode: ConnectionMode::Block(connection),
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
            NonBlockFuseConnection::new_with_unprivileged(mount_options, mount_path).await?;

        Ok(Self {
            unmount_notify,
            mode: ConnectionMode::NonBlock(connection),
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
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ConnectionMode::Block(connection) => {
                connection.read_vectored(header_buf, data_buf).await
            }
            #[cfg(any(
                all(target_os = "linux", feature = "unprivileged"),
                target_os = "freebsd"
            ))]
            ConnectionMode::NonBlock(connection) => {
                connection.read_vectored(header_buf, data_buf).await
            }
        }
    }

    pub async fn write_vectored<T: Deref<Target = [u8]> + Send, U: Deref<Target = [u8]> + Send>(
        &self,
        data: T,
        body_extend_data: Option<U>,
    ) -> CompleteIoResult<(T, Option<U>), usize> {
        match &self.mode {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ConnectionMode::Block(connection) => {
                connection.write_vectored(data, body_extend_data).await
            }
            #[cfg(any(
                all(target_os = "linux", feature = "unprivileged"),
                target_os = "freebsd"
            ))]
            ConnectionMode::NonBlock(connection) => {
                connection.write_vectored(data, body_extend_data).await
            }
        }
    }
}

#[derive(Debug)]
enum ConnectionMode {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Block(BlockFuseConnection),
    #[cfg(any(
        all(target_os = "linux", feature = "unprivileged"),
        target_os = "freebsd"
    ))]
    NonBlock(NonBlockFuseConnection),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct BlockFuseConnection {
    file: File,
    read: Mutex<()>,
    write: Mutex<()>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl BlockFuseConnection {
    #[cfg(target_os = "linux")]
    pub fn new() -> io::Result<Self> {
        const DEV_FUSE: &str = "/dev/fuse";

        let file = OpenOptions::new().write(true).read(true).open(DEV_FUSE)?;

        Ok(Self {
            file,
            read: Mutex::new(()),
            write: Mutex::new(()),
        })
    }

    #[cfg(target_os = "macos")]
    async fn new_with_unprivileged(
        mount_options: MountOptions,
        mount_path: impl AsRef<Path>,
    ) -> io::Result<Self> {
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

        let (child_result_tx, child_result_rx) = futures_channel::oneshot::channel();
        let child_task = async_global_executor::spawn(async move {
            let output = child.output().await;
            let _ = child_result_tx.send(output);
        });

        let fd_task = async_global_executor::spawn_blocking(move || {
            debug!("wait_thread start");
            recv_fuse_fd_blocking(sock1.as_raw_fd())
        });

        let mut fd_task = fd_task.fuse();
        let mut child_result_rx = child_result_rx.fuse();
        let timeout = async_io::Timer::after(MACFUSE_COMMFD_TIMEOUT);
        let mut timeout = timeout.fuse();

        let fd_result = select! {
            fd_result = fd_task => {
                fd_result.map_err(|err| {
                    macfuse_fd_receive_error(
                        &binary_path_for_error,
                        mount_path_for_error.as_os_str(),
                        err,
                    )
                })
            }
            child_result = child_result_rx => {
                match child_result {
                    Ok(Ok(output)) if output.status.success() => {
                        let retry_timeout = async_io::Timer::after(MACFUSE_COMMFD_TIMEOUT);
                        let mut retry_timeout = retry_timeout.fuse();
                        select! {
                            fd_result = fd_task => {
                                fd_result.map_err(|err| {
                                    macfuse_fd_receive_error(
                                        &binary_path_for_error,
                                        mount_path_for_error.as_os_str(),
                                        err,
                                    )
                                })
                            }
                            _ = retry_timeout => {
                                Err(macfuse_fd_timeout_error(
                                    &binary_path_for_error,
                                    mount_path_for_error.as_os_str(),
                                ))
                            }
                        }
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
            _ = timeout => {
                Err(macfuse_fd_timeout_error(
                    &binary_path_for_error,
                    mount_path_for_error.as_os_str(),
                ))
            }
        };

        let fd = match fd_result {
            Ok(fd) => {
                child_task.detach();
                fd
            }
            Err(err) => {
                let _ = child_task.cancel().await;
                return Err(err);
            }
        };

        // Safety: fd is valid
        let file = unsafe { File::from_raw_fd(fd) };

        Ok(Self {
            file,
            read: Mutex::new(()),
            write: Mutex::new(()),
        })
    }

    async fn read_vectored<T: DerefMut<Target = [u8]> + Send + 'static>(
        &self,
        mut header_buf: Vec<u8>,
        mut data_buf: T,
    ) -> CompleteIoResult<(Vec<u8>, T), usize> {
        use std::io::Read;
        use std::mem::ManuallyDrop;
        use std::os::fd::{AsRawFd, FromRawFd};

        let _guard = self.read.lock().await;
        let fd = self.file.as_raw_fd();

        let ((header_buf, data_buf), res) = async_global_executor::spawn_blocking(move || {
            // Safety: when we call read, the fd is still valid, when fd is closed and file is
            // dropped, the read operation will return error
            let file = unsafe { File::from_raw_fd(fd) };
            // avoid close the file
            let mut file = ManuallyDrop::new(file);

            let res = file.read_vectored(&mut [
                IoSliceMut::new(&mut header_buf),
                IoSliceMut::new(&mut data_buf),
            ]);

            ((header_buf, data_buf), res)
        })
        .await;

        ((header_buf, data_buf), res)
    }

    async fn write_vectored<T: Deref<Target = [u8]> + Send, U: Deref<Target = [u8]> + Send>(
        &self,
        data: T,
        body_extend_data: Option<U>,
    ) -> CompleteIoResult<(T, Option<U>), usize> {
        let _guard = self.write.lock().await;

        let res = {
            let body_extend_data = body_extend_data.as_deref();

            match body_extend_data {
                None => (&self.file).write_vectored(&[IoSlice::new(data.deref())]),

                Some(body_extend_data) => (&self.file)
                    .write_vectored(&[IoSlice::new(data.deref()), IoSlice::new(body_extend_data)]),
            }
        };

        match res {
            Err(err) => ((data, body_extend_data), Err(err)),
            Ok(n) => ((data, body_extend_data), Ok(n)),
        }
    }
}

#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "freebsd"
))]
#[derive(Debug)]
struct NonBlockFuseConnection {
    fd: Async<OwnedFd>,
    read: Mutex<()>,
    write: Mutex<()>,
}

#[cfg(any(
    all(target_os = "linux", feature = "unprivileged"),
    target_os = "freebsd"
))]
impl NonBlockFuseConnection {
    #[cfg(target_os = "freebsd")]
    fn new() -> io::Result<Self> {
        const DEV_FUSE: &str = "/dev/fuse";

        let file = OpenOptions::new().write(true).read(true).open(DEV_FUSE)?;

        Ok(Self {
            fd: Async::new(file.into())?,
            read: Mutex::new(()),
            write: Mutex::new(()),
        })
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

        if !child.status().await?.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "fusermount run failed",
            ));
        }

        let fd1 = sock1.as_raw_fd();
        let fd = async_global_executor::spawn_blocking(move || {
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
                    return Err(io::Error::new(io::ErrorKind::Other, "no fuse fd"));
                }

                fds[0]
            } else {
                return Err(io::Error::new(io::ErrorKind::Other, "get fuse fd failed"));
            };

            Ok(fd)
        })
        .await?;

        // Safety: fd is valid
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        Ok(Self {
            fd: Async::new(fd)?,
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

        let res = self
            .fd
            .read_with(|fd| {
                uio::readv(
                    fd,
                    &mut [
                        IoSliceMut::new(&mut header_buf),
                        IoSliceMut::new(&mut data_buf),
                    ],
                )
                .map_err(Into::into)
            })
            .await;

        ((header_buf, data_buf), res)
    }

    async fn write_vectored<T: Deref<Target = [u8]> + Send, U: Deref<Target = [u8]> + Send>(
        &self,
        data: T,
        body_extend_data: Option<U>,
    ) -> CompleteIoResult<(T, Option<U>), usize> {
        let _guard = self.write.lock().await;

        let res = {
            let body_extend_data = body_extend_data.as_deref();

            match body_extend_data {
                None => uio::writev(&self.fd, &[IoSlice::new(data.deref())]),

                Some(body_extend_data) => uio::writev(
                    &self.fd,
                    &[IoSlice::new(data.deref()), IoSlice::new(body_extend_data)],
                ),
            }
        };

        match res {
            Err(err) => ((data, body_extend_data), Err(err.into())),
            Ok(n) => ((data, body_extend_data), Ok(n)),
        }
    }
}

impl AsFd for FuseConnection {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match &self.mode {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            ConnectionMode::Block(connection) => {
                // Safety: we own the File
                connection.file.as_fd()
            }

            #[cfg(any(
                all(target_os = "linux", feature = "unprivileged"),
                target_os = "freebsd"
            ))]
            ConnectionMode::NonBlock(connection) => connection.fd.as_fd(),
        }
    }
}
