//! io_uring-based FUSE connection for Linux.
//!
//! Uses a dedicated io_uring ring thread to perform readv/writev on `/dev/fuse`
//! without blocking thread pool overhead. Communicates with the async tokio world
//! via channels.
//!
//! Performance advantage over the tokio `spawn_blocking` path:
//! - No thread context switches for each FUSE read/write
//! - Kernel processes readv/writev via the submission queue directly
//! - Can batch multiple response writes in a single io_uring submit

use std::fs::{File, OpenOptions};
use std::io;
use std::ops::DerefMut;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::io::FromRawFd;
use std::pin::pin;
use std::sync::Arc;
use std::thread;

use async_notify::Notify;
use futures_util::{select, FutureExt};
use io_uring::{opcode, types, IoUring};
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use super::CompleteIoResult;
use bytes::Bytes;

/// Number of submission queue entries in the io_uring ring.
const RING_SIZE: u32 = 64;

/// A FUSE connection powered by io_uring for zero-overhead kernel I/O.
#[derive(Debug)]
pub struct FuseConnection {
    unmount_notify: Arc<Notify>,
    inner: IoUringConnection,
}

/// Represents a pending read request sent to the ring thread.
struct ReadRequest {
    header_buf: Vec<u8>,
    data_buf: AlignedDataBuf,
    reply: oneshot::Sender<CompleteIoResult<(Vec<u8>, AlignedDataBuf), usize>>,
}

/// Represents a pending write request sent to the ring thread.
struct WriteRequest {
    data: Bytes,
    body_extend: Option<Bytes>,
    reply: oneshot::Sender<CompleteIoResult<(Bytes, Option<Bytes>), usize>>,
}

/// Combined request type for the single ring thread channel.
enum RingRequest {
    Read(ReadRequest),
    Write(WriteRequest),
}

/// Type-erased aligned data buffer that can be sent across threads.
pub(crate) struct AlignedDataBuf {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: The AlignedDataBuf is only accessed by one thread at a time
// (transferred via channel, not shared).
unsafe impl Send for AlignedDataBuf {}

impl AlignedDataBuf {
    pub fn new<T: DerefMut<Target = [u8]>>(buf: &mut T) -> Self {
        let slice = buf.deref_mut();
        Self {
            ptr: slice.as_mut_ptr(),
            len: slice.len(),
        }
    }
}

#[derive(Debug)]
struct IoUringConnection {
    tx: mpsc::Sender<RingRequest>,
    fd: i32,
    #[allow(dead_code)]
    file: Arc<File>, // kept alive for the fd
}

impl AsFd for FuseConnection {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.file.as_fd()
    }
}

impl AsRawFd for FuseConnection {
    fn as_raw_fd(&self) -> i32 {
        self.inner.fd
    }
}

impl FuseConnection {
    /// Opens `/dev/fuse` and starts the io_uring ring thread.
    pub fn new(unmount_notify: Arc<Notify>) -> io::Result<Self> {
        const DEV_FUSE: &str = "/dev/fuse";

        let file = OpenOptions::new().write(true).read(true).open(DEV_FUSE)?;
        let fd = file.as_raw_fd();
        debug!(fd, "io_uring: opened /dev/fuse");
        let file = Arc::new(file);

        let tx = IoUringConnection::start_ring_thread(fd)?;

        Ok(Self {
            unmount_notify,
            inner: IoUringConnection { tx, fd, file },
        })
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        let new_fd = unsafe { libc::dup(self.inner.fd) };
        if new_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = Arc::new(unsafe { File::from_raw_fd(new_fd) });
        let tx = IoUringConnection::start_ring_thread(new_fd)?;

        Ok(Self {
            unmount_notify: self.unmount_notify.clone(),
            inner: IoUringConnection {
                tx,
                fd: new_fd,
                file,
            },
        })
    }

    /// Mount with unprivileged fusermount3, then start the io_uring ring thread.
    #[cfg(all(target_os = "linux", feature = "unprivileged"))]
    pub async fn new_with_unprivileged(
        mount_options: crate::MountOptions,
        mount_path: impl AsRef<std::path::Path>,
        unmount_notify: Arc<Notify>,
    ) -> io::Result<Self> {
        use nix::sys::socket::{
            self, AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType,
        };
        use std::ffi::OsString;
        use std::os::fd::AsRawFd as _;
        use std::os::fd::FromRawFd as _;
        use tokio::process::Command;

        let (sock0, sock1) = socket::socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::empty(),
        )
        .map_err(io::Error::from)?;

        let binary_path = crate::find_fusermount3()?;
        let options = mount_options.build_with_unprivileged();
        let mount_path = mount_path.as_ref().as_os_str().to_os_string();

        const ENV: &str = "_FUSE_COMMFD";
        let fd0 = sock0.as_raw_fd();
        let mut child = Command::new(binary_path)
            .env(ENV, fd0.to_string())
            .args(vec![OsString::from("-o"), options, mount_path])
            .spawn()?;

        if !child.wait().await?.success() {
            return Err(io::Error::other("fusermount run failed"));
        }

        let fd1 = sock1.as_raw_fd();
        let fuse_fd = tokio::task::spawn_blocking(move || {
            let mut buf = vec![];
            let mut cmsg_buf = nix::cmsg_space!([std::os::unix::io::RawFd; 1]);
            let mut bufs = [std::io::IoSliceMut::new(&mut buf)];
            let msg =
                socket::recvmsg::<()>(fd1, &mut bufs[..], Some(&mut cmsg_buf), MsgFlags::empty())
                    .map_err(io::Error::from)?;
            if let Some(ControlMessageOwned::ScmRights(fds)) =
                msg.cmsgs().ok().and_then(|mut c| c.next())
            {
                if fds.is_empty() {
                    return Err(io::Error::other("no fuse fd"));
                }
                Ok(fds[0])
            } else {
                Err(io::Error::other("get fuse fd failed"))
            }
        })
        .await
        .unwrap()?;

        let file = Arc::new(unsafe { File::from_raw_fd(fuse_fd) });
        let tx = IoUringConnection::start_ring_thread(fuse_fd)?;

        Ok(Self {
            unmount_notify,
            inner: IoUringConnection {
                tx,
                fd: fuse_fd,
                file,
            },
        })
    }

    /// Read a FUSE request from `/dev/fuse` using io_uring readv.
    /// Returns None if unmount was signaled.
    pub async fn read_vectored<T: DerefMut<Target = [u8]> + Send + 'static>(
        &self,
        header_buf: Vec<u8>,
        mut data_buf: T,
    ) -> Option<CompleteIoResult<(Vec<u8>, T), usize>> {
        let (tx, rx) = oneshot::channel();

        // SAFETY: We hold `data_buf` alive until the oneshot completes,
        // and the ring thread only accesses it during the readv syscall.
        let aligned = AlignedDataBuf::new(&mut data_buf);

        let req = RingRequest::Read(ReadRequest {
            header_buf,
            data_buf: aligned,
            reply: tx,
        });

        if self.inner.tx.send(req).await.is_err() {
            return Some((
                (vec![], data_buf),
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "ring thread gone",
                )),
            ));
        }

        let mut unmount_fut = pin!(self.unmount_notify.notified().fuse());
        let mut read_fut = pin!(async {
            rx.await.unwrap_or((
                (
                    vec![],
                    AlignedDataBuf {
                        ptr: std::ptr::null_mut(),
                        len: 0,
                    },
                ),
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "ring cancelled")),
            ))
        }
        .fuse());

        select! {
            _ = unmount_fut => {
                debug!("io_uring read_vectored: unmount signaled");
                None
            },
            result = read_fut => {
                let ((header, _aligned_buf), res) = result;
                Some(((header, data_buf), res))
            }
        }
    }

    /// Write a FUSE response to `/dev/fuse` using io_uring writev.
    pub async fn write_vectored(
        &self,
        data: Bytes,
        body_extend_data: Option<Bytes>,
    ) -> CompleteIoResult<(Bytes, Option<Bytes>), usize> {
        let (tx, rx) = oneshot::channel();

        // Pass Bytes directly to the ring thread — zero-copy (Arc bump
        // only).  The ring thread reads .as_ptr() at writev time.
        let req = RingRequest::Write(WriteRequest {
            data: data.clone(),
            body_extend: body_extend_data.clone(),
            reply: tx,
        });

        if self.inner.tx.send(req).await.is_err() {
            return (
                (data, body_extend_data),
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "ring thread gone",
                )),
            );
        }

        match rx.await {
            Ok((_bufs, res)) => ((data, body_extend_data), res),
            Err(_) => (
                (data, body_extend_data),
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "ring cancelled")),
            ),
        }
    }
}

impl IoUringConnection {
    /// Start the io_uring ring thread. Returns a sender for ring requests.
    fn start_ring_thread(fd: i32) -> io::Result<mpsc::Sender<RingRequest>> {
        let (tx, rx) = mpsc::channel::<RingRequest>(RING_SIZE as usize);

        thread::Builder::new()
            .name("fuse-io-uring".into())
            .spawn(move || {
                if let Err(e) = ring_thread_main(fd, rx) {
                    tracing::error!(fd, error = %e, "io_uring ring thread exited with error");
                }
            })?;

        Ok(tx)
    }
}

/// User data tags for io_uring completions.
const TAG_READ: u64 = 1;
const TAG_WRITE_BASE: u64 = 0x1000;

/// Pending read with its iovec storage kept alive.
struct InflightRead {
    req: ReadRequest,
    _iovecs: Box<[libc::iovec; 2]>,
}

/// Pending write with its iovec storage kept alive.
struct InflightWrite {
    req: WriteRequest,
    _iovecs: Box<[libc::iovec; 2]>,
}

/// Main loop of the io_uring ring thread.
///
/// Processes read and write requests from a single channel, submitting them to
/// the ring and waiting for completions. All iovec arrays are heap-allocated
/// (Box) to ensure they remain at a stable address until the CQE arrives.
fn ring_thread_main(fd: i32, mut rx: mpsc::Receiver<RingRequest>) -> io::Result<()> {
    let mut ring: IoUring = IoUring::builder().build(RING_SIZE)?;

    let mut pending_read: Option<InflightRead> = None;
    let mut pending_writes: Vec<Option<InflightWrite>> = Vec::new();

    let mut read_inflight = false;
    let mut writes_inflight: usize = 0;

    loop {
        // If nothing is inflight, block until a request arrives.
        // Otherwise, drain the channel with try_recv.
        let blocking = !read_inflight && writes_inflight == 0;

        if blocking {
            match rx.blocking_recv() {
                None => return Ok(()), // channel closed, clean shutdown
                Some(req) => submit_request(
                    &mut ring,
                    fd,
                    req,
                    &mut pending_read,
                    &mut pending_writes,
                    &mut read_inflight,
                    &mut writes_inflight,
                )?,
            }
        }

        // Drain all pending requests from the channel
        while let Ok(req) = rx.try_recv() {
            submit_request(
                &mut ring,
                fd,
                req,
                &mut pending_read,
                &mut pending_writes,
                &mut read_inflight,
                &mut writes_inflight,
            )?;
        }

        if !read_inflight && writes_inflight == 0 {
            continue;
        }

        // Submit and wait for at least one completion
        ring.submit_and_wait(1)?;

        // Process completions
        for cqe in ring.completion() {
            let user_data = cqe.user_data();
            let result = cqe.result();

            if user_data == TAG_READ {
                read_inflight = false;
                if let Some(inflight) = pending_read.take() {
                    let io_result = if result < 0 {
                        Err(io::Error::from_raw_os_error(-result))
                    } else {
                        Ok(result as usize)
                    };
                    let _ = inflight
                        .req
                        .reply
                        .send(((inflight.req.header_buf, inflight.req.data_buf), io_result));
                }
            } else if user_data >= TAG_WRITE_BASE {
                writes_inflight -= 1;
                let idx = (user_data - TAG_WRITE_BASE) as usize;
                if let Some(inflight) = pending_writes.get_mut(idx).and_then(|s| s.take()) {
                    let io_result = if result < 0 {
                        Err(io::Error::from_raw_os_error(-result))
                    } else {
                        Ok(result as usize)
                    };
                    let _ = inflight
                        .req
                        .reply
                        .send(((inflight.req.data, inflight.req.body_extend), io_result));
                }
            }
        }

        // Compact pending_writes when all slots are done
        if writes_inflight == 0 {
            pending_writes.clear();
        }
    }
}

/// Submit a single request (read or write) to the io_uring ring.
fn submit_request(
    ring: &mut IoUring,
    fd: i32,
    req: RingRequest,
    pending_read: &mut Option<InflightRead>,
    pending_writes: &mut Vec<Option<InflightWrite>>,
    read_inflight: &mut bool,
    writes_inflight: &mut usize,
) -> io::Result<()> {
    match req {
        RingRequest::Read(req) => {
            if *read_inflight {
                // Only one read at a time; reply with error
                let _ = req.reply.send((
                    (req.header_buf, req.data_buf),
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "read already inflight",
                    )),
                ));
                return Ok(());
            }
            let iovecs = Box::new([
                libc::iovec {
                    iov_base: req.header_buf.as_ptr() as *mut libc::c_void,
                    iov_len: req.header_buf.len(),
                },
                libc::iovec {
                    iov_base: req.data_buf.ptr as *mut libc::c_void,
                    iov_len: req.data_buf.len,
                },
            ]);
            let entry = opcode::Readv::new(types::Fd(fd), iovecs.as_ptr(), 2)
                .build()
                .user_data(TAG_READ);
            unsafe {
                ring.submission()
                    .push(&entry)
                    .map_err(|_| io::Error::other("SQ full"))?;
            }
            *pending_read = Some(InflightRead {
                req,
                _iovecs: iovecs,
            });
            *read_inflight = true;
        }
        RingRequest::Write(req) => {
            let iov_count;
            let iovecs = Box::new(match &req.body_extend {
                None => {
                    iov_count = 1u32;
                    [
                        libc::iovec {
                            iov_base: req.data.as_ptr() as *mut libc::c_void,
                            iov_len: req.data.len(),
                        },
                        libc::iovec {
                            iov_base: std::ptr::null_mut(),
                            iov_len: 0,
                        },
                    ]
                }
                Some(body) => {
                    iov_count = 2;
                    [
                        libc::iovec {
                            iov_base: req.data.as_ptr() as *mut libc::c_void,
                            iov_len: req.data.len(),
                        },
                        libc::iovec {
                            iov_base: body.as_ptr() as *mut libc::c_void,
                            iov_len: body.len(),
                        },
                    ]
                }
            });

            let idx = pending_writes.len();
            let entry = opcode::Writev::new(types::Fd(fd), iovecs.as_ptr(), iov_count)
                .build()
                .user_data(TAG_WRITE_BASE + idx as u64);
            unsafe {
                ring.submission()
                    .push(&entry)
                    .map_err(|_| io::Error::other("SQ full"))?;
            }
            pending_writes.push(Some(InflightWrite {
                req,
                _iovecs: iovecs,
            }));
            *writes_inflight += 1;
        }
    }
    Ok(())
}
