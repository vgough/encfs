//! Worker pool implementation for handling FUSE requests concurrently.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use futures_channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures_util::stream::StreamExt;
use tracing::debug;

#[cfg(all(
    not(feature = "tokio-runtime"),
    not(feature = "io-uring-runtime"),
    feature = "async-io-runtime"
))]
use async_global_executor::{self as task, Task as JoinHandle};
#[cfg(any(
    all(not(feature = "async-io-runtime"), feature = "tokio-runtime"),
    feature = "io-uring-runtime"
))]
use tokio::task;
#[cfg(any(
    all(not(feature = "async-io-runtime"), feature = "tokio-runtime"),
    feature = "io-uring-runtime"
))]
use tokio::task::JoinHandle;

use crate::raw::abi::fuse_opcode;
use crate::raw::filesystem::Filesystem;
use crate::raw::FuseData;

use super::handlers::*;
use super::utils::InHeaderLite;

#[derive(Debug)]
/// Represents a work item to be processed by a worker thread in the worker pool
pub(crate) struct WorkItem {
    pub(crate) unique: u64,
    pub(crate) opcode: u32,
    pub(crate) in_header: InHeaderLite,
    /// Body data (excludes fixed-size fuse_in_header) - uses Bytes for zero-copy sharing
    pub(crate) data: Bytes,
    /// Inflight guard for backpressure control.
    /// None for FORGET/BATCH_FORGET messages to prevent thread explosion during large deletions.
    pub(crate) _inflight_guard: Option<InflightGuard>,
}

#[derive(Debug)]
/// RAII guard that tracks the number of in-flight requests
/// Increments counter on creation and decrements on drop
pub struct InflightGuard {
    inflight: Arc<AtomicUsize>,
    notify: Arc<async_notify::Notify>,
}

impl InflightGuard {
    pub fn new(inflight: Arc<AtomicUsize>, notify: Arc<async_notify::Notify>) -> Self {
        inflight.fetch_add(1, Ordering::AcqRel);
        Self { inflight, notify }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.inflight.fetch_sub(1, Ordering::AcqRel);
        self.notify.notify();
    }
}

#[derive(Debug)]
/// Dispatch context shared across all workers
pub(crate) struct DispatchCtx<FS: Filesystem + Send + Sync + 'static> {
    pub(crate) fs: Arc<FS>,
    pub(crate) resp: Vec<UnboundedSender<FuseData>>,
    pub(crate) direct_io: bool,
    pub(crate) force_readdir_plus: bool,
    pub(crate) _inflight: Arc<AtomicUsize>,
    pub(crate) _inflight_notify: Arc<async_notify::Notify>,
}

impl<FS: Filesystem + Send + Sync + 'static> DispatchCtx<FS> {
    #[inline]
    pub(crate) fn resp_for(&self, unique: u64) -> &UnboundedSender<FuseData> {
        &self.resp[unique as usize % self.resp.len()]
    }
}

#[derive(Debug)]
/// Worker pool for processing FUSE requests
pub(crate) struct Workers<FS: Filesystem + Send + Sync + 'static> {
    /// Input queues for each worker (unbounded)
    senders: Vec<UnboundedSender<WorkItem>>,
    /// Round-robin counter for load balancing
    next: AtomicUsize,
    #[allow(dead_code)]
    handles: Vec<JoinHandle<()>>,
    _ctx: Arc<DispatchCtx<FS>>,
}

impl<FS: Filesystem + Send + Sync + 'static> Workers<FS> {
    pub(crate) fn new(
        worker_count: usize,
        _queue_capacity: usize,
        _ctx: Arc<DispatchCtx<FS>>,
    ) -> Self {
        let mut senders = Vec::with_capacity(worker_count);
        let mut handles = Vec::with_capacity(worker_count);
        for idx in 0..worker_count {
            let (tx, mut rx): (UnboundedSender<WorkItem>, UnboundedReceiver<WorkItem>) =
                unbounded();
            let ctx_clone = _ctx.clone();
            #[cfg(all(
                not(feature = "tokio-runtime"),
                not(feature = "io-uring-runtime"),
                feature = "async-io-runtime"
            ))]
            let handle = task::spawn(async move {
                while let Some(item) = rx.next().await {
                    let ctx = ctx_clone.clone();
                    task::spawn(async move {
                        process_work_item(&ctx, idx, item).await;
                    })
                    .detach();
                }
                debug!(worker=%idx, "worker exit");
            });
            #[cfg(any(
                all(not(feature = "async-io-runtime"), feature = "tokio-runtime"),
                feature = "io-uring-runtime"
            ))]
            let handle = task::spawn(async move {
                while let Some(item) = rx.next().await {
                    let ctx = ctx_clone.clone();
                    // Inline FUSE_READ — cache-hit reads take <1ms so the
                    // spawn overhead (~2µs per task::spawn) is measurable
                    // at 2000+ reads/sec.  Everything else spawns a task.
                    if item.opcode == fuse_opcode::FUSE_READ as u32 {
                        process_work_item(&ctx, idx, item).await;
                    } else {
                        task::spawn(async move {
                            process_work_item(&ctx, idx, item).await;
                        });
                    }
                }
                debug!(worker=%idx, "worker exit");
            });
            senders.push(tx);
            handles.push(handle);
        }
        Self {
            senders,
            next: AtomicUsize::new(0),
            handles,
            _ctx,
        }
    }

    pub(crate) fn submit(&self, item: WorkItem) {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        if self.senders[idx].unbounded_send(item).is_err() {
            tracing::warn!("failed to enqueue work item, channel closed");
        }
    }
}

/// Dispatch work item to the appropriate handler based on opcode.
/// The `item` (including `InflightGuard`) is held until the handler completes,
/// ensuring backpressure accurately reflects in-flight FS operations.
async fn process_work_item<FS: Filesystem + Send + Sync + 'static>(
    ctx: &DispatchCtx<FS>,
    worker_idx: usize,
    item: WorkItem,
) {
    let opcode_result = fuse_opcode::try_from(item.opcode);
    dispatch_to_worker! {
        match opcode_result, {
            ctx => ctx,
            worker_idx => worker_idx,
            item => item,
            FUSE_FORGET   => handle_forget_inline,
            FUSE_LOOKUP   => handle_lookup_inline,
            FUSE_GETATTR  => handle_getattr_inline,
            FUSE_OPEN     => handle_open_inline,
            FUSE_READ     => handle_read_inline,
            FUSE_WRITE    => handle_write_inline,
            FUSE_READDIR  => handle_readdir_inline,
            FUSE_SETATTR  => handle_setattr_inline,
            FUSE_READLINK => handle_readlink_inline,
            FUSE_SYMLINK  => handle_symlink_inline,
            FUSE_MKNOD    => handle_mknod_inline,
            FUSE_MKDIR    => handle_mkdir_inline,
            FUSE_UNLINK   => handle_unlink_inline,
            FUSE_RMDIR    => handle_rmdir_inline,
            FUSE_RENAME   => handle_rename_inline,
            FUSE_LINK     => handle_link_inline,
            FUSE_STATFS   => handle_statfs_inline,
            FUSE_IOCTL   => handle_ioctl_inline,
            FUSE_RELEASE  => handle_release_inline,
            FUSE_FSYNC    => handle_fsync_inline,
            FUSE_SETXATTR => handle_setxattr_inline,
            FUSE_GETXATTR => handle_getxattr_inline,
            FUSE_LISTXATTR => handle_listxattr_inline,
            FUSE_REMOVEXATTR => handle_removexattr_inline,
            FUSE_FLUSH    => handle_flush_inline,
            FUSE_OPENDIR => handle_opendir_inline,
            FUSE_RELEASEDIR => handle_releasedir_inline,
            FUSE_FSYNCDIR => handle_fsyncdir_inline,
            FUSE_ACCESS  => handle_access_inline,
            FUSE_CREATE  => handle_create_inline,
            FUSE_BMAP    => handle_bmap_inline,
            FUSE_FALLOCATE => handle_fallocate_inline,
            FUSE_READDIRPLUS => handle_readdirplus_inline,
            FUSE_RENAME2 => handle_rename2_inline,
            FUSE_LSEEK => handle_lseek_inline,
            FUSE_COPY_FILE_RANGE => handle_copy_file_range_inline,
            FUSE_POLL => handle_poll_inline,
            FUSE_DESTROY => handle_destroy_inline,
            FUSE_INTERRUPT => handle_interrupt_inline,
            FUSE_NOTIFY_REPLY => handle_notify_reply_inline,
            FUSE_BATCH_FORGET => handle_batch_forget_inline,
            _ => {
                match opcode_result {
                    #[cfg(feature = "file-lock")]
                    Ok(fuse_opcode::FUSE_GETLK) => {
                        debug!(worker=%worker_idx, unique=item.unique, "worker handling GETLK");
                        handle_getlk_inline(ctx, item).await;
                    }
                    #[cfg(feature = "file-lock")]
                    Ok(fuse_opcode::FUSE_SETLK | fuse_opcode::FUSE_SETLKW) => {
                        debug!(worker=%worker_idx, unique=item.unique, "worker handling SETLK/SETLKW");
                        let is_blocking = item.opcode == fuse_opcode::FUSE_SETLKW as u32;
                        handle_setlk_inline(ctx, item, is_blocking).await;
                    }
                    #[cfg(target_os = "macos")]
                    Ok(fuse_opcode::FUSE_SETVOLNAME) => {
                        debug!(worker=%worker_idx, unique=item.unique, "worker handling SETVOLNAME");
                        handle_setvolname_inline(ctx, item).await;
                    }
                    #[cfg(target_os = "macos")]
                    Ok(fuse_opcode::FUSE_GETXTIMES) => {
                        debug!(worker=%worker_idx, unique=item.unique, "worker handling GETXTIMES");
                        handle_getxtimes_inline(ctx, item).await;
                    }
                    #[cfg(target_os = "macos")]
                    Ok(fuse_opcode::FUSE_EXCHANGE) => {
                        debug!(worker=%worker_idx, unique=item.unique, "worker handling EXCHANGE");
                        handle_exchange_inline(ctx, item).await;
                    }
                    Ok(_) => {
                        debug!(worker=%worker_idx, unique=item.unique, opcode=item.opcode, "opcode not yet handled in worker");
                    }
                    Err(err) => {
                        debug!(worker=%worker_idx, unique=item.unique, raw=item.opcode, "unknown opcode {}", err.0);
                    }
                }
            }
        }
    }
}

/// Macro for dispatching work items to handler functions
macro_rules! dispatch_to_worker {
    (
        match $target:expr, {
            ctx => $ctx:expr,
            worker_idx => $worker_idx:expr,
            item => $item:expr,

            $( $op:ident => $handler:ident, )*

            _ => { $($other_logic:tt)* }
        }
    ) => {
        match $target {
            $(
                Ok(fuse_opcode::$op) => {
                    debug!(
                        worker = %$worker_idx,
                        unique = $item.unique,
                        "worker handling {}",
                        stringify!($op).replace("FUSE_", "")
                    );
                    $handler($ctx, $item).await;
                },
            )*
            _ => { $($other_logic)* }
        }
    };
}

pub(super) use dispatch_to_worker;
