//! Worker pool implementation for handling FUSE requests concurrently.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use futures_channel::mpsc::{channel, Receiver, Sender, UnboundedSender};
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use tracing::debug;

#[cfg(all(not(feature = "tokio-runtime"), feature = "async-io-runtime"))]
use async_global_executor::{self as task, Task as JoinHandle};
#[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
use tokio::task;
#[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
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
    pub(crate) resp: UnboundedSender<FuseData>,
    pub(crate) direct_io: bool,
    pub(crate) force_readdir_plus: bool,
    pub(crate) _inflight: Arc<AtomicUsize>,
    pub(crate) _inflight_notify: Arc<async_notify::Notify>,
}

#[derive(Debug)]
/// Worker pool for processing FUSE requests
pub(crate) struct Workers<FS: Filesystem + Send + Sync + 'static> {
    /// Input queues for each worker
    senders: Vec<Sender<WorkItem>>,
    /// Round-robin counter for load balancing
    next: AtomicUsize,
    #[allow(dead_code)]
    handles: Vec<JoinHandle<()>>,
    _ctx: Arc<DispatchCtx<FS>>,
}

impl<FS: Filesystem + Send + Sync + 'static> Workers<FS> {
    pub(crate) fn new(
        worker_count: usize,
        queue_capacity: usize,
        _ctx: Arc<DispatchCtx<FS>>,
    ) -> Self {
        let mut senders = Vec::with_capacity(worker_count);
        let mut handles = Vec::with_capacity(worker_count);
        for idx in 0..worker_count {
            let (tx, mut rx): (Sender<WorkItem>, Receiver<WorkItem>) = channel(queue_capacity);
            let ctx_clone = _ctx.clone();
            #[cfg(all(not(feature = "tokio-runtime"), feature = "async-io-runtime"))]
            let handle = task::spawn(async move {
                while let Some(item) = rx.next().await {
                    process_work_item(&ctx_clone, idx, item).await;
                }
                debug!(worker=%idx, "worker exit");
            });
            #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
            let handle = task::spawn(async move {
                while let Some(item) = rx.next().await {
                    process_work_item(&ctx_clone, idx, item).await;
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

    pub(crate) async fn submit(&self, item: WorkItem) {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        if self.senders[idx].clone().send(item).await.is_err() {
            // failed to enqueue
            tracing::warn!("failed to enqueue work item, channel closed");
        }
    }
}

/// Dispatch work item to the appropriate handler based on opcode
async fn process_work_item<FS: Filesystem + Send + Sync + 'static>(
    ctx: &Arc<DispatchCtx<FS>>,
    worker_idx: usize,
    item: WorkItem,
) {
    let opcode_result = fuse_opcode::try_from(item.opcode);
    dispatch_to_worker! {
        match opcode_result, {
            ctx => ctx,
            worker_idx => worker_idx,
            item => item,
            FUSE_LOOKUP   => worker_lookup,
            FUSE_GETATTR  => worker_getattr,
            FUSE_OPEN     => worker_open,
            FUSE_READ     => worker_read,
            FUSE_WRITE    => worker_write,
            FUSE_READDIR  => worker_readdir,
            FUSE_SETATTR  => worker_setattr,
            FUSE_READLINK => worker_readlink,
            FUSE_SYMLINK  => worker_symlink,
            FUSE_MKNOD    => worker_mknod,
            FUSE_MKDIR    => worker_mkdir,
            FUSE_UNLINK   => worker_unlink,
            FUSE_RMDIR    => worker_rmdir,
            FUSE_RENAME   => worker_rename,
            FUSE_LINK     => worker_link,
            FUSE_STATFS   => worker_statfs,
            FUSE_RELEASE  => worker_release,
            FUSE_FSYNC    => worker_fsync,
            FUSE_SETXATTR => worker_setxattr,
            FUSE_GETXATTR => worker_getxattr,
            FUSE_LISTXATTR => worker_listxattr,
            FUSE_REMOVEXATTR => worker_removexattr,
            FUSE_FLUSH    => worker_flush,
            FUSE_OPENDIR => worker_opendir,
            FUSE_RELEASEDIR => worker_releasedir,
            FUSE_FSYNCDIR => worker_fsyncdir,
            FUSE_ACCESS  => worker_access,
            FUSE_CREATE  => worker_create,
            FUSE_BMAP    => worker_bmap,
            FUSE_FALLOCATE => worker_fallocate,
            FUSE_READDIRPLUS => worker_readdirplus,
            FUSE_RENAME2 => worker_rename2,
            FUSE_LSEEK => worker_lseek,
            FUSE_COPY_FILE_RANGE => worker_copy_file_range,
            FUSE_POLL => worker_poll,
            FUSE_BATCH_FORGET => worker_batch_forget,
            _ => {
                match opcode_result {
                    #[cfg(feature = "file-lock")]
                    Ok(fuse_opcode::FUSE_GETLK) => {
                        debug!(worker=%worker_idx, unique=item.unique, "worker handling GETLK");
                        worker_getlk(ctx, item).await;
                    }
                    #[cfg(feature = "file-lock")]
                    Ok(fuse_opcode::FUSE_SETLK | fuse_opcode::FUSE_SETLKW) => {
                        debug!(worker=%worker_idx, unique=item.unique, "worker handling SETLK/SETLKW");
                        let is_blocking = item.opcode == fuse_opcode::FUSE_SETLKW as u32;
                        worker_setlk(ctx, item, is_blocking).await;
                    }
                    #[cfg(target_os = "macos")]
                    Ok(fuse_opcode::FUSE_SETVOLNAME) => {
                        debug!(worker=%worker_idx, unique=item.unique, "worker handling SETVOLNAME");
                        worker_setvolname(ctx, item).await;
                    }
                    #[cfg(target_os = "macos")]
                    Ok(fuse_opcode::FUSE_GETXTIMES) => {
                        debug!(worker=%worker_idx, unique=item.unique, "worker handling GETXTIMES");
                        worker_getxtimes(ctx, item).await;
                    }
                    #[cfg(target_os = "macos")]
                    Ok(fuse_opcode::FUSE_EXCHANGE) => {
                        debug!(worker=%worker_idx, unique=item.unique, "worker handling EXCHANGE");
                        worker_exchange(ctx, item).await;
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
