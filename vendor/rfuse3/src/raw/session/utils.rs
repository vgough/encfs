//! Utility types and helper functions for the FUSE session.

use bincode::Options;
use bytes::Bytes;
use futures_util::future::Either;
use futures_util::sink::{Sink, SinkExt};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::io::Result as IoResult;
use std::pin::pin;
use tracing::Span;

#[cfg(all(not(feature = "tokio-runtime"), feature = "async-io-runtime"))]
use async_global_executor as task;
#[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
use tokio::task;
use tracing::Instrument;

use crate::helper::*;
use crate::raw::abi::*;
use crate::raw::buffer_pool::AlignedBuffer;
use crate::raw::request::Request;
use crate::Errno;

#[derive(Debug, Clone, Copy)]
/// Lightweight version of fuse_in_header containing essential fields
pub(crate) struct InHeaderLite {
    pub(crate) nodeid: u64,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) pid: u32,
}

/// Check if the opcode is a FORGET message (FUSE_FORGET or FUSE_BATCH_FORGET).
/// These messages don't need replies and shouldn't count toward inflight limits.
#[inline]
pub(super) fn is_forget_opcode(opcode: u32) -> bool {
    opcode == fuse_opcode::FUSE_FORGET as u32 || opcode == fuse_opcode::FUSE_BATCH_FORGET as u32
}

/// Apply direct_io flag to open_flags if enabled
pub(super) fn apply_direct_io(open_flags: &mut u32, direct_io: bool) {
    if direct_io {
        *open_flags |= FOPEN_DIRECT_IO;
    }
}

/// Reply with an error code in worker context
#[inline]
pub(super) fn reply_error_in_worker(
    err: Errno,
    unique: u64,
) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
    let out_header = fuse_out_header {
        len: FUSE_OUT_HEADER_SIZE as u32,
        error: err.into(),
        unique,
    };
    get_bincode_config().serialize(&out_header)
}

/// Reply with an error code in place (for non-worker contexts)
pub(super) async fn reply_error_in_place<S>(err: Errno, request: Request, sender: S)
where
    S: Sink<Either<Vec<u8>, (Vec<u8>, Bytes)>>,
{
    let out_header = fuse_out_header {
        len: FUSE_OUT_HEADER_SIZE as u32,
        error: err.into(),
        unique: request.unique,
    };

    let data = get_bincode_config()
        .serialize(&out_header)
        .expect("won't happened");

    let _ = pin!(sender).send(Either::Left(data)).await;
}

/// Spawn an async task with proper instrumentation
#[inline]
pub(super) fn spawn<F>(span: Span, fut: F)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    task::spawn(fut.instrument(span));

    #[cfg(all(not(feature = "tokio-runtime"), feature = "async-io-runtime"))]
    task::spawn(fut.instrument(span)).detach()
}

/// Result type for reading from the FUSE connection
pub(super) enum ReadResult {
    Destroy,
    Request {
        in_header: IoResult<fuse_in_header>,
        header_buffer: Vec<u8>,
        data_buffer: AlignedBuffer,
    },
}

impl Debug for ReadResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadResult::Destroy => f.debug_struct("ReadResult::Destroy").finish(),
            ReadResult::Request { in_header, .. } => f
                .debug_struct("ReadResult::Request")
                .field("in_header", in_header)
                .finish_non_exhaustive(),
        }
    }
}
