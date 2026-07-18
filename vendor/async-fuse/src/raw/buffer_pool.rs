#[cfg(feature = "buffer-pool")]
use std::sync::atomic::{AtomicUsize, Ordering};

use aligned_box::AlignedBox;
use std::error::Error;
#[cfg(feature = "buffer-pool")]
use std::io::{Error as IoError, ErrorKind, Result as IoResult};

#[cfg(all(
    feature = "buffer-pool",
    not(feature = "tokio-runtime"),
    feature = "async-io-runtime"
))]
use async_lock::Mutex;
#[cfg(all(
    feature = "buffer-pool",
    not(feature = "async-io-runtime"),
    feature = "tokio-runtime"
))]
use tokio::sync::Mutex;

/// Alignment for Direct I/O support (512 bytes is typical for block devices)
const BUFFER_ALIGNMENT: usize = 512;

/// Default pool capacity
#[cfg(feature = "buffer-pool")]
const DEFAULT_POOL_CAPACITY: usize = 64;

/// An aligned buffer that can be reused through the buffer pool
pub struct AlignedBuffer {
    inner: AlignedBox<[u8]>,
    capacity: usize,
}

impl std::fmt::Debug for AlignedBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBuffer")
            .field("capacity", &self.capacity)
            .field("len", &self.inner.len())
            .finish()
    }
}

impl AlignedBuffer {
    /// Create a new aligned buffer with the specified size
    pub fn try_new(size: usize) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let inner = AlignedBox::<[u8]>::slice_from_default(BUFFER_ALIGNMENT, size)
            .map_err(|err| format!("aligned buffer allocation failed: {err:?}"))?;
        Ok(Self {
            inner,
            capacity: size,
        })
    }

    /// Get the buffer capacity
    #[cfg(feature = "buffer-pool")]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Reset the buffer for reuse
    #[cfg(feature = "buffer-pool")]
    pub fn reset(&mut self) {
        // No need to zero out - FUSE read will overwrite the content
        // Removing fill(0) for performance (1MB+ buffer would be slow to clear)
    }

    /// Get a mutable slice of the buffer
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner[..]
    }

    /// Get an immutable slice of the buffer
    pub fn as_slice(&self) -> &[u8] {
        &self.inner[..]
    }
}

impl std::ops::Deref for AlignedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl std::ops::DerefMut for AlignedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

/// A thread-safe buffer pool for reusing aligned buffers
///
/// This reduces memory allocation overhead for FUSE read/write operations
/// by recycling buffers instead of allocating new ones for each request.
#[cfg(feature = "buffer-pool")]
#[derive(Debug)]
pub struct BufferPool {
    /// Pool of available buffers
    pool: Mutex<Vec<AlignedBuffer>>,
    /// Size of buffers in this pool
    buffer_size: usize,
    /// Maximum number of buffers to keep in pool
    max_capacity: usize,
    /// Statistics: total acquisitions
    acquisitions: AtomicUsize,
    /// Statistics: pool hits (reused buffers)
    hits: AtomicUsize,
}

#[cfg(feature = "buffer-pool")]
impl BufferPool {
    /// Create a new buffer pool with the specified buffer size
    pub fn new(buffer_size: usize) -> Self {
        Self::with_capacity(buffer_size, DEFAULT_POOL_CAPACITY)
    }

    /// Create a new buffer pool with specified buffer size and maximum capacity
    pub fn with_capacity(buffer_size: usize, max_capacity: usize) -> Self {
        Self {
            pool: Mutex::new(Vec::with_capacity(max_capacity)),
            buffer_size,
            max_capacity,
            acquisitions: AtomicUsize::new(0),
            hits: AtomicUsize::new(0),
        }
    }

    /// Acquire a buffer from the pool, or create a new one if pool is empty
    pub async fn acquire(&self) -> IoResult<AlignedBuffer> {
        self.acquisitions.fetch_add(1, Ordering::Relaxed);

        let mut pool = self.pool.lock().await;
        if let Some(mut buf) = pool.pop() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            buf.reset();
            Ok(buf)
        } else {
            drop(pool);
            AlignedBuffer::try_new(self.buffer_size)
                .map_err(|err| IoError::new(ErrorKind::Other, err))
        }
    }

    /// Try to acquire a buffer synchronously (non-blocking)
    /// Returns None if the pool lock is contended
    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    pub fn try_acquire(&self) -> Option<IoResult<AlignedBuffer>> {
        self.acquisitions.fetch_add(1, Ordering::Relaxed);

        if let Ok(mut pool) = self.pool.try_lock() {
            if let Some(mut buf) = pool.pop() {
                self.hits.fetch_add(1, Ordering::Relaxed);
                buf.reset();
                return Some(Ok(buf));
            }
        }
        Some(
            AlignedBuffer::try_new(self.buffer_size)
                .map_err(|err| IoError::new(ErrorKind::Other, err)),
        )
    }

    /// Release a buffer back to the pool for reuse
    pub async fn release(&self, buf: AlignedBuffer) {
        // Only keep buffers of the expected size
        if buf.capacity() != self.buffer_size {
            return;
        }

        let mut pool = self.pool.lock().await;
        if pool.len() < self.max_capacity {
            pool.push(buf);
        }
        // If pool is full, just drop the buffer
    }

    /// Try to release a buffer synchronously (non-blocking)
    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    pub fn try_release(&self, buf: AlignedBuffer) {
        if buf.capacity() != self.buffer_size {
            return;
        }

        if let Ok(mut pool) = self.pool.try_lock() {
            if pool.len() < self.max_capacity {
                pool.push(buf);
            }
        }
        // If lock is contended or pool is full, just drop the buffer
    }

    /// Get the current number of buffers in the pool
    pub async fn available(&self) -> usize {
        self.pool.lock().await.len()
    }

    /// Get pool statistics
    pub fn stats(&self) -> BufferPoolStats {
        let acquisitions = self.acquisitions.load(Ordering::Relaxed);
        let hits = self.hits.load(Ordering::Relaxed);
        BufferPoolStats {
            acquisitions,
            hits,
            hit_rate: if acquisitions > 0 {
                hits as f64 / acquisitions as f64
            } else {
                0.0
            },
        }
    }
}

/// Statistics about buffer pool usage
#[cfg(feature = "buffer-pool")]
#[derive(Debug, Clone, Copy)]
pub struct BufferPoolStats {
    /// Total number of buffer acquisitions
    pub acquisitions: usize,
    /// Number of times a buffer was reused from the pool
    pub hits: usize,
    /// Hit rate (hits / acquisitions)
    pub hit_rate: f64,
}

#[cfg(all(test, feature = "buffer-pool"))]
mod tests {
    use super::*;

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    #[tokio::test]
    async fn test_buffer_pool_basic() {
        let pool = BufferPool::new(4096);

        // Acquire a buffer
        let buf1 = pool.acquire().await.expect("buffer allocation failed");
        assert_eq!(buf1.capacity(), 4096);

        // Release it
        pool.release(buf1).await;

        // Acquire again - should reuse
        let buf2 = pool.acquire().await.expect("buffer allocation failed");
        assert_eq!(buf2.capacity(), 4096);

        let stats = pool.stats();
        assert_eq!(stats.acquisitions, 2);
        assert_eq!(stats.hits, 1);
    }

    #[cfg(all(not(feature = "async-io-runtime"), feature = "tokio-runtime"))]
    #[tokio::test]
    async fn test_buffer_pool_capacity() {
        let pool = BufferPool::with_capacity(1024, 2);

        // Acquire 3 buffers
        let buf1 = pool.acquire().await.expect("buffer allocation failed");
        let buf2 = pool.acquire().await.expect("buffer allocation failed");
        let buf3 = pool.acquire().await.expect("buffer allocation failed");

        // Release all 3
        pool.release(buf1).await;
        pool.release(buf2).await;
        pool.release(buf3).await; // This one should be dropped

        // Pool should only have 2 buffers
        assert_eq!(pool.available().await, 2);
    }
}
