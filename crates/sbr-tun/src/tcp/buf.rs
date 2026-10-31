//! Elastic byte queues for connection buffers.
//!
//! A connection's send and receive buffers hold chunks only while they hold
//! bytes, so an idle connection costs no buffer memory however large its
//! window is. Chunks come from a pool shared by the whole stack, which
//! keeps a bounded number of spares (keeping busy connections off the
//! allocator) and counts what every buffer holds against an optional
//! limit.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Waker;

/// Allocation unit. Smaller on mobile: a connection holding one byte
/// each way still holds a chunk each way, and the extension may have
/// hundreds of connections.
pub const CHUNK: usize = if super::MOBILE { 4 * 1024 } else { 16 * 1024 };

type Chunk = Box<[u8]>;

pub struct Pool {
    free: Mutex<Vec<Chunk>>,
    keep: usize,
    /// Bytes of chunks held by buffers.
    used: AtomicUsize,
    /// Receive window advertised but not yet filled, across connections:
    /// memory the apps may already be sending into.
    promised: AtomicUsize,
    limit: usize,
    /// Writers waiting for memory under the limit.
    waiters: Mutex<Vec<Waker>>,
    waiting: AtomicBool,
}

impl Pool {
    /// Keeps at most `keep_bytes` of spare chunks; `limit` caps what
    /// buffers hold in total (0: no cap).
    pub fn new(keep_bytes: usize, limit: usize) -> Arc<Self> {
        Arc::new(Self {
            free: Mutex::new(Vec::new()),
            keep: keep_bytes / CHUNK,
            used: AtomicUsize::new(0),
            promised: AtomicUsize::new(0),
            limit,
            waiters: Mutex::new(Vec::new()),
            waiting: AtomicBool::new(false),
        })
    }

    /// Bytes buffers may still take before reaching the limit.
    pub fn headroom(&self) -> usize {
        if self.limit == 0 {
            return usize::MAX;
        }
        self.limit
            .saturating_sub(self.used.load(Ordering::SeqCst))
            .saturating_sub(self.promised.load(Ordering::Relaxed))
    }

    /// A connection's outstanding window went from `old` to `new` bytes.
    pub fn promise(&self, old: usize, new: usize) {
        if new > old {
            self.promised.fetch_add(new - old, Ordering::Relaxed);
        } else {
            self.promised.fetch_sub(old - new, Ordering::Relaxed);
        }
    }

    /// Wake `w` on the next `put`. Callers check `headroom` again after
    /// this: a `put` between their first check and this call sees no waiter.
    /// `waiting` and `used` are sequentially consistent so that either the
    /// `put` sees the waiter or the second check sees the freed chunk.
    pub fn wait(&self, w: &Waker) {
        let mut ws = self.waiters.lock().unwrap();
        if !ws.iter().any(|x| x.will_wake(w)) {
            ws.push(w.clone());
        }
        self.waiting.store(true, Ordering::SeqCst);
    }

    fn get(&self) -> Chunk {
        self.used.fetch_add(CHUNK, Ordering::Relaxed);
        self.free
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| vec![0u8; CHUNK].into_boxed_slice())
    }

    fn put(&self, c: Chunk) {
        self.used.fetch_sub(CHUNK, Ordering::SeqCst);
        {
            let mut f = self.free.lock().unwrap();
            if f.len() < self.keep {
                f.push(c);
            }
        }
        if self.waiting.load(Ordering::SeqCst) {
            let ws = {
                let mut ws = self.waiters.lock().unwrap();
                self.waiting.store(false, Ordering::Release);
                std::mem::take(&mut *ws)
            };
            ws.into_iter().for_each(Waker::wake);
        }
    }

    #[cfg(test)]
    pub fn spare(&self) -> usize {
        self.free.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }
}

/// A FIFO of bytes stored in pooled chunks.
pub struct ChunkBuf {
    pool: Arc<Pool>,
    chunks: VecDeque<Chunk>,
    /// Offset of the first byte within the first chunk.
    head: usize,
    len: usize,
}

impl ChunkBuf {
    pub fn new(pool: Arc<Pool>) -> Self {
        Self {
            pool,
            chunks: VecDeque::new(),
            head: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes that fit in the chunks already held.
    pub fn slack(&self) -> usize {
        self.chunks.len() * CHUNK - self.head - self.len
    }

    pub fn push(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let end = self.head + self.len;
            let mut used = end - self.chunks.len().saturating_sub(1) * CHUNK;
            if self.chunks.is_empty() || used == CHUNK {
                self.chunks.push_back(self.pool.get());
                used = 0;
            }
            let n = (CHUNK - used).min(data.len());
            self.chunks.back_mut().unwrap()[used..used + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
        }
    }

    /// Copy `dst.len()` bytes starting `off` bytes from the front.
    pub fn copy_out(&self, off: usize, dst: &mut [u8]) {
        assert!(off + dst.len() <= self.len, "copy_out past the end");
        let mut pos = self.head + off;
        let mut done = 0;
        while done < dst.len() {
            let (i, at) = (pos / CHUNK, pos % CHUNK);
            let n = (CHUNK - at).min(dst.len() - done);
            dst[done..done + n].copy_from_slice(&self.chunks[i][at..at + n]);
            done += n;
            pos += n;
        }
    }

    /// Drop `n` bytes from the front, returning emptied chunks to the pool.
    pub fn consume(&mut self, n: usize) {
        assert!(n <= self.len, "consume past the end");
        self.head += n;
        self.len -= n;
        while self.head >= CHUNK {
            self.pool.put(self.chunks.pop_front().unwrap());
            self.head -= CHUNK;
        }
        if self.len == 0 {
            self.head = 0;
            if let Some(c) = self.chunks.pop_front() {
                self.pool.put(c);
            }
        }
    }

    /// Move up to `dst.len()` bytes out of the front.
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let n = dst.len().min(self.len);
        self.copy_out(0, &mut dst[..n]);
        self.consume(n);
        n
    }

    pub fn clear(&mut self) {
        self.consume(self.len);
    }

    /// Bytes of chunk memory held.
    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.chunks.len() * CHUNK
    }
}

impl Drop for ChunkBuf {
    fn drop(&mut self) {
        while let Some(c) = self.chunks.pop_front() {
            self.pool.put(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_across_chunks() {
        let pool = Pool::new(4 * CHUNK, 0);
        let mut b = ChunkBuf::new(pool.clone());
        let data: Vec<u8> = (0..3 * CHUNK + 123).map(|i| (i % 251) as u8).collect();
        for piece in data.chunks(1000) {
            b.push(piece);
        }
        assert_eq!(b.len(), data.len());
        assert_eq!(pool.used(), 4 * CHUNK);
        let mut mid = vec![0u8; CHUNK + 7];
        b.copy_out(CHUNK - 3, &mut mid);
        assert_eq!(mid, &data[CHUNK - 3..2 * CHUNK + 4]);
        let mut out = Vec::new();
        let mut tmp = [0u8; 777];
        loop {
            let n = b.read(&mut tmp);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(out, data);
        assert_eq!(b.held(), 0, "an empty buffer holds no chunks");
        assert_eq!(pool.spare(), 4);
        assert_eq!(pool.used(), 0);
    }

    #[test]
    fn pool_keeps_bounded_spares_and_counts_drops() {
        let pool = Pool::new(CHUNK, 3 * CHUNK);
        let mut b = ChunkBuf::new(pool.clone());
        b.push(&vec![1u8; 5 * CHUNK]);
        assert_eq!(pool.headroom(), 0);
        b.clear();
        assert_eq!(pool.spare(), 1);
        b.push(&[1u8; 10]);
        drop(b);
        assert_eq!((pool.used(), pool.headroom()), (0, 3 * CHUNK));
    }
}
