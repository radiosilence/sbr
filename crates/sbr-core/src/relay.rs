//! Bidirectional copy between the client and the outbound.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Per-direction buffer. 64 KiB is the knee for loopback/LAN throughput on
/// both Linux and Darwin; the Apple network extension uses less to fit its
/// memory ceiling (see `sbr-apple`).
pub const DEFAULT_BUFFER: usize = 64 * 1024;

/// Bytes relayed so far, open connections included, so a UI can show a live
/// rate instead of jumps when long connections close.
#[derive(Default, Debug)]
pub struct Traffic {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

impl Traffic {
    pub fn snapshot(&self) -> (u64, u64) {
        (self.up.load(Ordering::Relaxed), self.down.load(Ordering::Relaxed))
    }
}

/// Copy until both directions hit EOF, propagating half-closes. Returns
/// (client→remote, remote→client) byte counts.
pub async fn relay<A, B>(client: &mut A, remote: &mut B, buffer: usize, traffic: &Traffic) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut client = Counted { inner: client, traffic };
    tokio::io::copy_bidirectional_with_sizes(&mut client, remote, buffer, buffer).await
}

/// Counts at the client side: reads are upload, writes are download. One
/// relaxed add per buffer-sized chunk, which is noise next to the copy.
struct Counted<'a, S: ?Sized> {
    inner: &'a mut S,
    traffic: &'a Traffic,
}

impl<S: AsyncRead + Unpin + ?Sized> AsyncRead for Counted<'_, S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut *self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            self.traffic.up.fetch_add(n as u64, Ordering::Relaxed);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin + ?Sized> AsyncWrite for Counted<'_, S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.traffic.down.fetch_add(n as u64, Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_while_open() {
        let (mut c, mut client) = tokio::io::duplex(1024);
        let (mut remote, mut r) = tokio::io::duplex(1024);
        let traffic = Arc::new(Traffic::default());
        let t = traffic.clone();
        let task = tokio::spawn(async move { relay(&mut client, &mut remote, 512, &t).await });
        c.write_all(b"hello").await.unwrap();
        let mut b = [0u8; 5];
        r.read_exact(&mut b).await.unwrap();
        r.write_all(b"abc").await.unwrap();
        c.read_exact(&mut b[..3]).await.unwrap();
        // Visible before either side closes.
        assert_eq!(traffic.snapshot(), (5, 3));
        drop((c, r));
        assert_eq!(task.await.unwrap().unwrap(), (5, 3));
        assert_eq!(traffic.snapshot(), (5, 3));
    }
}
