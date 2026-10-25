//! Bidirectional copy between the client and the outbound.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncWrite};

/// Per-direction buffer. 64 KiB is the knee for loopback/LAN throughput on
/// both Linux and Darwin; the Apple network extension uses less to fit its
/// memory ceiling (see `sbr-apple`).
pub const DEFAULT_BUFFER: usize = 64 * 1024;

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
    let r = tokio::io::copy_bidirectional_with_sizes(client, remote, buffer, buffer).await;
    if let Ok((up, down)) = r {
        traffic.up.fetch_add(up, Ordering::Relaxed);
        traffic.down.fetch_add(down, Ordering::Relaxed);
    }
    r
}
