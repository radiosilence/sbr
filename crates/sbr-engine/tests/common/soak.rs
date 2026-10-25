//! Bulk soak through an echo path: random write sizes, random reader
//! stalls, every byte checked by position. The `soak_*` tests that use it
//! are `#[ignore]`d because they move 128 MiB each; run them with
//!
//! ```text
//! cargo test -p sbr-engine --release --test e2e --test upstream_servers --test tun soak -- --ignored --nocapture
//! ```
//!
//! They cover the paths the user's phone depends on: VLESS + REALITY +
//! Vision against Xray, hysteria2 against apernet's server (both need their
//! binaries, see `upstream_servers.rs`), shadowsocks-2022, and the TUN
//! (root and `/dev/net/tun` only). `SBR_SOAK_MB` changes the volume. A
//! stall reports how far each side got.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Prime, so the pattern never lines up with buffer or record sizes.
const PERIOD: usize = 1_048_573;
const MAX_WRITE: usize = 256 * 1024;
const MAX_READ: usize = 64 * 1024;
/// No progress for this long is a hang.
const STALL: Duration = Duration::from_secs(30);

pub fn soak_bytes() -> u64 {
    std::env::var("SBR_SOAK_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(128)
        << 20
}

/// xorshift64*.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) % n as u64) as usize
    }

    /// Mostly bulk, with runs of tiny and MTU-sized pieces.
    fn write_size(&mut self) -> usize {
        match self.below(4) {
            0 => 1 + self.below(16),
            1 => 1 + self.below(1500),
            2 => 1 + self.below(16 * 1024),
            _ => 1 + self.below(MAX_WRITE),
        }
    }
}

fn pattern() -> Arc<Vec<u8>> {
    let mut x = 0x243f_6a88_85a3_08d3u64;
    let mut p: Vec<u8> = (0..PERIOD)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    // Periodic past the end, so any window starting below PERIOD is valid.
    p.extend_from_within(..MAX_WRITE);
    Arc::new(p)
}

/// Write `total` bytes into `s` and read them back from the far end's echo.
/// The writer flushes after every write, as any client of a buffered stream
/// must; the reader stalls at random so every buffer on the path fills.
pub async fn soak_echo<S>(label: &str, s: S, total: u64, seed: u64)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let pat = pattern();
    let written = Arc::new(AtomicU64::new(0));
    let (mut r, mut w) = tokio::io::split(s);
    let start = Instant::now();
    let writer = {
        let (pat, written) = (pat.clone(), written.clone());
        tokio::spawn(async move {
            let mut rng = Rng(seed | 1);
            let mut pos = 0u64;
            // Alternate bulk and trickle phases of 1 MiB. A trickle against a
            // full path makes the relay's writes go pending with a short
            // buffer and then retry with a longer one, which is where
            // miscounting writers lose bytes.
            let mut trickle = false;
            let mut phase_end = 0u64;
            while pos < total {
                if pos >= phase_end {
                    trickle = rng.below(4) == 0;
                    phase_end = pos + (1 << 20);
                }
                let n = if trickle { 1 + rng.below(2000) } else { rng.write_size() };
                let n = n.min((total - pos) as usize);
                let off = (pos % PERIOD as u64) as usize;
                w.write_all(&pat[off..off + n]).await.unwrap();
                w.flush().await.unwrap();
                pos += n as u64;
                written.store(pos, Ordering::Relaxed);
                if trickle && rng.below(16) == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                } else if rng.below(128) == 0 {
                    tokio::time::sleep(Duration::from_millis(1 + rng.below(10) as u64)).await;
                }
            }
            w
        })
    };
    let mut rng = Rng(seed.rotate_left(17) | 1);
    let mut buf = vec![0u8; MAX_READ];
    let mut pos = 0u64;
    while pos < total {
        let want = (1 + rng.below(MAX_READ)).min((total - pos) as usize);
        let n = match tokio::time::timeout(STALL, r.read(&mut buf[..want])).await {
            Ok(r) => r.unwrap_or_else(|e| panic!("{label}: read error at {pos}/{total}: {e}")),
            Err(_) => panic!(
                "{label}: stalled: read {pos}, written {} of {total}",
                written.load(Ordering::Relaxed)
            ),
        };
        assert!(n > 0, "{label}: early EOF at {pos}/{total}");
        let off = (pos % PERIOD as u64) as usize;
        if buf[..n] != pat[off..off + n] {
            let i = buf[..n].iter().zip(&pat[off..]).position(|(a, b)| a != b).unwrap();
            panic!(
                "{label}: wrong byte at offset {} (lost, duplicated or corrupted data)",
                pos + i as u64
            );
        }
        pos += n as u64;
        match rng.below(64) {
            0 => tokio::time::sleep(Duration::from_millis(1 + rng.below(50) as u64)).await,
            1 if rng.below(16) == 0 => tokio::time::sleep(Duration::from_millis(500)).await,
            _ => {}
        }
    }
    let _w = writer.await.unwrap();
    let secs = start.elapsed().as_secs_f64();
    eprintln!(
        "{label}: {} MiB echoed in {secs:.1}s ({:.0} Mbit/s each way)",
        total >> 20,
        total as f64 * 8.0 / secs / 1e6
    );
}

/// SOCKS5 CONNECT through a no-auth proxy on localhost.
pub async fn socks5(proxy: u16, target: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.set_nodelay(true).unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("IPv4 targets only")
    };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0, "socks reply");
    s
}
