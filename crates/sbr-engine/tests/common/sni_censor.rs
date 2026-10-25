//! A model of TCP SNI filtering as the GFW does it (GFW Report on the
//! Henan firewall, IEEE S&P 2025; Niere et al., "Circumventing the GFW with
//! TLS Record Fragmentation", 2023): the censor looks at the first segment
//! of a connection, finds the server name in the ClientHello, and answers a
//! blocked name with a reset. It never reassembles TCP segments. Whether it
//! reassembles TLS records found within that one segment is the knob.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Records {
    /// Only the first TLS record is inspected.
    First,
    /// Every record in the first segment, bodies joined.
    Joined,
}

pub struct SniCensor {
    pub port: u16,
    /// Connections reset for revealing the name.
    pub resets: Arc<AtomicUsize>,
    /// Connections let through.
    pub passed: Arc<AtomicUsize>,
}

impl SniCensor {
    pub fn resets(&self) -> usize {
        self.resets.load(Ordering::SeqCst)
    }
    pub fn passed(&self) -> usize {
        self.passed.load(Ordering::SeqCst)
    }
}

/// Relays to `upstream`, resetting connections whose first segment reveals `name`.
pub async fn start(upstream: SocketAddr, name: &'static str, records: Records) -> SniCensor {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let resets = Arc::new(AtomicUsize::new(0));
    let passed = Arc::new(AtomicUsize::new(0));
    let (r, p) = (resets.clone(), passed.clone());
    tokio::spawn(async move {
        loop {
            let (mut c, _) = l.accept().await.unwrap();
            let (r, p) = (r.clone(), p.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let Ok(n) = c.read(&mut buf).await else { return };
                if n == 0 {
                    return;
                }
                if reveals(&buf[..n], name.as_bytes(), records) {
                    r.fetch_add(1, Ordering::SeqCst);
                    #[allow(deprecated)] // Linger 0 is the point: drop sends RST.
                    let _ = c.set_linger(Some(Duration::ZERO));
                    return;
                }
                p.fetch_add(1, Ordering::SeqCst);
                let Ok(mut s) = TcpStream::connect(upstream).await else {
                    return;
                };
                if s.write_all(&buf[..n]).await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
            });
        }
    });
    SniCensor { port, resets, passed }
}

fn reveals(seg: &[u8], name: &[u8], records: Records) -> bool {
    let mut body = Vec::new();
    let mut d = seg;
    while d.len() >= 5 && d[0] == 22 {
        let len = u16::from_be_bytes([d[3], d[4]]) as usize;
        let end = (5 + len).min(d.len());
        body.extend_from_slice(&d[5..end]);
        d = &d[end..];
        if records == Records::First {
            break;
        }
    }
    body.windows(name.len()).any(|w| w == name)
}
