//! UDP NAT shared by every packet inbound (TUN, SOCKS5 UDP).
//!
//! One session per (inbound, client source). The session is routed once,
//! on its first packet, like sing-box; after that it is full-cone: the
//! client may talk to any destination through the chosen outbound.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use sbr_core::router::{Action, RouteOptions};
use sbr_core::sniff::{self, Sniffed};
use sbr_core::{Destination, Host, Metadata, Network};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::Engine;

/// sing-box `C.UDPTimeout`.
pub const UDP_TIMEOUT: Duration = Duration::from_secs(300);
/// DNS sessions are short-lived (sing-box `ProtocolTimeouts["dns"]`).
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const QUEUE: usize = 128;

/// How a packet inbound delivers datagrams back to its client.
pub trait UdpWriteBack: Send + Sync + 'static {
    /// Send `payload` to client `to`, appearing to come from `from`.
    fn write_back(&self, payload: &[u8], from: &Destination, to: SocketAddr) -> io::Result<()>;
}

pub struct UdpPacket {
    pub source: SocketAddr,
    pub destination: Destination,
    pub payload: Bytes,
}

type Key = (Arc<str>, SocketAddr);

struct Session {
    tx: mpsc::Sender<(Destination, Bytes)>,
}

#[derive(Default)]
pub(crate) struct Nat {
    sessions: Mutex<HashMap<Key, Session>>,
}

/// Monotonic milliseconds since an arbitrary epoch, for cheap idle tracking.
fn now_ms(epoch: Instant) -> u64 {
    epoch.elapsed().as_millis() as u64
}

impl Engine {
    /// Feed one client datagram. Never blocks: a full session queue drops
    /// the packet, which is what UDP promised anyway.
    pub fn handle_udp(
        self: &Arc<Self>,
        inbound: &Arc<str>,
        inbound_type: &'static str,
        pkt: UdpPacket,
        back: Arc<dyn UdpWriteBack>,
    ) {
        let key = (inbound.clone(), pkt.source);
        let mut sessions = self.nat.sessions.lock().unwrap();
        if let Some(s) = sessions.get(&key) {
            match s.tx.try_send((pkt.destination, pkt.payload)) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => return,
                Err(mpsc::error::TrySendError::Closed(p)) => {
                    sessions.remove(&key);
                    return self.spawn_session(&mut sessions, key, inbound_type, p.0, p.1, back);
                }
            }
        }
        self.spawn_session(&mut sessions, key, inbound_type, pkt.destination, pkt.payload, back);
    }

    fn spawn_session(
        self: &Arc<Self>,
        sessions: &mut HashMap<Key, Session>,
        key: Key,
        inbound_type: &'static str,
        dest: Destination,
        first: Bytes,
        back: Arc<dyn UdpWriteBack>,
    ) {
        let (tx, rx) = mpsc::channel(QUEUE);
        sessions.insert(key.clone(), Session { tx });
        let engine = self.clone();
        tokio::spawn(async move {
            let meta = Metadata::new(key.0.clone(), inbound_type, Network::Udp, key.1, dest);
            if let Err(e) = engine.run_session(meta, first, rx, back).await {
                debug!(source = %key.1, error = %e, "udp session ended");
            }
            let mut s = engine.nat.sessions.lock().unwrap();
            if s.get(&key).is_some_and(|s| s.tx.is_closed()) {
                s.remove(&key);
            }
        });
    }

    async fn run_session(
        self: &Arc<Self>,
        mut meta: Metadata,
        first: Bytes,
        mut rx: mpsc::Receiver<(Destination, Bytes)>,
        back: Arc<dyn UdpWriteBack>,
    ) -> io::Result<()> {
        let source = meta.source;
        let mut opts = RouteOptions::default();
        let mut i = 0;
        let mut matched = None;
        let action = loop {
            let Some((idx, action)) = self.router.next(&meta, i) else {
                break Action::Route {
                    outbound: self.router.final_outbound(),
                    options: opts,
                };
            };
            i = idx + 1;
            match action {
                Action::Sniff { sniffers, .. } => {
                    if meta.protocol.is_none()
                        && let Sniffed::Found { protocol, domain } = sniff::packet(&first, sniffers)
                    {
                        meta.protocol = Some(protocol);
                        meta.sniffed_domain = domain.map(Into::into);
                    }
                }
                Action::RouteOptions(o) => opts.merge(o),
                Action::Resolve { strategy, .. } => self.resolve(&mut meta, *strategy).await,
                Action::Route { outbound, options } => {
                    opts.merge(options);
                    matched = Some(idx);
                    break Action::Route {
                        outbound: *outbound,
                        options: opts,
                    };
                }
                a => {
                    matched = Some(idx);
                    break a.clone();
                }
            }
        };

        match action {
            Action::HijackDns => {
                let engine = self.clone();
                let mut next = Some((meta.destination.clone(), first));
                loop {
                    let (dest, payload) = match next.take() {
                        Some(p) => p,
                        None => match tokio::time::timeout(DNS_TIMEOUT, rx.recv()).await {
                            Ok(Some(p)) => p,
                            _ => return Ok(()),
                        },
                    };
                    // Answer concurrently: one slow upstream mustn't stall the rest.
                    let (engine, back, meta) = (engine.clone(), back.clone(), meta.clone());
                    tokio::spawn(async move {
                        match engine.dns.exchange(&payload, &meta).await {
                            Ok(resp) => {
                                let _ = back.write_back(&resp, &dest, source);
                            }
                            Err(e) => debug!(error = %e, "dns exchange failed"),
                        }
                    });
                }
            }
            Action::Reject { .. } => {
                debug!(source = %source, dest = %meta.destination, "udp rejected");
                while tokio::time::timeout(UDP_TIMEOUT, rx.recv())
                    .await
                    .is_ok_and(|p| p.is_some())
                {}
                Ok(())
            }
            Action::Route { outbound, options } => {
                let out = self.outbounds[outbound].clone();
                let first_dest = options.apply(&meta.destination);
                debug!(source = %source, dest = %meta.destination, outbound = out.tag(), "udp route");
                let conn: Arc<dyn sbr_core::PacketConn> = match out.connect_udp(&first_dest).await {
                    Ok(c) => Arc::from(c),
                    Err(e) => {
                        warn!(dest = %first_dest, outbound = out.tag(), error = %e, "udp connect failed");
                        return Err(e);
                    }
                };
                let timeout = options.udp_timeout.unwrap_or_else(|| {
                    if meta.protocol == Some(sbr_core::Protocol::Dns) {
                        DNS_TIMEOUT
                    } else {
                        UDP_TIMEOUT
                    }
                });
                let epoch = Instant::now();
                let last = Arc::new(AtomicU64::new(0));
                let (reg, cancelled) = self.tracker.register(meta.clone(), self.chain(outbound), matched);

                // Remote → client.
                let unmap = match (&meta.destination.host, options.udp_disable_domain_unmapping) {
                    (Host::Domain(_), false) => Some(meta.destination.clone()),
                    _ => None,
                };
                let reader = {
                    let (conn, back, last) = (conn.clone(), back.clone(), last.clone());
                    let tracked = reg.conn.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        loop {
                            let (n, from) = match conn.recv_from(&mut buf).await {
                                Ok(r) => r,
                                Err(_) => return,
                            };
                            last.store(now_ms(epoch), Ordering::Relaxed);
                            tracked.add_down(n);
                            // Report replies from the address the client asked for, so
                            // SOCKS5 clients that sent to a domain recognise them.
                            let from = match &unmap {
                                Some(d) if d.port == from.port => d.clone(),
                                _ => from,
                            };
                            if back.write_back(&buf[..n], &from, source).is_err() {
                                return;
                            }
                        }
                    })
                };

                // Client → remote.
                let mut pending = Some((meta.destination.clone(), first));
                let forward = async {
                    loop {
                        let (dest, payload) = match pending.take() {
                            Some(p) => p,
                            None => {
                                let idle_for =
                                    Duration::from_millis(now_ms(epoch).saturating_sub(last.load(Ordering::Relaxed)));
                                let Some(remaining) = timeout.checked_sub(idle_for) else {
                                    break Ok(());
                                };
                                match tokio::time::timeout(remaining, rx.recv()).await {
                                    Ok(Some(p)) => p,
                                    Ok(None) => break Ok(()),
                                    Err(_) => continue, // re-check: the reader may have kept it alive
                                }
                            }
                        };
                        last.store(now_ms(epoch), Ordering::Relaxed);
                        let target = if options.udp_connect {
                            first_dest.clone()
                        } else {
                            options.apply(&dest)
                        };
                        reg.conn.add_up(payload.len());
                        if let Err(e) = conn.send_to(&payload, &target).await {
                            debug!(dest = %target, error = %e, "udp send failed");
                        }
                    }
                };
                let result = tokio::select! {
                    biased;
                    r = forward => r,
                    _ = cancelled.wait() => Ok(()),
                };
                reader.abort();
                result
            }
            _ => unreachable!("non-final action"),
        }
    }
}
