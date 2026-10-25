//! UDP NAT shared by every packet inbound (TUN, SOCKS5 UDP).
//!
//! One session per (inbound, client source). The session is routed once,
//! on its first packet, like sing-box; after that it is full-cone: the
//! client may talk to any destination through the chosen outbound.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use sbr_core::router::{Action, RouteOptions};
use sbr_core::sniff::{self, Sniffed};
use sbr_core::{Destination, Host, Metadata, Network};
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, warn};

use crate::Engine;

/// sing-box `C.UDPTimeout`.
pub const UDP_TIMEOUT: Duration = Duration::from_secs(300);
/// How long a UDP session whose outbound could not connect keeps answering
/// the client's retries with unreachable, after its last packet.
const FAILED_UDP_HOLD: Duration = Duration::from_secs(10);

/// DNS sessions are short-lived (sing-box `ProtocolTimeouts["dns"]`).
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const QUEUE: usize = 128;
/// Payload bytes queued across all sessions. Queues fill while an outbound
/// handshakes, and 512 sessions of 128 jumbo datagrams would otherwise pin
/// hundreds of megabytes, far past the iOS extension's memory limit.
const MAX_QUEUED_BYTES: usize = 4 << 20;
/// `hijack-dns` exchanges in flight across all sessions. Each one holds a
/// task and upstream state until its timeout, so a flood of distinct names
/// against a stalled upstream must not grow without bound.
const MAX_DNS_INFLIGHT: usize = 128;

/// How a packet inbound delivers datagrams back to its client.
pub trait UdpWriteBack: Send + Sync + 'static {
    /// Send `payload` to client `to`, appearing to come from `from`.
    fn write_back(&self, payload: &[u8], from: &Destination, to: SocketAddr) -> io::Result<()>;

    /// Tell client `to` that its flow to `from` can't be carried. Packet
    /// inbounds that can (TUN, via ICMP) make the client fail fast.
    fn unreachable(&self, _from: &Destination, _to: SocketAddr) {}
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

pub(crate) struct Nat {
    sessions: Mutex<HashMap<Key, Session>>,
    queued: Arc<AtomicUsize>,
    dns_inflight: Arc<Semaphore>,
}

impl Default for Nat {
    fn default() -> Self {
        Self {
            sessions: Mutex::default(),
            queued: Arc::default(),
            dns_inflight: Arc::new(Semaphore::new(MAX_DNS_INFLIGHT)),
        }
    }
}

/// A session's queue. Queued payload bytes count against `Nat::queued` until
/// they are received or the queue is dropped.
struct Rx {
    rx: mpsc::Receiver<(Destination, Bytes)>,
    queued: Arc<AtomicUsize>,
}

impl Rx {
    async fn recv(&mut self) -> Option<(Destination, Bytes)> {
        let p = self.rx.recv().await?;
        self.queued.fetch_sub(p.1.len(), Ordering::Relaxed);
        Some(p)
    }
}

impl Drop for Rx {
    fn drop(&mut self) {
        self.rx.close();
        while let Ok(p) = self.rx.try_recv() {
            self.queued.fetch_sub(p.1.len(), Ordering::Relaxed);
        }
    }
}

/// Monotonic milliseconds since an arbitrary epoch, for cheap idle tracking.
fn now_ms(epoch: Instant) -> u64 {
    epoch.elapsed().as_millis() as u64
}

impl Nat {
    pub(crate) fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Drop every session; their tasks exit when the queue closes.
    pub(crate) fn clear(&self) -> usize {
        let mut s = self.sessions.lock().unwrap();
        let n = s.len();
        s.clear();
        n
    }
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
            let len = pkt.payload.len();
            if self.nat.queued.fetch_add(len, Ordering::Relaxed) + len > MAX_QUEUED_BYTES {
                self.nat.queued.fetch_sub(len, Ordering::Relaxed);
                return;
            }
            match s.tx.try_send((pkt.destination, pkt.payload)) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.nat.queued.fetch_sub(len, Ordering::Relaxed);
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(p)) => {
                    self.nat.queued.fetch_sub(len, Ordering::Relaxed);
                    sessions.remove(&key);
                    return self.spawn_session(&mut sessions, key, inbound_type, p.0, p.1, back);
                }
            }
        }
        if self.max_connections != 0 && sessions.len() >= self.max_connections {
            debug!(source = %pkt.source, limit = self.max_connections, "udp session limit reached");
            return;
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
        let rx = Rx {
            rx,
            queued: self.nat.queued.clone(),
        };
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
        mut rx: Rx,
        back: Arc<dyn UdpWriteBack>,
    ) -> io::Result<()> {
        let source = meta.source;
        // DNS: FakeIP destination → domain before routing; replies must
        // still appear to come from the fake address.
        let fake_origin = Some(meta.destination.clone());
        self.restore_domain(&mut meta)?;
        let fake_origin = fake_origin.filter(|o| *o != meta.destination);
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
                Action::Resolve { server, strategy } => self.resolve(&mut meta, server.as_deref(), *strategy).await,
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
                    let Ok(permit) = self.nat.dns_inflight.clone().try_acquire_owned() else {
                        debug!(source = %source, "dns exchange limit reached; query dropped");
                        continue;
                    };
                    let (engine, back, meta) = (engine.clone(), back.clone(), meta.clone());
                    tokio::spawn(async move {
                        let _permit = permit;
                        match engine.dns.exchange(&payload, &meta).await {
                            Ok(resp) => {
                                let _ = back.write_back(&resp, &dest, source);
                            }
                            Err(e) => tracing::warn!(error = %e, "dns exchange failed"),
                        }
                    });
                }
            }
            Action::Reject { .. } => {
                debug!(source = %source, dest = %meta.destination, "udp rejected");
                back.unreachable(&meta.destination, source);
                while let Ok(Some(p)) = tokio::time::timeout(UDP_TIMEOUT, rx.recv()).await {
                    back.unreachable(&p.0, source);
                }
                Ok(())
            }
            Action::Route { outbound, options } => {
                let out = self.outbounds[outbound].clone();
                let first_dest = options.apply(&meta.destination);
                let first_dest_c = first_dest.clone();
                debug!(source = %source, dest = %meta.destination, outbound = out.tag(), "udp route");
                let conn: Arc<dyn sbr_core::PacketConn> = match out.connect_udp(&first_dest).await {
                    Ok(c) => Arc::from(c),
                    Err(e) => {
                        // Keep the session as a dead end for a while: each
                        // retry is answered at once instead of being routed,
                        // dialled and logged again. QUIC clients retry many
                        // times a second.
                        warn!(dest = %first_dest, outbound = out.tag(), error = %e, "udp connect failed");
                        back.unreachable(&meta.destination, source);
                        while let Ok(Some(p)) = tokio::time::timeout(FAILED_UDP_HOLD, rx.recv()).await {
                            back.unreachable(&p.0, source);
                        }
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

                // Remote → client. Replies are reported from the address the
                // client sent to: the FakeIP it used, the address before
                // `override_address`/`override_port`, or the domain it named
                // (SOCKS5 clients sending to a name).
                let original = fake_origin.clone().unwrap_or_else(|| meta.destination.clone());
                let unmap_domain = fake_origin.is_some()
                    || (matches!(meta.destination.host, Host::Domain(_)) && !options.udp_disable_domain_unmapping);
                let unmap = move |from: Destination| -> Destination {
                    if from == first_dest_c || (unmap_domain && from.port == original.port) {
                        original.clone()
                    } else {
                        from
                    }
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
                            let from = unmap(from);
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
                        let dest = self.unfake(dest); // FakeIP
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
