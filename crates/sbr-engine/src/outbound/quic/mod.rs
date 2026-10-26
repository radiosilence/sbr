//! Shared QUIC plumbing for `hysteria2` and `tuic`.
//!
//! Each outbound keeps a small set of QUIC connections ([`Pool`]) and
//! multiplexes every TCP stream and UDP session over them. They are dialed on
//! first use, replaced once all have died, and each is closed by its watcher
//! task once it has carried nothing for `idle_timeout`. While closed it costs nothing:
//! no socket, no keep-alive, no timers. That matters more than the
//! reconnect RTT on a phone.

pub(crate) mod brutal;
mod initial;
pub(crate) mod socket;
mod tls;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use quinn::congestion::ControllerFactory;
use quinn::{
    ClientConfig, Connecting, Endpoint, EndpointConfig, IdleTimeout, MtuDiscoveryConfig, TransportConfig, VarInt,
};
use sbr_config::{QuicOptions, TlsOutbound};
use sbr_core::{Destination, Host};
use tokio::sync::Notify;

use self::socket::{HopDial, HopSocket, PLACEHOLDER_PEER, PacketConnSocket, Salamander, Socket, Witness};
use super::Upstream;

pub(crate) use tls::client_config;

/// sing-box's default for both protocols when `idle_timeout` is unset.
pub(crate) const DEFAULT_IDLE: Duration = Duration::from_secs(30);
/// hysteria's handshake timeout, used for the whole dial + auth.
pub(crate) const DEFAULT_HANDSHAKE: Duration = Duration::from_secs(15);

pub(crate) fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// Protocol defaults, overridden by the user's `QuicOptions`.
pub(crate) struct Tuning {
    pub stream_window: u64,
    pub conn_window: u64,
    pub keep_alive: Option<Duration>,
    pub incoming_uni: u32,
}

/// Ceiling on a QUIC connection's flow-control windows where the process has
/// a hard memory limit. Each window lets the peer park that much unread data
/// in our memory, and the send window holds as much again unacknowledged, so
/// the protocols' defaults (up to 20 MiB) put a speed test over the iOS
/// Network Extension's ~50 MB jetsam limit. 4 MiB still covers 1 Gbit/s at
/// 30 ms.
const MOBILE_WINDOW_CAP: u64 = if cfg!(any(target_os = "ios", target_os = "tvos", target_os = "visionos")) {
    4 << 20
} else {
    u64::MAX
};

pub(crate) fn transport(q: &QuicOptions, d: Tuning, cc: Arc<dyn ControllerFactory + Send + Sync>) -> TransportConfig {
    let mut t = TransportConfig::default();
    #[allow(clippy::unnecessary_min_or_max, reason = "the cap is u64::MAX off iOS and tvOS")]
    let conn = q
        .connection_receive_window
        .unwrap_or(d.conn_window)
        .min(MOBILE_WINDOW_CAP);
    let stream = q.stream_receive_window.unwrap_or(d.stream_window).min(conn);
    let var = |v: u64| VarInt::from_u64(v).unwrap_or(VarInt::MAX);
    t.stream_receive_window(var(stream))
        .receive_window(var(conn))
        .send_window(conn)
        .max_idle_timeout(Some(
            IdleTimeout::try_from(q.idle_timeout.unwrap_or(DEFAULT_IDLE)).unwrap_or(IdleTimeout::from(VarInt::MAX)),
        ))
        .keep_alive_interval(q.keep_alive_period.or(d.keep_alive))
        .max_concurrent_uni_streams(d.incoming_uni.into())
        .congestion_controller_factory(cc);
    if q.max_concurrent_streams > 0 {
        t.max_concurrent_bidi_streams(q.max_concurrent_streams.into());
    }
    if q.initial_packet_size >= 1200 {
        t.initial_mtu(q.initial_packet_size);
    }
    if q.disable_path_mtu_discovery {
        t.mtu_discovery_config(None);
    } else {
        t.mtu_discovery_config(Some(MtuDiscoveryConfig::default()));
    }
    t
}

/// Port hopping parameters.
pub(crate) struct Hop {
    pub ranges: Vec<(u16, u16)>,
    pub interval: (Duration, Duration),
}

/// Opens QUIC connections to one server through the outbound's upstream.
pub(crate) struct Dialer {
    pub upstream: Upstream,
    /// Port is 0 when only hopping ports are configured.
    pub server: Destination,
    pub hop: Option<Hop>,
    pub salamander: Option<String>,
    /// Hide the SNI from Initial-decrypting censors ([`initial`]). Pointless
    /// under Salamander, which already hides the whole packet.
    pub scramble: bool,
    pub tls: Arc<rustls::ClientConfig>,
    pub server_name: String,
    pub handshake_timeout: Duration,
    migrations: AtomicU64,
}

/// How long a migrated connection may go without hearing from the server on
/// its new path before it is given up.
const MIGRATE_TIMEOUT: Duration = Duration::from_secs(4);

impl Dialer {
    pub(crate) fn new(
        upstream: Upstream,
        server: Destination,
        tls: &TlsOutbound,
        alpn: &[&str],
        early: bool,
    ) -> Result<Self, String> {
        let host = match &server.host {
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(d) => d.to_string(),
        };
        let t = client_config(tls, &host, alpn, early)?;
        Ok(Self {
            upstream,
            server,
            hop: None,
            salamander: None,
            scramble: true,
            tls: t.config,
            server_name: t.server_name,
            handshake_timeout: tls.handshake_timeout.unwrap_or(DEFAULT_HANDSHAKE),
            migrations: AtomicU64::new(0),
        })
    }

    /// A fresh endpoint on a fresh socket, and the handshake in progress.
    pub(crate) async fn start(&self, transport: TransportConfig) -> io::Result<(Endpoint, Connecting)> {
        let (socket, peer) = self.socket(None).await?;
        let endpoint =
            Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime))?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(self.tls.clone()).map_err(io_err)?;
        let mut config = ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(transport));
        let connecting = endpoint.connect_with(config, peer, &self.server_name).map_err(io_err)?;
        Ok((endpoint, connecting))
    }

    /// Only a socket sbr owns can be moved; a detour's path is its own.
    pub(crate) fn migratable(&self) -> bool {
        matches!(self.upstream, Upstream::System(..))
    }

    /// Move a live connection to a fresh socket stack (same obfuscation and
    /// hopping) on the current default path, keeping its streams. True once
    /// the server answers on the new socket; otherwise the connection is
    /// closed so the next use redials over the new path. A newer migration
    /// supersedes this one and decides instead.
    pub(crate) async fn migrate(&self, endpoint: &Endpoint, conn: &quinn::Connection) -> bool {
        let generation = self.migrations.fetch_add(1, Ordering::AcqRel) + 1;
        let r = async {
            let (socket, _) = self.socket(Some(conn.remote_address())).await?;
            let witness = Witness::new(socket);
            endpoint.rebind_abstract(witness.clone())?;
            tokio::select! {
                _ = witness.heard() => Ok(()),
                e = conn.closed() => Err(io_err(e)),
                _ = tokio::time::sleep(MIGRATE_TIMEOUT) => Err(io_err("no reply on the new path")),
            }
        }
        .await;
        match r {
            Ok(()) => true,
            Err(_) if self.migrations.load(Ordering::Acquire) != generation => true,
            Err(e) => {
                tracing::warn!(error = %e, "QUIC migration failed, closing the connection");
                conn.close(VarInt::from_u32(0), b"");
                false
            }
        }
    }

    /// The socket stack quinn talks through. `keep`: keep presenting this
    /// server address (a migration) instead of resolving the server again.
    async fn socket(&self, keep: Option<SocketAddr>) -> io::Result<(Socket, SocketAddr)> {
        let (socket, peer): (Socket, SocketAddr) = match &self.hop {
            None => match (keep, &self.upstream) {
                (Some(peer), Upstream::System(opts, _)) => (socket::system(peer, opts)?, peer),
                _ => base_socket(&self.upstream, &self.server, self.server.port).await?,
            },
            Some(hop) => {
                let upstream = self.upstream.clone();
                let server = self.server.clone();
                let dial: HopDial = Arc::new(move |port| {
                    let upstream = upstream.clone();
                    let server = server.clone();
                    Box::pin(async move { base_socket(&upstream, &server, port).await })
                });
                let detour = matches!(self.upstream, Upstream::Detour(_));
                let hop = HopSocket::new(dial, hop.ranges.clone(), hop.interval, detour, keep).await?;
                let peer = hop.peer();
                (hop as Socket, peer)
            }
        };
        let socket: Socket = match &self.salamander {
            Some(pw) => Salamander::new(socket, pw),
            None if self.scramble => initial::Scramble::new(socket),
            None => socket,
        };
        Ok((socket, peer))
    }
}

/// The socket for one server port: a real UDP socket (system) or the
/// detour's packet connection.
async fn base_socket(upstream: &Upstream, server: &Destination, port: u16) -> io::Result<(Socket, SocketAddr)> {
    let dest = Destination::new(server.host.clone(), port);
    match upstream {
        Upstream::System(opts, dns) => {
            let addr = sbr_core::dial::resolve(&dest, opts.domain_strategy, dns.as_ref())
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {dest}")))?;
            Ok((socket::system(addr, opts)?, addr))
        }
        Upstream::Detour(o) => {
            let pc = o.connect_udp(&dest).await?;
            Ok((PacketConnSocket::new(pc, dest) as Socket, PLACEHOLDER_PEER))
        }
    }
}

// ---------------------------------------------------------------------------

/// Count of streams and UDP sessions on a connection. Reaching zero arms the
/// idle close; the watcher swaps in [`CLOSED`] so no new user can sneak in
/// between the check and the close.
#[derive(Default)]
pub(crate) struct Usage {
    users: AtomicUsize,
    notify: Notify,
}

const CLOSED: usize = usize::MAX / 2;

pub(crate) struct UseGuard(Arc<Usage>);

impl Usage {
    pub(crate) fn acquire(self: &Arc<Self>) -> Option<UseGuard> {
        let prev = self.users.fetch_add(1, Ordering::AcqRel);
        if prev >= CLOSED {
            return None;
        }
        if prev == 0 {
            self.notify.notify_one();
        }
        Some(UseGuard(self.clone()))
    }

    pub(crate) fn active(&self) -> bool {
        let n = self.users.load(Ordering::Acquire);
        n > 0 && n < CLOSED
    }
}

impl Drop for UseGuard {
    fn drop(&mut self) {
        if self.0.users.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.notify.notify_one();
        }
    }
}

/// Closes `conn` after `idle` without users and, while it has users, calls
/// `heartbeat` every period. Every wait is a deadline or an event: an idle
/// connection is closed once, an active one wakes only for heartbeats.
pub(crate) async fn watch(
    conn: quinn::Connection,
    usage: Arc<Usage>,
    idle: Duration,
    heartbeat: Option<(Duration, Box<dyn Fn() + Send + Sync>)>,
) {
    loop {
        let notified = usage.notify.notified();
        if !usage.active() {
            tokio::select! {
                _ = conn.closed() => return,
                _ = notified => {}
                _ = tokio::time::sleep(idle) => {
                    if usage.users.compare_exchange(0, CLOSED, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                        conn.close(VarInt::from_u32(0), b"");
                        return;
                    }
                }
            }
        } else if let Some((every, beat)) = &heartbeat {
            tokio::select! {
                _ = conn.closed() => return,
                _ = notified => {}
                _ = tokio::time::sleep(*every) => beat(),
            }
        } else {
            tokio::select! {
                _ = conn.closed() => return,
                _ = notified => {}
            }
        }
    }
}

pub(crate) trait Pooled: Send + Sync {
    fn conn(&self) -> &quinn::Connection;
    fn usage(&self) -> &Arc<Usage>;
}

/// The outbound's live connections, dialed on demand. Concurrent misses
/// share one dial.
///
/// A pool `width` wide dials that many connections at once and hands each
/// new stream to the one carrying fewest. quinn runs a connection's packet
/// protection, ACKs and congestion control on one task, so a single
/// connection is bound to one core; striping lets bulk transfers use more.
pub(crate) struct Pool<S> {
    slots: Mutex<Vec<Arc<S>>>,
    width: usize,
    dialing: tokio::sync::Mutex<()>,
}

impl<S: Pooled> Pool<S> {
    pub(crate) fn new(width: usize) -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
            width: width.max(1),
            dialing: tokio::sync::Mutex::new(()),
        }
    }

    fn try_current(&self) -> Option<(Arc<S>, UseGuard)> {
        let mut slots = self.slots.lock().unwrap();
        slots.retain(|s| s.conn().close_reason().is_none());
        let mut order: Vec<_> = slots.iter().collect();
        order.sort_by_key(|s| s.usage().users.load(Ordering::Acquire));
        order.into_iter().find_map(|s| Some((s.clone(), s.usage().acquire()?)))
    }

    /// The live connections.
    pub(crate) fn live(&self) -> Vec<Arc<S>> {
        let slots = self.slots.lock().unwrap();
        slots
            .iter()
            .filter(|s| s.conn().close_reason().is_none())
            .cloned()
            .collect()
    }

    pub(crate) async fn get<F, Fut>(&self, dial: F) -> io::Result<(Arc<S>, UseGuard)>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = io::Result<Arc<S>>>,
    {
        if let Some(hit) = self.try_current() {
            return Ok(hit);
        }
        let _dialing = self.dialing.lock().await;
        if let Some(hit) = self.try_current() {
            return Ok(hit);
        }
        let mut first_err = None;
        let mut fresh = Vec::with_capacity(self.width);
        for r in futures_util::future::join_all((0..self.width).map(|_| dial())).await {
            match r {
                Ok(s) => fresh.push(s),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if fresh.is_empty() {
            return Err(first_err.unwrap_or_else(|| io_err("QUIC dial failed")));
        }
        let s = fresh[0].clone();
        let g = s
            .usage()
            .acquire()
            .ok_or_else(|| io_err("fresh QUIC connection closed"))?;
        *self.slots.lock().unwrap() = fresh;
        Ok((s, g))
    }
}

// ---------------------------------------------------------------------------

/// QUIC variable-length integer (RFC 9000 §16).
pub(crate) fn put_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=63 => out.push(v as u8),
        64..=16383 => out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
        16384..=1_073_741_823 => out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Returns the value and its encoded length, or `None` if `b` is too short.
pub(crate) fn get_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for x in &b[1..len] {
        v = (v << 8) | u64::from(*x);
    }
    Some((v, len))
}

/// A received UDP payload and its source.
pub(crate) type Packet = (Bytes, Destination);

/// Reassembles fragmented UDP packets of one session. Like sing-quic, a few
/// packets may be in flight at once; the oldest partial packet is dropped.
#[derive(Default)]
pub(crate) struct Defrag {
    partial: Vec<Partial>,
}

struct Partial {
    id: u16,
    parts: Vec<Option<Bytes>>,
    have: usize,
    dest: Option<Destination>,
}

const MAX_PARTIAL: usize = 4;

impl Defrag {
    /// `dest` may be absent on later fragments (TUIC).
    pub(crate) fn feed(
        &mut self,
        id: u16,
        index: u8,
        total: u8,
        dest: Option<Destination>,
        data: Bytes,
    ) -> Option<Packet> {
        if total <= 1 {
            return Some((data, dest?));
        }
        if index >= total {
            return None;
        }
        let pos = match self.partial.iter().position(|p| p.id == id) {
            Some(i) if self.partial[i].parts.len() == usize::from(total) => i,
            found => {
                if let Some(i) = found {
                    self.partial.remove(i);
                }
                if self.partial.len() >= MAX_PARTIAL {
                    self.partial.remove(0);
                }
                self.partial.push(Partial {
                    id,
                    parts: vec![None; usize::from(total)],
                    have: 0,
                    dest: None,
                });
                self.partial.len() - 1
            }
        };
        let p = &mut self.partial[pos];
        if p.parts[usize::from(index)].is_some() {
            return None;
        }
        p.parts[usize::from(index)] = Some(data);
        p.have += 1;
        if p.dest.is_none() {
            p.dest = dest;
        }
        if p.have < p.parts.len() {
            return None;
        }
        let p = self.partial.remove(pos);
        let mut out = BytesMut::with_capacity(p.parts.iter().flatten().map(Bytes::len).sum());
        for part in p.parts.iter().flatten() {
            out.extend_from_slice(part);
        }
        Some((out.freeze(), p.dest?))
    }
}

/// UDP sessions of one connection, by session id.
pub(crate) struct Sessions<K> {
    pub map: Mutex<HashMap<K, SessionEntry>>,
}

pub(crate) struct SessionEntry {
    pub tx: tokio::sync::mpsc::Sender<Packet>,
    pub defrag: Defrag,
}

/// Per-session receive queue depth; excess packets are dropped (UDP).
pub(crate) const UDP_QUEUE: usize = 64;

impl<K: std::hash::Hash + Eq> Sessions<K> {
    pub(crate) fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn deliver(&self, key: &K, id: u16, index: u8, total: u8, dest: Option<Destination>, data: Bytes) {
        let mut map = self.map.lock().unwrap();
        let Some(e) = map.get_mut(key) else { return };
        if let Some(p) = e.defrag.feed(id, index, total, dest, data) {
            let _ = e.tx.try_send(p);
        }
    }
}

/// `host:port` as sent by hysteria2 (IPv6 in brackets).
pub(crate) fn parse_host_port(s: &str) -> Option<Destination> {
    let (h, p) = s.rsplit_once(':')?;
    Some(Destination::from_host_port(h, p.parse().ok()?))
}

/// Await the next packet for a UDP session and copy it into `buf`.
pub(crate) async fn recv_into(
    rx: &Mutex<tokio::sync::mpsc::Receiver<Packet>>,
    buf: &mut [u8],
) -> io::Result<(usize, Destination)> {
    // The std mutex is only held inside a poll, never across an await.
    let (data, from) = std::future::poll_fn(|cx| rx.lock().unwrap().poll_recv(cx))
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "QUIC connection closed"))?;
    let n = data.len().min(buf.len());
    buf[..n].copy_from_slice(&data[..n]);
    Ok((n, from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        for v in [0u64, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824, (1 << 62) - 1] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(get_varint(&b), Some((v, b.len())));
            assert_eq!(get_varint(&b[..b.len() - 1]), None);
        }
        let mut b = Vec::new();
        put_varint(&mut b, 0x401);
        assert_eq!(b, [0x44, 0x01]);
    }

    #[test]
    fn defrag_reorders_and_evicts() {
        let d = || Some(Destination::from_host_port("1.2.3.4", 5));
        let mut f = Defrag::default();
        assert!(f.feed(1, 1, 3, None, Bytes::from_static(b"b")).is_none());
        assert!(f.feed(1, 2, 3, None, Bytes::from_static(b"c")).is_none());
        assert!(f.feed(1, 2, 3, None, Bytes::from_static(b"c")).is_none(), "duplicate");
        let (p, dest) = f.feed(1, 0, 3, d(), Bytes::from_static(b"a")).unwrap();
        assert_eq!(&p[..], b"abc");
        assert_eq!(dest, d().unwrap());
        for id in 10..20 {
            f.feed(id, 0, 2, d(), Bytes::new());
        }
        assert!(f.partial.len() <= MAX_PARTIAL);
        assert_eq!(parse_host_port("[::1]:53").unwrap().to_string(), "[::1]:53");
    }
}
