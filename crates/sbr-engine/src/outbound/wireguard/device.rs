//! The WireGuard device task: UDP I/O, Noise (boringtun), and driving the
//! smoltcp stack.
//!
//! One task per endpoint. Each wakeup it drains every datagram the socket
//! has queued, decrypts them into the stack, runs one `Interface::poll`, then
//! encrypts and sends everything the stack emitted. Socket I/O goes through
//! `quinn-udp`: on Linux that is `recvmmsg` + GRO in and GSO out (WireGuard
//! data packets of a flow are all the same size, so a burst leaves in one
//! syscall); elsewhere it degrades to one datagram per call.
//!
//! Power: the task only wakes for packets, a kick from a socket handle, a
//! smoltcp deadline (retransmit, delayed ACK), or WireGuard timers. Timers
//! tick once a second while traffic flowed in the last 30 s, at the
//! persistent-keepalive interval when one is configured, and never otherwise.

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use sbr_core::{Destination, PacketConn};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use super::stack::{Shared, TX_BATCH};

/// Datagrams handled per wakeup before the stack gets polled.
const RX_BATCH: usize = 256;
const ACTIVE_WINDOW: Duration = Duration::from_secs(30);
const TICK: Duration = Duration::from_secs(1);
/// Sessions older than this are not used to send after an idle period:
/// the peer drops data under keys past REJECT_AFTER_TIME (180 s).
const STALE_SESSION: Duration = Duration::from_secs(170);
/// Largest WireGuard datagram we handle (inner MTU is at most 65535).
const MAX_DATAGRAM: usize = 65535 + 64;
/// GSO/GRO super-datagrams stay below 64 KiB.
const GSO_MAX_BYTES: usize = 65000;

pub struct PeerSetup {
    pub tunn: Tunn,
    pub public: [u8; 32],
    pub allowed: Vec<IpNet>,
    pub reserved: [u8; 3],
    /// Where to send; learned from the peer when `None` (socket transport).
    pub endpoint: Option<SocketAddr>,
    pub keepalive: u16,
}

/// The endpoint's own UDP socket.
pub struct UdpIo {
    sock: UdpSocket,
    state: UdpSocketState,
    /// Dual-stack IPv6 socket: IPv4 peers are addressed as mapped addresses.
    v6: bool,
}

impl UdpIo {
    pub fn new(sock: UdpSocket, v6: bool) -> io::Result<Self> {
        let state = UdpSocketState::new((&sock).into())?;
        Ok(Self { sock, state, v6 })
    }

    fn try_recv(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> io::Result<usize> {
        self.sock
            .try_io(Interest::READABLE, || self.state.recv((&self.sock).into(), bufs, meta))
    }

    async fn send(&self, to: SocketAddr, contents: &[u8], segment: Option<usize>) -> io::Result<()> {
        let destination = match (self.v6, to.ip()) {
            (true, IpAddr::V4(v4)) => SocketAddr::new(v4.to_ipv6_mapped().into(), to.port()),
            _ => to,
        };
        let t = Transmit {
            destination,
            ecn: None,
            contents,
            segment_size: segment,
            src_ip: None,
        };
        loop {
            match self
                .sock
                .try_io(Interest::WRITABLE, || self.state.try_send((&self.sock).into(), &t))
            {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.sock.writable().await?,
                Err(e) => return Err(e),
            }
        }
    }
}

pub enum Transport {
    Socket(UdpIo),
    /// Through a detour outbound: one association per peer.
    Detour {
        conns: Vec<(Arc<dyn PacketConn>, Destination)>,
        rx: mpsc::Receiver<(usize, Vec<u8>)>,
        /// Received while waiting for readiness.
        pending: Option<(usize, Vec<u8>)>,
    },
}

impl Transport {
    /// Wait until a datagram may be available.
    async fn ready(&mut self) -> io::Result<()> {
        match self {
            Transport::Socket(s) => s.sock.readable().await,
            Transport::Detour { rx, pending, .. } => {
                if pending.is_none() {
                    *pending = Some(rx.recv().await.ok_or(io::ErrorKind::BrokenPipe)?);
                }
                Ok(())
            }
        }
    }
}

pub struct Device {
    pub shared: Arc<Shared>,
    pub peers: Vec<PeerSetup>,
    pub transport: Transport,
    pub private: StaticSecret,
    pub public: PublicKey,
}

/// Outgoing datagrams to one destination, coalesced for GSO.
struct Batch {
    buf: Vec<u8>,
    dest: Option<SocketAddr>,
    seg: usize,
    count: usize,
    max_segments: usize,
}

struct Io {
    shared: Arc<Shared>,
    /// Output buffer for handshakes and the detour path.
    scratch: Vec<u8>,
    /// Reusable packet buffers.
    pool: Vec<Vec<u8>>,
    batch: Batch,
}

impl Device {
    pub async fn run(self) {
        let Device {
            shared,
            mut peers,
            mut transport,
            private,
            public,
        } = self;
        let (rx_slots, rx_size, max_segments) = match &transport {
            Transport::Socket(u) => (
                quinn_udp::BATCH_SIZE,
                if u.state.gro_segments() > 1 {
                    64 * 1024
                } else {
                    MAX_DATAGRAM
                },
                u.state.max_gso_segments().max(1),
            ),
            Transport::Detour { .. } => (1, MAX_DATAGRAM, 1),
        };
        let mut rx_bufs: Vec<Vec<u8>> = (0..rx_slots).map(|_| vec![0u8; rx_size]).collect();
        let mut io = Io {
            shared: shared.clone(),
            scratch: vec![0u8; MAX_DATAGRAM],
            pool: Vec::new(),
            batch: Batch {
                buf: Vec::with_capacity(64 * 1024 + 2048),
                dest: None,
                seg: 0,
                count: 0,
                max_segments,
            },
        };
        let keepalive = peers.iter().map(|p| p.keepalive).filter(|k| *k > 0).min();
        let mut rx_batch: Vec<Vec<u8>> = Vec::with_capacity(RX_BATCH);
        let mut tx_out: Vec<Vec<u8>> = Vec::with_capacity(TX_BATCH);
        let mut last_traffic = Instant::now() - ACTIVE_WINDOW;
        let mut last_tick = Instant::now();

        loop {
            // 1. Ingress: everything queued on the socket, without blocking.
            let received = io
                .drain(
                    &mut transport,
                    &mut peers,
                    &private,
                    &public,
                    &mut rx_bufs,
                    &mut rx_batch,
                )
                .await;

            // 2. One stack poll.
            let delay;
            {
                let mut st = shared.stack.lock().unwrap();
                let st = &mut *st;
                st.dev.rx.extend(rx_batch.drain(..));
                io.pool.append(&mut st.dev.rx_free);
                st.iface.poll(shared.now(), &mut st.dev, &mut st.sockets);
                std::mem::swap(&mut tx_out, &mut st.dev.tx);
                // Hand back buffers sent last round for smoltcp to reuse.
                if st.dev.tx_free.len() < TX_BATCH {
                    let take = io.pool.len().min(TX_BATCH - st.dev.tx_free.len());
                    let at = io.pool.len() - take;
                    st.dev.tx_free.extend(io.pool.drain(at..));
                }
                if st.has_closing() {
                    st.reap();
                }
                delay = st.iface.poll_delay(shared.now(), &st.sockets);
            }

            // 3. Egress.
            let sent = tx_out.len();
            if sent > 0 || received > 0 {
                let now = Instant::now();
                if now.duration_since(last_traffic) >= ACTIVE_WINDOW {
                    // Waking from idle: refresh timers, retire stale sessions.
                    for p in peers.iter_mut() {
                        if p.tunn.time_since_last_handshake().is_some_and(|t| t >= STALE_SESSION) {
                            p.tunn.set_static_private(private.clone(), public, None);
                        }
                    }
                    io.tick(&mut transport, &mut peers).await;
                    last_tick = now;
                }
                last_traffic = now;
            }
            for pkt in tx_out.drain(..) {
                io.send_ip(&mut transport, &mut peers, &pkt).await;
                io.pool.push(pkt);
            }
            io.flush(&transport).await;

            // An RTT probe asked for a fresh handshake.
            if shared.want_handshake.swap(false, Ordering::Relaxed) {
                io.initiate(&transport, &mut peers).await;
            }

            // 4. WireGuard timers.
            let active = last_traffic.elapsed() < ACTIVE_WINDOW;
            let tick_every = if active {
                Some(TICK)
            } else {
                keepalive.map(|k| Duration::from_secs(k as u64))
            };
            if let Some(every) = tick_every
                && last_tick.elapsed() >= every
            {
                io.tick(&mut transport, &mut peers).await;
                last_tick = Instant::now();
            }

            // More queued than one batch: go again before sleeping.
            if received >= RX_BATCH || sent >= TX_BATCH {
                tokio::task::yield_now().await;
                continue;
            }

            // 5. Sleep until something happens.
            let mut deadline: Option<Duration> = delay.map(|d| Duration::from_micros(d.total_micros()));
            if let Some(every) = tick_every {
                let until_tick = every.saturating_sub(last_tick.elapsed());
                deadline = Some(deadline.map_or(until_tick, |d| d.min(until_tick)));
            }
            let sleep = async {
                match deadline {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                biased;
                _ = shared.kick.notified() => {}
                r = transport.ready() => if r.is_err() { return },
                _ = sleep => {}
            }
        }
    }
}

fn route(peers: &[PeerSetup], dst: IpAddr) -> Option<usize> {
    let mut best: Option<(usize, u8)> = None;
    for (i, p) in peers.iter().enumerate() {
        for net in &p.allowed {
            if net.contains(&dst) && best.is_none_or(|(_, len)| net.prefix_len() > len) {
                best = Some((i, net.prefix_len()));
            }
        }
    }
    best.map(|(i, _)| i)
}

fn set_reserved(peer: &PeerSetup, data: &mut [u8]) {
    if data.len() >= 4 && peer.reserved != [0; 3] {
        data[1..4].copy_from_slice(&peer.reserved);
    }
}

/// Send one datagram right away (handshakes, keepalives, the detour path).
async fn send_wire(transport: &Transport, peer: &PeerSetup, idx: usize, data: &mut [u8]) {
    set_reserved(peer, data);
    let r = match transport {
        Transport::Socket(u) => match peer.endpoint {
            Some(to) => u.send(to, data, None).await,
            None => {
                trace!("wireguard: peer endpoint unknown yet, dropping");
                Ok(())
            }
        },
        Transport::Detour { conns, .. } => {
            let (conn, dest) = &conns[idx];
            conn.send_to(data, dest).await
        }
    };
    if let Err(e) = r {
        debug!(error = %e, "wireguard: send failed");
    }
}

impl Io {
    /// Receive and decrypt every datagram available right now (up to a
    /// batch). Returns how many datagrams were handled.
    #[allow(clippy::too_many_arguments)]
    async fn drain(
        &mut self,
        transport: &mut Transport,
        peers: &mut [PeerSetup],
        private: &StaticSecret,
        public: &PublicKey,
        rx_bufs: &mut [Vec<u8>],
        rx_batch: &mut Vec<Vec<u8>>,
    ) -> usize {
        let mut handled = 0;
        let mut metas = [RecvMeta::default(); quinn_udp::BATCH_SIZE];
        while handled < RX_BATCH {
            match transport {
                Transport::Socket(u) => {
                    let n = {
                        let slots = rx_bufs.len().min(quinn_udp::BATCH_SIZE);
                        let mut iovs: Vec<IoSliceMut<'_>> = rx_bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
                        match u.try_recv(&mut iovs, &mut metas[..slots]) {
                            Ok(n) => n,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                // ICMP errors surface here on some platforms; try again later.
                                trace!(error = %e, "wireguard: recv error");
                                break;
                            }
                        }
                    };
                    for (buf, meta) in rx_bufs.iter_mut().zip(&metas[..n]) {
                        let from = SocketAddr::new(meta.addr.ip().to_canonical(), meta.addr.port());
                        let stride = meta.stride.max(1);
                        for dgram in buf[..meta.len].chunks_mut(stride) {
                            handled += 1;
                            self.handle_datagram(transport, peers, private, public, dgram, Some(from), None, rx_batch)
                                .await;
                        }
                    }
                }
                Transport::Detour { rx, pending, .. } => {
                    let Ok((idx, mut data)) = pending.take().ok_or(()).or_else(|_| rx.try_recv()) else {
                        break;
                    };
                    handled += 1;
                    self.handle_datagram(transport, peers, private, public, &mut data, None, Some(idx), rx_batch)
                        .await;
                }
            }
        }
        handled
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_datagram(
        &mut self,
        transport: &Transport,
        peers: &mut [PeerSetup],
        private: &StaticSecret,
        public: &PublicKey,
        data: &mut [u8],
        from: Option<SocketAddr>,
        hint: Option<usize>,
        rx_batch: &mut Vec<Vec<u8>>,
    ) {
        if data.len() >= 4 {
            // Reserved bytes (WARP) are ignored on receive, like sing-box.
            data[1..4].fill(0);
        }
        let mut handshake_response = false;
        let idx = match Tunn::parse_incoming_packet(data) {
            Ok(Packet::HandshakeInit(p)) => hint
                .or_else(|| {
                    peers
                        .iter()
                        .position(|peer| peer.endpoint.is_some() && peer.endpoint == from)
                })
                .or_else(|| {
                    let half = parse_handshake_anon(private, public, &p).ok()?;
                    peers.iter().position(|peer| peer.public == half.peer_static_public)
                }),
            Ok(Packet::HandshakeResponse(p)) => {
                handshake_response = true;
                Some((p.receiver_idx >> 8) as usize)
            }
            Ok(Packet::PacketCookieReply(p)) => Some((p.receiver_idx >> 8) as usize),
            Ok(Packet::PacketData(p)) => Some((p.receiver_idx >> 8) as usize),
            Err(_) => None,
        };
        let Some(idx) = idx.filter(|i| *i < peers.len()) else {
            trace!("wireguard: datagram for no known peer");
            return;
        };
        let mut out = self.pool.pop().unwrap_or_default();
        out.resize(data.len().max(148), 0);
        let peer = &mut peers[idx];
        let delivered = match peer.tunn.decapsulate(from.map(|a| a.ip()), data, &mut out) {
            TunnResult::WriteToNetwork(pkt) => {
                let n = pkt.len();
                send_wire(transport, peer, idx, &mut out[..n]).await;
                // A completed handshake releases packets queued behind it.
                while let TunnResult::WriteToNetwork(pkt) = peer.tunn.decapsulate(None, &[], &mut self.scratch) {
                    let n = pkt.len();
                    send_wire(transport, peer, idx, &mut self.scratch[..n]).await;
                }
                None
            }
            TunnResult::WriteToTunnelV4(pkt, src) => Some((pkt.len(), IpAddr::V4(src))),
            TunnResult::WriteToTunnelV6(pkt, src) => Some((pkt.len(), IpAddr::V6(src))),
            TunnResult::Done => None,
            TunnResult::Err(e) => {
                trace!(error = ?e, "wireguard: decapsulate");
                self.pool.push(out);
                return;
            }
        };
        if handshake_response && let (_, _, _, _, Some(rtt)) = peer.tunn.stats() {
            let rtt = Duration::from_millis(rtt as u64);
            self.shared.handshake.send_replace(Some((Instant::now(), rtt)));
        }
        // Authenticated: follow the peer if it roamed.
        if from.is_some() && peer.endpoint != from {
            peer.endpoint = from;
        }
        match delivered {
            // Cryptokey routing: the inner source must be one of the peer's allowed IPs.
            Some((n, src)) if peer.allowed.iter().any(|net| net.contains(&src)) => {
                out.truncate(n);
                rx_batch.push(out);
            }
            _ => self.pool.push(out),
        }
    }

    async fn send_ip(&mut self, transport: &mut Transport, peers: &mut [PeerSetup], pkt: &[u8]) {
        let Some(dst) = Tunn::dst_address(pkt) else { return };
        let Some(idx) = route(peers, dst) else {
            trace!(%dst, "wireguard: no peer for destination");
            return;
        };
        let peer = &mut peers[idx];
        let dest = match (&*transport, peer.endpoint) {
            (Transport::Socket(_), Some(d)) => d,
            (Transport::Socket(_), None) => {
                trace!("wireguard: peer endpoint unknown yet, dropping");
                return;
            }
            (Transport::Detour { .. }, _) => {
                if let TunnResult::WriteToNetwork(out) = peer.tunn.encapsulate(pkt, &mut self.scratch) {
                    let n = out.len();
                    send_wire(transport, peer, idx, &mut self.scratch[..n]).await;
                }
                return;
            }
        };
        let b = &mut self.batch;
        if b.count > 0
            && (b.dest != Some(dest) || b.count >= b.max_segments || b.buf.len() + pkt.len() + 32 > GSO_MAX_BYTES)
        {
            self.flush(transport).await;
        }
        // Encrypt straight into the batch: no copy between crypto and syscall.
        let b = &mut self.batch;
        let start = b.buf.len();
        b.buf.resize(start + pkt.len().max(116) + 32, 0);
        let n = match peer.tunn.encapsulate(pkt, &mut b.buf[start..]) {
            TunnResult::WriteToNetwork(out) => out.len(),
            TunnResult::Err(e) => {
                trace!(error = ?e, "wireguard: encapsulate");
                0
            }
            _ => 0,
        };
        b.buf.truncate(start + n);
        if n == 0 {
            return;
        }
        set_reserved(peer, &mut b.buf[start..]);
        if b.count == 0 {
            (b.dest, b.seg, b.count) = (Some(dest), n, 1);
        } else if n == b.seg {
            b.count += 1;
        } else if n < b.seg {
            // A shorter datagram may only end a GSO batch.
            b.count += 1;
            self.flush(transport).await;
        } else {
            let tail = b.buf.split_off(start);
            self.flush(transport).await;
            let b = &mut self.batch;
            b.buf.extend_from_slice(&tail);
            (b.dest, b.seg, b.count) = (Some(dest), n, 1);
        }
    }

    async fn flush(&mut self, transport: &Transport) {
        let b = &mut self.batch;
        if b.count == 0 {
            return;
        }
        if let (Transport::Socket(u), Some(dest)) = (transport, b.dest) {
            let seg = (b.count > 1).then_some(b.seg);
            if let Err(e) = u.send(dest, &b.buf, seg).await {
                debug!(error = %e, %dest, "wireguard: send failed");
            }
        }
        b.buf.clear();
        b.count = 0;
    }

    async fn initiate(&mut self, transport: &Transport, peers: &mut [PeerSetup]) {
        for (idx, peer) in peers.iter_mut().enumerate() {
            if let TunnResult::WriteToNetwork(out) = peer.tunn.format_handshake_initiation(&mut self.scratch, false) {
                let n = out.len();
                send_wire(transport, peer, idx, &mut self.scratch[..n]).await;
            }
        }
    }

    async fn tick(&mut self, transport: &mut Transport, peers: &mut [PeerSetup]) {
        for (idx, peer) in peers.iter_mut().enumerate() {
            if let TunnResult::WriteToNetwork(out) = peer.tunn.update_timers(&mut self.scratch) {
                let n = out.len();
                send_wire(transport, peer, idx, &mut self.scratch[..n]).await;
            }
        }
    }
}
