//! The WireGuard device task: UDP I/O, Noise (boringtun), and driving the
//! smoltcp stack.
//!
//! One task per endpoint. Each wakeup it drains every datagram the socket
//! has queued, decrypts them into the stack, runs one `Interface::poll`, then
//! encrypts and sends everything the stack emitted. Batching per wakeup
//! keeps the per-packet cost to the crypto and one syscall.
//!
//! Power: the task only wakes for packets, a kick from a socket handle, a
//! smoltcp deadline (retransmit, delayed ACK), or WireGuard timers. Timers
//! tick once a second while traffic flowed in the last 30 s, at the
//! persistent-keepalive interval when one is configured, and never otherwise.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use sbr_core::{Destination, PacketConn};
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
/// Largest WireGuard datagram we expect (MTU is at most 65535 plus overhead).
const MAX_DATAGRAM: usize = 65535 + 64;

pub struct PeerSetup {
    pub tunn: Tunn,
    pub public: [u8; 32],
    pub allowed: Vec<IpNet>,
    pub reserved: [u8; 3],
    /// Where to send; learned from the peer when `None` (socket transport).
    pub endpoint: Option<SocketAddr>,
    pub keepalive: u16,
}

pub enum Transport {
    Socket(UdpSocket),
    /// Through a detour outbound: one association per peer.
    Detour {
        conns: Vec<(Arc<dyn PacketConn>, Destination)>,
        rx: mpsc::Receiver<(usize, Vec<u8>)>,
        /// Received while waiting for readiness.
        pending: Option<(usize, Vec<u8>)>,
    },
}

pub struct Device {
    pub shared: Arc<Shared>,
    pub peers: Vec<PeerSetup>,
    pub transport: Transport,
    pub private: StaticSecret,
    pub public: PublicKey,
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
        let mut io = Io {
            scratch: vec![0u8; MAX_DATAGRAM],
            recv_buf: vec![0u8; MAX_DATAGRAM],
            pool: Vec::new(),
        };
        let keepalive = peers.iter().map(|p| p.keepalive).filter(|k| *k > 0).min();
        let mut rx_batch: Vec<Vec<u8>> = Vec::with_capacity(RX_BATCH);
        let mut tx_out: Vec<Vec<u8>> = Vec::with_capacity(TX_BATCH);
        let mut last_traffic = Instant::now() - ACTIVE_WINDOW;
        let mut last_tick = Instant::now();

        loop {
            // 1. Ingress: everything queued on the socket, without blocking.
            let received = io
                .drain(&mut transport, &mut peers, &private, &public, &mut rx_batch)
                .await;

            // 2. One stack poll.
            let now_stack = shared.now();
            let delay;
            {
                let mut st = shared.stack.lock().unwrap();
                let st = &mut *st;
                st.dev.rx.extend(rx_batch.drain(..));
                io.pool.append(&mut st.dev.rx_free);
                st.iface.poll(now_stack, &mut st.dev, &mut st.sockets);
                std::mem::swap(&mut tx_out, &mut st.dev.tx);
                // Hand back buffers sent last round for smoltcp to reuse.
                if st.dev.tx_free.len() < TX_BATCH {
                    let want = TX_BATCH - st.dev.tx_free.len();
                    let take = io.pool.len().min(want);
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

impl Transport {
    /// Wait until a datagram may be available.
    async fn ready(&mut self) -> io::Result<()> {
        match self {
            Transport::Socket(s) => s.readable().await,
            Transport::Detour { rx, pending, .. } => {
                if pending.is_none() {
                    *pending = Some(rx.recv().await.ok_or(io::ErrorKind::BrokenPipe)?);
                }
                Ok(())
            }
        }
    }
}

struct Io {
    /// Output buffer for encapsulation/handshakes.
    scratch: Vec<u8>,
    recv_buf: Vec<u8>,
    /// Reusable packet buffers.
    pool: Vec<Vec<u8>>,
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

async fn send_wire(transport: &mut Transport, peer: &PeerSetup, idx: usize, data: &mut [u8]) {
    if data.len() >= 4 && peer.reserved != [0; 3] {
        data[1..4].copy_from_slice(&peer.reserved);
    }
    match transport {
        Transport::Socket(sock) => {
            let Some(to) = peer.endpoint else {
                trace!("wireguard: peer endpoint unknown yet, dropping");
                return;
            };
            loop {
                match sock.try_send_to(data, to) {
                    Ok(_) => return,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if sock.writable().await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, %to, "wireguard: send failed");
                        return;
                    }
                }
            }
        }
        Transport::Detour { conns, .. } => {
            let (conn, dest) = &conns[idx];
            if let Err(e) = conn.send_to(data, dest).await {
                debug!(error = %e, "wireguard: detour send failed");
            }
        }
    }
}

impl Io {
    /// Receive and decrypt every datagram available right now. Returns how
    /// many datagrams were read.
    async fn drain(
        &mut self,
        transport: &mut Transport,
        peers: &mut [PeerSetup],
        private: &StaticSecret,
        public: &PublicKey,
        rx_batch: &mut Vec<Vec<u8>>,
    ) -> usize {
        let mut n = 0;
        while n < RX_BATCH {
            let (len, from, hint) = match transport {
                Transport::Socket(sock) => match sock.try_recv_from(&mut self.recv_buf) {
                    Ok((len, from)) => (len, Some(SocketAddr::new(from.ip().to_canonical(), from.port())), None),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        // ICMP errors surface here on some platforms; keep going.
                        trace!(error = %e, "wireguard: recv error");
                        break;
                    }
                },
                Transport::Detour { rx, pending, .. } => match pending.take().ok_or(()).or_else(|_| rx.try_recv()) {
                    Ok((idx, data)) => {
                        let len = data.len().min(self.recv_buf.len());
                        self.recv_buf[..len].copy_from_slice(&data[..len]);
                        (len, None, Some(idx))
                    }
                    Err(_) => break,
                },
            };
            n += 1;
            self.handle_datagram(transport, peers, private, public, len, from, hint, rx_batch)
                .await;
        }
        n
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_datagram(
        &mut self,
        transport: &mut Transport,
        peers: &mut [PeerSetup],
        private: &StaticSecret,
        public: &PublicKey,
        len: usize,
        from: Option<SocketAddr>,
        hint: Option<usize>,
        rx_batch: &mut Vec<Vec<u8>>,
    ) {
        let data = &mut self.recv_buf[..len];
        if len >= 4 {
            // Reserved bytes (WARP) are ignored on receive, like sing-box.
            data[1..4].fill(0);
        }
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
            Ok(Packet::HandshakeResponse(p)) => Some((p.receiver_idx >> 8) as usize),
            Ok(Packet::PacketCookieReply(p)) => Some((p.receiver_idx >> 8) as usize),
            Ok(Packet::PacketData(p)) => Some((p.receiver_idx >> 8) as usize),
            Err(_) => None,
        };
        let Some(idx) = idx.filter(|i| *i < peers.len()) else {
            trace!("wireguard: datagram for no known peer");
            return;
        };
        let mut out = self.pool.pop().unwrap_or_default();
        out.resize(len.max(148), 0);
        let peer = &mut peers[idx];
        let src_ip = from.map(|a| a.ip());
        let delivered = match peer.tunn.decapsulate(src_ip, &self.recv_buf[..len], &mut out) {
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
        match peer.tunn.encapsulate(pkt, &mut self.scratch) {
            TunnResult::WriteToNetwork(out) => {
                let n = out.len();
                send_wire(transport, peer, idx, &mut self.scratch[..n]).await;
            }
            TunnResult::Err(e) => trace!(error = ?e, "wireguard: encapsulate"),
            _ => {}
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
