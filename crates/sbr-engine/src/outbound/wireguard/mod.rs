//! The `wireguard` endpoint as an outbound: a userspace WireGuard device
//! (boringtun for Noise) with a smoltcp stack terminating TCP and UDP flows
//! inside the tunnel.
//!
//! Flows the peer opens towards us are not routed (sing-box would hand them
//! to its router as an inbound); smoltcp answers them with a reset.
//!
//! The device starts on first use, so a configured-but-unused endpoint costs
//! no socket and no wakeups.

mod conn;
mod device;
mod stack;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};
use sbr_config::{DomainStrategy, WireGuardEndpoint};
use sbr_core::dial::{self, DialOptions};
use sbr_core::dns::Dns;
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Outbound, PacketConn, Stream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use self::conn::{WgPacketConn, WgTcp, WgUdp};
use self::device::{Device, PeerSetup, Transport};
use self::stack::Shared;
use super::Upstream;

/// Handshakes older than this are redone for an RTT probe (sessions are
/// rekeyed after 120 s of use).
const FRESH_HANDSHAKE: Duration = Duration::from_secs(120);

pub struct WireGuard {
    tag: String,
    cfg: WireGuardEndpoint,
    upstream: Upstream,
    dns: Arc<dyn Dns>,
    /// The device, started on first use and again if its task has ended
    /// (a panic, or every detour connection gone).
    running: std::sync::Mutex<Option<Arc<Running>>>,
    starting: tokio::sync::Mutex<()>,
}

struct Running {
    shared: Arc<Shared>,
    task: JoinHandle<()>,
    started: std::time::Instant,
    /// Detour receive tasks: they end only when a datagram finds the device
    /// gone, so they are stopped with it.
    readers: Vec<JoinHandle<()>>,
}

/// A device that stopped this soon after starting is not restarted until
/// this has passed: on a path that fails at once, every connect would
/// otherwise start it again.
const RESTART_AFTER: Duration = Duration::from_secs(5);

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
        for r in &self.readers {
            r.abort();
        }
        // Nothing drives this stack any more: fail the connections on it
        // rather than leave them waiting for a device that is gone.
        let mut st = self.shared.stack.lock().unwrap_or_else(|e| e.into_inner());
        for (_, s) in st.sockets.iter_mut() {
            match s {
                smoltcp::socket::Socket::Tcp(t) => t.abort(),
                smoltcp::socket::Socket::Udp(u) => u.close(),
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }
}

impl WireGuard {
    pub fn new(tag: String, cfg: &WireGuardEndpoint, upstream: Upstream, dns: Arc<dyn Dns>) -> Result<Self, String> {
        if cfg.workers > 1 {
            debug!(
                tag,
                "wireguard: `workers` is ignored; sbr runs one device task and at most one egress thread per endpoint"
            );
        }
        Ok(Self {
            tag,
            cfg: cfg.clone(),
            upstream,
            dns,
            running: std::sync::Mutex::new(None),
            starting: tokio::sync::Mutex::new(()),
        })
    }

    fn current(&self) -> Option<Arc<Running>> {
        let r = self.running.lock().unwrap();
        r.as_ref().filter(|r| !r.task.is_finished()).cloned()
    }

    async fn running(&self) -> io::Result<Arc<Shared>> {
        if let Some(r) = self.current() {
            return Ok(r.shared.clone());
        }
        let _starting = self.starting.lock().await;
        if let Some(r) = self.current() {
            return Ok(r.shared.clone());
        }
        {
            let mut slot = self.running.lock().unwrap();
            if let Some(old) = slot.as_ref() {
                if old.started.elapsed() < RESTART_AFTER {
                    return Err(io::Error::other("wireguard: device stopped"));
                }
                warn!(tag = %self.tag, "wireguard: device stopped, restarting");
            }
            slot.take();
        }
        let r = Arc::new(self.start().await?);
        *self.running.lock().unwrap() = Some(r.clone());
        Ok(r.shared.clone())
    }

    async fn start(&self) -> io::Result<Running> {
        let cfg = &self.cfg;
        let private = StaticSecret::from(cfg.private_key);
        let public = PublicKey::from(&private);
        let mut seed = [0u8; 8];
        fill_random(&mut seed);
        let shared = Arc::new(Shared::new(&cfg.address, cfg.mtu as usize, u64::from_le_bytes(seed)));

        let mut peers = Vec::with_capacity(cfg.peers.len());
        for (i, p) in cfg.peers.iter().enumerate() {
            let keepalive = (p.persistent_keepalive_interval > 0).then_some(p.persistent_keepalive_interval);
            peers.push(PeerSetup {
                tunn: Tunn::new(
                    private.clone(),
                    PublicKey::from(p.public_key),
                    p.pre_shared_key,
                    keepalive,
                    i as u32,
                    None,
                ),
                public: p.public_key,
                allowed: p.allowed_ips.clone(),
                reserved: p.reserved,
                endpoint: None,
                keepalive: p.persistent_keepalive_interval,
            });
        }

        let mut rebind = None;
        let mut readers = Vec::new();
        let transport = match &self.upstream {
            Upstream::System(opts, dns) => {
                for (peer, p) in peers.iter_mut().zip(&cfg.peers) {
                    if let Some(host) = &p.address {
                        let d = Destination::from_host_port(host, p.port);
                        peer.endpoint = dial::resolve(&d, opts.domain_strategy, dns.as_ref())
                            .await?
                            .first()
                            .copied();
                    }
                }
                let v6 = peers.iter().any(|p| p.endpoint.is_some_and(|e| e.is_ipv6()));
                // A client of one server: nobody else may send to us, so the
                // socket can be connected. A listening endpoint must accept
                // any source.
                let only = match &peers[..] {
                    [p] if cfg.listen_port == 0 => p.endpoint,
                    _ => None,
                };
                if cfg.listen_port == 0 {
                    // A new path wants a new socket: a connected one keeps the
                    // old source address. The peer follows us to the new port
                    // on our next authenticated packet.
                    let opts = opts.clone();
                    rebind = Some(Box::new(move || device::UdpIo::new(bind(v6, 0, &opts)?, v6, only)) as _);
                }
                Transport::Socket(Arc::new(device::UdpIo::new(
                    bind(v6, cfg.listen_port, opts)?,
                    v6,
                    only,
                )?))
            }
            Upstream::Detour(out) => {
                let (tx, rx) = mpsc::channel(1024);
                let mut conns = Vec::new();
                for (i, p) in cfg.peers.iter().enumerate() {
                    let host = p.address.as_deref().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "wireguard: detour needs peer addresses")
                    })?;
                    let dest = Destination::from_host_port(host, p.port);
                    let conn: Arc<dyn PacketConn> = Arc::from(out.connect_udp(&dest).await?);
                    let (c, tx) = (conn.clone(), tx.clone());
                    readers.push(tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        while let Ok((n, _)) = c.recv_from(&mut buf).await {
                            if tx.send((i, buf[..n].to_vec())).await.is_err() {
                                return;
                            }
                        }
                    }));
                    conns.push((conn, dest));
                }
                Transport::Detour {
                    conns,
                    rx,
                    pending: None,
                }
            }
        };
        let dev = Device {
            shared: shared.clone(),
            peers,
            transport,
            private,
            public,
            rebind,
        };
        let task = tokio::spawn(dev.run());
        Ok(Running {
            shared,
            task,
            started: std::time::Instant::now(),
            readers,
        })
    }

    /// Resolve with the engine DNS, preferring the families we have
    /// tunnel addresses for.
    async fn resolve_all(dns: &dyn Dns, cfg: &WireGuardEndpoint, d: &Destination) -> io::Result<Vec<IpAddr>> {
        if let Some(ip) = d.ip() {
            return Ok(vec![ip]);
        }
        let has4 = cfg.address.iter().any(|a| a.addr().is_ipv4());
        let has6 = cfg.address.iter().any(|a| a.addr().is_ipv6());
        let strategy = cfg.dial.domain_strategy.or(match (has4, has6) {
            (true, false) => Some(DomainStrategy::Ipv4Only),
            (false, true) => Some(DomainStrategy::Ipv6Only),
            _ => None,
        });
        dns.lookup(d.domain().unwrap_or_default(), strategy).await
    }
}

fn fill_random(buf: &mut [u8]) {
    use aws_lc_rs::rand::SecureRandom;
    aws_lc_rs::rand::SystemRandom::new().fill(buf).expect("system RNG");
}

/// The endpoint's UDP socket, with large kernel buffers: one socket carries
/// every flow in the tunnel.
fn bind(v6: bool, port: u16, opts: &DialOptions) -> io::Result<tokio::net::UdpSocket> {
    let family: IpAddr = if v6 {
        std::net::Ipv6Addr::UNSPECIFIED.into()
    } else {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    };
    let sock = dial::bind_udp_port(family, port, opts)?.into_std()?;
    let s2 = socket2::SockRef::from(&sock);
    if v6 {
        let _ = s2.set_only_v6(false);
    }
    // Best effort: the kernel clamps to its limits.
    let _ = s2.set_recv_buffer_size(4 << 20);
    let _ = s2.set_send_buffer_size(4 << 20);
    sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(sock)
}

impl Outbound for WireGuard {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "wireguard"
    }

    fn network_changed(&self) {
        if let Some(r) = self.current() {
            r.shared.rebind.store(true, Ordering::Relaxed);
            r.shared.kick.notify_one();
        }
    }

    /// The round trip of the last handshake (boringtun times it): a real
    /// measurement to the peer at the cost of one handshake. A recent one is
    /// reused, so probing an active endpoint sends nothing.
    fn probe_rtt(&self) -> Option<BoxFuture<'_, io::Result<Duration>>> {
        Some(Box::pin(async move {
            let shared = self.running().await?;
            let mut rx = shared.handshake.subscribe();
            if let Some((at, rtt)) = *rx.borrow_and_update()
                && at.elapsed() < FRESH_HANDSHAKE
            {
                return Ok(rtt);
            }
            shared.want_handshake.store(true, Ordering::Relaxed);
            shared.kick.notify_one();
            loop {
                rx.changed()
                    .await
                    .map_err(|_| io::Error::other("wireguard: device stopped"))?;
                if let Some((_, rtt)) = *rx.borrow_and_update() {
                    return Ok(rtt);
                }
            }
        }))
    }

    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            let shared = self.running().await?;
            let ips = Self::resolve_all(self.dns.as_ref(), &self.cfg, dest).await?;
            let timeout = self.cfg.dial.connect_timeout.unwrap_or(Duration::from_secs(10));
            let mut last = None;
            // Serial, like sing-box's DialSerial.
            for ip in ips {
                match tokio::time::timeout(timeout, WgTcp::connect(shared.clone(), ip, dest.port)).await {
                    Ok(Ok(s)) => return Ok(Box::new(s) as Stream),
                    Ok(Err(e)) => last = Some(e),
                    Err(_) => {
                        last = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("wireguard: connect {ip}"),
                        ))
                    }
                }
            }
            Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {dest}"))))
        })
    }

    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            let shared = self.running().await?;
            let first = Self::resolve_all(self.dns.as_ref(), &self.cfg, dest)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {dest}")))?;
            let sock = WgUdp::bind(shared, first)?;
            let dns = self.dns.clone();
            let cfg = Arc::new(self.cfg.clone());
            let family_v6 = first.is_ipv6();
            let resolve = Arc::new(move |d: &Destination| -> BoxFuture<'static, io::Result<IpAddr>> {
                let (dns, cfg, d) = (dns.clone(), cfg.clone(), d.clone());
                Box::pin(async move {
                    Self::resolve_all(dns.as_ref(), &cfg, &d)
                        .await?
                        .into_iter()
                        .find(|ip| ip.is_ipv6() == family_v6)
                        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {d}")))
                })
            });
            Ok(Box::new(WgPacketConn { sock, resolve }) as BoxPacketConn)
        })
    }
}
