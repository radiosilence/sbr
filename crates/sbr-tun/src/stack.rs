//! The system stack: TCP via NAT onto a kernel listener, UDP handed up as
//! datagrams. See the crate docs for the trick.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tracing::{debug, trace, warn};

use crate::device::{Device, HEADROOM, RecvBatch};
use crate::nat::Nat;
use crate::packet::{self, ACK, PROTO_TCP, PROTO_UDP, SYN};

#[derive(Clone, Debug)]
pub struct StackConfig {
    /// The interface address and the next one (used as the NAT source).
    pub inet4: Option<(Ipv4Addr, Ipv4Addr)>,
    pub inet6: Option<(Ipv6Addr, Ipv6Addr)>,
    pub mtu: usize,
}

impl StackConfig {
    /// Derive from interface prefixes the way sing-box does: the NAT
    /// source is the address after the interface address.
    pub fn from_prefixes(prefixes: &[ipnet::IpNet], mtu: usize) -> Self {
        let mut c = Self {
            inet4: None,
            inet6: None,
            mtu,
        };
        for p in prefixes {
            match p {
                ipnet::IpNet::V4(v4) if c.inet4.is_none() => {
                    c.inet4 = Some((v4.addr(), Ipv4Addr::from(u32::from(v4.addr()).wrapping_add(1))));
                }
                ipnet::IpNet::V6(v6) if c.inet6.is_none() => {
                    c.inet6 = Some((v6.addr(), Ipv6Addr::from(u128::from(v6.addr()).wrapping_add(1))));
                }
                _ => {}
            }
        }
        c
    }
}

/// A TCP connection from an app, terminated by the kernel. Dropping it
/// releases the NAT entry (after a grace period for trailing segments).
pub struct Accepted {
    pub stream: TcpStream,
    /// The app's address.
    pub source: SocketAddr,
    /// Where the app was connecting to.
    pub destination: SocketAddr,
    _guard: NatGuard,
}

struct NatGuard {
    nat: Arc<Mutex<Nat>>,
    port: u16,
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        self.nat.lock().unwrap().close(self.port);
    }
}

/// A datagram from an app.
pub struct UdpIn {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: Bytes,
}

struct Family {
    addr: IpAddr,
    next: IpAddr,
    port: u16,
    nat: Arc<Mutex<Nat>>,
}

pub struct Stack {
    device: Arc<Device>,
    tasks: JoinSet<()>,
}

impl Stack {
    /// Start the packet loop and listeners. The device's addresses must
    /// already be configured (true for adopted NE fds and `Device::create`).
    pub async fn start(
        device: Device,
        cfg: StackConfig,
        on_tcp: impl Fn(Accepted) + Send + Sync + 'static,
        on_udp: impl Fn(UdpIn) + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let device = Arc::new(device);
        let on_tcp = Arc::new(on_tcp);
        let mut tasks = JoinSet::new();
        let mut fams: [Option<Arc<Family>>; 2] = [None, None];
        let pairs = [
            cfg.inet4.map(|(a, n)| (IpAddr::V4(a), IpAddr::V4(n))),
            cfg.inet6.map(|(a, n)| (IpAddr::V6(a), IpAddr::V6(n))),
        ];
        for (slot, pair) in fams.iter_mut().zip(pairs) {
            let Some((addr, next)) = pair else { continue };
            let listener = TcpListener::bind(SocketAddr::new(addr, 0)).await?;
            let port = listener.local_addr()?.port();
            let fam = Arc::new(Family {
                addr,
                next,
                port,
                nat: Arc::new(Mutex::new(Nat::default())),
            });
            debug!(%addr, port, "system stack listening");
            tasks.spawn(accept_loop(listener, fam.clone(), on_tcp.clone()));
            *slot = Some(fam);
        }
        if fams.iter().all(Option::is_none) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "tun: no interface address"));
        }
        tasks.spawn(packet_loop(device.clone(), fams, cfg.mtu, on_udp));
        Ok(Self { device, tasks })
    }

    /// Deliver a datagram to an app: `from` is what the app will see as the
    /// sender. Drops (rather than blocks) when the interface is congested.
    pub fn write_udp(&self, from: SocketAddr, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        UDP_BUF.with(|b| {
            let mut b = b.borrow_mut();
            let mut pkt = std::mem::take(&mut *b);
            packet::build_udp(&mut pkt, from, to, payload);
            let len = pkt.len();
            // Shift right to make headroom; the buffer is reused per thread.
            pkt.splice(0..0, [0u8; HEADROOM]);
            let r = match self.device.try_send(&mut pkt, len) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
                r => r,
            };
            *b = pkt;
            r
        })
    }

    pub fn device(&self) -> &Device {
        &self.device
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

thread_local! {
    static UDP_BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

async fn accept_loop(listener: TcpListener, fam: Arc<Family>, on_tcp: Arc<dyn Fn(Accepted) + Send + Sync>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "tun accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        if peer.ip() != fam.next {
            continue; // not one of ours
        }
        let Some((source, destination)) = fam.nat.lock().unwrap().accept(peer.port()) else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        on_tcp(Accepted {
            stream,
            source,
            destination,
            _guard: NatGuard {
                nat: fam.nat.clone(),
                port: peer.port(),
            },
        });
    }
}

/// Go's `netip.Addr.IsGlobalUnicast`: what sing-tun forwards.
fn global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified() || v4.is_loopback() || v4.is_multicast() || v4.is_broadcast() || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))]
const BATCH: (usize, usize) = (4, 32);
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
const BATCH: (usize, usize) = (8, 64);

async fn packet_loop(
    device: Arc<Device>,
    fams: [Option<Arc<Family>>; 2],
    mtu: usize,
    on_udp: impl Fn(UdpIn) + Send + Sync + 'static,
) {
    let mut batch = RecvBatch::new(BATCH.0, BATCH.1, mtu.max(1500) + 64);
    loop {
        let n = match device.recv_batch(&mut batch).await {
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "tun read failed; stopping");
                return;
            }
        };
        for i in 0..n {
            let len = batch.len(i);
            if len == 0 {
                continue;
            }
            if let Some(len) = process(&fams, batch.buf(i), len, &on_udp)
                && let Err(e) = device.send(batch.buf(i), len).await
            {
                debug!(error = %e, "tun write failed");
            }
        }
    }
}

/// Handle one packet in `buf[HEADROOM..HEADROOM + len]`. Returns the length
/// to write back into the TUN (TCP rewritten in place), or None if consumed
/// or dropped.
fn process(fams: &[Option<Arc<Family>>; 2], buf: &mut [u8], len: usize, on_udp: &impl Fn(UdpIn)) -> Option<usize> {
    let pkt = &mut buf[HEADROOM..HEADROOM + len];
    let h = packet::parse(pkt)?;
    let fam = fams[h.v6 as usize].as_ref()?;
    match h.proto {
        PROTO_TCP => {
            let flags = packet::tcp_flags(pkt, &h);
            let rewrite = if h.src.ip() == fam.addr && h.src.port() == fam.port {
                // Our listener replying: restore the original flow.
                fam.nat
                    .lock()
                    .unwrap()
                    .inbound(h.dst.port())
                    .map(|(src, dst)| (dst, src))
            } else if global_unicast(h.dst.ip()) {
                let syn_only = flags & SYN != 0 && flags & ACK == 0;
                let port = fam.nat.lock().unwrap().outbound(h.src, h.dst, syn_only);
                port.map(|p| (SocketAddr::new(fam.next, p), SocketAddr::new(fam.addr, fam.port)))
            } else {
                None
            };
            let Some((src, dst)) = rewrite else {
                trace!(src = %h.src, dst = %h.dst, flags, "tcp: no NAT entry, dropped");
                return None;
            };
            packet::rewrite(pkt, &h, src, dst);
            Some(len)
        }
        PROTO_UDP if global_unicast(h.dst.ip()) => {
            let payload = Bytes::copy_from_slice(&pkt[h.l4 + 8..h.len]);
            on_udp(UdpIn {
                source: h.src,
                destination: h.dst,
                payload,
            });
            None
        }
        _ => None,
    }
}
