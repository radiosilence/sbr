//! The userspace IP side of the WireGuard endpoint. TCP runs on sbr-tun's
//! userspace TCP (`sbr_tun::tcp`), owned by the device task, whose buffers
//! hold memory only for bytes in flight or unread and share a stack-wide
//! cap. UDP runs on a smoltcp interface plus the virtual device that hands
//! IP packets to and from the tunnel.
//!
//! The smoltcp stack sits behind one `std::sync::Mutex` that is only ever
//! held for synchronous work (a socket read/write, or one `Interface::poll`).
//! UDP handles read and write socket buffers directly under that lock; the
//! device task does the polling, encryption and UDP I/O.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant as StdInstant};

use ipnet::IpNet;
use sbr_tun::TcpConfig;
use sbr_tun::tcp::Connector;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Checksum, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use tokio::sync::{Notify, watch};

const MOBILE: bool = cfg!(any(
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
));

/// Limits for the tunnel's TCP. Buffers are elastic, so the per-connection
/// sizes cost only what a flow actually has buffered. The receive buffer is
/// the window advertised: 1 MiB covers about 80 Mbit/s at 100 ms. The send
/// buffer also caps bytes in flight. On iOS all buffers together stop at
/// 8 MiB, inside the Network Extension's ~50 MB alongside the TUN stack's
/// own 8 MiB; at that cap windows stop opening and writes wait, with one
/// buffer chunk (4 KiB) per connection each way always allowed.
pub fn tcp_config() -> TcpConfig {
    TcpConfig {
        rx_buffer: if MOBILE { 256 << 10 } else { 1 << 20 },
        tx_buffer: 256 << 10,
        max_connections: 0,
        pool_keep: if MOBILE { 1 << 20 } else { 8 << 20 },
        memory_limit: if MOBILE { 8 << 20 } else { 0 },
        defer_handshake: false,
    }
}

const UDP_PACKETS: usize = 64;
const UDP_BUFFER: usize = 128 * 1024;
/// Packets the stack may emit per `poll` before the device task gets to
/// encrypt and send them; bounds latency and the batch buffer.
pub const TX_BATCH: usize = 256;

/// Packet buffers in flight between the device task and smoltcp.
pub struct VirtDev {
    pub rx: VecDeque<Vec<u8>>,
    /// Buffers smoltcp is done with (returned to the device task).
    pub rx_free: Vec<Vec<u8>>,
    pub tx: Vec<Vec<u8>>,
    pub tx_free: Vec<Vec<u8>>,
    mtu: usize,
}

impl VirtDev {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            rx_free: Vec::new(),
            tx: Vec::with_capacity(TX_BATCH),
            tx_free: Vec::new(),
            mtu,
        }
    }
}

pub struct RxTok<'a> {
    buf: Vec<u8>,
    free: &'a mut Vec<Vec<u8>>,
}

impl phy::RxToken for RxTok<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        let r = f(&self.buf);
        self.free.push(self.buf);
        r
    }
}

pub struct TxTok<'a> {
    tx: &'a mut Vec<Vec<u8>>,
    free: &'a mut Vec<Vec<u8>>,
}

impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = self.free.pop().unwrap_or_default();
        buf.resize(len, 0);
        let r = f(&mut buf);
        self.tx.push(buf);
        r
    }
}

impl phy::Device for VirtDev {
    type RxToken<'a> = RxTok<'a>;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _: Instant) -> Option<(RxTok<'_>, TxTok<'_>)> {
        let buf = self.rx.pop_front()?;
        Some((
            RxTok {
                buf,
                free: &mut self.rx_free,
            },
            TxTok {
                tx: &mut self.tx,
                free: &mut self.tx_free,
            },
        ))
    }

    fn transmit(&mut self, _: Instant) -> Option<TxTok<'_>> {
        if self.tx.len() >= TX_BATCH {
            return None;
        }
        Some(TxTok {
            tx: &mut self.tx,
            free: &mut self.tx_free,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // WireGuard authenticates every packet, so verifying inner checksums
        // on receive is wasted work; the peer still checks ours.
        let mut ck = ChecksumCapabilities::default();
        ck.ipv4 = Checksum::Tx;
        ck.tcp = Checksum::Tx;
        ck.udp = Checksum::Tx;
        ck.icmpv4 = Checksum::Tx;
        ck.icmpv6 = Checksum::Tx;
        caps.checksum = ck;
        caps
    }
}

pub struct Stack {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
    pub dev: VirtDev,
    used_ports: HashSet<u16>,
    port_seed: u64,
}

/// What stream handles share with the device task.
pub struct Shared {
    pub stack: Mutex<Stack>,
    /// Opens TCP connections on the device task's stack.
    pub tcp: Connector,
    pub v4: Option<Ipv4Address>,
    pub v6: Option<Ipv6Address>,
    addrs: Vec<IpAddr>,
    /// Kicks the device task: a UDP datagram to send, a socket added, a
    /// rebind or handshake requested. (TCP streams wake it through `tcp`.)
    pub kick: Notify,
    /// Set by `probe_rtt`: initiate a handshake with every peer.
    pub want_handshake: AtomicBool,
    /// Set on a network change: replace the UDP socket.
    pub rebind: AtomicBool,
    /// When the last handshake we initiated completed, and its round trip.
    pub handshake: watch::Sender<Option<(StdInstant, Duration)>>,
    epoch: StdInstant,
}

impl Shared {
    pub fn new(addresses: &[IpNet], mtu: usize, seed: u64, tcp: Connector) -> Self {
        let mut dev = VirtDev::new(mtu);
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = seed;
        let epoch = StdInstant::now();
        let mut iface = Interface::new(cfg, &mut dev, Instant::from_micros(0));
        let (mut v4, mut v6) = (None, None);
        iface.update_ip_addrs(|addrs| {
            for a in addresses {
                let cidr = match a.addr() {
                    IpAddr::V4(ip) => {
                        v4.get_or_insert(ip);
                        IpCidr::new(IpAddress::Ipv4(ip), a.prefix_len())
                    }
                    IpAddr::V6(ip) => {
                        v6.get_or_insert(ip);
                        IpCidr::new(IpAddress::Ipv6(ip), a.prefix_len())
                    }
                };
                let _ = addrs.push(cidr);
            }
        });
        // Medium::Ip has no neighbours; everything goes "via" ourselves.
        if let Some(ip) = v4 {
            let _ = iface.routes_mut().add_default_ipv4_route(ip);
        }
        if let Some(ip) = v6 {
            let _ = iface.routes_mut().add_default_ipv6_route(ip);
        }
        Self {
            stack: Mutex::new(Stack {
                iface,
                sockets: SocketSet::new(Vec::new()),
                dev,
                used_ports: HashSet::new(),
                port_seed: seed | 1,
            }),
            tcp,
            v4,
            v6,
            addrs: addresses.iter().map(IpNet::addr).collect(),
            kick: Notify::new(),
            want_handshake: AtomicBool::new(false),
            rebind: AtomicBool::new(false),
            handshake: watch::Sender::new(None),
            epoch,
        }
    }

    pub fn now(&self) -> Instant {
        Instant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    /// Our tunnel address in `remote`'s family.
    pub fn local_ip(&self, remote: IpAddr) -> io::Result<IpAddr> {
        match remote {
            IpAddr::V4(_) => self.v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.v6.map(IpAddr::V6),
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("wireguard: no local address for {remote}"),
            )
        })
    }

    /// One of our tunnel addresses.
    pub fn is_local(&self, ip: IpAddr) -> bool {
        self.addrs.contains(&ip)
    }
}

impl Stack {
    fn local_port(&mut self) -> io::Result<u16> {
        for _ in 0..64 {
            // xorshift: ports need to be unpredictable-ish, not secret.
            self.port_seed ^= self.port_seed << 13;
            self.port_seed ^= self.port_seed >> 7;
            self.port_seed ^= self.port_seed << 17;
            let port = 32768 + (self.port_seed % 28232) as u16;
            if self.used_ports.insert(port) {
                return Ok(port);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "wireguard: no free local port",
        ))
    }

    /// `local` is one of our addresses (`Shared::local_ip`).
    pub fn udp_bind(&mut self, local: IpAddr) -> io::Result<SocketHandle> {
        let lport = self.local_port()?;
        let buf = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_PACKETS], vec![0u8; UDP_BUFFER]);
        let mut s = udp::Socket::new(buf(), buf());
        s.bind((IpAddress::from(local), lport))
            .map_err(|e| io::Error::other(format!("wireguard: bind: {e}")))?;
        Ok(self.sockets.add(s))
    }

    pub fn release_udp(&mut self, h: SocketHandle) {
        let s = self.sockets.remove(h);
        if let smoltcp::socket::Socket::Udp(s) = s {
            self.used_ports.remove(&s.endpoint().port);
        }
    }
}
