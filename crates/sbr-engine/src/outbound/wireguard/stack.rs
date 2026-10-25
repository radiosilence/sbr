//! The userspace TCP/IP side of the WireGuard endpoint: a smoltcp interface
//! plus the virtual device that hands IP packets to and from the tunnel.
//!
//! The whole stack sits behind one `std::sync::Mutex` that is only ever held
//! for synchronous work (a socket read/write, or one `Interface::poll`).
//! Stream handles read and write socket buffers directly under that lock, so
//! payload is copied exactly once on each side of the stack; the device task
//! does the polling, encryption and UDP I/O.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant as StdInstant;

use ipnet::IpNet;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Checksum, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use tokio::sync::Notify;

/// TCP socket buffers. Allocated zeroed, so the OS commits pages only as the
/// ring is actually used; idle or small flows stay cheap even on iOS.
#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos"))]
pub const TCP_BUFFER: usize = 256 * 1024;
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
pub const TCP_BUFFER: usize = 1024 * 1024;

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
    pub v4: Option<Ipv4Address>,
    pub v6: Option<Ipv6Address>,
    used_ports: HashSet<(bool, u16)>,
    /// TCP sockets whose handle was dropped; removed once fully closed.
    closing: Vec<(SocketHandle, u16)>,
    port_seed: u64,
}

/// What stream handles share with the device task.
pub struct Shared {
    pub stack: Mutex<Stack>,
    /// Kicks the device task: new data to send, window opened, socket added.
    pub kick: Notify,
    epoch: StdInstant,
}

impl Shared {
    pub fn new(addresses: &[IpNet], mtu: usize, seed: u64) -> Self {
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
                v4,
                v6,
                used_ports: HashSet::new(),
                closing: Vec::new(),
                port_seed: seed | 1,
            }),
            kick: Notify::new(),
            epoch,
        }
    }

    pub fn now(&self) -> Instant {
        Instant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }
}

impl Stack {
    fn local_port(&mut self, tcp: bool) -> io::Result<u16> {
        for _ in 0..64 {
            // xorshift: ports need to be unpredictable-ish, not secret.
            self.port_seed ^= self.port_seed << 13;
            self.port_seed ^= self.port_seed >> 7;
            self.port_seed ^= self.port_seed << 17;
            let port = 32768 + (self.port_seed % 28232) as u16;
            if self.used_ports.insert((tcp, port)) {
                return Ok(port);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "wireguard: no free local port",
        ))
    }

    pub fn local_addr(&self, remote: IpAddr) -> io::Result<IpAddress> {
        match remote {
            IpAddr::V4(_) => self.v4.map(IpAddress::Ipv4),
            IpAddr::V6(_) => self.v6.map(IpAddress::Ipv6),
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("wireguard: no local address for {remote}"),
            )
        })
    }

    /// Returns the socket and its local port.
    pub fn tcp_connect(&mut self, remote: IpAddr, port: u16) -> io::Result<(SocketHandle, u16)> {
        let local = self.local_addr(remote)?;
        let lport = self.local_port(true)?;
        let mut s = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        );
        s.set_nagle_enabled(false);
        s.set_congestion_control(tcp::CongestionControl::Cubic);
        // Abort if the peer stops acknowledging (dead tunnel), instead of
        // retransmitting forever.
        s.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
        let r = s.connect(self.iface.context(), (IpAddress::from(remote), port), (local, lport));
        if let Err(e) = r {
            self.used_ports.remove(&(true, lport));
            return Err(io::Error::other(format!("wireguard: connect: {e}")));
        }
        Ok((self.sockets.add(s), lport))
    }

    pub fn udp_bind(&mut self, family: IpAddr) -> io::Result<SocketHandle> {
        let local = self.local_addr(family)?;
        let lport = self.local_port(false)?;
        let buf = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; UDP_PACKETS], vec![0u8; UDP_BUFFER]);
        let mut s = udp::Socket::new(buf(), buf());
        s.bind((local, lport))
            .map_err(|e| io::Error::other(format!("wireguard: bind: {e}")))?;
        Ok(self.sockets.add(s))
    }

    /// A stream handle went away: close gracefully and reap later.
    pub fn release_tcp(&mut self, h: SocketHandle, port: u16) {
        let s = self.sockets.get_mut::<tcp::Socket>(h);
        s.close();
        self.closing.push((h, port));
    }

    pub fn release_udp(&mut self, h: SocketHandle) {
        let s = self.sockets.remove(h);
        if let smoltcp::socket::Socket::Udp(s) = s {
            self.used_ports.remove(&(false, s.endpoint().port));
        }
    }

    /// Drop sockets that finished closing. TIME-WAIT is cut short: ports are
    /// ours alone and randomised, so there is nothing to protect.
    pub fn reap(&mut self) {
        let mut i = 0;
        while i < self.closing.len() {
            let (h, port) = self.closing[i];
            let s = self.sockets.get_mut::<tcp::Socket>(h);
            if matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait) {
                self.sockets.remove(h);
                self.used_ports.remove(&(true, port));
                self.closing.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Reset instead of closing (connect failed or was cancelled).
    pub fn abort_tcp(&mut self, h: SocketHandle, port: u16) {
        let s = self.sockets.get_mut::<tcp::Socket>(h);
        s.abort();
        self.closing.push((h, port));
    }

    pub fn has_closing(&self) -> bool {
        !self.closing.is_empty()
    }
}
