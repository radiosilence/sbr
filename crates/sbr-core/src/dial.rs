//! System TCP dialer: resolution, Happy Eyeballs, socket options.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use sbr_config::{Dial, DomainStrategy};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;

use crate::dns::Dns;
use crate::{Destination, Host};

/// sing-box `C.TCPConnectTimeout`.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// sing-box `C.TCPKeepAliveInitial` / `C.TCPKeepAliveInterval`.
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(300);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(75);
/// Interface outbound sockets bind to when they don't name one: set by the
/// TUN inbound's `auto_route` so our own traffic can't loop into the tunnel
/// (sing-box `auto_detect_interface`).
static DEFAULT_INTERFACE: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

pub fn set_default_interface(iface: Option<String>) {
    *DEFAULT_INTERFACE.write().unwrap() = iface;
}

fn effective_interface(opts: &DialOptions, dest: IpAddr) -> Option<String> {
    // Loopback can't loop into a tunnel, and binding it to a physical NIC fails.
    opts.bind_interface.clone().or_else(|| {
        if dest.is_loopback() {
            None
        } else {
            DEFAULT_INTERFACE.read().unwrap().clone()
        }
    })
}

/// RFC 8305 "Connection Attempt Delay".
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Default)]
pub struct DialOptions {
    pub connect_timeout: Option<Duration>,
    pub keepalive: Option<Duration>,
    pub disable_keepalive: bool,
    pub domain_strategy: Option<DomainStrategy>,
    pub bind_interface: Option<String>,
}

impl From<&Dial> for DialOptions {
    fn from(d: &Dial) -> Self {
        Self {
            connect_timeout: d.connect_timeout,
            keepalive: d.tcp_keep_alive,
            disable_keepalive: d.disable_tcp_keep_alive,
            domain_strategy: d.domain_strategy,
            bind_interface: d.bind_interface.clone(),
        }
    }
}

/// Resolve `dest` to socket addresses in dial order.
pub async fn resolve(
    dest: &Destination,
    strategy: Option<DomainStrategy>,
    dns: &dyn Dns,
) -> io::Result<Vec<SocketAddr>> {
    Ok(match &dest.host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, dest.port)],
        Host::Domain(d) => dns
            .lookup(d, strategy)
            .await?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, dest.port))
            .collect(),
    })
}

pub async fn connect(dest: &Destination, opts: &DialOptions, dns: &dyn Dns) -> io::Result<TcpStream> {
    let timeout = opts.connect_timeout.unwrap_or(CONNECT_TIMEOUT);
    let fut = async {
        let addrs = resolve(dest, opts.domain_strategy, dns).await?;
        happy_eyeballs(addrs, opts).await
    };
    let stream = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("connect {dest}: timed out")))??;
    tune(&stream, opts)?;
    Ok(stream)
}

/// An unconnected UDP socket for `family_of`'s address family, honouring
/// `bind_interface`.
pub fn bind_udp(family_of: IpAddr, opts: &DialOptions) -> io::Result<tokio::net::UdpSocket> {
    let domain = if family_of.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    sock.set_nonblocking(true)?;
    if let Some(iface) = effective_interface(opts, family_of) {
        bind_device_sock(&sock, &iface, family_of)?;
    }
    let any: SocketAddr = if family_of.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    sock.bind(&any.into())?;
    tokio::net::UdpSocket::from_std(sock.into())
}

async fn happy_eyeballs(addrs: Vec<SocketAddr>, opts: &DialOptions) -> io::Result<TcpStream> {
    if addrs.len() == 1 {
        return connect_one(addrs[0], effective_interface(opts, addrs[0].ip())).await;
    }
    let mut set = JoinSet::new();
    let mut last_err = None;
    let mut pending = addrs.into_iter();
    loop {
        if let Some(addr) = pending.next() {
            set.spawn(connect_one(addr, effective_interface(opts, addr.ip())));
        }
        let next = if pending.len() > 0 {
            match tokio::time::timeout(ATTEMPT_DELAY, set.join_next()).await {
                Ok(r) => r,
                Err(_) => continue, // slow attempt: start the next one alongside it
            }
        } else {
            set.join_next().await
        };
        match next {
            Some(Ok(Ok(s))) => return Ok(s), // dropping `set` aborts the losers
            Some(Ok(Err(e))) => last_err = Some(e),
            Some(Err(e)) => last_err = Some(io::Error::other(e)),
            None if pending.len() == 0 => {
                return Err(last_err.unwrap_or_else(|| io::Error::other("no addresses")));
            }
            None => {}
        }
    }
}

async fn connect_one(addr: SocketAddr, bind_interface: Option<String>) -> io::Result<TcpStream> {
    let sock = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(iface) = bind_interface {
        bind_device_sock(&SockRef::from(&sock), &iface, addr.ip())?;
    }
    sock.connect(addr).await
}

fn tune(s: &TcpStream, opts: &DialOptions) -> io::Result<()> {
    s.set_nodelay(true)?;
    if !opts.disable_keepalive {
        let ka = TcpKeepalive::new().with_time(opts.keepalive.unwrap_or(KEEPALIVE_IDLE));
        #[cfg(not(target_os = "openbsd"))]
        let ka = ka.with_interval(KEEPALIVE_INTERVAL);
        SockRef::from(s).set_tcp_keepalive(&ka)?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_device_sock(sock: &socket2::Socket, iface: &str, _ip: IpAddr) -> io::Result<()> {
    sock.bind_device(Some(iface.as_bytes()))
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
fn bind_device_sock(sock: &socket2::Socket, iface: &str, ip: IpAddr) -> io::Result<()> {
    let idx = std::num::NonZeroU32::new(nix_if_nametoindex(iface)?).ok_or_else(|| io::Error::other("bad interface"))?;
    match ip {
        IpAddr::V4(_) => sock.bind_device_by_index_v4(Some(idx)),
        IpAddr::V6(_) => sock.bind_device_by_index_v6(Some(idx)),
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
fn nix_if_nametoindex(name: &str) -> io::Result<u32> {
    unsafe extern "C" {
        fn if_nametoindex(name: *const std::ffi::c_char) -> u32;
    }
    let c = std::ffi::CString::new(name).map_err(io::Error::other)?;
    // SAFETY: `c` is a valid NUL-terminated string for the duration of the call.
    match unsafe { if_nametoindex(c.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        i => Ok(i),
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
)))]
fn bind_device_sock(_: &socket2::Socket, _: &str, _: IpAddr) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bind_interface is not supported on this platform",
    ))
}
