//! System TCP dialer: resolution, Happy Eyeballs, socket options.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use sbr_config::{Dial, DomainStrategy};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;

use crate::{Destination, Host};

/// sing-box `C.TCPConnectTimeout`.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// sing-box `C.TCPKeepAliveInitial` / `C.TCPKeepAliveInterval`.
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(300);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(75);
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

pub async fn resolve(
    host: &str,
    port: u16,
    strategy: Option<DomainStrategy>,
) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    let (v4, v6): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv4());
    let ordered = match strategy.unwrap_or(DomainStrategy::AsIs) {
        DomainStrategy::Ipv4Only => v4,
        DomainStrategy::Ipv6Only => v6,
        DomainStrategy::PreferIpv4 => v4.into_iter().chain(v6).collect(),
        DomainStrategy::PreferIpv6 => v6.into_iter().chain(v4).collect(),
        DomainStrategy::AsIs => interleave(v6, v4),
    };
    if ordered.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no usable addresses for {host}"),
        ));
    }
    Ok(ordered)
}

fn interleave(a: Vec<SocketAddr>, b: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut a, mut b) = (a.into_iter(), b.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => return out,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
}

pub async fn connect(dest: &Destination, opts: &DialOptions) -> io::Result<TcpStream> {
    let timeout = opts.connect_timeout.unwrap_or(CONNECT_TIMEOUT);
    let fut = async {
        let addrs = match &dest.host {
            Host::Ip(ip) => vec![SocketAddr::new(*ip, dest.port)],
            Host::Domain(d) => resolve(d, dest.port, opts.domain_strategy).await?,
        };
        happy_eyeballs(addrs, opts).await
    };
    let stream = tokio::time::timeout(timeout, fut).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("connect {dest}: timed out"),
        )
    })??;
    tune(&stream, opts)?;
    Ok(stream)
}

async fn happy_eyeballs(addrs: Vec<SocketAddr>, opts: &DialOptions) -> io::Result<TcpStream> {
    if addrs.len() == 1 {
        return connect_one(addrs[0], opts.bind_interface.clone()).await;
    }
    let mut set = JoinSet::new();
    let mut last_err = None;
    let mut pending = addrs.into_iter();
    loop {
        if let Some(addr) = pending.next() {
            set.spawn(connect_one(addr, opts.bind_interface.clone()));
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
        bind_device(&sock, &iface, addr.ip())?;
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
fn bind_device(sock: &TcpSocket, iface: &str, _ip: IpAddr) -> io::Result<()> {
    SockRef::from(sock).bind_device(Some(iface.as_bytes()))
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
fn bind_device(sock: &TcpSocket, iface: &str, ip: IpAddr) -> io::Result<()> {
    let idx = std::num::NonZeroU32::new(nix_if_nametoindex(iface)?)
        .ok_or_else(|| io::Error::other("bad interface"))?;
    match ip {
        IpAddr::V4(_) => SockRef::from(sock).bind_device_by_index_v4(Some(idx)),
        IpAddr::V6(_) => SockRef::from(sock).bind_device_by_index_v6(Some(idx)),
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
fn bind_device(_: &TcpSocket, _: &str, _: IpAddr) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bind_interface is not supported on this platform",
    ))
}
