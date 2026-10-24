use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// A destination as requested by the client: either a resolved IP or a
/// domain we have not (and may never) resolve locally.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Domain(Arc<str>),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Destination {
    pub host: Host,
    pub port: u16,
}

impl Destination {
    pub fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }

    /// Parse `host:port`, `[v6]:port` or a bare domain; domains are
    /// lowercased because every matcher compares in lowercase.
    pub fn from_host_port(host: &str, port: u16) -> Self {
        let trimmed = host.trim_start_matches('[').trim_end_matches(']');
        let host = match trimmed.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(trimmed.trim_end_matches('.').to_ascii_lowercase().into()),
        };
        Self { host, port }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self.host {
            Host::Ip(ip) => Some(ip),
            Host::Domain(_) => None,
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match &self.host {
            Host::Domain(d) => Some(d),
            Host::Ip(_) => None,
        }
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.ip().map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl From<SocketAddr> for Destination {
    fn from(a: SocketAddr) -> Self {
        Self {
            host: Host::Ip(a.ip().to_canonical()),
            port: a.port(),
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            Host::Ip(ip) => write!(f, "{ip}:{}", self.port),
            Host::Domain(d) => write!(f, "{d}:{}", self.port),
        }
    }
}

/// Go's `!netip.Addr.IsGlobalUnicast()`-ish check that sing-box uses for
/// `ip_is_private`: anything that is not a public unicast address.
pub fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00 // unique local
                || (seg0 & 0xffc0) == 0xfe80 // link local
        }
    }
}
