use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use sbr_config::{Network, SocksOutbound, UdpOverTcp};
use sbr_core::dns::Dns;
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Host, PacketConn, Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use super::Upstream;
use crate::socks5;
use sbr_core::Outbound;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Version {
    V4,
    V4a,
    V5,
}

pub struct Socks {
    tag: String,
    server: Destination,
    version: Version,
    auth: Option<(String, String)>,
    network: Option<Network>,
    uot: Option<UdpOverTcp>,
    upstream: Upstream,
    dns: Arc<dyn Dns>,
}

impl Socks {
    pub fn new(tag: String, c: &SocksOutbound, upstream: Upstream, dns: Arc<dyn Dns>) -> Self {
        let auth = c.username.clone().map(|u| (u, c.password.clone().unwrap_or_default()));
        let version = match c.version.as_str() {
            "4" => Version::V4,
            "4a" => Version::V4a,
            _ => Version::V5,
        };
        Self {
            tag,
            server: Destination::from_host_port(&c.server.server, c.server.server_port),
            version,
            auth,
            network: c.network,
            uot: c.udp_over_tcp,
            upstream,
            dns,
        }
    }

    fn auth(&self) -> Option<(&str, &str)> {
        self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()))
    }

    async fn open(&self, dest: &Destination) -> io::Result<Stream> {
        let mut s = self.upstream.connect(&self.server).await?;
        match self.version {
            Version::V5 => socks5::client_connect(&mut s, dest, self.auth()).await?,
            v => {
                // SOCKS4 can only carry IPv4; 4a lets the server resolve.
                let dest = match (&dest.host, v) {
                    (Host::Domain(_), Version::V4) => {
                        let ip = self
                            .dns
                            .lookup(
                                dest.domain().unwrap_or_default(),
                                Some(sbr_config::DomainStrategy::Ipv4Only),
                            )
                            .await?
                            .into_iter()
                            .find(IpAddr::is_ipv4)
                            .ok_or_else(|| {
                                io::Error::new(io::ErrorKind::NotFound, format!("no IPv4 address for {dest}"))
                            })?;
                        Destination::new(Host::Ip(ip), dest.port)
                    }
                    _ => dest.clone(),
                };
                socks4_connect(&mut s, &dest, self.auth.as_ref().map(|a| a.0.as_str())).await?
            }
        }
        Ok(s)
    }
}

async fn socks4_connect(s: &mut Stream, dest: &Destination, user: Option<&str>) -> io::Result<()> {
    let mut req = vec![4, 1];
    req.extend_from_slice(&dest.port.to_be_bytes());
    let domain = match &dest.host {
        Host::Ip(IpAddr::V4(ip)) => {
            req.extend_from_slice(&ip.octets());
            None
        }
        Host::Ip(IpAddr::V6(_)) => {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "SOCKS4 cannot reach IPv6"));
        }
        Host::Domain(d) => {
            req.extend_from_slice(&[0, 0, 0, 1]); // 4a marker
            Some(d)
        }
    };
    req.extend_from_slice(user.unwrap_or_default().as_bytes());
    req.push(0);
    if let Some(d) = domain {
        req.extend_from_slice(d.as_bytes());
        req.push(0);
    }
    s.write_all(&req).await?;
    s.flush().await?;
    let mut rep = [0u8; 8];
    s.read_exact(&mut rep).await?;
    if rep[1] != 90 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS4 server replied {}", rep[1]),
        ));
    }
    Ok(())
}

impl Outbound for Socks {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "socks"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            if self.network == Some(Network::Udp) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "socks: TCP disabled by `network`",
                ));
            }
            self.open(dest).await
        })
    }

    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            if self.network == Some(Network::Tcp) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "socks: UDP disabled by `network`",
                ));
            }
            if let Some(uot) = self.uot {
                let s = self.open(&super::uot::request_destination(uot.version)).await?;
                return Ok(Box::new(super::uot::UotConn::new(s, uot.version, dest)?) as BoxPacketConn);
            }
            if self.version != Version::V5 {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "socks: UDP needs SOCKS5"));
            }
            let mut ctrl = self.upstream.connect(&self.server).await?;
            let any = Destination::new(Host::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0);
            let bound = socks5::client_command(&mut ctrl, socks5::CMD_UDP_ASSOCIATE, &any, self.auth()).await?;
            // Servers commonly answer 0.0.0.0: the relay is on the server's host.
            let relay = match bound.ip() {
                Some(ip) if !ip.is_unspecified() => bound,
                _ => Destination::new(self.server.host.clone(), bound.port),
            };
            // Dialing directly, the relay's name is resolved once here so
            // replies can be matched against the address datagrams go to.
            let relay = match (&relay.host, &self.upstream) {
                (Host::Domain(_), Upstream::System(opts, dns)) => {
                    let addr = sbr_core::dial::resolve(&relay, opts.domain_strategy, dns.as_ref())
                        .await?
                        .into_iter()
                        .next()
                        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {relay}")))?;
                    Destination::from(addr)
                }
                _ => relay,
            };
            let conn = self.upstream.connect_udp(&relay).await?;
            Ok(Box::new(SocksPacket::new(conn, relay, ctrl)) as BoxPacketConn)
        })
    }
}

/// RFC 1928 UDP relay client. The association lives as long as the TCP
/// control connection, which a background task watches.
struct SocksPacket {
    conn: BoxPacketConn,
    relay: Destination,
    closed: watch::Receiver<bool>,
    watcher: tokio::task::JoinHandle<()>,
    send_buf: Mutex<Option<Vec<u8>>>,
}

impl SocksPacket {
    fn new(conn: BoxPacketConn, relay: Destination, mut ctrl: Stream) -> Self {
        let (tx, closed) = watch::channel(false);
        let watcher = tokio::spawn(async move {
            let mut sink = [0u8; 64];
            while matches!(ctrl.read(&mut sink).await, Ok(n) if n > 0) {}
            let _ = tx.send(true);
        });
        Self {
            conn,
            relay,
            closed,
            watcher,
            send_buf: Mutex::new(Some(Vec::with_capacity(2048))),
        }
    }
}

impl Drop for SocksPacket {
    fn drop(&mut self) {
        // Dropping the control connection ends the association server-side.
        self.watcher.abort();
    }
}

impl PacketConn for SocksPacket {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            if *self.closed.borrow() {
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            let mut out = self.send_buf.lock().unwrap().take().unwrap_or_default();
            out.clear();
            out.extend_from_slice(&[0, 0, 0]);
            socks5::write_addr(&mut out, dest)?;
            out.extend_from_slice(buf);
            let r = self.conn.send_to(&out, &self.relay).await;
            *self.send_buf.lock().unwrap() = Some(out);
            r
        })
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(async move {
            let mut closed = self.closed.clone();
            loop {
                let (n, source) = tokio::select! {
                    r = self.conn.recv_from(buf) => r?,
                    _ = closed.wait_for(|c| *c) => return Err(io::ErrorKind::ConnectionAborted.into()),
                };
                if !from_relay(&source, &self.relay) {
                    continue;
                }
                if n < 4 || buf[2] != 0 {
                    continue; // fragments are optional and unsupported (like sing-box)
                }
                let mut cur = std::io::Cursor::new(&buf[3..n]);
                let Ok(from) = socks5::read_addr(&mut cur).await else {
                    continue;
                };
                let off = 3 + cur.position() as usize;
                buf.copy_within(off..n, 0);
                return Ok((n - off, from));
            }
        })
    }
}

/// Only the relay the server named may answer on the association.
fn from_relay(source: &Destination, relay: &Destination) -> bool {
    source.port == relay.port
        && match (&source.host, &relay.host) {
            (Host::Ip(a), Host::Ip(b)) => a.to_canonical() == b.to_canonical(),
            (Host::Domain(a), Host::Domain(b)) => a.eq_ignore_ascii_case(b),
            // Through a detour the relay's name is resolved remotely, so its
            // address is not known here.
            (Host::Ip(_), Host::Domain(_)) => true,
            (Host::Domain(_), Host::Ip(_)) => false,
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_only_from_relay() {
        let relay = Destination::from_host_port("192.0.2.1", 1080);
        assert!(from_relay(&relay, &relay));
        assert!(from_relay(
            &Destination::from_host_port("::ffff:192.0.2.1", 1080),
            &relay
        ));
        assert!(!from_relay(&Destination::from_host_port("192.0.2.2", 1080), &relay));
        assert!(!from_relay(&Destination::from_host_port("192.0.2.1", 1081), &relay));
    }
}
