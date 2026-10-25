use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use sbr_config::Dial;
use sbr_core::dial::{self, DialOptions};
use sbr_core::dns::Dns;
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Host, Outbound, PacketConn, Stream};
use tokio::net::UdpSocket;

use super::BuildContext;

pub struct Direct {
    tag: String,
    opts: DialOptions,
    dns: Arc<dyn Dns>,
}

impl Direct {
    pub fn new(tag: String, d: &Dial, ctx: &BuildContext) -> Self {
        Self {
            dns: ctx.dns_for(Some(&tag), d),
            opts: DialOptions::from(d),
            tag,
        }
    }
}

impl Outbound for Direct {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "direct"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move { Ok(Box::new(dial::connect(dest, &self.opts, self.dns.as_ref()).await?) as Stream) })
    }
    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            Ok(Box::new(DirectPacket::new(dest, self.opts.clone(), self.dns.clone()).await?) as BoxPacketConn)
        })
    }
}

/// A plain UDP socket. Family follows the first destination; domains are
/// resolved per send through the engine's DNS (which caches).
pub struct DirectPacket {
    sock: UdpSocket,
    v6: bool,
    opts: DialOptions,
    dns: Arc<dyn Dns>,
}

impl DirectPacket {
    pub async fn new(first: &Destination, opts: DialOptions, dns: Arc<dyn Dns>) -> io::Result<Self> {
        let addr = resolve_one(first, &opts, dns.as_ref()).await?;
        let sock = dial::bind_udp(addr.ip(), &opts)?;
        Ok(Self {
            sock,
            v6: addr.is_ipv6(),
            opts,
            dns,
        })
    }
}

async fn resolve_one(d: &Destination, opts: &DialOptions, dns: &dyn Dns) -> io::Result<SocketAddr> {
    match &d.host {
        Host::Ip(ip) => Ok(SocketAddr::new(*ip, d.port)),
        Host::Domain(_) => dial::resolve(d, opts.domain_strategy, dns)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {d}"))),
    }
}

impl PacketConn for DirectPacket {
    fn send_to<'a>(&'a self, buf: &'a [u8], dest: &'a Destination) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut addr = resolve_one(dest, &self.opts, self.dns.as_ref()).await?;
            // An IPv6 socket reaches IPv4 via mapped addresses; an IPv4 one can't reach IPv6.
            if self.v6
                && let std::net::IpAddr::V4(v4) = addr.ip()
            {
                addr = SocketAddr::new(v4.to_ipv6_mapped().into(), addr.port());
            }
            self.sock.send_to(buf, addr).await.map(|_| ())
        })
    }
    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<(usize, Destination)>> {
        Box::pin(async move {
            let (n, from) = self.sock.recv_from(buf).await?;
            Ok((n, Destination::from(from)))
        })
    }
}

pub struct Block {
    pub tag: String,
}

impl Outbound for Block {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "block"
    }
    fn connect<'a>(&'a self, _: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async { Err(io::Error::new(io::ErrorKind::PermissionDenied, "blocked")) })
    }
    fn connect_udp<'a>(&'a self, _: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async { Err(io::Error::new(io::ErrorKind::PermissionDenied, "blocked")) })
    }
}
