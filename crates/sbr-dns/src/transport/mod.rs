//! Upstream transports. Every remote transport reaches its server through
//! an [`Outbound`] (the server's `detour`, or a direct dialer built from its
//! dial fields), so DNS can be proxied like any other traffic.

mod https;
mod local;
mod stream;
pub(crate) mod tls;
mod udp;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::Message;
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Host, Outbound, Stream};

pub(crate) use https::Https;
pub(crate) use local::{Hosts, Local, for_dial};
pub(crate) use stream::StreamTransport;
pub(crate) use udp::Udp;

pub(crate) trait Transport: Send + Sync {
    /// Send `query` (ID irrelevant: transports pick their own) and return
    /// the response.
    fn exchange<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, io::Result<Message>>;
}

/// Resolves a server's own domain through its `domain_resolver`.
pub(crate) type Resolver = Arc<dyn Fn(Arc<str>) -> BoxFuture<'static, io::Result<Vec<IpAddr>>> + Send + Sync>;

/// A remote server: where it is and how to get there.
#[derive(Clone)]
pub(crate) struct Remote {
    pub host: Host,
    pub port: u16,
    pub dialer: Arc<dyn Outbound>,
    /// Set when the server address is a domain to be resolved locally.
    pub resolver: Option<Resolver>,
}

impl Remote {
    /// Candidate destinations in dial order. Without a resolver a domain is
    /// passed through (a `detour` resolves it on its side).
    async fn targets(&self) -> io::Result<Vec<Destination>> {
        match (&self.host, &self.resolver) {
            (Host::Domain(d), Some(r)) => {
                let ips = r(d.clone()).await?;
                if ips.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::NotFound, format!("no address for {d}")));
                }
                Ok(ips
                    .into_iter()
                    .map(|ip| Destination::new(Host::Ip(ip), self.port))
                    .collect())
            }
            (host, _) => Ok(vec![Destination::new(host.clone(), self.port)]),
        }
    }

    pub async fn connect(&self) -> io::Result<Stream> {
        let mut last = None;
        for t in self.targets().await? {
            match self.dialer.connect(&t).await {
                Ok(s) => return Ok(s),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no target")))
    }

    pub async fn connect_udp(&self) -> io::Result<(BoxPacketConn, Destination)> {
        let t = self.targets().await?.swap_remove(0);
        Ok((self.dialer.connect_udp(&t).await?, t))
    }
}

/// A transport that answers every query with a fixed rcode (legacy `rcode://`).
pub(crate) struct Rcode(pub u16);

impl Transport for Rcode {
    fn exchange<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, io::Result<Message>> {
        Box::pin(async move { Ok(crate::msg::status(query, self.0)) })
    }
}
