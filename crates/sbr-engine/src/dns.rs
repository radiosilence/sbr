//! Glue between the engine and `sbr-dns`: dialers for DNS servers, and
//! giving FakeIP / reverse-mapped destinations their domain back.

use std::io;
use std::sync::{Arc, OnceLock, Weak};

use sbr_config::{DnsOptions, Options};
use sbr_core::dns::SystemDns;
use sbr_core::router::RuleSets;
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Host, Metadata, Outbound, Stream};
use sbr_dns::{DnsRouter, ServerDial};

use crate::outbound::{BuildContext, direct::Direct};
use crate::{Engine, Settings};

/// Outbounds, filled in once built. DNS servers are built first (outbounds
/// resolve through DNS) yet dial through outbounds (`detour`), so they hold
/// this weakly: the engine owns it, and dropping the engine breaks the cycle.
pub(crate) type LateOutbounds = Arc<OnceLock<Vec<Arc<dyn Outbound>>>>;

/// An outbound looked up by index on first use.
struct Late {
    tag: String,
    index: usize,
    all: Weak<OnceLock<Vec<Arc<dyn Outbound>>>>,
}

impl Late {
    fn get(&self) -> io::Result<Arc<dyn Outbound>> {
        self.all
            .upgrade()
            .and_then(|all| all.get().map(|v| v[self.index].clone()))
            .ok_or_else(|| io::Error::other(format!("outbound {} is not available", self.tag)))
    }
}

impl Outbound for Late {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "late"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move { self.get()?.connect(dest).await })
    }
    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move { self.get()?.connect_udp(dest).await })
    }
}

/// A `detour` for a dialer with its own `domain_resolver`: sing-box resolves
/// the server's domain locally in that case instead of leaving it to the
/// detour.
pub(crate) struct ResolveFirst {
    inner: Arc<dyn Outbound>,
    dns: Arc<dyn sbr_core::dns::Dns>,
    strategy: Option<sbr_config::DomainStrategy>,
}

impl ResolveFirst {
    pub fn new(
        inner: Arc<dyn Outbound>,
        dns: Arc<dyn sbr_core::dns::Dns>,
        strategy: Option<sbr_config::DomainStrategy>,
    ) -> Self {
        Self { inner, dns, strategy }
    }

    async fn targets(&self, dest: &Destination) -> io::Result<Vec<Destination>> {
        Ok(sbr_core::dial::resolve(dest, self.strategy, self.dns.as_ref())
            .await?
            .into_iter()
            .map(Destination::from)
            .collect())
    }
}

impl Outbound for ResolveFirst {
    fn tag(&self) -> &str {
        self.inner.tag()
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            let mut last = None;
            for t in self.targets(dest).await? {
                match self.inner.connect(&t).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last = Some(e),
                }
            }
            Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {dest}"))))
        })
    }
    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            let t = self.targets(dest).await?.into_iter().next();
            let t = t.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {dest}")))?;
            self.inner.connect_udp(&t).await
        })
    }
}

pub(crate) fn build(
    cfg: &DnsOptions,
    options: &Options,
    sets: &RuleSets,
    late: &LateOutbounds,
    settings: &Settings,
) -> Result<DnsRouter, sbr_dns::BuildError> {
    let dialer = |sd: &ServerDial| -> Arc<dyn Outbound> {
        let via = match &sd.dial.detour {
            Some(t) => Some(t.as_str()),
            // Legacy servers without detour went through the default outbound.
            None if sd.default_outbound => Some(options.final_outbound()),
            None => None,
        };
        match via.and_then(|t| options.outbounds.iter().position(|o| o.tag == t).map(|i| (t, i))) {
            Some((tag, index)) => Arc::new(Late {
                tag: tag.to_owned(),
                index,
                all: Arc::downgrade(late),
            }),
            // Server addresses reach this dialer already resolved (sbr-dns
            // resolves them through `domain_resolver`), so the OS resolver
            // here is never consulted for names.
            None => Arc::new(Direct::new(
                format!("dns:{}", sd.tag),
                sd.dial,
                &BuildContext {
                    dns: Arc::new(SystemDns),
                    default_resolver: None,
                },
            )),
        }
    };
    DnsRouter::new(cfg, sets, &dialer, &|p| std::fs::read(crate::resolve_path(settings, p)))
}

impl Engine {
    /// FakeIP: a fake destination address becomes the domain it stands for;
    /// with `reverse_mapping`, a real address that DNS answered recently
    /// gains that domain for matching. Fails for a fake address with no
    /// mapping, which sing-box refuses too.
    pub(crate) fn restore_domain(&self, meta: &mut Metadata) -> io::Result<()> {
        let Some(ip) = meta.destination.ip() else {
            return Ok(());
        };
        match self.dns.fakeip_lookup(ip) {
            Some(Some(domain)) => {
                meta.destination.host = Host::Domain(domain);
                Ok(())
            }
            Some(None) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing FakeIP record for {ip}"),
            )),
            None => {
                if meta.sniffed_domain.is_none() {
                    meta.sniffed_domain = self.dns.reverse_lookup(ip);
                }
                Ok(())
            }
        }
    }

    /// FakeIP for later datagrams of a UDP session.
    pub(crate) fn unfake(&self, d: Destination) -> Destination {
        match d.ip().and_then(|ip| self.dns.fakeip_lookup(ip)) {
            Some(Some(domain)) => Destination::new(Host::Domain(domain), d.port),
            _ => d,
        }
    }
}
