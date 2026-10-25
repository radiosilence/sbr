//! Outbound registry. Each protocol lives in its own module and registers in
//! `build_one`; protocol modules only depend on `BuildContext` and `Upstream`.

mod direct;
pub mod group;
mod http;
mod shadowsocks;
mod socks;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use sbr_config::{Dial, Outbound as OutboundConfig, OutboundKind};
use sbr_core::dial::{self, DialOptions};
use sbr_core::dns::Dns;
use sbr_core::{BoxPacketConn, Destination, Stream};

pub use group::{GroupEnv, Selector, UrlTest};
pub use sbr_core::{Group, Outbound, PacketConn};

/// Shared services outbounds may need while being built.
#[derive(Clone)]
pub struct BuildContext {
    pub dns: Arc<dyn Dns>,
    /// Services `selector`/`urltest` use (connection registry, cache file, probes).
    pub groups: Arc<GroupEnv>,
}

/// How an outbound reaches its server: the system network, or another
/// outbound (`detour`).
#[derive(Clone)]
pub enum Upstream {
    System(DialOptions, Arc<dyn Dns>),
    Detour(Arc<dyn Outbound>),
}

impl Upstream {
    pub fn new(d: &Dial, ctx: &BuildContext, detour: Option<Arc<dyn Outbound>>) -> Self {
        match detour {
            Some(o) => Upstream::Detour(o),
            None => Upstream::System(DialOptions::from(d), ctx.dns.clone()),
        }
    }

    pub async fn connect(&self, dest: &Destination) -> io::Result<Stream> {
        match self {
            Upstream::System(opts, dns) => Ok(Box::new(dial::connect(dest, opts, dns.as_ref()).await?)),
            Upstream::Detour(o) => o.connect(dest).await,
        }
    }

    /// A UDP association towards `dest` (the protocol's server).
    pub async fn connect_udp(&self, dest: &Destination) -> io::Result<BoxPacketConn> {
        match self {
            Upstream::System(opts, dns) => Ok(Box::new(
                direct::DirectPacket::new(dest, opts.clone(), dns.clone()).await?,
            )),
            Upstream::Detour(o) => o.connect_udp(dest).await,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("outbounds[{0}]: detour/group cycle through {1:?}")]
    Cycle(usize, String),
    #[error("outbounds[{0}] ({1}): {2}")]
    Invalid(usize, String, String),
}

/// Instantiate every outbound, resolving detours and group members first.
/// Returns them in config order so indices match the router's.
pub fn build_all(configs: &[OutboundConfig], ctx: &BuildContext) -> Result<Vec<Arc<dyn Outbound>>, BuildError> {
    let index: HashMap<&str, usize> = configs.iter().enumerate().map(|(i, c)| (c.tag.as_str(), i)).collect();
    let mut b = Builder {
        configs,
        index,
        ctx,
        built: vec![None; configs.len()],
        visiting: vec![false; configs.len()],
        servers: HashMap::new(),
        urltests: HashMap::new(),
    };
    for i in 0..configs.len() {
        b.build(i)?;
    }
    let _ = ctx.groups.servers.set(b.servers);
    let _ = ctx.groups.urltests.set(b.urltests);
    Ok(b.built.into_iter().map(|o| o.expect("built")).collect())
}

struct Builder<'a> {
    configs: &'a [OutboundConfig],
    index: HashMap<&'a str, usize>,
    ctx: &'a BuildContext,
    built: Vec<Option<Arc<dyn Outbound>>>,
    visiting: Vec<bool>,
    /// Leaf tag → how to reach its own server (URL-less urltest probes).
    servers: HashMap<String, (Upstream, Destination)>,
    urltests: HashMap<String, Arc<UrlTest>>,
}

/// The server and dialer of outbounds that have one. Protocols added later
/// should be listed here so URL-less `urltest` can measure them.
fn server_of(kind: &OutboundKind) -> Option<(&sbr_config::ServerAddr, &Dial)> {
    match kind {
        OutboundKind::Socks(s) => Some((&s.server, &s.dial)),
        OutboundKind::Http(s) => Some((&s.server, &s.dial)),
        OutboundKind::Shadowsocks(s) => Some((&s.server, &s.dial)),
        _ => None,
    }
}

impl Builder<'_> {
    fn dep(&mut self, tag: &str) -> Result<Arc<dyn Outbound>, BuildError> {
        self.build(self.index[tag])
    }

    fn upstream(&mut self, d: &Dial) -> Result<Upstream, BuildError> {
        let detour = match &d.detour {
            Some(t) => Some(self.dep(t)?),
            None => None,
        };
        Ok(Upstream::new(d, self.ctx, detour))
    }

    fn build(&mut self, i: usize) -> Result<Arc<dyn Outbound>, BuildError> {
        if let Some(o) = &self.built[i] {
            return Ok(o.clone());
        }
        let cfg = &self.configs[i];
        if self.visiting[i] {
            return Err(BuildError::Cycle(i, cfg.tag.clone()));
        }
        self.visiting[i] = true;
        let tag = cfg.tag.clone();
        let invalid = |e: String| BuildError::Invalid(i, cfg.tag.clone(), e);
        if let Some((server, dial)) = server_of(&cfg.kind) {
            let up = self.upstream(dial)?;
            let dest = Destination::from_host_port(&server.server, server.server_port);
            self.servers.insert(tag.clone(), (up, dest));
        }
        let out: Arc<dyn Outbound> = match &cfg.kind {
            OutboundKind::Direct(d) => {
                if d.detour.is_some() {
                    return Err(invalid("direct outbound cannot have a detour".into()));
                }
                Arc::new(direct::Direct::new(tag, d, self.ctx))
            }
            OutboundKind::Block => Arc::new(direct::Block { tag }),
            OutboundKind::Socks(s) => Arc::new(socks::Socks::new(tag, s, self.upstream(&s.dial)?)),
            OutboundKind::Http(h) => Arc::new(http::HttpConnect::new(tag, h, self.upstream(&h.dial)?)),
            OutboundKind::Shadowsocks(s) => {
                Arc::new(shadowsocks::Shadowsocks::new(tag, s, self.upstream(&s.dial)?).map_err(invalid)?)
            }
            OutboundKind::Selector(g) => {
                let members = g.outbounds.iter().map(|t| self.dep(t)).collect::<Result<Vec<_>, _>>()?;
                Arc::new(Selector::new(
                    tag,
                    members,
                    g.default.as_deref(),
                    g.interrupt_exist_connections,
                    self.ctx.groups.clone(),
                ))
            }
            OutboundKind::UrlTest(g) => {
                let members = g.outbounds.iter().map(|t| self.dep(t)).collect::<Result<Vec<_>, _>>()?;
                let u = UrlTest::new(tag.clone(), members, g, self.ctx.groups.clone()).map_err(invalid)?;
                self.urltests.insert(tag, u.clone());
                u
            }
        };
        self.visiting[i] = false;
        self.built[i] = Some(out.clone());
        Ok(out)
    }
}
