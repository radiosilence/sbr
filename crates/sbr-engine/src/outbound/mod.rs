//! Outbound registry. Each protocol lives in its own module and registers in
//! `build_one`; protocol modules only depend on `BuildContext` and `Upstream`.

mod direct;
mod group;
mod http;
mod proto;
mod shadowsocks;
mod socks;
mod trojan;
mod vision;
mod vless;
mod vmess;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use sbr_config::{Dial, Outbound as OutboundConfig, OutboundKind};
use sbr_core::dial::{self, DialOptions};
use sbr_core::dns::Dns;
use sbr_core::{BoxPacketConn, Destination, Stream};

pub use group::Selector;
pub use sbr_core::{Group, Outbound, PacketConn};

/// Shared services outbounds may need while being built.
#[derive(Clone)]
pub struct BuildContext {
    pub dns: Arc<dyn Dns>,
    /// Resolves relative file paths in outbound options (certificates).
    pub base_dir: Option<std::path::PathBuf>,
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

    /// Like [`Upstream::connect`], plus the raw socket when dialed directly
    /// (TLS fragmentation watches its ACKs).
    pub async fn connect_raw(&self, dest: &Destination) -> io::Result<(Stream, Option<i32>)> {
        match self {
            Upstream::System(opts, dns) => {
                let s = dial::connect(dest, opts, dns.as_ref()).await?;
                #[cfg(unix)]
                let fd = Some(std::os::fd::AsRawFd::as_raw_fd(&s));
                #[cfg(not(unix))]
                let fd = None;
                Ok((Box::new(s), fd))
            }
            Upstream::Detour(o) => Ok((o.connect(dest).await?, None)),
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
    };
    for i in 0..configs.len() {
        b.build(i)?;
    }
    Ok(b.built.into_iter().map(|o| o.expect("built")).collect())
}

struct Builder<'a> {
    configs: &'a [OutboundConfig],
    index: HashMap<&'a str, usize>,
    ctx: &'a BuildContext,
    built: Vec<Option<Arc<dyn Outbound>>>,
    visiting: Vec<bool>,
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
        let out: Arc<dyn Outbound> = match &cfg.kind {
            OutboundKind::Direct(d) => {
                if d.detour.is_some() {
                    return Err(invalid("direct outbound cannot have a detour".into()));
                }
                Arc::new(direct::Direct::new(tag, d, self.ctx))
            }
            OutboundKind::Block => Arc::new(direct::Block { tag }),
            OutboundKind::Socks(s) => Arc::new(socks::Socks::new(tag, s, self.upstream(&s.dial)?)),
            OutboundKind::Http(h) => {
                let up = self.upstream(&h.dial)?;
                Arc::new(http::HttpConnect::new(tag, h, up, self.ctx).map_err(invalid)?)
            }
            OutboundKind::Trojan(c) => {
                let up = self.upstream(&c.common.dial)?;
                Arc::new(trojan::Trojan::new(tag, c, up, self.ctx).map_err(invalid)?)
            }
            OutboundKind::Vless(c) => {
                let up = self.upstream(&c.common.dial)?;
                Arc::new(vless::Vless::new(tag, c, up, self.ctx).map_err(invalid)?)
            }
            OutboundKind::Vmess(c) => {
                let up = self.upstream(&c.common.dial)?;
                Arc::new(vmess::Vmess::new(tag, c, up, self.ctx).map_err(invalid)?)
            }
            OutboundKind::Shadowsocks(s) => {
                Arc::new(shadowsocks::Shadowsocks::new(tag, s, self.upstream(&s.dial)?).map_err(invalid)?)
            }
            OutboundKind::Selector(g) => {
                let members = g.outbounds.iter().map(|t| self.dep(t)).collect::<Result<Vec<_>, _>>()?;
                Arc::new(Selector::new(tag, "selector", members, g.default.as_deref()))
            }
            OutboundKind::UrlTest(g) => {
                // No latency probing yet: behaves as a selector pinned to the first member.
                let members = g.outbounds.iter().map(|t| self.dep(t)).collect::<Result<Vec<_>, _>>()?;
                Arc::new(Selector::new(tag, "urltest", members, None))
            }
        };
        self.visiting[i] = false;
        self.built[i] = Some(out.clone());
        Ok(out)
    }
}
