mod group;
mod http;
mod shadowsocks;
mod socks;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use sbr_config::{Dial, Outbound as OutboundConfig, OutboundKind};
use sbr_core::dial::{self, DialOptions};
use sbr_core::{BoxFuture, Destination, Stream};

pub use group::Selector;

pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    fn kind(&self) -> &'static str;
    /// Open a TCP stream to `dest` through this outbound.
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>>;
    fn as_selector(&self) -> Option<&Selector> {
        None
    }
}

/// How an outbound reaches its server: the system network, or another
/// outbound (`detour`).
#[derive(Clone)]
pub enum Upstream {
    System(DialOptions),
    Detour(Arc<dyn Outbound>),
}

impl Upstream {
    pub async fn connect(&self, dest: &Destination) -> io::Result<Stream> {
        match self {
            Upstream::System(opts) => Ok(Box::new(dial::connect(dest, opts).await?)),
            Upstream::Detour(o) => o.connect(dest).await,
        }
    }
}

struct Direct {
    tag: String,
    opts: DialOptions,
}

impl Outbound for Direct {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "direct"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move { Ok(Box::new(dial::connect(dest, &self.opts).await?) as Stream) })
    }
}

struct Block {
    tag: String,
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
pub fn build_all(configs: &[OutboundConfig]) -> Result<Vec<Arc<dyn Outbound>>, BuildError> {
    let index: HashMap<&str, usize> = configs
        .iter()
        .enumerate()
        .map(|(i, c)| (c.tag.as_str(), i))
        .collect();
    let mut built: Vec<Option<Arc<dyn Outbound>>> = vec![None; configs.len()];
    let mut visiting = vec![false; configs.len()];
    for i in 0..configs.len() {
        build_one(i, configs, &index, &mut built, &mut visiting)?;
    }
    Ok(built.into_iter().map(|o| o.expect("built")).collect())
}

fn build_one(
    i: usize,
    configs: &[OutboundConfig],
    index: &HashMap<&str, usize>,
    built: &mut Vec<Option<Arc<dyn Outbound>>>,
    visiting: &mut Vec<bool>,
) -> Result<Arc<dyn Outbound>, BuildError> {
    if let Some(o) = &built[i] {
        return Ok(o.clone());
    }
    let cfg = &configs[i];
    if visiting[i] {
        return Err(BuildError::Cycle(i, cfg.tag.clone()));
    }
    visiting[i] = true;
    let dep = |tag: &str, built: &mut Vec<Option<Arc<dyn Outbound>>>, visiting: &mut Vec<bool>| {
        build_one(index[tag], configs, index, built, visiting)
    };
    let upstream =
        |d: &Dial, built: &mut Vec<_>, visiting: &mut Vec<_>| -> Result<Upstream, BuildError> {
            Ok(match &d.detour {
                Some(t) => Upstream::Detour(dep(t, built, visiting)?),
                None => Upstream::System(DialOptions::from(d)),
            })
        };
    let tag = cfg.tag.clone();
    let invalid = |e: String| BuildError::Invalid(i, tag.clone(), e);
    let out: Arc<dyn Outbound> = match &cfg.kind {
        OutboundKind::Direct(d) => {
            if d.detour.is_some() {
                return Err(invalid("direct outbound cannot have a detour".into()));
            }
            Arc::new(Direct {
                tag: cfg.tag.clone(),
                opts: DialOptions::from(d),
            })
        }
        OutboundKind::Block => Arc::new(Block {
            tag: cfg.tag.clone(),
        }),
        OutboundKind::Socks(s) => Arc::new(socks::Socks::new(
            cfg.tag.clone(),
            s,
            upstream(&s.dial, built, visiting)?,
        )),
        OutboundKind::Http(h) => Arc::new(http::HttpConnect::new(
            cfg.tag.clone(),
            h,
            upstream(&h.dial, built, visiting)?,
        )),
        OutboundKind::Shadowsocks(s) => Arc::new(
            shadowsocks::Shadowsocks::new(cfg.tag.clone(), s, upstream(&s.dial, built, visiting)?)
                .map_err(invalid)?,
        ),
        OutboundKind::Selector(g) => {
            let members = g
                .outbounds
                .iter()
                .map(|t| dep(t, built, visiting))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Selector::new(
                cfg.tag.clone(),
                "selector",
                members,
                g.default.as_deref(),
            ))
        }
        OutboundKind::UrlTest(g) => {
            // No latency probing yet: behaves as a selector pinned to the first member.
            let members = g
                .outbounds
                .iter()
                .map(|t| dep(t, built, visiting))
                .collect::<Result<Vec<_>, _>>()?;
            Arc::new(Selector::new(cfg.tag.clone(), "urltest", members, None))
        }
    };
    visiting[i] = false;
    built[i] = Some(out.clone());
    Ok(out)
}
