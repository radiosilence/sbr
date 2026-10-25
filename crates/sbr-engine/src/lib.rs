//! The sbr runtime: builds inbounds and outbounds from a sing-box config and
//! moves bytes between them.

pub mod dispatch;
mod dns;
mod httpx;
pub mod inbound;
pub mod outbound;
mod socks5;
pub mod udp;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sbr_config::{InboundKind, Options};
use sbr_core::dns::{Dns, SystemDns};
use sbr_core::relay::{self, Traffic};
use sbr_core::router::{Router, RuleSets};
use sbr_core::{Metadata, Stream};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

pub use dispatch::{InboundStream, OpenError};
pub use outbound::{BuildContext, Group, Outbound, PacketConn, Selector};
pub use sbr_config;
pub use sbr_core;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] sbr_config::Error),
    #[error(transparent)]
    Outbound(#[from] outbound::BuildError),
    #[error(transparent)]
    Router(#[from] sbr_core::router::BuildError),
    #[error(transparent)]
    Dns(#[from] sbr_dns::BuildError),
    #[error("inbounds[{0}] ({1}): listen {2}: {3}")]
    Listen(usize, String, SocketAddr, io::Error),
    #[error("inbounds[{0}] ({1}): {2}")]
    Inbound(usize, String, String),
}

/// Knobs that are about the host, not the config.
#[derive(Clone)]
pub struct Settings {
    /// Per-direction relay buffer.
    pub relay_buffer: usize,
    /// Resolves relative paths (local rule-sets, cache files).
    pub base_dir: Option<std::path::PathBuf>,
    /// DNS implementation, overriding the config's `dns` section (which
    /// otherwise builds an `sbr_dns::DnsRouter`; no section means the OS
    /// resolver).
    pub dns: Option<Arc<dyn Dns>>,
    /// Pre-opened TUN file descriptor (Apple Network Extension, Android
    /// VpnService). When set, the `tun` inbound adopts it instead of creating
    /// and configuring an interface.
    pub tun_fd: Option<i32>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            relay_buffer: relay::DEFAULT_BUFFER,
            base_dir: None,
            dns: None,
            tun_fd: None,
        }
    }
}

pub struct Engine {
    pub(crate) outbounds: Vec<Arc<dyn Outbound>>,
    pub(crate) router: Router,
    pub(crate) dns: Arc<dyn Dns>,
    pub(crate) nat: udp::Nat,
    /// Owns the outbounds DNS servers dial through (see `dns::LateOutbounds`).
    _dns_outbounds: dns::LateOutbounds,
    pub traffic: Traffic,
    active: AtomicUsize,
    relay_buffer: usize,
}

impl Engine {
    pub fn new(options: &Options, settings: &Settings) -> Result<Self, Error> {
        // Rule-sets are compiled once, for the route and DNS rules both.
        let rule_sets = RuleSets::compile(&options.route.rule_sets, |path| {
            std::fs::read_to_string(resolve_path(settings, path))
        })?;
        let late = dns::LateOutbounds::default();
        let dns: Arc<dyn Dns> = match (&settings.dns, &options.dns) {
            (Some(d), _) => d.clone(),
            (None, Some(cfg)) => Arc::new(dns::build(cfg, options, &rule_sets, &late, settings)?),
            (None, None) => Arc::new(SystemDns),
        };
        let ctx = BuildContext {
            dns: dns.clone(),
            default_resolver: options.route.default_domain_resolver.clone(),
        };
        let outbounds = outbound::build_all(&options.outbounds, &ctx)?;
        let _ = late.set(outbounds.clone());
        let router = Router::with_sets(&options.route.rules, &rule_sets, options.final_outbound(), |tag| {
            outbounds.iter().position(|o| o.tag() == tag)
        })?;
        Ok(Self {
            outbounds,
            router,
            dns,
            nat: udp::Nat::default(),
            _dns_outbounds: late,
            traffic: Traffic::default(),
            active: AtomicUsize::new(0),
            relay_buffer: settings.relay_buffer,
        })
    }

    pub fn outbound(&self, tag: &str) -> Option<&Arc<dyn Outbound>> {
        self.outbounds.iter().find(|o| o.tag() == tag)
    }

    pub fn outbounds(&self) -> &[Arc<dyn Outbound>] {
        &self.outbounds
    }

    pub fn dns(&self) -> &Arc<dyn Dns> {
        &self.dns
    }

    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub(crate) async fn relay<A>(&self, meta: &Metadata, mut client: A, mut remote: Stream) -> io::Result<()>
    where
        A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        self.active.fetch_add(1, Ordering::Relaxed);
        let r = relay::relay(&mut client, &mut remote, self.relay_buffer, &self.traffic).await;
        self.active.fetch_sub(1, Ordering::Relaxed);
        match r {
            Ok((up, down)) => {
                debug!(dest = %meta.destination, up, down, "closed");
                Ok(())
            }
            // Resets mid-stream are normal life for a proxy.
            Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

pub fn resolve_path(settings: &Settings, path: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(path);
    match &settings.base_dir {
        Some(base) if p.is_relative() => base.join(p),
        _ => p.to_path_buf(),
    }
}

/// A running config: the engine plus its listeners.
pub struct Instance {
    pub engine: Arc<Engine>,
    pub listening: Vec<(String, SocketAddr)>,
    tasks: JoinSet<()>,
}

impl Instance {
    /// Bind every inbound and start accepting. Must run inside a Tokio runtime.
    pub async fn start(options: &Options, settings: Settings) -> Result<Self, Error> {
        for w in &options.warnings {
            warn!("{w}");
        }
        let engine = Arc::new(Engine::new(options, &settings)?);
        let mut tasks = JoinSet::new();
        let mut listening = Vec::new();
        for (i, ib) in options.inbounds.iter().enumerate() {
            let p = match &ib.kind {
                InboundKind::Mixed(p) | InboundKind::Socks(p) | InboundKind::Http(p) => p,
                InboundKind::Tun(_) => {
                    return Err(Error::Inbound(i, ib.tag.clone(), "tun inbound not wired yet".into()));
                }
            };
            let addr = SocketAddr::new(p.listen.listen, p.listen.listen_port);
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| Error::Listen(i, ib.tag.clone(), addr, e))?;
            let local = listener
                .local_addr()
                .map_err(|e| Error::Listen(i, ib.tag.clone(), addr, e))?;
            info!(inbound = %ib.tag, %local, "listening");
            listening.push((ib.tag.clone(), local));
            let ctx = Arc::new(inbound::Context::new(engine.clone(), &ib.tag, &ib.kind));
            tasks.spawn(accept_loop(listener, ctx));
        }
        Ok(Self {
            engine,
            listening,
            tasks,
        })
    }

    /// Stop accepting. In-flight connections finish on their own or die
    /// with the runtime.
    pub fn shutdown(mut self) {
        self.tasks.abort_all();
    }
}

async fn accept_loop(listener: TcpListener, ctx: Arc<inbound::Context>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = inbound::handle(ctx.clone(), stream).await {
                        debug!(inbound = %ctx.tag, %peer, error = %e, "connection error");
                    }
                });
            }
            Err(e) => {
                // EMFILE and friends: back off instead of spinning.
                warn!(inbound = %ctx.tag, error = %e, "accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}
