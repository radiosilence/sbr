//! The sbr runtime: builds inbounds and outbounds from a sing-box config and
//! moves bytes between them.

pub mod cache;
pub mod clash;
pub mod dispatch;
pub mod fetch;
mod httpx;
pub mod inbound;
pub mod outbound;
mod ruleset;
mod socks5;
pub mod track;
pub mod udp;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sbr_config::{InboundKind, Options};
use sbr_core::dns::{Dns, SystemDns};
use sbr_core::relay::{self, Traffic};
use sbr_core::router::Router;
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
    #[error("inbounds[{0}] ({1}): listen {2}: {3}")]
    Listen(usize, String, SocketAddr, io::Error),
    #[error("inbounds[{0}] ({1}): {2}")]
    Inbound(usize, String, String),
    /// Cache file, remote rule-sets, Clash API.
    #[error("{0}")]
    Service(String),
}

/// Knobs that are about the host, not the config.
#[derive(Clone)]
pub struct Settings {
    /// Per-direction relay buffer.
    pub relay_buffer: usize,
    /// Resolves relative paths (local rule-sets, cache files).
    pub base_dir: Option<std::path::PathBuf>,
    /// DNS implementation; defaults to the OS resolver.
    pub dns: Option<Arc<dyn Dns>>,
    /// Pre-opened TUN file descriptor (Apple Network Extension, Android
    /// VpnService). When set, the `tun` inbound adopts it instead of creating
    /// and configuring an interface.
    pub tun_fd: Option<i32>,
    /// Trust anchors for sbr's own HTTPS fetches (remote rule-sets, external
    /// UI, urltest). Defaults to the Mozilla roots (`webpki-roots`).
    pub http_roots: Option<Arc<rustls::RootCertStore>>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            relay_buffer: relay::DEFAULT_BUFFER,
            base_dir: None,
            dns: None,
            tun_fd: None,
            http_roots: None,
        }
    }
}

pub struct Engine {
    pub(crate) outbounds: Vec<Arc<dyn Outbound>>,
    pub(crate) router: Router,
    pub(crate) dns: Arc<dyn Dns>,
    pub(crate) nat: udp::Nat,
    pub traffic: Traffic,
    active: AtomicUsize,
    relay_buffer: usize,
    /// Live connections (Clash API, `interrupt_exist_connections`).
    pub tracker: Arc<track::Tracker>,
    /// `experimental.cache_file`, when enabled and openable.
    pub cache: Option<Arc<cache::CacheFile>>,
    pub(crate) groups: Arc<outbound::GroupEnv>,
    pub(crate) remote_sets: Option<Arc<ruleset::RemoteSets>>,
    pub(crate) http: fetch::HttpClient,
}

impl Engine {
    pub fn new(options: &Options, settings: &Settings) -> Result<Self, Error> {
        let dns: Arc<dyn Dns> = settings.dns.clone().unwrap_or_else(|| Arc::new(SystemDns));
        let cache = options.experimental.cache_file.as_ref().and_then(|c| {
            let path = resolve_path(settings, c.path.as_deref().unwrap_or("cache.db"));
            cache::CacheFile::open(&path, c)
                .inspect_err(|e| warn!("cache file: {e}"))
                .ok()
        });
        let http = fetch::HttpClient::new(settings.http_roots.clone());
        let tracker = Arc::new(track::Tracker::default());
        let groups = Arc::new(outbound::GroupEnv::new(tracker.clone(), cache.clone(), http.clone()));
        let ctx = BuildContext {
            dns: dns.clone(),
            groups: groups.clone(),
        };
        let outbounds = outbound::build_all(&options.outbounds, &ctx)?;
        let router = Router::new(
            &options.route.rules,
            &options.route.rule_sets,
            options.final_outbound(),
            |tag| outbounds.iter().position(|o| o.tag() == tag),
            |path| std::fs::read(resolve_path(settings, path)),
        )?
        .with_default_mode(
            options
                .experimental
                .clash_api
                .as_ref()
                .and_then(|c| c.default_mode.as_deref()),
            &options.route.rules,
        );
        if let Some(mode) = cache.as_ref().and_then(|c| c.load_mode()) {
            router.clash_mode().set(&mode);
        }
        let remote = ruleset::RemoteSets::new(&options.route.rule_sets, settings, cache.clone(), http.clone());
        let mut engine = Self {
            outbounds,
            router,
            dns,
            nat: udp::Nat::default(),
            traffic: Traffic::default(),
            active: AtomicUsize::new(0),
            relay_buffer: settings.relay_buffer,
            tracker,
            cache,
            groups,
            remote_sets: None,
            http,
        };
        if !remote.sets.is_empty() {
            remote.restore(&engine, settings);
            engine.remote_sets = Some(Arc::new(remote));
        }
        Ok(engine)
    }

    /// Build everything (outbounds, router, local rule-sets) without opening
    /// the cache file or touching the network: `sbr check`.
    pub fn check(options: &Options, settings: &Settings) -> Result<(), Error> {
        let mut o = options.clone();
        o.experimental.cache_file = None;
        Self::new(&o, settings).map(drop)
    }

    pub fn router(&self) -> &Router {
        &self.router
    }

    /// Delay history and urltest groups.
    pub fn groups(&self) -> &Arc<outbound::GroupEnv> {
        &self.groups
    }

    /// Outbound tags from the leaf that will carry traffic up to `outbound`
    /// (sing-box `chains` order).
    pub fn chain(&self, outbound: usize) -> Vec<Arc<str>> {
        let mut cur = self.outbounds[outbound].clone();
        let mut chain: Vec<Arc<str>> = vec![cur.tag().into()];
        for _ in 0..32 {
            let next = match cur.as_group() {
                Some(g) => g.selected(),
                None => break,
            };
            chain.push(next.tag().into());
            cur = next;
        }
        chain.reverse();
        chain
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
    /// Where the Clash API listens, if enabled.
    pub clash_api: Option<SocketAddr>,
    tasks: JoinSet<()>,
}

impl Instance {
    /// Bind every inbound and start accepting. Must run inside a Tokio runtime.
    pub async fn start(options: &Options, settings: Settings) -> Result<Self, Error> {
        for w in &options.warnings {
            warn!("{w}");
        }
        let engine = Arc::new(Engine::new(options, &settings)?);
        if options.experimental.cache_file.is_some() && engine.cache.is_none() {
            return Err(Error::Service("cache file could not be opened".into()));
        }
        let mut tasks = JoinSet::new();
        if let Some(sets) = &engine.remote_sets {
            sets.initial(&engine).await.map_err(Error::Service)?;
            tasks.spawn(sets.clone().run(engine.clone()));
        }
        engine.groups.start();
        let mut clash_api = None;
        if let Some(api) = &options.experimental.clash_api
            && let Some((addr, serve)) = clash::start(engine.clone(), api, &settings, options)
                .await
                .map_err(Error::Service)?
        {
            clash_api = Some(addr);
            tasks.spawn(serve);
        }
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
            clash_api,
            tasks,
        })
    }

    /// Stop accepting. In-flight connections finish on their own or die
    /// with the runtime.
    pub fn shutdown(mut self) {
        self.tasks.abort_all();
        self.engine.groups.shutdown();
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
