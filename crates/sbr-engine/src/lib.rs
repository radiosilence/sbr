//! The sbr runtime: builds inbounds and outbounds from a sing-box config and
//! moves bytes between them.

pub mod cache;
pub mod clash;
pub mod dispatch;
mod dns;
pub mod fetch;
pub mod health;
mod httpx;
pub mod inbound;
pub mod outbound;
mod ruleset;
mod socks5;
pub mod tls;
pub mod track;
pub mod transport;
pub mod udp;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sbr_config::{InboundKind, Options};
use sbr_core::Metadata;
use sbr_core::dns::{Dns, SystemDns};
use sbr_core::relay::{self, Traffic};
use sbr_core::router::{ClashMode, Router, RuleSets};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

pub use dispatch::{InboundStream, OpenError};
pub use outbound::{BuildContext, Group, Outbound, PacketConn, Selector};
pub use sbr_config;
pub use sbr_core;

/// Built for a host with a hard memory limit (the iOS Network Extension's
/// ~50 MB): buffers and windows that scale memory per connection are sized
/// down.
pub(crate) const MOBILE: bool = cfg!(any(target_os = "ios", target_os = "tvos", target_os = "visionos"));

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
    /// DNS implementation, overriding the config's `dns` section (which
    /// otherwise builds an `sbr_dns::DnsRouter`; no section means the OS
    /// resolver).
    pub dns: Option<Arc<dyn Dns>>,
    /// Pre-opened TUN file descriptor (Apple Network Extension, Android
    /// VpnService). The `tun` inbound adopts it instead of creating an
    /// interface, and takes ownership: it is closed when the instance stops or
    /// fails to start.
    pub tun_fd: Option<i32>,
    /// Trust anchors for sbr's own HTTPS fetches (remote rule-sets, external
    /// UI, urltest). Defaults to the Mozilla roots (`webpki-roots`).
    pub http_roots: Option<Arc<rustls::RootCertStore>>,
    /// Cap on concurrent TCP connections, and separately on UDP NAT
    /// sessions; 0 = unlimited. Over the cap, new TCP connections are refused
    /// and new UDP flows dropped, so a burst can't push a memory-capped host
    /// (the iOS Network Extension) into jetsam.
    pub max_connections: usize,
    /// sbr extension for embedders: which TCP the `tun` inbound runs,
    /// overriding its `stack` field. `None` follows the config (`gvisor`
    /// is the userspace stack; `system`, `mixed` and unset are the kernel).
    pub tun_stack: Option<TunTcp>,
    /// Buffer and connection limits for the userspace TCP stack.
    pub tun_tcp: sbr_tun::TcpConfig,
}

/// Who terminates TCP from the TUN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunTcp {
    Kernel,
    Userspace,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            relay_buffer: relay::DEFAULT_BUFFER,
            base_dir: None,
            dns: None,
            tun_fd: None,
            http_roots: None,
            max_connections: 0,
            tun_stack: None,
            tun_tcp: sbr_tun::TcpConfig::default(),
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
    /// Live connections (Clash API, `interrupt_exist_connections`).
    pub tracker: Arc<track::Tracker>,
    /// `experimental.cache_file`, when enabled and openable.
    pub cache: Option<Arc<cache::CacheFile>>,
    pub(crate) groups: Arc<outbound::GroupEnv>,
    pub(crate) remote_sets: Option<Arc<ruleset::RemoteSets>>,
    pub(crate) http: fetch::HttpClient,
    pub(crate) max_connections: usize,
}

impl Engine {
    pub fn new(options: &Options, settings: &Settings) -> Result<Self, Error> {
        let cache = options.experimental.cache_file.as_ref().and_then(|c| {
            let path = resolve_path(settings, c.path.as_deref().unwrap_or("cache.db"));
            cache::CacheFile::open(&path, c)
                .inspect_err(|e| warn!("cache file: {e}"))
                .ok()
        });
        let http = fetch::HttpClient::new(settings.http_roots.clone());
        let tracker = Arc::new(track::Tracker::default());
        let groups = Arc::new(outbound::GroupEnv::new(tracker.clone(), cache.clone(), http.clone()));
        // Rule-sets are compiled once, for the route and DNS rules both;
        // remote ones are filled (and later refreshed) in place.
        let rule_sets = RuleSets::compile(&options.route.rule_sets, |path| {
            std::fs::read(resolve_path(settings, path))
        })?;
        // The Clash mode is shared by route and DNS `clash_mode` items.
        let dns_rules = options.dns.iter().flat_map(|d| d.rules.iter().map(|r| &r.rule));
        rule_sets.clash_mode().configure(
            options
                .experimental
                .clash_api
                .as_ref()
                .and_then(|c| c.default_mode.as_deref()),
            ClashMode::modes_in(options.route.rules.iter().chain(dns_rules)),
        );
        if let Some(mode) = cache.as_ref().and_then(|c| c.load_mode()) {
            rule_sets.clash_mode().set(&mode);
        }
        let late = dns::LateOutbounds::default();
        let dns: Arc<dyn Dns> = match (&settings.dns, &options.dns) {
            (Some(d), _) => d.clone(),
            (None, Some(cfg)) => Arc::new(dns::build(cfg, options, &rule_sets, &late, settings)?),
            (None, None) => Arc::new(SystemDns),
        };
        let ctx = BuildContext {
            dns: dns.clone(),
            base_dir: settings.base_dir.clone(),
            default_resolver: options.route.default_domain_resolver.clone(),
            groups: groups.clone(),
        };
        let outbounds = outbound::build_all(&options.outbounds, &ctx)?;
        let _ = late.set(outbounds.clone());
        let router = Router::with_sets(&options.route.rules, &rule_sets, options.final_outbound(), |tag| {
            outbounds.iter().position(|o| o.tag() == tag)
        })?;
        let remote = ruleset::RemoteSets::new(&options.route.rule_sets, settings, cache.clone(), http.clone());
        let mut engine = Self {
            outbounds,
            router,
            dns,
            nat: udp::Nat::default(),
            _dns_outbounds: late,
            traffic: Traffic::default(),
            active: AtomicUsize::new(0),
            relay_buffer: settings.relay_buffer,
            max_connections: settings.max_connections,
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

    /// TCP connections the engine is routing, connecting or relaying.
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Open UDP NAT sessions.
    pub fn udp_sessions(&self) -> usize {
        self.nat.len()
    }

    /// The route rule a tracked connection matched, as dashboards show it:
    /// `payload => action`, or `final` for `route.final`.
    pub fn rule_label(&self, rule: Option<usize>) -> String {
        match rule.and_then(|i| self.router.rule_info(i)) {
            Some(r) => format!("{} => {}", r.payload, r.action),
            None => "final".into(),
        }
    }

    /// Take a connection slot, or `None` when `max_connections` is reached.
    pub(crate) fn admit(&self) -> Option<Slot<'_>> {
        let n = self.active.fetch_add(1, Ordering::Relaxed);
        if self.max_connections != 0 && n >= self.max_connections {
            self.active.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Slot(&self.active))
    }

    /// The host's network path changed (Wi-Fi ↔ cellular, VPN reconnect).
    ///
    /// Drops state bound to the old path: UDP NAT sessions (their sockets
    /// were routed over the old interface; QUIC/WebRTC clients re-establish
    /// on the next packet). In-flight TCP is left alone: it either survives
    /// (same interface) or fails fast on its own. Pooled upstream state
    /// (multiplex sessions, QUIC connections, DNS cache) belongs here too as
    /// it lands, so the next request dials over the new path. Outbounds with
    /// long-lived sockets (WireGuard) replace them. Outbound health is
    /// forgotten (a different network has a different censor), as are
    /// automatic ClientHello fragmentation levels, and `urltest`
    /// groups re-probe: at once if in use, otherwise on their next use.
    pub fn network_changed(&self) {
        let udp = self.nat.clear();
        for o in &self.outbounds {
            o.network_changed();
        }
        self.groups.network_changed();
        crate::tls::network_changed();
        info!(udp_sessions = udp, "network changed: reset path-bound state");
    }

    /// The host moved to a new network path (Wi-Fi ↔ cellular). Like
    /// `network_changed`, except outbounds that can migrate (hysteria2 over
    /// sbr's own socket) move their live QUIC connection to a fresh socket on
    /// the new path, so the TCP streams and UDP sessions they carry continue.
    /// Where the server does not answer on the new path within a few seconds,
    /// that connection is closed and its UDP sessions dropped, as a reset would.
    pub async fn network_migrate(&self) {
        let (mut moving, mut migrating) = (Vec::new(), Vec::new());
        for o in &self.outbounds {
            match o.migrate() {
                Some(f) => {
                    migrating.push(o.tag());
                    moving.push(async move { (o.tag(), f.await) });
                }
                None => o.network_changed(),
            }
        }
        let mut dropped = self.nat.retain(|c| migrating.contains(&c));
        self.groups.network_changed();
        crate::tls::network_changed();
        let results = futures_util::future::join_all(moving).await;
        let failed: Vec<&str> = results.iter().filter(|r| !r.1).map(|r| r.0).collect();
        if !failed.is_empty() {
            dropped += self.nat.retain(|c| !failed.contains(&c));
        }
        info!(
            migrated = results.len() - failed.len(),
            failed = ?failed,
            udp_sessions_dropped = dropped,
            "network changed: migrated QUIC connections"
        );
    }

    pub(crate) async fn relay<A, B>(&self, meta: &Metadata, mut client: A, mut remote: B) -> io::Result<()>
    where
        A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let r = relay::relay(&mut client, &mut remote, self.relay_buffer, &self.traffic).await;
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

/// A held connection slot; released on drop.
pub(crate) struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
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
    tuns: Vec<Arc<sbr_tun::Stack>>,
}

impl Instance {
    /// Bind every inbound and start accepting. Must run inside a Tokio runtime.
    pub async fn start(options: &Options, settings: Settings) -> Result<Self, Error> {
        for w in &options.warnings {
            warn!("{w}");
        }
        // The platform's tun fd is ours from here on: closed on every early
        // return, and handed to exactly one tun inbound.
        // SAFETY: the caller transfers ownership of `tun_fd` (see `Settings`).
        let mut tun_fd = settings
            .tun_fd
            .map(|fd| unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) });
        let engine = Arc::new(Engine::new(options, &settings)?);
        // A cache is an optimisation; never let it stop the tunnel.
        if options.experimental.cache_file.is_some() && engine.cache.is_none() {
            warn!("cache file could not be opened; running without it");
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
        let mut tuns = Vec::new();
        for (i, ib) in options.inbounds.iter().enumerate() {
            let p = match &ib.kind {
                InboundKind::Mixed(p) | InboundKind::Socks(p) | InboundKind::Http(p) => p,
                InboundKind::Tun(t) => {
                    if settings.tun_fd.is_some() && tun_fd.is_none() {
                        return Err(Error::Inbound(
                            i,
                            ib.tag.clone(),
                            "only one tun inbound can use the platform tun".into(),
                        ));
                    }
                    let fd = tun_fd.take().map(std::os::fd::IntoRawFd::into_raw_fd);
                    let tun_settings = Settings {
                        tun_fd: fd,
                        ..settings.clone()
                    };
                    let stack = inbound::tun::start(engine.clone(), &ib.tag, t, &tun_settings)
                        .await
                        .map_err(|e| Error::Inbound(i, ib.tag.clone(), e.to_string()))?;
                    tuns.push(stack);
                    continue;
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
            tuns,
        })
    }

    /// Stop accepting. In-flight connections finish on their own or die
    /// with the runtime.
    pub fn shutdown(mut self) {
        self.tasks.abort_all();
        self.engine.groups.shutdown();
        self.tuns.clear();
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
