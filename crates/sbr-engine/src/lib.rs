//! The sbr runtime: builds inbounds and outbounds from a sing-box config and
//! moves bytes between them.

mod httpx;
pub mod inbound;
pub mod outbound;
mod socks5;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sbr_config::Options;
use sbr_core::relay::{self, Traffic};
use sbr_core::router::{Decision, Router};
use sbr_core::{Metadata, Stream};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

pub use outbound::{Outbound, Selector};
pub use sbr_config;

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
}

#[derive(Debug)]
pub enum OpenError {
    Rejected { drop: bool },
    Io(io::Error),
}

/// Knobs that are about the host, not the config.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Per-direction relay buffer.
    pub relay_buffer: usize,
    /// Resolves `local` rule-set paths. Defaults to the filesystem.
    pub base_dir: Option<std::path::PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            relay_buffer: relay::DEFAULT_BUFFER,
            base_dir: None,
        }
    }
}

pub struct Engine {
    outbounds: Vec<Arc<dyn Outbound>>,
    router: Router,
    pub traffic: Traffic,
    active: AtomicUsize,
    relay_buffer: usize,
}

impl Engine {
    pub fn new(options: &Options, settings: &Settings) -> Result<Self, Error> {
        let outbounds = outbound::build_all(&options.outbounds)?;
        let router = Router::new(
            &options.route.rules,
            &options.route.rule_sets,
            options.final_outbound(),
            |tag| outbounds.iter().position(|o| o.tag() == tag),
            |path| {
                let p = std::path::Path::new(path);
                let p = match &settings.base_dir {
                    Some(base) if p.is_relative() => base.join(p),
                    _ => p.to_path_buf(),
                };
                std::fs::read_to_string(p)
            },
        )?;
        Ok(Self {
            outbounds,
            router,
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

    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Route and connect. Inbounds call this, then reply to the client.
    pub async fn open(&self, meta: &Metadata) -> Result<Stream, OpenError> {
        match self.router.route(meta) {
            Decision::Reject { drop } => {
                info!(inbound = %meta.inbound, dest = %meta.destination, "rejected");
                Err(OpenError::Rejected { drop })
            }
            Decision::Route(i) => {
                let out = &self.outbounds[i];
                debug!(inbound = %meta.inbound, dest = %meta.destination, outbound = out.tag(), "route");
                out.connect(&meta.destination).await.map_err(|e| {
                    warn!(inbound = %meta.inbound, dest = %meta.destination, outbound = out.tag(), error = %e, "connect failed");
                    OpenError::Io(e)
                })
            }
        }
    }

    pub async fn relay<A>(
        &self,
        meta: &Metadata,
        mut client: A,
        mut remote: Stream,
    ) -> io::Result<()>
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
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
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
            let (sbr_config::InboundKind::Mixed(p)
            | sbr_config::InboundKind::Socks(p)
            | sbr_config::InboundKind::Http(p)) = &ib.kind;
            let addr = SocketAddr::new(p.listen.listen, p.listen.listen_port);
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| Error::Listen(i, ib.tag.clone(), addr, e))?;
            let local = listener
                .local_addr()
                .map_err(|e| Error::Listen(i, ib.tag.clone(), addr, e))?;
            info!(inbound = %ib.tag, %local, "listening");
            listening.push((ib.tag.clone(), local));
            let ctx = Arc::new(inbound::Context::from_kind(
                engine.clone(),
                &ib.tag,
                &ib.kind,
            ));
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
