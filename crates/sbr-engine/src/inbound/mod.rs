pub mod http;
pub mod socks;
pub mod tun;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use sbr_config::{InboundKind, User};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::debug;

use crate::Engine;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavor {
    Mixed,
    Socks,
    Http,
}

pub struct Context {
    pub engine: Arc<Engine>,
    pub tag: Arc<str>,
    pub flavor: Flavor,
    pub users: Vec<User>,
}

impl Context {
    /// Proxy inbounds only (mixed/socks/http).
    pub fn new(engine: Arc<Engine>, tag: &str, kind: &InboundKind) -> Self {
        let (flavor, p) = match kind {
            InboundKind::Mixed(p) => (Flavor::Mixed, p),
            InboundKind::Socks(p) => (Flavor::Socks, p),
            InboundKind::Http(p) => (Flavor::Http, p),
            InboundKind::Tun(_) => unreachable!("tun is not a proxy inbound"),
        };
        Self {
            engine,
            tag: tag.into(),
            flavor,
            users: p.users.clone(),
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self.flavor {
            Flavor::Mixed => "mixed",
            Flavor::Socks => "socks",
            Flavor::Http => "http",
        }
    }

    pub fn check_user(&self, user: &str, pass: &str) -> bool {
        // Not constant-time; matches sing-box. Local proxy auth is a speed bump, not a vault.
        self.users.iter().any(|u| u.username == user && u.password == pass)
    }

    pub fn check_basic(&self, header: &[u8]) -> Option<Arc<str>> {
        let v = std::str::from_utf8(header).ok()?.trim();
        let b64 = v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic "))?;
        let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
        let (u, p) = std::str::from_utf8(&raw).ok()?.split_once(':')?;
        self.check_user(u, p).then(|| u.into())
    }
}

/// Time a client has to finish the SOCKS or HTTP handshake (the request and
/// any authentication). Until then it holds a connection slot.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Serve one accepted connection. The connection slot is taken before the
/// handshake, so idle or slow clients count against `max_connections` and
/// a SOCKS5 UDP association counts for as long as its control connection.
pub async fn handle(ctx: Arc<Context>, stream: TcpStream) -> io::Result<()> {
    let Some(_slot) = ctx.engine.admit() else {
        debug!(inbound = %ctx.tag, limit = ctx.engine.max_connections, "connection limit reached");
        return Ok(());
    };
    stream.set_nodelay(true)?;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    match ctx.flavor {
        Flavor::Socks => socks::handle(&ctx, stream, deadline).await,
        Flavor::Http => http::handle(&ctx, stream, Vec::new(), deadline).await,
        Flavor::Mixed => {
            let mut first = [0u8; 1];
            let n = within(deadline, stream.peek(&mut first)).await?;
            match (n, first[0]) {
                (0, _) => Ok(()),
                (_, 5) => socks::handle(&ctx, stream, deadline).await,
                (_, 4) => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SOCKS4 not supported by sbr yet",
                )),
                _ => http::handle(&ctx, stream, Vec::new(), deadline).await,
            }
        }
    }
}

/// Run a handshake step, failing with `TimedOut` at `deadline`.
async fn within<T>(deadline: Instant, step: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout_at(deadline, step)
        .await
        .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "inbound handshake timed out")))
}
