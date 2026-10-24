pub mod http;
pub mod socks;

use std::sync::Arc;

use base64::Engine as _;
use sbr_config::{InboundKind, User};
use tokio::net::TcpStream;

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
    pub fn from_kind(engine: Arc<Engine>, tag: &str, kind: &InboundKind) -> Self {
        let (flavor, p) = match kind {
            InboundKind::Mixed(p) => (Flavor::Mixed, p),
            InboundKind::Socks(p) => (Flavor::Socks, p),
            InboundKind::Http(p) => (Flavor::Http, p),
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
        self.users
            .iter()
            .any(|u| u.username == user && u.password == pass)
    }

    pub fn check_basic(&self, header: &[u8]) -> Option<Arc<str>> {
        let v = std::str::from_utf8(header).ok()?.trim();
        let b64 = v
            .strip_prefix("Basic ")
            .or_else(|| v.strip_prefix("basic "))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .ok()?;
        let (u, p) = std::str::from_utf8(&raw).ok()?.split_once(':')?;
        self.check_user(u, p).then(|| u.into())
    }
}

pub async fn handle(ctx: Arc<Context>, stream: TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    match ctx.flavor {
        Flavor::Socks => socks::handle(&ctx, stream).await,
        Flavor::Http => http::handle(&ctx, stream, Vec::new()).await,
        Flavor::Mixed => {
            let mut first = [0u8; 1];
            let n = stream.peek(&mut first).await?;
            match (n, first[0]) {
                (0, _) => Ok(()),
                (_, 5) => socks::handle(&ctx, stream).await,
                (_, 4) => Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "SOCKS4 not supported by sbr yet",
                )),
                _ => http::handle(&ctx, stream, Vec::new()).await,
            }
        }
    }
}
