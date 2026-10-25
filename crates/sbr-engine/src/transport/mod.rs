//! How V2Ray-family outbounds reach their server: TCP (via [`Upstream`]),
//! optional TLS, then an optional v2ray transport. Every layer takes a
//! [`Stream`] and yields one.

mod h2;
mod http;
mod prefixed;
mod ws;

use std::io;

use sbr_config::{Transport, V2rayCommon};
use sbr_core::{Destination, Host, Stream};

use crate::outbound::Upstream;
use crate::tls::{TlsClient, TlsConn};

pub use prefixed::Prefixed;

/// TCP to the proxy server, then TLS when configured.
#[derive(Clone)]
pub struct ServerDialer {
    upstream: Upstream,
    server: Destination,
    tls: Option<TlsClient>,
}

impl ServerDialer {
    pub fn new(upstream: Upstream, server: Destination, tls: Option<TlsClient>) -> Self {
        Self { upstream, server, tls }
    }

    pub fn has_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// `host:port` with IPv6 bracketed (Go's `Socksaddr.String()`).
    pub fn server_authority(&self) -> String {
        self.server.to_string()
    }

    /// Host only, IPv6 bracketed.
    pub fn server_host(&self) -> String {
        match &self.server.host {
            Host::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(d) => d.to_string(),
        }
    }

    pub fn tls_server_name(&self) -> Option<String> {
        let n = self.tls.as_ref()?.server_name()?;
        Some(if n.contains(':') { format!("[{n}]") } else { n })
    }

    /// The dialer with `alpn` as TLS default ALPN (see [`TlsClient::with_default_alpn`]).
    fn with_default_alpn(&self, alpn: &[&str]) -> Self {
        Self {
            upstream: self.upstream.clone(),
            server: self.server.clone(),
            tls: self.tls.as_ref().map(|t| t.with_default_alpn(alpn)),
        }
    }

    /// Plain TCP (or the detour's stream).
    pub async fn tcp(&self) -> io::Result<(Stream, Option<i32>)> {
        self.upstream.connect_raw(&self.server).await
    }

    /// TCP + TLS, keeping the concrete TLS type (XTLS Vision needs it).
    pub async fn tls(&self) -> io::Result<TlsConn> {
        let tls = self
            .tls
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS required"))?;
        let (s, fd) = self.tcp().await?;
        tls.connect(s, fd).await
    }

    pub async fn connect(&self) -> io::Result<Stream> {
        match &self.tls {
            None => Ok(self.tcp().await?.0),
            Some(_) => Ok(Box::new(self.tls().await?)),
        }
    }
}

enum Kind {
    Plain,
    Ws(ws::WsClient),
    HttpUpgrade(http::HttpUpgradeClient),
    Grpc(h2::H2Pool, http::HttpRequestTemplate),
    Http(http::HttpClient),
}

/// A V2Ray-family outbound's way to its server.
pub struct ProxyDialer {
    base: ServerDialer,
    kind: Kind,
}

impl ProxyDialer {
    /// Errors name the offending config field.
    pub fn new(c: &V2rayCommon, upstream: Upstream, base_dir: Option<&std::path::Path>) -> Result<Self, String> {
        let server = Destination::from_host_port(&c.server.server, c.server.server_port);
        let tls = match c.tls() {
            Some(t) => Some(TlsClient::new(t, &c.server.server, base_dir)?),
            None => None,
        };
        let base = ServerDialer::new(upstream, server, tls);
        let kind = match &c.transport {
            None => Kind::Plain,
            Some(Transport::Ws {
                path,
                headers,
                max_early_data,
                early_data_header_name,
            }) => Kind::Ws(ws::WsClient::new(
                base.with_default_alpn(&["http/1.1"]),
                path.as_deref(),
                headers,
                *max_early_data,
                early_data_header_name.as_deref(),
            )),
            Some(Transport::HttpUpgrade { host, path, headers }) => Kind::HttpUpgrade(http::HttpUpgradeClient::new(
                base.with_default_alpn(&["http/1.1"]),
                host.as_deref(),
                path.as_deref(),
                headers,
            )),
            Some(Transport::Grpc { service_name, .. }) => {
                let d = base.with_default_alpn(&["h2"]);
                // :authority is the TLS server name (with the server port) when set.
                let authority = match d.tls_server_name() {
                    Some(n) => format!("{n}:{}", c.server.server_port),
                    None => d.server_authority(),
                };
                let service = service_name.as_deref().unwrap_or_default();
                let tpl = http::HttpRequestTemplate::grpc(&authority, service);
                Kind::Grpc(h2::H2Pool::new(d), tpl)
            }
            Some(Transport::Http {
                host,
                path,
                method,
                headers,
                ..
            }) => Kind::Http(http::HttpClient::new(
                base.with_default_alpn(&["h2"]),
                host,
                path.as_deref(),
                method.as_deref(),
                headers,
            )),
            Some(Transport::Quic) => return Err("transport.type: quic transport not supported by sbr yet".into()),
        };
        Ok(Self { base, kind })
    }

    pub fn has_transport(&self) -> bool {
        !matches!(self.kind, Kind::Plain)
    }

    pub fn server(&self) -> &ServerDialer {
        &self.base
    }

    pub async fn connect(&self) -> io::Result<Stream> {
        match &self.kind {
            Kind::Plain => self.base.connect().await,
            Kind::Ws(c) => c.connect().await,
            Kind::HttpUpgrade(c) => c.connect().await,
            Kind::Grpc(pool, tpl) => Ok(Box::new(pool.open(tpl.build()?, true).await?)),
            Kind::Http(c) => c.connect().await,
        }
    }
}
