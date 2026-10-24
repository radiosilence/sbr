use std::io;

use sbr_config::SocksOutbound;
use sbr_core::{BoxFuture, Destination, Stream};

use super::{Outbound, Upstream};
use crate::socks5;

pub struct Socks {
    tag: String,
    server: Destination,
    auth: Option<(String, String)>,
    upstream: Upstream,
}

impl Socks {
    pub fn new(tag: String, c: &SocksOutbound, upstream: Upstream) -> Self {
        let auth = c
            .username
            .clone()
            .map(|u| (u, c.password.clone().unwrap_or_default()));
        Self {
            tag,
            server: Destination::from_host_port(&c.server.server, c.server.server_port),
            auth,
            upstream,
        }
    }
}

impl Outbound for Socks {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "socks"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            let mut s = self.upstream.connect(&self.server).await?;
            let auth = self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
            socks5::client_connect(&mut s, dest, auth).await?;
            Ok(s)
        })
    }
}
