//! Trojan client (sing-box `transport/trojan`): hex(SHA-224(password)),
//! CRLF, command, SOCKS address, CRLF, then the payload. UDP packets are
//! framed as address, length, CRLF, payload.

use std::io;

use aws_lc_rs::digest;
use sbr_config::TrojanOutbound;
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Outbound, Stream};

use super::proto::{Framing, HeaderStream, PacketHandle, Response, StreamPacketConn, put_socks_addr};
use super::{BuildContext, Upstream};
use crate::transport::ProxyDialer;

pub struct Trojan {
    tag: String,
    key: [u8; 56],
    dialer: ProxyDialer,
    tcp: bool,
    udp: bool,
}

impl Trojan {
    pub fn new(tag: String, c: &TrojanOutbound, upstream: Upstream, ctx: &BuildContext) -> Result<Self, String> {
        Ok(Self {
            tag,
            key: key(&c.password),
            dialer: ProxyDialer::new(&c.common, upstream, ctx)?,
            tcp: c.common.tcp(),
            udp: c.common.udp(),
        })
    }

    fn header(&self, command: u8, dest: &Destination) -> Vec<u8> {
        let mut h = Vec::with_capacity(56 + 2 + 1 + 1 + 1 + 255 + 2 + 2);
        h.extend_from_slice(&self.key);
        h.extend_from_slice(b"\r\n");
        h.push(command);
        put_socks_addr(&mut h, dest);
        h.extend_from_slice(b"\r\n");
        h
    }
}

/// hex(SHA-224(password)).
fn key(password: &str) -> [u8; 56] {
    let d = digest::digest(&digest::SHA224, password.as_bytes());
    let mut out = [0u8; 56];
    for (i, b) in d.as_ref().iter().enumerate() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 15) as usize];
    }
    out
}

fn disabled(net: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, format!("{net} is disabled by `network`"))
}

impl Outbound for Trojan {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "trojan"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            if !self.tcp {
                return Err(disabled("tcp"));
            }
            let s = self.dialer.connect().await?;
            Ok(Box::new(HeaderStream::new(s, self.header(1, dest), Response::None)) as Stream)
        })
    }
    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            if !self.udp {
                return Err(disabled("udp"));
            }
            let s = self.dialer.connect().await?;
            let s: Stream = Box::new(HeaderStream::new(s, self.header(3, dest), Response::None));
            let conn = StreamPacketConn::new(s, Framing::Trojan, dest.clone());
            Ok(Box::new(PacketHandle(conn)) as BoxPacketConn)
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn key_is_hex_sha224() {
        assert_eq!(
            &super::key("password")[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }
}
