//! VLESS client (sing-box `sing-vmess/vless`), with the `xtls-rprx-vision`
//! flow in [`super::vision`].

use std::io;

use aws_lc_rs::digest;
use sbr_config::{PacketEncoding, VlessOutbound};
use sbr_core::{BoxFuture, BoxPacketConn, Destination, Outbound, Stream};

use super::proto::{Framing, HeaderStream, PacketHandle, Response, StreamPacketConn, put_vmess_addr};
use super::vision::VisionStream;
use super::{BuildContext, Upstream};
use crate::transport::ProxyDialer;

pub const FLOW_VISION: &str = "xtls-rprx-vision";
const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;
const CMD_MUX: u8 = 3;

pub struct Vless {
    tag: String,
    uuid: [u8; 16],
    vision: bool,
    xudp: bool,
    dialer: ProxyDialer,
    tcp: bool,
    udp: bool,
}

/// A UUID string, or (like Xray/sing-box) any other string mapped through
/// UUIDv5 in the nil namespace.
pub fn parse_uuid(s: &str) -> [u8; 16] {
    let t = s.trim();
    let t = t.strip_prefix("urn:uuid:").unwrap_or(t);
    let t = t.strip_prefix('{').and_then(|t| t.strip_suffix('}')).unwrap_or(t);
    let hex: String = t.chars().filter(|c| *c != '-').collect();
    let dashes_ok = t.len() == 32 || (t.len() == 36 && [8, 13, 18, 23].iter().all(|&i| t.as_bytes()[i] == b'-'));
    if dashes_ok && hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 16];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        return out;
    }
    let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(&[0u8; 16]);
    ctx.update(s.as_bytes());
    let d = ctx.finish();
    let mut out: [u8; 16] = d.as_ref()[..16].try_into().unwrap();
    out[6] = (out[6] & 0x0f) | 0x50;
    out[8] = (out[8] & 0x3f) | 0x80;
    out
}

impl Vless {
    pub fn new(tag: String, c: &VlessOutbound, upstream: Upstream, ctx: &BuildContext) -> Result<Self, String> {
        let dialer = ProxyDialer::new(&c.common, upstream, ctx.base_dir.as_deref())?;
        let xudp = match c.packet_encoding {
            PacketEncoding::Xudp => true,
            PacketEncoding::None => false,
            PacketEncoding::PacketAddr => return Err("packet_encoding: packetaddr is not supported by sbr yet".into()),
        };
        Ok(Self {
            tag,
            uuid: parse_uuid(&c.uuid),
            vision: c.flow.as_deref() == Some(FLOW_VISION),
            xudp,
            dialer,
            tcp: c.common.tcp(),
            udp: c.common.udp(),
        })
    }

    fn request(&self, command: u8, dest: &Destination, flow: bool) -> Vec<u8> {
        let mut h = Vec::with_capacity(1 + 16 + 1 + 18 + 1 + 2 + 1 + 256);
        h.push(0);
        h.extend_from_slice(&self.uuid);
        if flow {
            // Protobuf field 1 (string): tag, length, value.
            h.push((2 + FLOW_VISION.len()) as u8);
            h.push(0x0a);
            h.push(FLOW_VISION.len() as u8);
            h.extend_from_slice(FLOW_VISION.as_bytes());
        } else {
            h.push(0);
        }
        h.push(command);
        if command != CMD_MUX {
            put_vmess_addr(&mut h, dest);
        }
        h
    }

    /// A VLESS stream with `command`, over Vision when configured.
    async fn open(&self, command: u8, dest: &Destination) -> io::Result<Stream> {
        if self.vision {
            let tls = self.dialer.server().tls().await?;
            let header = self.request(command, dest, true);
            return Ok(Box::new(VisionStream::new(tls, header, self.uuid)));
        }
        let s = self.dialer.connect().await?;
        Ok(Box::new(HeaderStream::new(
            s,
            self.request(command, dest, false),
            Response::Vless,
        )))
    }
}

fn disabled(net: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, format!("{net} is disabled by `network`"))
}

impl Outbound for Vless {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "vless"
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        Box::pin(async move {
            if !self.tcp {
                return Err(disabled("tcp"));
            }
            self.open(CMD_TCP, dest).await
        })
    }
    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        Box::pin(async move {
            if !self.udp {
                return Err(disabled("udp"));
            }
            let conn = if self.xudp {
                StreamPacketConn::new(self.open(CMD_MUX, dest).await?, Framing::Xudp, dest.clone())
            } else {
                // Plain VLESS UDP never carries the flow (sing-vmess `WritePacketRequest`).
                let s = self.dialer.connect().await?;
                let s: Stream = Box::new(HeaderStream::new(
                    s,
                    self.request(CMD_UDP, dest, false),
                    Response::Vless,
                ));
                StreamPacketConn::new(s, Framing::Length, dest.clone())
            };
            Ok(Box::new(PacketHandle(conn)) as BoxPacketConn)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids() {
        assert_eq!(
            parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811"),
            [
                0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11
            ]
        );
        // uuid.NewV5(uuid.Nil, "example") from gofrs/uuid.
        let v5 = parse_uuid("example");
        assert_eq!(v5[6] >> 4, 5);
        assert_eq!(v5[8] & 0xc0, 0x80);
    }
}
