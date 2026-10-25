//! DNS seam. The engine owns one `Dns`; the default resolves through the OS.
//! The full DNS router (servers, rules, FakeIP, cache) plugs in here.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use sbr_config::{DomainResolver, DomainStrategy};

use crate::{BoxFuture, Metadata};

pub trait Dns: Send + Sync {
    /// Resolve for dialing. Results are already filtered/ordered by `strategy`.
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: Option<DomainStrategy>,
    ) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
    /// Answer a raw DNS query (hijack-dns). `meta` is the hijacked flow.
    /// An error means "no answer" (the client sees a drop).
    fn exchange<'a>(&'a self, query: &'a [u8], meta: &'a Metadata) -> BoxFuture<'a, io::Result<Vec<u8>>>;

    /// `lookup` on behalf of a connection (the `resolve` route action), so DNS
    /// rules can match its inbound, user and so on.
    fn lookup_for<'a>(
        &'a self,
        domain: &'a str,
        strategy: Option<DomainStrategy>,
        meta: &'a Metadata,
    ) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        let _ = meta;
        self.lookup(domain, strategy)
    }

    /// A resolver for one dialer: a `domain_resolver` (server plus query
    /// options), and/or the outbound tag DNS rules' `outbound` item matches.
    /// `None` means "use `self` as is".
    fn bind(&self, spec: &ResolverSpec<'_>) -> Option<Arc<dyn Dns>> {
        let _ = spec;
        None
    }

    /// FakeIP: the domain a fake address stands for. `Some(None)` is an
    /// address inside a FakeIP range with no (or no longer a) mapping.
    fn fakeip_lookup(&self, ip: IpAddr) -> Option<Option<Arc<str>>> {
        let _ = ip;
        None
    }

    /// `reverse_mapping`: the domain an address was last returned for.
    fn reverse_lookup(&self, ip: IpAddr) -> Option<Arc<str>> {
        let _ = ip;
        None
    }
}

/// See [`Dns::bind`].
#[derive(Clone, Copy, Debug, Default)]
pub struct ResolverSpec<'a> {
    pub resolver: Option<&'a DomainResolver>,
    pub outbound: Option<&'a str>,
}

pub fn apply_strategy(addrs: Vec<IpAddr>, strategy: Option<DomainStrategy>) -> Vec<IpAddr> {
    let (v4, v6): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv4());
    match strategy.unwrap_or(DomainStrategy::AsIs) {
        DomainStrategy::Ipv4Only => v4,
        DomainStrategy::Ipv6Only => v6,
        DomainStrategy::PreferIpv4 => v4.into_iter().chain(v6).collect(),
        DomainStrategy::PreferIpv6 => v6.into_iter().chain(v4).collect(),
        DomainStrategy::AsIs => {
            // Interleave, IPv6 first (RFC 8305).
            let mut out = Vec::with_capacity(v4.len() + v6.len());
            let (mut a, mut b) = (v6.into_iter(), v4.into_iter());
            loop {
                match (a.next(), b.next()) {
                    (None, None) => return out,
                    (x, y) => out.extend(x.into_iter().chain(y)),
                }
            }
        }
    }
}

/// getaddrinfo-backed resolver; `exchange` answers A/AAAA and returns an
/// empty NOERROR for other types so clients fall back quickly.
#[derive(Default)]
pub struct SystemDns;

impl Dns for SystemDns {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: Option<DomainStrategy>,
    ) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let addrs: Vec<IpAddr> = tokio::net::lookup_host((domain, 0))
                .await?
                .map(|a| a.ip().to_canonical())
                .collect();
            let out = apply_strategy(addrs, strategy);
            if out.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no usable addresses for {domain}"),
                ));
            }
            Ok(out)
        })
    }

    fn exchange<'a>(&'a self, query: &'a [u8], _meta: &'a Metadata) -> BoxFuture<'a, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let q =
                wire::Query::parse(query).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad DNS query"))?;
            let ips = match q.qtype {
                wire::TYPE_A | wire::TYPE_AAAA => match self.lookup(&q.name, None).await {
                    Ok(ips) => ips,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
                    Err(_) => return Ok(q.response(wire::RCODE_SERVFAIL, &[], 0)),
                },
                _ => Vec::new(),
            };
            Ok(q.response(wire::RCODE_NOERROR, &ips, 60))
        })
    }
}

/// Just enough DNS wire format for the system responder and the sniffer.
pub mod wire {
    use std::net::IpAddr;

    pub const TYPE_A: u16 = 1;
    pub const TYPE_AAAA: u16 = 28;
    pub const RCODE_NOERROR: u8 = 0;
    pub const RCODE_SERVFAIL: u8 = 2;
    pub const RCODE_REFUSED: u8 = 5;

    pub struct Query<'a> {
        raw: &'a [u8],
        /// End of the first question section.
        question_end: usize,
        pub id: u16,
        pub name: String,
        pub qtype: u16,
    }

    impl<'a> Query<'a> {
        pub fn parse(raw: &'a [u8]) -> Option<Self> {
            if raw.len() < 12 || raw[2] & 0x80 != 0 {
                return None; // too short, or a response
            }
            let qdcount = u16::from_be_bytes([raw[4], raw[5]]);
            if qdcount == 0 {
                return None;
            }
            let mut i = 12;
            let mut name = String::new();
            loop {
                let len = *raw.get(i)? as usize;
                i += 1;
                if len == 0 {
                    break;
                }
                if len & 0xc0 != 0 || name.len() + len > 253 {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(std::str::from_utf8(raw.get(i..i + len)?).ok()?);
                i += len;
            }
            let qtype = u16::from_be_bytes([*raw.get(i)?, *raw.get(i + 1)?]);
            raw.get(i + 3)?;
            Some(Self {
                raw,
                question_end: i + 4,
                id: u16::from_be_bytes([raw[0], raw[1]]),
                name: name.to_ascii_lowercase(),
                qtype,
            })
        }

        /// Build a response echoing the first question, with answers of the
        /// queried family taken from `ips`.
        pub fn response(&self, rcode: u8, ips: &[IpAddr], ttl: u32) -> Vec<u8> {
            let answers: Vec<&IpAddr> = ips
                .iter()
                .filter(|ip| matches!((self.qtype, ip), (TYPE_A, IpAddr::V4(_)) | (TYPE_AAAA, IpAddr::V6(_))))
                .collect();
            let mut out = Vec::with_capacity(self.question_end + answers.len() * 28);
            out.extend_from_slice(&self.raw[..2]);
            let rd = self.raw[2] & 0x01;
            out.push(0x80 | rd); // QR, opcode 0, RD echoed
            out.push(0x80 | (rcode & 0x0f)); // RA
            out.extend_from_slice(&[0, 1]);
            out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&self.raw[12..self.question_end]);
            for ip in answers {
                out.extend_from_slice(&[0xc0, 0x0c]);
                out.extend_from_slice(&self.qtype.to_be_bytes());
                out.extend_from_slice(&[0, 1]);
                out.extend_from_slice(&ttl.to_be_bytes());
                match ip {
                    IpAddr::V4(v4) => {
                        out.extend_from_slice(&[0, 4]);
                        out.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        out.extend_from_slice(&[0, 16]);
                        out.extend_from_slice(&v6.octets());
                    }
                }
            }
            out
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn roundtrip() {
            let q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03com\x00\x00\x01\x00\x01";
            let p = Query::parse(q).unwrap();
            assert_eq!(p.name, "example.com");
            assert_eq!(p.qtype, TYPE_A);
            let r = p.response(RCODE_NOERROR, &["1.2.3.4".parse().unwrap(), "::1".parse().unwrap()], 60);
            assert_eq!(&r[..2], b"\x12\x34");
            assert_eq!(r[2] & 0x80, 0x80);
            assert_eq!(
                u16::from_be_bytes([r[6], r[7]]),
                1,
                "only the A record answers an A query"
            );
            assert_eq!(&r[r.len() - 4..], &[1, 2, 3, 4]);
            assert!(Query::parse(&r).is_none(), "responses are not queries");
        }
    }
}
