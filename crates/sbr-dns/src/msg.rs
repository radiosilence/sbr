//! DNS message helpers on top of hickory-proto.

use std::io;
use std::net::IpAddr;

pub use hickory_proto::op::Message;
use hickory_proto::op::{Edns, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use ipnet::IpNet;
use sbr_config::{DnsRecord, RecordData};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;

pub fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

pub fn decode(raw: &[u8]) -> io::Result<Message> {
    Message::from_vec(raw).map_err(invalid)
}

pub fn encode(m: &Message) -> io::Result<Vec<u8>> {
    m.to_vec().map_err(invalid)
}

/// A recursive query for `name`/`qtype`, as the client would send it.
pub fn query(name: &str, qtype: u16) -> io::Result<Message> {
    let mut name = Name::from_ascii(name).map_err(invalid)?;
    name.set_fqdn(true);
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(name, RecordType::from(qtype)));
    Ok(m)
}

/// The question name, lowercase, without the trailing dot.
pub fn domain_of(q: &Query) -> String {
    let mut s = q.name().to_ascii().to_ascii_lowercase();
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// An empty response to `req` with `rcode` (sing-box `FixedResponseStatus`).
pub fn status(req: &Message, rcode: u16) -> Message {
    let mut m = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
    m.metadata.authoritative = true;
    m.metadata.recursion_desired = true;
    m.metadata.recursion_available = true;
    m.metadata.response_code = <ResponseCode as From<u16>>::from(rcode);
    m.queries.clone_from(&req.queries);
    m
}

/// Answer `req` with the addresses of the queried family.
pub fn addresses(req: &Message, addrs: &[IpAddr], ttl: u32) -> Message {
    let mut m = status(req, 0);
    if let Some(q) = req.queries.first() {
        let qtype = u16::from(q.query_type());
        for ip in addrs {
            let data = match (qtype, ip) {
                (TYPE_A, IpAddr::V4(v4)) => RData::A(A(*v4)),
                (TYPE_AAAA, IpAddr::V6(v6)) => RData::AAAA(AAAA(*v6)),
                _ => continue,
            };
            m.add_answer(Record::from_rdata(q.name().clone(), ttl, data));
        }
    }
    m
}

pub fn rcode(m: &Message) -> u16 {
    u16::from(m.metadata.response_code)
}

/// A/AAAA answers (sing-box `MessageToAddresses`, which also reads HTTPS
/// hints; those are left out here since nothing dials them).
pub fn answer_addrs(m: &Message) -> Vec<IpAddr> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0).to_canonical()),
            _ => None,
        })
        .collect()
}

/// sing-box `computeTimeToLive`: the SOA negative TTL for an empty answer,
/// else the smallest non-zero TTL of any record.
pub fn response_ttl(m: &Message) -> u32 {
    if m.answers.is_empty() {
        for r in &m.authorities {
            if let RData::SOA(soa) = &r.data {
                return r.ttl.min(soa.minimum);
            }
        }
    }
    let mut ttl = 0u32;
    for r in m.answers.iter().chain(&m.authorities).chain(&m.additionals) {
        if r.record_type() == RecordType::OPT {
            continue;
        }
        if ttl == 0 || (r.ttl > 0 && r.ttl < ttl) {
            ttl = r.ttl;
        }
    }
    ttl
}

pub fn set_ttl(m: &mut Message, ttl: u32) {
    for r in m.answers.iter_mut().chain(&mut m.authorities).chain(&mut m.additionals) {
        if r.record_type() != RecordType::OPT {
            r.ttl = ttl;
        }
    }
}

/// The EDNS Client Subnet carried by a message, as a prefix.
pub fn client_subnet(m: &Message) -> Option<IpNet> {
    match m.edns.as_ref()?.option(EdnsCode::Subnet)? {
        EdnsOption::Subnet(s) => {
            let addr = s.addr();
            IpNet::new(addr, s.source_prefix()).ok().map(|n| n.trunc())
        }
        _ => None,
    }
}

/// Add or replace the ECS option (sing-box `SetClientSubnet`).
pub fn set_client_subnet(m: &mut Message, subnet: IpNet) {
    let edns = m.edns.get_or_insert_with(|| {
        let mut e = Edns::new();
        e.set_max_payload(1232);
        e
    });
    edns.options_mut().remove(EdnsCode::Subnet);
    edns.options_mut().insert(EdnsOption::Subnet(ClientSubnet::new(
        subnet.network(),
        subnet.prefix_len(),
        0,
    )));
}

pub fn remove_client_subnet(m: &mut Message) {
    if let Some(e) = m.edns.as_mut() {
        e.options_mut().remove(EdnsCode::Subnet);
    }
}

/// A query the cache can answer for anyone: one question, no records
/// besides an OPT that carries at most ECS.
pub fn is_simple(m: &Message) -> bool {
    m.queries.len() == 1
        && m.answers.is_empty()
        && m.authorities.is_empty()
        && m.additionals.is_empty()
        && m.edns.as_ref().is_none_or(|e| {
            !e.flags().dnssec_ok && e.version() == 0 && e.options().as_ref().iter().all(|(c, _)| *c == EdnsCode::Subnet)
        })
}

/// Shrink a response to fit `max` bytes on the wire, setting TC when
/// answers had to go (the client retries over TCP).
pub fn truncate_to(mut m: Message, max: usize) -> io::Result<Vec<u8>> {
    let mut raw = encode(&m)?;
    if raw.len() <= max {
        return Ok(raw);
    }
    while raw.len() > max {
        if m.additionals.pop().is_some() || m.authorities.pop().is_some() {
        } else if m.answers.pop().is_some() {
            m.metadata.truncation = true;
        } else {
            m.metadata.truncation = true;
            m.edns = None;
            raw = encode(&m)?;
            break;
        }
        raw = encode(&m)?;
    }
    Ok(raw)
}

/// The UDP payload size a client accepts (512 without EDNS).
pub fn udp_size(m: &Message) -> usize {
    m.edns.as_ref().map_or(512, |e| (e.max_payload() as usize).max(512))
}

/// Build a predefined record, rewriting a `*.` wildcard owner to the
/// question name when it matches (sing-box `rewriteRecords`).
pub fn predefined_record(rec: &DnsRecord, question: &Query) -> io::Result<Record> {
    match rec {
        DnsRecord::Wire(raw) => {
            let mut d = BinDecoder::new(raw);
            Record::read(&mut d).map_err(invalid)
        }
        DnsRecord::Text { name, ttl, data } => {
            let qname = question.name().to_ascii().to_ascii_lowercase();
            let owner = match name.strip_prefix('*') {
                Some(suffix) if qname.ends_with(suffix) => question.name().clone(),
                _ => Name::from_ascii(name).map_err(invalid)?,
            };
            let n = |s: &str| Name::from_ascii(s).map_err(invalid);
            let data = match data {
                RecordData::A(a) => RData::A(A(*a)),
                RecordData::Aaaa(a) => RData::AAAA(AAAA(*a)),
                RecordData::Cname(c) => RData::CNAME(CNAME(n(c)?)),
                RecordData::Ns(c) => RData::NS(NS(n(c)?)),
                RecordData::Ptr(c) => RData::PTR(PTR(n(c)?)),
                RecordData::Mx(p, x) => RData::MX(MX::new(*p, n(x)?)),
                RecordData::Txt(t) => RData::TXT(TXT::new(t.clone())),
            };
            let mut r = Record::from_rdata(owner, *ttl, data);
            r.dns_class = DNSClass::IN;
            Ok(r)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_rules() {
        let q = query("a.test", TYPE_A).unwrap();
        let mut m = addresses(&q, &["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()], 300);
        m.answers[1].ttl = 30;
        assert_eq!(response_ttl(&m), 30);
        set_ttl(&mut m, 7);
        assert!(m.answers.iter().all(|r| r.ttl == 7));
        assert_eq!(answer_addrs(&m).len(), 2);
    }

    #[test]
    fn ecs_roundtrip() {
        let mut q = query("a.test", TYPE_A).unwrap();
        assert!(is_simple(&q));
        set_client_subnet(&mut q, "1.2.3.0/24".parse().unwrap());
        assert!(is_simple(&q));
        let raw = encode(&q).unwrap();
        let back = decode(&raw).unwrap();
        assert_eq!(client_subnet(&back), Some("1.2.3.0/24".parse().unwrap()));
        remove_client_subnet(&mut q);
        assert_eq!(client_subnet(&q), None);
    }

    #[test]
    fn truncation() {
        let q = query("a.test", TYPE_A).unwrap();
        let ips: Vec<IpAddr> = (0..100u8).map(|i| IpAddr::from([10, 0, 0, i])).collect();
        let m = addresses(&q, &ips, 60);
        let raw = truncate_to(m, 512).unwrap();
        assert!(raw.len() <= 512);
        let back = decode(&raw).unwrap();
        assert!(back.metadata.truncation);
        assert!(!back.answers.is_empty());
    }
}
