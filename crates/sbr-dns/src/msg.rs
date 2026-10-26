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

/// Drop the address hints of a family the strategy excludes from HTTPS/SVCB
/// answers. Clients (Safari, Network.framework) dial those hints directly, so
/// an `ipv4_only` resolver that only filtered AAAA still handed out IPv6.
pub fn filter_hints(m: &mut Message, keep_v4: bool, keep_v6: bool) {
    use hickory_proto::rr::rdata::svcb::SvcParamKey;
    for rec in m.answers.iter_mut().chain(m.additionals.iter_mut()) {
        let svcb = match &mut rec.data {
            RData::HTTPS(h) => &mut h.0,
            RData::SVCB(s) => s,
            _ => continue,
        };
        svcb.svc_params.retain(|(k, _)| match k {
            SvcParamKey::Ipv4Hint => keep_v4,
            SvcParamKey::Ipv6Hint => keep_v6,
            _ => true,
        });
    }
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

/// The longest TTL honoured, so that a poisoned or misconfigured answer
/// cannot stay cached until LRU eviction. Unbound and BIND default to a day
/// as well.
pub const MAX_TTL: u32 = 86_400;

/// A TTL from the wire: values with the top bit set are zero (RFC 2181 §8),
/// and long ones are capped at [`MAX_TTL`].
fn clamp_ttl(ttl: u32) -> u32 {
    if ttl > i32::MAX as u32 { 0 } else { ttl.min(MAX_TTL) }
}

/// sing-box `computeTimeToLive`: the SOA negative TTL for an empty answer,
/// else the smallest non-zero TTL of any record; clamped by [`clamp_ttl`].
pub fn response_ttl(m: &Message) -> u32 {
    if m.answers.is_empty() {
        for r in &m.authorities {
            if let RData::SOA(soa) = &r.data {
                return clamp_ttl(r.ttl).min(clamp_ttl(soa.minimum));
            }
        }
    }
    let mut ttl = 0u32;
    for r in m.answers.iter().chain(&m.authorities).chain(&m.additionals) {
        if r.record_type() == RecordType::OPT {
            continue;
        }
        let t = clamp_ttl(r.ttl);
        if ttl == 0 || (t > 0 && t < ttl) {
            ttl = t;
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
/// answers had to go (the client retries over TCP). Records go from the end
/// of the additional, then authority, then answer sections.
pub fn truncate_to(mut m: Message, max: usize) -> io::Result<Vec<u8>> {
    let raw = encode(&m)?;
    if raw.len() <= max {
        return Ok(raw);
    }
    let (answers, authorities) = (m.answers.len(), m.authorities.len());
    let records: Vec<Record> = std::mem::take(&mut m.answers)
        .into_iter()
        .chain(std::mem::take(&mut m.authorities))
        .chain(std::mem::take(&mut m.additionals))
        .collect();
    // Keeps the first `k` records of answers ++ authorities ++ additionals.
    let keep = |m: &mut Message, k: usize| {
        let (an, rest) = records[..k].split_at(k.min(answers));
        let (ns, ar) = rest.split_at(rest.len().min(authorities));
        m.answers = an.to_vec();
        m.authorities = ns.to_vec();
        m.additionals = ar.to_vec();
        encode(m)
    };
    // The encoded size grows with every record kept, so the largest count
    // that fits is found by bisection: O(n log n) rather than one encoding
    // per removed record. `lo` fits (or is 0), `hi` does not.
    let (mut lo, mut hi) = (0, records.len());
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if keep(&mut m, mid)?.len() <= max {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    if lo < answers {
        m.metadata.truncation = true;
    }
    let raw = keep(&mut m, lo)?;
    if raw.len() <= max {
        return Ok(raw);
    }
    m.metadata.truncation = true;
    m.edns = None;
    encode(&m)
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
    fn hints_of_an_excluded_family_are_dropped() {
        use hickory_proto::rr::rdata::HTTPS;
        use hickory_proto::rr::rdata::svcb::{Alpn, IpHint, SVCB, SvcParamKey, SvcParamValue};
        let q = query("a.test", TYPE_HTTPS).unwrap();
        let mut m = status(&q, 0);
        let svcb = SVCB::new(
            1,
            Name::root(),
            vec![
                (SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(vec!["h3".into()]))),
                (
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(vec![A::new(1, 2, 3, 4)])),
                ),
                (
                    SvcParamKey::Ipv6Hint,
                    SvcParamValue::Ipv6Hint(IpHint(vec![AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)])),
                ),
            ],
        );
        m.answers.push(Record::from_rdata(
            Name::from_ascii("a.test.").unwrap(),
            60,
            RData::HTTPS(HTTPS(svcb)),
        ));
        filter_hints(&mut m, true, false);
        let RData::HTTPS(h) = &m.answers[0].data else { panic!() };
        let keys: Vec<_> = h.0.svc_params.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, [SvcParamKey::Alpn, SvcParamKey::Ipv4Hint]);
    }

    #[test]
    fn ttl_rules() {
        let q = query("a.test", TYPE_A).unwrap();
        let mut m = addresses(&q, &["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()], 300);
        m.answers[1].ttl = 30;
        assert_eq!(response_ttl(&m), 30);
        set_ttl(&mut m, 7);
        assert!(m.answers.iter().all(|r| r.ttl == 7));
        assert_eq!(answer_addrs(&m).len(), 2);

        // RFC 2181 §8: a TTL with the top bit set counts as zero.
        m.answers[0].ttl = 0x8000_0000;
        m.answers[1].ttl = 30;
        assert_eq!(response_ttl(&m), 30);
        m.answers[1].ttl = u32::MAX;
        assert_eq!(response_ttl(&m), 0);
        m.answers[0].ttl = 0x7fff_ffff;
        assert_eq!(response_ttl(&m), MAX_TTL);
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
        // As many answers as fit: one more would not.
        let mut more = back.clone();
        more.answers.push(Record::from_rdata(
            more.answers[0].name.clone(),
            60,
            RData::A(A::new(10, 1, 1, 1)),
        ));
        assert!(encode(&more).unwrap().len() > 512);

        // Additionals go before answers; nothing that fits is dropped.
        let mut m = addresses(&q, &ips[..3], 60);
        for i in 0..40u8 {
            m.additionals.push(Record::from_rdata(
                Name::from_ascii(format!("x{i}.a.test.")).unwrap(),
                60,
                RData::A(A::new(10, 2, 0, i)),
            ));
        }
        let back = decode(&truncate_to(m, 512).unwrap()).unwrap();
        assert!(!back.metadata.truncation);
        assert_eq!(back.answers.len(), 3);
        assert!(!back.additionals.is_empty() && back.additionals.len() < 40);

        // A large answer still truncates quickly.
        let ips: Vec<IpAddr> = (0..3_000u32)
            .map(|i| IpAddr::from((0x0a00_0000 + i).to_be_bytes()))
            .collect();
        let raw = truncate_to(addresses(&q, &ips, 60), 512).unwrap();
        assert!(raw.len() <= 512 && decode(&raw).unwrap().metadata.truncation);
    }
}
