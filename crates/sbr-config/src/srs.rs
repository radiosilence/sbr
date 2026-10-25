//! sing-box binary rule-sets (`.srs`, `common/srs` upstream).
//!
//! Layout: `"SRS"`, a version byte, then a zlib stream holding a uvarint rule
//! count and the rules. A default rule is a list of `(item type, payload)`
//! records closed by `0xFF` and an invert byte; a logical rule is a mode byte,
//! its sub-rules and an invert byte. Domains are stored as a succinct
//! (LOUDS) trie over reversed names (`sing/common/domain`), IP CIDRs as
//! merged address ranges.
//!
//! [`PlainRuleSet`] mirrors sing-box's `PlainRuleSetCompat` field for field,
//! including items sbr cannot match on (process, Wi-Fi, …), so that `sbr
//! rule-set compile/decompile` round-trip anything sing-box produces. Only
//! [`PlainRuleSet::into_rules`] (what the router consumes) rejects them.

use std::io::{Read, Write};
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::Value;

use crate::obj::Obj;
use crate::{Error, LogicalMode, Matchers, Network, PortRange, Result, Rule, RuleAction, RuleKind};

const MAGIC: [u8; 3] = *b"SRS";
/// sing-box `C.RuleSetVersionCurrent`.
pub const VERSION_CURRENT: u8 = 5;
/// Decompressed size cap: geosite-style sets are a few MB; refuse zip bombs.
const MAX_DECOMPRESSED: u64 = 256 << 20;
const MAX_DEPTH: usize = 100;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const ITEM_FINAL: u8 = 0xFF;

/// A whole rule-set, source or binary.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PlainRuleSet {
    pub version: u8,
    pub rules: Vec<HeadlessRule>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HeadlessRule {
    Default(Box<DefaultRule>),
    Logical(LogicalRule),
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogicalRule {
    pub mode: LogicalMode,
    pub rules: Vec<HeadlessRule>,
    pub invert: bool,
}

/// sing-box `DefaultHeadlessRule`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DefaultRule {
    pub query_type: Vec<u16>,
    pub network: Vec<String>,
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub source_ip_cidr: Vec<IpNet>,
    pub ip_cidr: Vec<IpNet>,
    pub source_port: Vec<u16>,
    pub source_port_range: Vec<String>,
    pub port: Vec<u16>,
    pub port_range: Vec<String>,
    pub process_name: Vec<String>,
    pub process_path: Vec<String>,
    pub process_path_regex: Vec<String>,
    pub package_name: Vec<String>,
    pub package_name_regex: Vec<String>,
    /// wifi=0, cellular=1, ethernet=2, other=3.
    pub network_type: Vec<u8>,
    pub network_is_expensive: bool,
    pub network_is_constrained: bool,
    pub wifi_ssid: Vec<String>,
    pub wifi_bssid: Vec<String>,
    pub network_interface_address: Vec<(u8, Vec<IpNet>)>,
    pub default_interface_address: Vec<IpNet>,
    /// AdGuard filter lines (`||example.org^`). Binary-only, like sing-box:
    /// produced by `rule-set convert --type adguard`, not valid in source.
    pub adguard_domain: Vec<String>,
    pub invert: bool,
}

// ---------------------------------------------------------------------------
// Binary decoding

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

fn eof() -> String {
    "unexpected end of rule-set".into()
}

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> std::result::Result<u8, String> {
        let b = *self.buf.get(self.pos).ok_or_else(eof)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(eof)?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn uvarint(&mut self) -> std::result::Result<u64, String> {
        let mut x = 0u64;
        for shift in (0..70).step_by(7) {
            let b = self.byte()?;
            if shift == 63 && b > 1 {
                return Err("uvarint overflows 64 bits".into());
            }
            x |= u64::from(b & 0x7f) << shift;
            if b < 0x80 {
                return Ok(x);
            }
        }
        Err("uvarint overflows 64 bits".into())
    }

    /// A uvarint length that must fit in what is left (every element is at
    /// least `min` bytes), so a corrupt length can't make us allocate GBs.
    fn len(&mut self, min: usize) -> std::result::Result<usize, String> {
        let n = self.uvarint()?;
        let left = (self.buf.len() - self.pos) as u64;
        if n.saturating_mul(min.max(1) as u64) > left {
            return Err(eof());
        }
        Ok(n as usize)
    }

    fn bool(&mut self) -> std::result::Result<bool, String> {
        Ok(self.byte()? != 0)
    }

    fn strings(&mut self) -> std::result::Result<Vec<String>, String> {
        let n = self.len(1)?;
        (0..n)
            .map(|_| {
                let l = self.len(1)?;
                String::from_utf8(self.take(l)?.to_vec()).map_err(|_| "invalid UTF-8 string".to_string())
            })
            .collect()
    }

    fn u16s(&mut self) -> std::result::Result<Vec<u16>, String> {
        let n = self.len(2)?;
        (0..n)
            .map(|_| Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())))
            .collect()
    }

    fn u64s(&mut self) -> std::result::Result<Vec<u64>, String> {
        let n = self.len(8)?;
        (0..n)
            .map(|_| Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())))
            .collect()
    }

    fn bytes(&mut self) -> std::result::Result<Vec<u8>, String> {
        let n = self.len(1)?;
        Ok(self.take(n)?.to_vec())
    }

    fn addr(&mut self) -> std::result::Result<IpAddr, String> {
        match self.uvarint()? {
            4 => Ok(IpAddr::from(<[u8; 4]>::try_from(self.take(4)?).unwrap())),
            16 => Ok(IpAddr::from(<[u8; 16]>::try_from(self.take(16)?).unwrap())),
            n => Err(format!("invalid address length {n}")),
        }
    }

    fn prefix(&mut self) -> std::result::Result<IpNet, String> {
        let a = self.addr()?;
        let bits = self.byte()?;
        IpNet::new(a, bits).map_err(|_| format!("invalid prefix length {bits}"))
    }

    fn prefixes(&mut self) -> std::result::Result<Vec<IpNet>, String> {
        let n = self.len(2)?;
        (0..n).map(|_| self.prefix()).collect()
    }

    /// `common/srs/ip_set.go`: version 1, u64 count, then from/to address pairs.
    fn ip_set(&mut self) -> std::result::Result<Vec<IpNet>, String> {
        if self.byte()? != 1 {
            return Err("unknown IP set version".into());
        }
        let n = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
        if n.saturating_mul(10) > (self.buf.len() - self.pos) as u64 {
            return Err(eof());
        }
        let mut out = Vec::new();
        for _ in 0..n {
            match (self.addr()?, self.addr()?) {
                (IpAddr::V4(a), IpAddr::V4(b)) if a <= b => range_to_prefixes4(a.into(), b.into(), &mut out),
                (IpAddr::V6(a), IpAddr::V6(b)) if a <= b => range_to_prefixes6(a.into(), b.into(), &mut out),
                _ => return Err("malformed IP range".into()),
            }
        }
        Ok(out)
    }
}

/// Smallest CIDR cover of `[from, to]` (netipx `IPRange.Prefixes`).
fn range_to_prefixes4(mut from: u32, to: u32, out: &mut Vec<IpNet>) {
    loop {
        // Largest block aligned at `from` that doesn't pass `to`.
        let mut bits = from.trailing_zeros().min(32);
        while bits > 0 && (u64::from(from) + (1u64 << bits) - 1) > u64::from(to) {
            bits -= 1;
        }
        out.push(IpNet::new(IpAddr::from(std::net::Ipv4Addr::from(from)), 32 - bits as u8).unwrap());
        let next = u64::from(from) + (1u64 << bits);
        if next > u64::from(to) {
            return;
        }
        from = next as u32;
    }
}

fn range_to_prefixes6(mut from: u128, to: u128, out: &mut Vec<IpNet>) {
    loop {
        let mut bits = from.trailing_zeros().min(128);
        while bits > 0 && (bits == 128 || from.checked_add((1u128 << bits) - 1).is_none_or(|e| e > to)) {
            if bits == 128 && from == 0 && to == u128::MAX {
                break;
            }
            bits -= 1;
        }
        out.push(IpNet::new(IpAddr::from(std::net::Ipv6Addr::from(from)), 128 - bits as u8).unwrap());
        if bits == 128 {
            return;
        }
        match from.checked_add(1u128 << bits) {
            Some(next) if next <= to => from = next,
            _ => return,
        }
    }
}

/// Read a binary rule-set.
pub fn read(data: &[u8]) -> Result<PlainRuleSet> {
    if data.len() < 4 || data[..3] != MAGIC {
        return Err(Error::at("", "invalid sing-box rule-set file"));
    }
    let version = data[3];
    if version == 0 || version > VERSION_CURRENT {
        return Err(Error::at("version", format!("unsupported version {version}")));
    }
    let mut raw = Vec::new();
    flate2::read::ZlibDecoder::new(&data[4..])
        .take(MAX_DECOMPRESSED + 1)
        .read_to_end(&mut raw)
        .map_err(|e| Error::at("", format!("decompress: {e}")))?;
    if raw.len() as u64 > MAX_DECOMPRESSED {
        return Err(Error::at("", "rule-set too large"));
    }
    let mut c = Cursor { buf: &raw, pos: 0 };
    let n = c.len(2).map_err(|e| Error::at("rules", e))?;
    let mut rules = Vec::with_capacity(n);
    for i in 0..n {
        let path = format!("rules[{i}]");
        rules.push(read_rule(&mut c, 0, &path).map_err(|e| Error::at(&path, e))?);
    }
    Ok(PlainRuleSet { version, rules })
}

fn read_rule(c: &mut Cursor, depth: usize, path: &str) -> std::result::Result<HeadlessRule, String> {
    if depth > MAX_DEPTH {
        return Err("logical rule nested too deep".into());
    }
    match c.byte()? {
        0 => Ok(HeadlessRule::Default(Box::new(read_default(c)?))),
        1 => {
            let mode = match c.byte()? {
                0 => LogicalMode::And,
                1 => LogicalMode::Or,
                m => return Err(format!("unknown logical mode {m}")),
            };
            let n = c.len(2)?;
            let mut rules = Vec::with_capacity(n);
            for i in 0..n {
                rules.push(read_rule(c, depth + 1, &format!("{path}.rules[{i}]"))?);
            }
            Ok(HeadlessRule::Logical(LogicalRule {
                mode,
                rules,
                invert: c.bool()?,
            }))
        }
        t => Err(format!("unknown rule type {t}")),
    }
}

fn read_default(c: &mut Cursor) -> std::result::Result<DefaultRule, String> {
    let mut r = DefaultRule::default();
    loop {
        match c.byte()? {
            ITEM_QUERY_TYPE => r.query_type = c.u16s()?,
            ITEM_NETWORK => r.network = c.strings()?,
            ITEM_DOMAIN => {
                let (domain, suffix) = dump_domains(&Succinct::read(c)?.keys());
                r.domain = domain;
                r.domain_suffix = suffix;
            }
            ITEM_DOMAIN_KEYWORD => r.domain_keyword = c.strings()?,
            ITEM_DOMAIN_REGEX => r.domain_regex = c.strings()?,
            ITEM_SOURCE_IP_CIDR => r.source_ip_cidr = c.ip_set()?,
            ITEM_IP_CIDR => r.ip_cidr = c.ip_set()?,
            ITEM_SOURCE_PORT => r.source_port = c.u16s()?,
            ITEM_SOURCE_PORT_RANGE => r.source_port_range = c.strings()?,
            ITEM_PORT => r.port = c.u16s()?,
            ITEM_PORT_RANGE => r.port_range = c.strings()?,
            ITEM_PROCESS_NAME => r.process_name = c.strings()?,
            ITEM_PROCESS_PATH => r.process_path = c.strings()?,
            ITEM_PROCESS_PATH_REGEX => r.process_path_regex = c.strings()?,
            ITEM_PACKAGE_NAME => r.package_name = c.strings()?,
            ITEM_PACKAGE_NAME_REGEX => r.package_name_regex = c.strings()?,
            ITEM_WIFI_SSID => r.wifi_ssid = c.strings()?,
            ITEM_WIFI_BSSID => r.wifi_bssid = c.strings()?,
            ITEM_ADGUARD_DOMAIN => r.adguard_domain = dump_adguard(&Succinct::read(c)?.keys()),
            ITEM_NETWORK_TYPE => r.network_type = c.bytes()?,
            ITEM_NETWORK_IS_EXPENSIVE => r.network_is_expensive = true,
            ITEM_NETWORK_IS_CONSTRAINED => r.network_is_constrained = true,
            ITEM_NETWORK_INTERFACE_ADDRESS => {
                let n = c.len(2)?;
                for _ in 0..n {
                    let ty = c.byte()?;
                    r.network_interface_address.push((ty, c.prefixes()?));
                }
            }
            ITEM_DEFAULT_INTERFACE_ADDRESS => r.default_interface_address = c.prefixes()?,
            ITEM_FINAL => {
                r.invert = c.bool()?;
                return Ok(r);
            }
            t => return Err(format!("unknown rule item type {t}")),
        }
    }
}

// ---------------------------------------------------------------------------
// The succinct domain set (sing `common/domain/set.go`).

const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';
const SUFFIX_LABEL: u8 = 0x08; // '\b'

/// A LOUDS trie: in BFS order, each node contributes a 0 bit per child
/// (whose byte is in `labels`) and then a 1 bit. The k-th 0 bit overall is
/// the edge to node k+1. `leaves` marks nodes where a key ends.
struct Succinct {
    leaves: Vec<u64>,
    bitmap: Vec<u64>,
    labels: Vec<u8>,
}

fn get_bit(bm: &[u64], i: usize) -> bool {
    bm.get(i >> 6).is_some_and(|w| w & (1 << (i & 63)) != 0)
}

fn set_bit(bm: &mut Vec<u64>, i: usize) {
    if i >> 6 >= bm.len() {
        bm.resize((i >> 6) + 1, 0);
    }
    bm[i >> 6] |= 1 << (i & 63);
}

impl Succinct {
    fn read(c: &mut Cursor) -> std::result::Result<Self, String> {
        c.byte()?; // format version, ignored upstream too
        let s = Succinct {
            leaves: c.u64s()?,
            bitmap: c.u64s()?,
            labels: c.bytes()?,
        };
        let ones: usize = s.bitmap.iter().map(|w| w.count_ones() as usize).sum();
        let last = s
            .bitmap
            .iter()
            .enumerate()
            .rev()
            .find(|(_, w)| **w != 0)
            .map(|(i, w)| i * 64 + 63 - w.leading_zeros() as usize);
        let zeros = last.map_or(0, |l| l + 1 - ones);
        if ones != zeros + 1 || s.labels.len() != zeros {
            return Err("malformed succinct domain set".into());
        }
        Ok(s)
    }

    /// Mirror of `newSuccinctSet`, bit for bit. `keys` must be sorted and unique.
    fn build(keys: &[Vec<u8>]) -> Self {
        let mut s = Succinct {
            leaves: Vec::new(),
            bitmap: Vec::new(),
            labels: Vec::new(),
        };
        if keys.is_empty() {
            // Go would index keys[0] and panic; an empty set is one root with no children.
            set_bit(&mut s.bitmap, 0);
            return s;
        }
        let mut l_idx = 0;
        let mut queue = vec![(0usize, keys.len(), 0usize)];
        let mut i = 0;
        while i < queue.len() {
            let (mut start, end, col) = queue[i];
            if col == keys[start].len() {
                start += 1;
                set_bit(&mut s.leaves, i);
            }
            let mut j = start;
            while j < end {
                let from = j;
                while j < end && keys[j][col] == keys[from][col] {
                    j += 1;
                }
                queue.push((from, j, col + 1));
                s.labels.push(keys[from][col]);
                l_idx += 1; // a 0 bit: nothing to set
            }
            set_bit(&mut s.bitmap, l_idx);
            l_idx += 1;
            i += 1;
        }
        s
    }

    fn write(&self, w: &mut Vec<u8>) {
        w.push(0);
        put_uvarint(w, self.leaves.len() as u64);
        for x in &self.leaves {
            w.extend_from_slice(&x.to_be_bytes());
        }
        put_uvarint(w, self.bitmap.len() as u64);
        for x in &self.bitmap {
            w.extend_from_slice(&x.to_be_bytes());
        }
        put_uvarint(w, self.labels.len() as u64);
        w.extend_from_slice(&self.labels);
    }

    /// Every key, in trie (sorted) order.
    fn keys(&self) -> Vec<Vec<u8>> {
        // child_start[n]..child_start[n+1] are node n's edge (label) indices.
        let mut child_start = vec![0usize];
        let mut zeros = 0;
        let total = self.labels.len() * 2 + 1;
        for bit in 0..total {
            if get_bit(&self.bitmap, bit) {
                child_start.push(zeros);
            } else {
                zeros += 1;
            }
        }
        let mut out = Vec::new();
        let mut key = Vec::new();
        // (node, next edge to visit)
        let mut stack = vec![(0usize, child_start[0])];
        while let Some(&mut (node, ref mut edge)) = stack.last_mut() {
            if *edge >= child_start[node + 1] {
                stack.pop();
                key.pop();
                continue;
            }
            let k = *edge;
            *edge += 1;
            let child = k + 1;
            key.push(self.labels[k]);
            if get_bit(&self.leaves, child) {
                out.push(key.clone());
            }
            stack.push((child, child_start[child]));
        }
        out
    }
}

fn reverse_domain(s: &[u8]) -> Vec<u8> {
    // Go reverses by rune; do the same so multi-byte names survive.
    match std::str::from_utf8(s) {
        Ok(t) => t.chars().rev().collect::<String>().into_bytes(),
        Err(_) => s.iter().rev().copied().collect(),
    }
}

/// `Matcher.Dump`: back to `domain` / `domain_suffix` lists.
fn dump_domains(keys: &[Vec<u8>]) -> (Vec<String>, Vec<String>) {
    use std::collections::BTreeSet;
    let mut domains = BTreeSet::new();
    let mut prefixes = BTreeSet::new();
    let mut suffixes = Vec::new();
    for key in keys {
        let key = String::from_utf8_lossy(&reverse_domain(key)).into_owned();
        match key.as_bytes().first() {
            Some(&PREFIX_LABEL) => {
                prefixes.insert(key[1..].to_owned());
            }
            Some(&ROOT_LABEL) => suffixes.push(key[1..].to_owned()),
            Some(_) => {
                domains.insert(key);
            }
            None => {}
        }
    }
    for p in prefixes {
        // Version 1 encoded `domain_suffix: a.com` as `a.com` + `\r.a.com`.
        if let Some(root) = p.strip_prefix('.')
            && domains.remove(root)
        {
            suffixes.push(root.to_owned());
            continue;
        }
        suffixes.push(p);
    }
    suffixes.sort();
    (domains.into_iter().collect(), suffixes)
}

fn domain_keys(domain: &[String], suffix: &[String], legacy: bool) -> Vec<Vec<u8>> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut list = Vec::new();
    for d in suffix {
        if !seen.insert(d.clone()) {
            continue;
        }
        if d.starts_with('.') {
            list.push(reverse_domain(format!("\r{d}").as_bytes()));
        } else if legacy {
            list.push(reverse_domain(d.as_bytes()));
            let dotted = format!(".{d}");
            if seen.insert(dotted.clone()) {
                list.push(reverse_domain(format!("\r{dotted}").as_bytes()));
            }
        } else {
            list.push(reverse_domain(format!("\n{d}").as_bytes()));
        }
    }
    for d in domain {
        if seen.insert(d.clone()) {
            list.push(reverse_domain(d.as_bytes()));
        }
    }
    list.sort();
    list.dedup();
    list
}

/// `AdGuardMatcher.Dump`.
fn dump_adguard(keys: &[Vec<u8>]) -> Vec<String> {
    keys.iter()
        .filter_map(|k| {
            let mut key = reverse_domain(k);
            let (suffix, start) = match key.first()? {
                &PREFIX_LABEL => (false, false),
                &ROOT_LABEL => (true, false),
                _ => (false, true),
            };
            if !start {
                key.remove(0);
            }
            let has_end = key.last() != Some(&SUFFIX_LABEL);
            if !has_end {
                key.pop();
            }
            let mut s = String::from_utf8_lossy(&key).into_owned();
            if suffix {
                s.insert_str(0, "||");
            } else if start {
                s.insert(0, '|');
            }
            if has_end {
                s.push('^');
            }
            Some(s)
        })
        .collect()
}

fn adguard_keys(lines: &[String]) -> Vec<Vec<u8>> {
    let mut list: Vec<Vec<u8>> = lines
        .iter()
        .map(|line| {
            let mut l = line.as_str();
            let (mut suffix, mut start) = (false, false);
            if let Some(r) = l.strip_prefix("||") {
                l = r;
                suffix = true;
            } else if let Some(r) = l.strip_prefix('|') {
                l = r;
                start = true;
            }
            let end = l.ends_with('^');
            if end {
                l = &l[..l.len() - 1];
            }
            let mut s = String::new();
            if suffix {
                s.push(ROOT_LABEL as char);
            } else if !start {
                s.push(PREFIX_LABEL as char);
            }
            s.push_str(l);
            if !end {
                if s.ends_with('.') {
                    s.pop();
                }
                s.push(SUFFIX_LABEL as char);
            }
            reverse_domain(s.as_bytes())
        })
        .collect();
    list.sort();
    list.dedup();
    list
}

// ---------------------------------------------------------------------------
// Binary encoding

fn put_uvarint(w: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        w.push(x as u8 | 0x80);
        x >>= 7;
    }
    w.push(x as u8);
}

fn put_strings(w: &mut Vec<u8>, item: u8, v: &[String]) {
    w.push(item);
    put_uvarint(w, v.len() as u64);
    for s in v {
        put_uvarint(w, s.len() as u64);
        w.extend_from_slice(s.as_bytes());
    }
}

fn put_u16s(w: &mut Vec<u8>, item: u8, v: &[u16]) {
    w.push(item);
    put_uvarint(w, v.len() as u64);
    for x in v {
        w.extend_from_slice(&x.to_be_bytes());
    }
}

fn put_addr(w: &mut Vec<u8>, a: IpAddr) {
    match a {
        IpAddr::V4(a) => {
            put_uvarint(w, 4);
            w.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            put_uvarint(w, 16);
            w.extend_from_slice(&a.octets());
        }
    }
}

fn put_prefix(w: &mut Vec<u8>, p: &IpNet) {
    put_addr(w, p.addr());
    w.push(p.prefix_len());
}

/// netipx `IPSetBuilder` semantics: merge overlapping and adjacent ranges,
/// IPv4 before IPv6.
fn put_ip_set(w: &mut Vec<u8>, item: u8, nets: &[IpNet]) {
    let mut v4: Vec<(u32, u32)> = Vec::new();
    let mut v6: Vec<(u128, u128)> = Vec::new();
    for n in nets {
        match n.trunc() {
            IpNet::V4(n) => v4.push((n.network().into(), n.broadcast().into())),
            IpNet::V6(n) => v6.push((n.network().into(), n.broadcast().into())),
        }
    }
    fn merge<T: Ord + Copy>(mut v: Vec<(T, T)>, next: impl Fn(T) -> Option<T>) -> Vec<(T, T)> {
        v.sort_unstable();
        let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
        for (s, e) in v {
            if let Some(last) = out.last_mut()
                && next(last.1).is_none_or(|n| s <= n)
            {
                last.1 = last.1.max(e);
                continue;
            }
            out.push((s, e));
        }
        out
    }
    let v4 = merge(v4, |x| x.checked_add(1));
    let v6 = merge(v6, |x| x.checked_add(1));
    w.push(item);
    w.push(1);
    w.extend_from_slice(&((v4.len() + v6.len()) as u64).to_be_bytes());
    for (s, e) in v4 {
        put_addr(w, IpAddr::from(std::net::Ipv4Addr::from(s)));
        put_addr(w, IpAddr::from(std::net::Ipv4Addr::from(e)));
    }
    for (s, e) in v6 {
        put_addr(w, IpAddr::from(std::net::Ipv6Addr::from(s)));
        put_addr(w, IpAddr::from(std::net::Ipv6Addr::from(e)));
    }
}

fn need(version: u8, min: u8, what: &str) -> std::result::Result<(), String> {
    if version < min {
        Err(format!(
            "`{what}` rule item is only supported in version {min} or later"
        ))
    } else {
        Ok(())
    }
}

fn write_default(w: &mut Vec<u8>, r: &DefaultRule, version: u8) -> std::result::Result<(), String> {
    w.push(0);
    if !r.query_type.is_empty() {
        put_u16s(w, ITEM_QUERY_TYPE, &r.query_type);
    }
    if !r.network.is_empty() {
        put_strings(w, ITEM_NETWORK, &r.network);
    }
    if !r.domain.is_empty() || !r.domain_suffix.is_empty() {
        if r.domain.iter().any(String::is_empty) {
            return Err("domain: empty item is not allowed".into());
        }
        if r.domain_suffix.iter().any(String::is_empty) {
            return Err("domain_suffix: empty item is not allowed".into());
        }
        w.push(ITEM_DOMAIN);
        Succinct::build(&domain_keys(&r.domain, &r.domain_suffix, version == 1)).write(w);
    }
    if !r.domain_keyword.is_empty() {
        put_strings(w, ITEM_DOMAIN_KEYWORD, &r.domain_keyword);
    }
    if !r.domain_regex.is_empty() {
        put_strings(w, ITEM_DOMAIN_REGEX, &r.domain_regex);
    }
    if !r.source_ip_cidr.is_empty() {
        put_ip_set(w, ITEM_SOURCE_IP_CIDR, &r.source_ip_cidr);
    }
    if !r.ip_cidr.is_empty() {
        put_ip_set(w, ITEM_IP_CIDR, &r.ip_cidr);
    }
    if !r.source_port.is_empty() {
        put_u16s(w, ITEM_SOURCE_PORT, &r.source_port);
    }
    if !r.source_port_range.is_empty() {
        put_strings(w, ITEM_SOURCE_PORT_RANGE, &r.source_port_range);
    }
    if !r.port.is_empty() {
        put_u16s(w, ITEM_PORT, &r.port);
    }
    if !r.port_range.is_empty() {
        put_strings(w, ITEM_PORT_RANGE, &r.port_range);
    }
    for (item, v) in [
        (ITEM_PROCESS_NAME, &r.process_name),
        (ITEM_PROCESS_PATH, &r.process_path),
        (ITEM_PROCESS_PATH_REGEX, &r.process_path_regex),
        (ITEM_PACKAGE_NAME, &r.package_name),
    ] {
        if !v.is_empty() {
            put_strings(w, item, v);
        }
    }
    if !r.package_name_regex.is_empty() {
        need(version, 5, "package_name_regex")?;
        put_strings(w, ITEM_PACKAGE_NAME_REGEX, &r.package_name_regex);
    }
    if !r.network_type.is_empty() {
        need(version, 3, "network_type")?;
        w.push(ITEM_NETWORK_TYPE);
        put_uvarint(w, r.network_type.len() as u64);
        w.extend_from_slice(&r.network_type);
    }
    if r.network_is_expensive {
        need(version, 3, "network_is_expensive")?;
        w.push(ITEM_NETWORK_IS_EXPENSIVE);
    }
    if r.network_is_constrained {
        need(version, 3, "network_is_constrained")?;
        w.push(ITEM_NETWORK_IS_CONSTRAINED);
    }
    if !r.network_interface_address.is_empty() {
        need(version, 4, "network_interface_address")?;
        w.push(ITEM_NETWORK_INTERFACE_ADDRESS);
        put_uvarint(w, r.network_interface_address.len() as u64);
        for (ty, prefixes) in &r.network_interface_address {
            w.push(*ty);
            put_uvarint(w, prefixes.len() as u64);
            for p in prefixes {
                put_prefix(w, p);
            }
        }
    }
    if !r.default_interface_address.is_empty() {
        need(version, 4, "default_interface_address")?;
        w.push(ITEM_DEFAULT_INTERFACE_ADDRESS);
        put_uvarint(w, r.default_interface_address.len() as u64);
        for p in &r.default_interface_address {
            put_prefix(w, p);
        }
    }
    if !r.wifi_ssid.is_empty() {
        put_strings(w, ITEM_WIFI_SSID, &r.wifi_ssid);
    }
    if !r.wifi_bssid.is_empty() {
        put_strings(w, ITEM_WIFI_BSSID, &r.wifi_bssid);
    }
    if !r.adguard_domain.is_empty() {
        need(version, 2, "AdGuard")?;
        w.push(ITEM_ADGUARD_DOMAIN);
        Succinct::build(&adguard_keys(&r.adguard_domain)).write(w);
    }
    w.push(ITEM_FINAL);
    w.push(r.invert as u8);
    Ok(())
}

fn write_rule(w: &mut Vec<u8>, r: &HeadlessRule, version: u8, path: &str) -> Result<()> {
    match r {
        HeadlessRule::Default(d) => write_default(w, d, version).map_err(|e| Error::at(path, e)),
        HeadlessRule::Logical(l) => {
            w.push(1);
            w.push(match l.mode {
                LogicalMode::And => 0,
                LogicalMode::Or => 1,
            });
            put_uvarint(w, l.rules.len() as u64);
            for (i, r) in l.rules.iter().enumerate() {
                write_rule(w, r, version, &format!("{path}.rules[{i}]"))?;
            }
            w.push(l.invert as u8);
            Ok(())
        }
    }
}

impl PlainRuleSet {
    /// The decompressed body, i.e. everything after the version byte before
    /// zlib. Compressors differ between Go and Rust, so this (not the file)
    /// is what is byte-identical across implementations.
    pub fn encode_body(&self) -> Result<Vec<u8>> {
        if self.version == 0 || self.version > VERSION_CURRENT {
            return Err(Error::at("version", format!("unsupported version {}", self.version)));
        }
        let mut body = Vec::new();
        put_uvarint(&mut body, self.rules.len() as u64);
        for (i, r) in self.rules.iter().enumerate() {
            write_rule(&mut body, r, self.version, &format!("rules[{i}]"))?;
        }
        Ok(body)
    }

    /// Encode as `.srs`, at `self.version`.
    pub fn write(&self) -> Result<Vec<u8>> {
        let body = self.encode_body()?;
        let mut out = Vec::with_capacity(body.len() / 2 + 8);
        out.extend_from_slice(&MAGIC);
        out.push(self.version);
        let mut z = flate2::write::ZlibEncoder::new(out, flate2::Compression::best());
        z.write_all(&body).expect("in-memory write");
        Ok(z.finish().expect("in-memory write"))
    }

    /// `sing-box rule-set compile` lowers the version to the oldest one that
    /// can carry the rules, so old cores keep loading new files.
    pub fn downgrade_version(&mut self) {
        let any = |f: &dyn Fn(&DefaultRule) -> bool| any_default(&self.rules, f);
        if self.version == 5 && !any(&|r| !r.package_name_regex.is_empty()) {
            self.version = 4;
        }
        if self.version == 4
            && !any(&|r| !r.network_interface_address.is_empty() || !r.default_interface_address.is_empty())
        {
            self.version = 3;
        }
        if self.version == 3
            && !any(&|r| !r.network_type.is_empty() || r.network_is_expensive || r.network_is_constrained)
        {
            self.version = 2;
        }
    }

    pub fn has_adguard(&self) -> bool {
        any_default(&self.rules, &|r| !r.adguard_domain.is_empty())
    }

    /// Parse the source (JSON) format, accepting every field sing-box does.
    pub fn from_json(input: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(&crate::types::strip_comments(input))?;
        let mut o = Obj::new(value, "")?;
        let version: u8 = o.req("version")?;
        if version == 0 || version > VERSION_CURRENT {
            return Err(Error::at("version", format!("unknown rule-set version {version}")));
        }
        let rules = crate::array(o.raw("rules"), "rules")?
            .into_iter()
            .enumerate()
            .map(|(i, v)| json_rule(Obj::new(v, format!("rules[{i}]"))?, 0))
            .collect::<Result<_>>()?;
        o.finish()?;
        Ok(Self { version, rules })
    }

    /// Source format, indented like `sing-box rule-set decompile`.
    pub fn to_json_pretty(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).expect("serializable");
        s.push('\n');
        s
    }

    /// The rules in the form sbr's router compiles. Fails on items sbr can't
    /// match on (process, Wi-Fi, DNS query type, …), naming the item.
    pub fn into_rules(self) -> Result<Vec<Rule>> {
        self.rules
            .into_iter()
            .enumerate()
            .map(|(i, r)| into_rule(r, &format!("rules[{i}]")))
            .collect()
    }
}

fn any_default(rules: &[HeadlessRule], f: &dyn Fn(&DefaultRule) -> bool) -> bool {
    rules.iter().any(|r| match r {
        HeadlessRule::Default(d) => f(d),
        HeadlessRule::Logical(l) => any_default(&l.rules, f),
    })
}

/// Decode a rule-set file in either format into router rules.
pub fn parse_rule_set(data: &[u8], format: crate::RuleSetFormat) -> Result<Vec<Rule>> {
    match format {
        crate::RuleSetFormat::Binary => read(data)?.into_rules(),
        crate::RuleSetFormat::Source => {
            let text = std::str::from_utf8(data).map_err(|_| Error::at("", "rule-set is not UTF-8"))?;
            crate::parse_rule_set_source(text)
        }
    }
}

// ---------------------------------------------------------------------------
// Conversion to router rules

fn into_rule(r: HeadlessRule, path: &str) -> Result<Rule> {
    match r {
        HeadlessRule::Logical(l) => Ok(Rule {
            kind: RuleKind::Logical {
                mode: l.mode,
                rules: l
                    .rules
                    .into_iter()
                    .enumerate()
                    .map(|(i, r)| into_rule(r, &format!("{path}.rules[{i}]")))
                    .collect::<Result<_>>()?,
            },
            invert: l.invert,
            action: RuleAction::None,
        }),
        HeadlessRule::Default(d) => {
            let d = *d;
            let unsupported = |name: &str| Error::at(&format!("{path}.{name}"), "not supported by sbr yet");
            for (name, present) in [
                ("query_type", !d.query_type.is_empty()),
                ("process_name", !d.process_name.is_empty()),
                ("process_path", !d.process_path.is_empty()),
                ("process_path_regex", !d.process_path_regex.is_empty()),
                ("package_name", !d.package_name.is_empty()),
                ("package_name_regex", !d.package_name_regex.is_empty()),
                ("network_type", !d.network_type.is_empty()),
                ("network_is_expensive", d.network_is_expensive),
                ("network_is_constrained", d.network_is_constrained),
                ("wifi_ssid", !d.wifi_ssid.is_empty()),
                ("wifi_bssid", !d.wifi_bssid.is_empty()),
                ("network_interface_address", !d.network_interface_address.is_empty()),
                ("default_interface_address", !d.default_interface_address.is_empty()),
            ] {
                if present {
                    return Err(unsupported(name));
                }
            }
            let network = d
                .network
                .iter()
                .map(|n| match n.as_str() {
                    "tcp" => Ok(Network::Tcp),
                    "udp" => Ok(Network::Udp),
                    "icmp" => Ok(Network::Icmp),
                    _ => Err(Error::at(&format!("{path}.network"), format!("unknown network {n:?}"))),
                })
                .collect::<Result<_>>()?;
            let lower = |v: Vec<String>| v.into_iter().map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>();
            let mut m = Matchers {
                network,
                domain: lower(d.domain),
                domain_suffix: lower(d.domain_suffix),
                domain_keyword: lower(d.domain_keyword),
                domain_regex: d.domain_regex,
                source_ip_cidr: d.source_ip_cidr,
                ip_cidr: d.ip_cidr,
                source_port: d.source_port,
                source_port_range: port_ranges(&d.source_port_range, &format!("{path}.source_port_range"))?,
                port: d.port,
                port_range: port_ranges(&d.port_range, &format!("{path}.port_range"))?,
                ..Default::default()
            };
            adguard_into(&d.adguard_domain, &mut m);
            Ok(Rule {
                kind: RuleKind::Default(Box::new(m)),
                invert: d.invert,
                action: RuleAction::None,
            })
        }
    }
}

/// AdGuard DNS filter lines as plain domain matchers. The common
/// `||host^` and `|host^` forms become exact suffix/domain entries (hash
/// lookups); anything with wildcards or open ends becomes a regex with the
/// same meaning as sing-box's AdGuard matcher.
fn adguard_into(lines: &[String], m: &mut Matchers) {
    for line in lines {
        let mut l = line.as_str();
        let (suffix, start) = if let Some(r) = l.strip_prefix("||") {
            l = r;
            (true, false)
        } else if let Some(r) = l.strip_prefix('|') {
            l = r;
            (false, true)
        } else {
            (false, false)
        };
        let end = match l.strip_suffix('^') {
            Some(r) => {
                l = r;
                true
            }
            None => {
                l = l.strip_suffix('.').unwrap_or(l);
                false
            }
        };
        let l = l.to_ascii_lowercase();
        if end && !l.contains('*') {
            if suffix {
                m.domain_suffix.push(l);
                continue;
            }
            if start {
                m.domain.push(l);
                continue;
            }
        }
        let mut re = String::from(if suffix {
            r"(?:^|\.)"
        } else if start {
            "^"
        } else {
            ""
        });
        for part in l.split('*').enumerate() {
            if part.0 > 0 {
                re.push_str(".*");
            }
            re.push_str(&regex_escape(part.1));
        }
        if end {
            re.push('$');
        }
        m.domain_regex.push(re);
    }
}

fn regex_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

fn port_ranges(v: &[String], path: &str) -> Result<Vec<PortRange>> {
    v.iter()
        .map(|s| crate::route::parse_port_range(s).ok_or_else(|| Error::at(path, format!("invalid port range {s:?}"))))
        .collect()
}

// ---------------------------------------------------------------------------
// Source (JSON) model

fn json_rule(mut o: Obj, depth: usize) -> Result<HeadlessRule> {
    if depth > MAX_DEPTH {
        return Err(Error::at(o.path(), "logical rule nested too deep"));
    }
    let ty = o.string("type")?.unwrap_or_else(|| "default".into());
    let r = match ty.as_str() {
        "default" => HeadlessRule::Default(Box::new(json_default(&mut o)?)),
        "logical" => {
            let mode = match o.req::<String>("mode")?.as_str() {
                "and" => LogicalMode::And,
                "or" => LogicalMode::Or,
                m => return Err(Error::at(&o.sub("mode"), format!("unknown logical mode {m:?}"))),
            };
            let path = o.sub("rules");
            let rules = crate::array(o.raw("rules"), &path)?
                .into_iter()
                .enumerate()
                .map(|(i, v)| json_rule(Obj::new(v, format!("{path}[{i}]"))?, depth + 1))
                .collect::<Result<_>>()?;
            HeadlessRule::Logical(LogicalRule {
                mode,
                rules,
                invert: o.bool("invert")?,
            })
        }
        t => return Err(Error::at(&o.sub("type"), format!("unknown rule type {t:?}"))),
    };
    o.finish()?;
    Ok(r)
}

fn json_prefixes(o: &mut Obj, key: &str) -> Result<Vec<IpNet>> {
    let path = o.sub(key);
    o.list::<String>(key)?
        .into_iter()
        .map(|s| parse_prefixable(&s).ok_or_else(|| Error::at(&path, format!("invalid prefix {s:?}"))))
        .collect()
}

fn parse_prefixable(s: &str) -> Option<IpNet> {
    s.parse::<IpNet>()
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))
}

fn interface_type(s: &str) -> Option<u8> {
    Some(match s {
        "wifi" => 0,
        "cellular" => 1,
        "ethernet" => 2,
        "other" => 3,
        _ => return None,
    })
}

fn interface_type_name(t: u8) -> String {
    match t {
        0 => "wifi".into(),
        1 => "cellular".into(),
        2 => "ethernet".into(),
        3 => "other".into(),
        t => format!("unknown({t})"),
    }
}

/// The DNS RR types `miekg/dns` names; sing-box prints these as strings.
const DNS_TYPES: &[(u16, &str)] = &[
    (1, "A"),
    (2, "NS"),
    (5, "CNAME"),
    (6, "SOA"),
    (12, "PTR"),
    (13, "HINFO"),
    (15, "MX"),
    (16, "TXT"),
    (28, "AAAA"),
    (33, "SRV"),
    (35, "NAPTR"),
    (39, "DNAME"),
    (41, "OPT"),
    (43, "DS"),
    (46, "RRSIG"),
    (47, "NSEC"),
    (48, "DNSKEY"),
    (50, "NSEC3"),
    (52, "TLSA"),
    (64, "SVCB"),
    (65, "HTTPS"),
    (99, "SPF"),
    (252, "AXFR"),
    (255, "ANY"),
    (257, "CAA"),
];

fn json_default(o: &mut Obj) -> Result<DefaultRule> {
    let query_type = {
        let path = o.sub("query_type");
        o.list::<Value>("query_type")?
            .into_iter()
            .map(|v| match v {
                Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
                Value::String(s) => DNS_TYPES.iter().find(|(_, n)| n.eq_ignore_ascii_case(&s)).map(|t| t.0),
                _ => None,
            })
            .map(|t| t.ok_or_else(|| Error::at(&path, "invalid DNS query type")))
            .collect::<Result<_>>()?
    };
    let network_type = {
        let path = o.sub("network_type");
        o.list::<String>("network_type")?
            .iter()
            .map(|s| interface_type(s).ok_or_else(|| Error::at(&path, format!("unknown interface type {s:?}"))))
            .collect::<Result<_>>()?
    };
    let network_interface_address = match o.raw("network_interface_address") {
        None => Vec::new(),
        Some(v) => {
            let path = o.sub("network_interface_address");
            let mut m = Obj::new(v, path.clone())?;
            let mut out = Vec::new();
            for key in m.keys() {
                let ty =
                    interface_type(&key).ok_or_else(|| Error::at(&path, format!("unknown interface type {key:?}")))?;
                out.push((ty, json_prefixes(&mut m, &key)?));
            }
            m.finish()?;
            out
        }
    };
    let r = DefaultRule {
        query_type,
        network: o.list("network")?,
        domain: o.list("domain")?,
        domain_suffix: o.list("domain_suffix")?,
        domain_keyword: o.list("domain_keyword")?,
        domain_regex: o.list("domain_regex")?,
        source_ip_cidr: json_prefixes(o, "source_ip_cidr")?,
        ip_cidr: json_prefixes(o, "ip_cidr")?,
        source_port: o.list("source_port")?,
        source_port_range: o.list("source_port_range")?,
        port: o.list("port")?,
        port_range: o.list("port_range")?,
        process_name: o.list("process_name")?,
        process_path: o.list("process_path")?,
        process_path_regex: o.list("process_path_regex")?,
        package_name: o.list("package_name")?,
        package_name_regex: o.list("package_name_regex")?,
        network_type,
        network_is_expensive: o.bool("network_is_expensive")?,
        network_is_constrained: o.bool("network_is_constrained")?,
        wifi_ssid: o.list("wifi_ssid")?,
        wifi_bssid: o.list("wifi_bssid")?,
        network_interface_address,
        default_interface_address: json_prefixes(o, "default_interface_address")?,
        adguard_domain: Vec::new(),
        invert: o.bool("invert")?,
    };
    Ok(r)
}

/// Go's `badoption.Listable`: one element is written bare.
struct Listable<'a, T>(&'a [T]);

impl<T: Serialize> Serialize for Listable<'_, T> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self.0 {
            [one] => one.serialize(s),
            all => all.serialize(s),
        }
    }
}

/// `badoption.Prefixable`: single addresses print without `/32`.
fn prefix_str(p: &IpNet) -> String {
    if p.prefix_len() == p.max_prefix_len() {
        p.addr().to_string()
    } else {
        p.to_string()
    }
}

impl Serialize for PlainRuleSet {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("version", &self.version)?;
        if !self.rules.is_empty() {
            m.serialize_entry("rules", &self.rules)?;
        }
        m.end()
    }
}

impl Serialize for HeadlessRule {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            HeadlessRule::Default(d) => d.serialize(s),
            HeadlessRule::Logical(l) => {
                let mut m = s.serialize_map(None)?;
                m.serialize_entry("type", "logical")?;
                m.serialize_entry(
                    "mode",
                    match l.mode {
                        LogicalMode::And => "and",
                        LogicalMode::Or => "or",
                    },
                )?;
                if !l.rules.is_empty() {
                    m.serialize_entry("rules", &l.rules)?;
                }
                if l.invert {
                    m.serialize_entry("invert", &true)?;
                }
                m.end()
            }
        }
    }
}

impl Serialize for DefaultRule {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        if !self.query_type.is_empty() {
            let v: Vec<Value> = self
                .query_type
                .iter()
                .map(|t| match DNS_TYPES.iter().find(|(n, _)| n == t) {
                    Some((_, name)) => Value::from(*name),
                    None => Value::from(*t),
                })
                .collect();
            m.serialize_entry("query_type", &Listable(&v))?;
        }
        macro_rules! list {
            ($($f:ident),*) => {$(
                if !self.$f.is_empty() {
                    m.serialize_entry(stringify!($f), &Listable(&self.$f))?;
                }
            )*};
        }
        let cidrs = |v: &[IpNet]| v.iter().map(prefix_str).collect::<Vec<_>>();
        list!(network, domain, domain_suffix, domain_keyword, domain_regex);
        if !self.source_ip_cidr.is_empty() {
            m.serialize_entry("source_ip_cidr", &Listable(&cidrs(&self.source_ip_cidr)))?;
        }
        if !self.ip_cidr.is_empty() {
            m.serialize_entry("ip_cidr", &Listable(&cidrs(&self.ip_cidr)))?;
        }
        list!(
            source_port,
            source_port_range,
            port,
            port_range,
            process_name,
            process_path,
            process_path_regex,
            package_name,
            package_name_regex
        );
        if !self.network_type.is_empty() {
            let v: Vec<String> = self.network_type.iter().map(|t| interface_type_name(*t)).collect();
            m.serialize_entry("network_type", &Listable(&v))?;
        }
        if self.network_is_expensive {
            m.serialize_entry("network_is_expensive", &true)?;
        }
        if self.network_is_constrained {
            m.serialize_entry("network_is_constrained", &true)?;
        }
        list!(wifi_ssid, wifi_bssid);
        if !self.network_interface_address.is_empty() {
            let mut obj = serde_json::Map::new();
            for (t, p) in &self.network_interface_address {
                let v = cidrs(p);
                obj.insert(interface_type_name(*t), serde_json::to_value(Listable(&v)).unwrap());
            }
            m.serialize_entry("network_interface_address", &obj)?;
        }
        if !self.default_interface_address.is_empty() {
            m.serialize_entry(
                "default_interface_address",
                &Listable(&cidrs(&self.default_interface_address)),
            )?;
        }
        if self.invert {
            m.serialize_entry("invert", &true)?;
        }
        m.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(json: &str) -> PlainRuleSet {
        let set = PlainRuleSet::from_json(json).unwrap();
        let bin = set.write().unwrap();
        let back = read(&bin).unwrap();
        assert_eq!(back.version, set.version);
        back
    }

    #[test]
    fn succinct_roundtrip() {
        let keys: Vec<Vec<u8>> = {
            let mut k = vec![
                b"moc.elgoog".to_vec(),
                b"moc.elgoog.\r".to_vec(),
                b"nc\n".to_vec(),
                b"a".to_vec(),
            ];
            k.sort();
            k
        };
        let s = Succinct::build(&keys);
        let mut buf = Vec::new();
        s.write(&mut buf);
        let mut c = Cursor { buf: &buf, pos: 0 };
        let back = Succinct::read(&mut c).unwrap();
        assert_eq!(back.keys(), keys);
    }

    #[test]
    fn domains_roundtrip_v1_and_v2() {
        for v in [1, 2, 3] {
            let back = roundtrip(&format!(
                r#"{{"version":{v},"rules":[{{"domain":["a.com","Ü.de"],"domain_suffix":["example.org",".cn"]}}]}}"#
            ));
            let HeadlessRule::Default(d) = &back.rules[0] else {
                panic!()
            };
            assert_eq!(d.domain, vec!["a.com", "Ü.de"], "v{v}");
            assert_eq!(d.domain_suffix, vec![".cn", "example.org"], "v{v}");
        }
    }

    #[test]
    fn everything_roundtrips() {
        let json = r#"{"version":4,"rules":[
            {"query_type":["A",64,"HTTPS"],"network":"tcp","domain_keyword":["goog"],"domain_regex":"^a$",
             "source_ip_cidr":["10.0.0.0/8","10.1.0.0/16"],"ip_cidr":["1.1.1.1","2001:db8::/32","1.0.0.0/24"],
             "source_port":[1,2],"source_port_range":"1000:2000","port":443,"port_range":[":80","8000:"],
             "process_name":"curl","process_path":"/bin/x","process_path_regex":"x","package_name":"com.x",
             "network_type":["wifi","cellular"],"network_is_expensive":true,"network_is_constrained":true,
             "wifi_ssid":"home","wifi_bssid":"00:00:00:00:00:00",
             "network_interface_address":{"wifi":["192.168.0.0/16"]},"default_interface_address":"10.0.0.1/32",
             "invert":true},
            {"type":"logical","mode":"or","rules":[{"port":53},{"type":"logical","mode":"and","rules":[{"network":"udp"}],"invert":true}]}
        ]}"#;
        let set = PlainRuleSet::from_json(json).unwrap();
        let back = roundtrip(json);
        let HeadlessRule::Default(d) = &back.rules[0] else {
            panic!()
        };
        assert_eq!(d.query_type, vec![1, 64, 65]);
        // IP sets come back merged and as minimal prefixes.
        assert_eq!(d.source_ip_cidr, vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]);
        assert_eq!(
            d.ip_cidr,
            ["1.0.0.0/24", "1.1.1.1/32", "2001:db8::/32"]
                .iter()
                .map(|s| s.parse::<IpNet>().unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(back.rules[1], set.rules[1]);
        let mut a = (**d).clone();
        let HeadlessRule::Default(b) = &set.rules[0] else {
            panic!()
        };
        a.ip_cidr.clone_from(&b.ip_cidr);
        a.source_ip_cidr.clone_from(&b.source_ip_cidr);
        assert_eq!(&a, &**b);
        // And JSON → model → JSON is stable.
        let again = PlainRuleSet::from_json(&back.to_json_pretty()).unwrap();
        assert_eq!(again, back);
    }

    #[test]
    fn version_gates() {
        let set = PlainRuleSet::from_json(r#"{"version":2,"rules":[{"network_type":"wifi"}]}"#).unwrap();
        assert!(set.write().is_err());
        let mut set = PlainRuleSet::from_json(r#"{"version":4,"rules":[{"domain":"a"}]}"#).unwrap();
        set.downgrade_version();
        assert_eq!(set.version, 2);
    }

    #[test]
    fn ranges_to_prefixes() {
        let mut v = Vec::new();
        range_to_prefixes4(0x0a000001, 0x0a000006, &mut v);
        let s: Vec<String> = v.iter().map(ToString::to_string).collect();
        assert_eq!(s, ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]);
        v.clear();
        range_to_prefixes4(0, u32::MAX, &mut v);
        assert_eq!(v, vec!["0.0.0.0/0".parse::<IpNet>().unwrap()]);
        v.clear();
        range_to_prefixes6(0, u128::MAX, &mut v);
        assert_eq!(v, vec!["::/0".parse::<IpNet>().unwrap()]);
        v.clear();
        range_to_prefixes6(u128::MAX, u128::MAX, &mut v);
        assert_eq!(
            v,
            vec!["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128".parse::<IpNet>().unwrap()]
        );
    }

    #[test]
    fn adguard() {
        let lines: Vec<String> = ["||ads.example^", "|exact.example^", "||track*.net^", "banner", "|start"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut keys = adguard_keys(&lines);
        keys.sort();
        let mut dumped = dump_adguard(&keys);
        dumped.sort();
        let mut want = lines.clone();
        want.sort();
        assert_eq!(dumped, want);
        let mut m = Matchers::default();
        adguard_into(&lines, &mut m);
        assert_eq!(m.domain_suffix, ["ads.example"]);
        assert_eq!(m.domain, ["exact.example"]);
        assert_eq!(m.domain_regex, [r"(?:^|\.)track.*\.net$", "banner", "^start"]);
    }

    #[test]
    fn unsupported_items_are_rejected_for_routing() {
        let set = PlainRuleSet::from_json(r#"{"version":2,"rules":[{"port":1},{"process_name":"x"}]}"#).unwrap();
        let err = read(&set.write().unwrap()).unwrap().into_rules().unwrap_err();
        assert_eq!(err.to_string(), "rules[1].process_name: not supported by sbr yet");
    }

    #[test]
    fn corrupt_input_is_an_error() {
        assert!(read(b"SRX\x01").is_err());
        let set = PlainRuleSet::from_json(r#"{"version":2,"rules":[{"domain":["a.com","b.com"]}]}"#).unwrap();
        let body = set.encode_body().unwrap();
        for cut in 0..body.len() {
            let mut out = MAGIC.to_vec();
            out.push(2);
            let mut z = flate2::write::ZlibEncoder::new(out, flate2::Compression::fast());
            z.write_all(&body[..cut]).unwrap();
            assert!(read(&z.finish().unwrap()).is_err(), "truncated at {cut}");
        }
    }
}
