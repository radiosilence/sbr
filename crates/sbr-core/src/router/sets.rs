//! Lookup structures tuned for large rule-sets (100k+ domains / CIDRs).

use std::collections::HashSet;
use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use ipnet::IpNet;
use regex::RegexSet;
use sbr_config::PortRange;

const MOBILE: bool = cfg!(any(target_os = "ios", target_os = "tvos", target_os = "visionos"));

#[derive(Default)]
pub struct DomainSet {
    exact: HashSet<Box<str>>,
    /// `example.com` in `domain_suffix`: matches itself and subdomains.
    suffix: HashSet<Box<str>>,
    /// `.example.com` in `domain_suffix`: subdomains only.
    dot_suffix: HashSet<Box<str>>,
    keyword: Option<AhoCorasick>,
    regex: Option<RegexSet>,
}

impl DomainSet {
    pub fn new(
        domain: &[String],
        suffix: &[String],
        keyword: &[String],
        regex: &[String],
    ) -> Result<Self, regex::Error> {
        let mut s = DomainSet::default();
        s.exact.extend(domain.iter().map(|d| d.as_str().into()));
        for d in suffix {
            match d.strip_prefix('.') {
                Some(rest) => s.dot_suffix.insert(rest.into()),
                None => s.suffix.insert(d.as_str().into()),
            };
        }
        if !keyword.is_empty() {
            s.keyword = Some(AhoCorasick::new(keyword).expect("keyword automaton"));
        }
        if !regex.is_empty() {
            // The default limits (10 MiB compiled, 2 MiB per lazy-DFA cache)
            // let one remote rule-set's patterns take a fifth of the iOS
            // extension's memory. Patterns over the size limit fail the
            // rule-set's load; a set whose lazy DFA outgrows its cache falls
            // back to slower engines per search instead.
            let (size, dfa) = if MOBILE {
                (4 << 20, 512 << 10)
            } else {
                (10 << 20, 2 << 20)
            };
            s.regex = Some(
                regex::RegexSetBuilder::new(regex)
                    .size_limit(size)
                    .dfa_size_limit(dfa)
                    .build()?,
            );
        }
        Ok(s)
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.suffix.is_empty()
            && self.dot_suffix.is_empty()
            && self.keyword.is_none()
            && self.regex.is_none()
    }

    pub fn matches(&self, domain: &str) -> bool {
        if self.exact.contains(domain) || self.suffix.contains(domain) {
            return true;
        }
        if !(self.suffix.is_empty() && self.dot_suffix.is_empty()) {
            let mut rest = domain;
            while let Some(i) = rest.find('.') {
                rest = &rest[i + 1..];
                if self.suffix.contains(rest) || self.dot_suffix.contains(rest) {
                    return true;
                }
            }
        }
        if let Some(k) = &self.keyword
            && k.is_match(domain)
        {
            return true;
        }
        self.regex.as_ref().is_some_and(|r| r.is_match(domain))
    }
}

/// Sorted, merged, non-overlapping ranges; lookup is a binary search.
#[derive(Default)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpSet {
    pub fn new(nets: &[IpNet]) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for n in nets {
            match n {
                IpNet::V4(n) => v4.push((u32::from(n.network()), u32::from(n.broadcast()))),
                IpNet::V6(n) => v6.push((u128::from(n.network()), u128::from(n.broadcast()))),
            }
        }
        Self {
            v4: merge(v4),
            v6: merge(v6),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(ip) => find(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => find(&self.v6, u128::from(ip)),
        }
    }
}

fn merge<T: Ord + Copy + num::One>(mut v: Vec<(T, T)>) -> Vec<(T, T)> {
    v.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for (s, e) in v {
        if let Some(last) = out.last_mut()
            && s <= last.1.saturating_inc()
        {
            last.1 = last.1.max(e);
            continue;
        }
        out.push((s, e));
    }
    out.shrink_to_fit();
    out
}

fn find<T: Ord + Copy>(v: &[(T, T)], x: T) -> bool {
    let i = v.partition_point(|&(s, _)| s <= x);
    i > 0 && x <= v[i - 1].1
}

mod num {
    pub trait One {
        fn saturating_inc(self) -> Self;
    }
    impl One for u32 {
        fn saturating_inc(self) -> Self {
            self.saturating_add(1)
        }
    }
    impl One for u128 {
        fn saturating_inc(self) -> Self {
            self.saturating_add(1)
        }
    }
}

#[derive(Default)]
pub struct PortSet {
    ranges: Vec<(u16, u16)>,
}

impl PortSet {
    pub fn new(ports: &[u16], ranges: &[PortRange]) -> Self {
        let mut r: Vec<(u16, u16)> = ports
            .iter()
            .map(|&p| (p, p))
            .chain(ranges.iter().map(|r| (r.start, r.end)))
            .collect();
        r.sort_unstable();
        Self { ranges: r }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn contains(&self, port: u16) -> bool {
        self.ranges.iter().any(|&(s, e)| s <= port && port <= e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_suffix_semantics() {
        let s = DomainSet::new(&[], &["example.com".into(), ".cn".into()], &[], &[]).unwrap();
        assert!(s.matches("example.com"));
        assert!(s.matches("a.b.example.com"));
        assert!(!s.matches("badexample.com"));
        assert!(s.matches("baidu.cn"));
        assert!(!s.matches("cn"), "leading dot means subdomains only");
    }

    #[test]
    fn regex_over_the_size_limit_fails_to_build() {
        // Unicode \w compiles to a large automaton; a thousand of them is far
        // past either limit.
        assert!(DomainSet::new(&[], &[], &[], &[r"\w{1000}".into()]).is_err());
        assert!(DomainSet::new(&[], &[], &[], &[r"^ads\.".into()]).is_ok());
    }

    #[test]
    fn domain_keyword_regex() {
        let s = DomainSet::new(&["x.org".into()], &[], &["goog".into()], &[r"^ads?\d+\.".into()]).unwrap();
        assert!(s.matches("x.org"));
        assert!(!s.matches("a.x.org"));
        assert!(s.matches("www.google.com"));
        assert!(s.matches("ad12.foo.net"));
        assert!(!s.matches("bad12.foo.net"));
    }

    #[test]
    fn ip_ranges() {
        let s = IpSet::new(&[
            "10.0.0.0/8".parse().unwrap(),
            "10.1.0.0/16".parse().unwrap(),
            "11.0.0.0/8".parse().unwrap(),
            "fd00::/8".parse().unwrap(),
        ]);
        assert_eq!(s.v4.len(), 1, "adjacent and nested ranges merge");
        assert!(s.contains("10.255.255.255".parse().unwrap()));
        assert!(s.contains("11.0.0.1".parse().unwrap()));
        assert!(!s.contains("12.0.0.0".parse().unwrap()));
        assert!(s.contains("fd12::1".parse().unwrap()));
        assert!(
            s.contains("::ffff:10.0.0.1".parse().unwrap()),
            "v4-mapped v6 is treated as v4"
        );
    }
}
