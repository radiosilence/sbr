//! The sing-box `dns` section as an [`sbr_core::dns::Dns`].
//!
//! [`DnsRouter`] owns the servers (transports), the DNS rules, the cache
//! and the FakeIP stores. It follows sing-box 1.13's ("legacy mode") rule
//! walk: rules are tried in order; `route-options` accumulate; the first
//! `route`/`reject`/`predefined` wins; a rule with address items
//! (`ip_cidr`, `ip_is_private`, `ip_accept_any`) is matched on the query
//! first and on the response's addresses after, and a response that fails
//! that second match moves the walk on to the next rule.
//!
//! It lives in its own crate because it carries its own wire format
//! (hickory-proto), TLS and HTTP/2 client, none of which the rest of the
//! engine needs, and so it can be tested without an engine.
//!
//! Servers reach upstream through `Arc<dyn Outbound>` dialers supplied by
//! the caller (the engine), so `detour` works through any protocol.

mod cache;
mod fakeip;
pub mod msg;
mod transport;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use ipnet::IpNet;
use lru::LruCache;
use sbr_config::{
    Dial, DnsOptions, DnsRouteOptions, DnsRuleAction, DnsServerKind, DomainStrategy, Predefined, RejectMethod,
};
use sbr_core::dns::{Dns, ResolverSpec, apply_strategy};
use sbr_core::router::{DnsQuery, Matcher, RuleSets};
use sbr_core::{BoxFuture, Destination, Host, Metadata, Network, Outbound};
use tracing::debug;

pub use fakeip::FakeIp;
use transport::{Remote, Transport};

use crate::cache::{Cache, Join, Key};
use crate::msg::{TYPE_A, TYPE_AAAA, TYPE_HTTPS, TYPE_SVCB};

/// sing-box `C.DNSTimeout`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("{0}: {1}")]
    At(String, String),
    #[error(transparent)]
    Rule(#[from] sbr_core::router::BuildError),
}

fn at(path: impl Into<String>, msg: impl Into<String>) -> BuildError {
    BuildError::At(path.into(), msg.into())
}

/// How a DNS server dials. The caller turns this into an [`Outbound`]:
/// the outbound named `detour`, the default outbound for legacy servers
/// without one, or a direct dialer built from `dial`.
pub struct ServerDial<'a> {
    pub tag: &'a str,
    pub dial: &'a Dial,
    /// Legacy-format server without `detour`: sing-box dialed these through
    /// the default outbound.
    pub default_outbound: bool,
}

/// Turns a server's dial fields into its dialer.
pub type DialerFactory<'a> = &'a dyn Fn(&ServerDial) -> Arc<dyn Outbound>;
/// Reads a file named in the config (hosts files, CA certificates).
pub type FileReader<'a> = &'a dyn Fn(&str) -> io::Result<Vec<u8>>;

/// Per-attempt timeout when another upstream server can be tried.
const FAILOVER_ATTEMPT: Duration = Duration::from_secs(4);
/// How often a failed upstream server is probed in the background; it is
/// skipped until a probe succeeds.
const FAILOVER_COOLDOWN: Duration = Duration::from_secs(60);

pub(crate) fn random_u16() -> u16 {
    use std::hash::BuildHasher;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: OnceLock<std::hash::RandomState> = OnceLock::new();
    static N: AtomicU64 = AtomicU64::new(0);
    SEED.get_or_init(std::hash::RandomState::new)
        .hash_one(N.fetch_add(1, Ordering::Relaxed)) as u16
}

fn strategy(s: Option<DomainStrategy>) -> Option<DomainStrategy> {
    s.filter(|s| *s != DomainStrategy::AsIs)
}

/// Per-query options: what the matched rules (or a `domain_resolver`) set.
#[derive(Clone, Debug, Default)]
struct QueryOpts {
    strategy: Option<DomainStrategy>,
    disable_cache: bool,
    disable_optimistic: bool,
    rewrite_ttl: Option<u32>,
    timeout: Option<Duration>,
    client_subnet: Option<IpNet>,
    remove_client_subnet: bool,
}

impl QueryOpts {
    fn apply(&mut self, o: &DnsRouteOptions) {
        if let Some(s) = strategy(o.strategy) {
            self.strategy = Some(s);
        }
        self.disable_cache |= o.disable_cache;
        self.disable_optimistic |= o.disable_optimistic_cache;
        if o.rewrite_ttl.is_some() {
            self.rewrite_ttl = o.rewrite_ttl;
        }
        if o.timeout.is_some() {
            self.timeout = o.timeout;
        }
        if o.client_subnet.is_some() {
            self.client_subnet = o.client_subnet;
            self.remove_client_subnet = false;
        }
        if o.remove_client_subnet {
            self.client_subnet = None;
            self.remove_client_subnet = true;
        }
    }

    fn from(o: &DnsRouteOptions) -> Self {
        let mut q = Self::default();
        q.apply(o);
        q
    }
}

struct Server {
    tag: Arc<str>,
    transport: Box<dyn Transport>,
    /// A network resolver (udp/tcp/tls/https): eligible for failover. Never
    /// `local`, which would send queries outside the tunnel.
    upstream: bool,
    fakeip: Option<Arc<FakeIp>>,
    /// Legacy server `strategy` and `client_subnet`.
    strategy: Option<DomainStrategy>,
    client_subnet: Option<IpNet>,
}

enum Action {
    Route { server: usize, options: DnsRouteOptions },
    RouteOptions(DnsRouteOptions),
    Reject { drop: bool },
    Predefined(Predefined),
}

struct Rule {
    matcher: Matcher,
    action: Action,
}

/// Where the rule walk sent a query.
enum Target<'a> {
    /// Query this server; the matcher is the rule's address limit, if any.
    Server(usize, Option<&'a Matcher>),
    Reject {
        drop: bool,
    },
    Predefined(&'a Predefined),
}

/// A failed exchange: the response failed the rule's address check, or
/// the query failed outright.
enum XErr {
    Rejected,
    Io(io::Error),
}

impl From<io::Error> for XErr {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<XErr> for io::Error {
    fn from(e: XErr) -> Self {
        match e {
            XErr::Rejected => io::Error::new(io::ErrorKind::NotFound, "response rejected by DNS rule"),
            XErr::Io(e) => e,
        }
    }
}

type Check<'a> = &'a (dyn Fn(&Message) -> bool + Send + Sync);

fn rcode_error(rcode: u16) -> io::Error {
    let kind = if rcode == 3 {
        io::ErrorKind::NotFound
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, format!("DNS rcode {rcode}"))
}

/// `reverse_mapping`: address → (domain, expiry).
type ReverseMap = LruCache<IpAddr, (Arc<str>, Instant)>;

struct Inner {
    servers: Vec<Server>,
    by_tag: HashMap<String, usize>,
    final_server: usize,
    rules: Vec<Rule>,
    cache: Option<Cache>,
    inflight: cache::Inflight,
    /// Stale entries being refreshed in the background (`optimistic`).
    refreshing: Mutex<HashSet<Key>>,
    strategy: Option<DomainStrategy>,
    timeout: Duration,
    client_subnet: Option<IpNet>,
    fakeips: Vec<Arc<FakeIp>>,
    reverse: Option<Mutex<ReverseMap>>,
    /// Upstream servers that recently failed, skipped until the instant.
    failed: Mutex<HashMap<usize, Instant>>,
    weak: Weak<Inner>,
}

/// The DNS router. Cheap to clone.
#[derive(Clone)]
pub struct DnsRouter {
    inner: Arc<Inner>,
}

/// A transport spec built in the fallible first phase of construction.
enum Spec {
    Local(Arc<dyn Outbound>),
    Hosts(transport::Hosts),
    Udp(Remote, Option<(usize, QueryOpts)>),
    Stream(Remote, Option<(usize, QueryOpts)>, Option<transport::tls::Tls>),
    Https(Box<transport::Https>, Option<(usize, QueryOpts)>),
    FakeIp(Arc<FakeIp>),
    Rcode(u16),
}

impl DnsRouter {
    /// Build from config. `sets` are the compiled `route.rule_set`s.
    pub fn new(cfg: &DnsOptions, sets: &RuleSets, dialer: DialerFactory, read: FileReader) -> Result<Self, BuildError> {
        let mut by_tag = HashMap::new();
        for (i, s) in cfg.servers.iter().enumerate() {
            by_tag.insert(s.tag.clone(), i);
        }
        let resolver_of = |i: usize| -> Result<Option<(usize, QueryOpts)>, BuildError> {
            match &cfg.servers[i].dial.domain_resolver {
                None => Ok(None),
                Some(r) => by_tag
                    .get(&r.server)
                    .map(|&idx| Some((idx, QueryOpts::from(&r.options))))
                    .ok_or_else(|| at(format!("dns.servers[{i}].domain_resolver"), "server not found")),
            }
        };

        let mut specs = Vec::with_capacity(cfg.servers.len().max(1));
        for (i, s) in cfg.servers.iter().enumerate() {
            let path = format!("dns.servers[{i}]");
            let sd = ServerDial {
                tag: &s.tag,
                dial: &s.dial,
                default_outbound: s.legacy.as_ref().is_some_and(|l| l.default_outbound),
            };
            let remote = |addr: &sbr_config::ServerAddr| -> Result<(Remote, Option<(usize, QueryOpts)>), BuildError> {
                let host = Destination::from_host_port(&addr.server, addr.server_port).host;
                let resolver = resolver_of(i)?;
                if matches!(host, Host::Domain(_)) && resolver.is_none() && s.dial.detour.is_none() {
                    let field = if s.legacy.is_some() {
                        "address_resolver"
                    } else {
                        "domain_resolver"
                    };
                    return Err(at(
                        format!("{path}.{field}"),
                        format!("required: server address {:?} is a domain", addr.server),
                    ));
                }
                let resolver = if matches!(host, Host::Domain(_)) {
                    resolver
                } else {
                    None
                };
                Ok((
                    Remote {
                        host,
                        port: addr.server_port,
                        dialer: dialer(&sd),
                        resolver: None,
                    },
                    resolver,
                ))
            };
            let tls = |t: &sbr_config::TlsOutbound, host: &str, alpn: &[&str]| {
                transport::tls::Tls::new(t, host, alpn, read).map_err(|e| at(format!("{path}.tls"), e))
            };
            specs.push(match &s.kind {
                DnsServerKind::Local => Spec::Local(dialer(&sd)),
                DnsServerKind::Hosts {
                    path: files,
                    predefined,
                } => {
                    let default = files.is_empty();
                    let files: Vec<&str> = if default {
                        vec!["/etc/hosts"]
                    } else {
                        files.iter().map(String::as_str).collect()
                    };
                    let mut texts = Vec::new();
                    for f in files {
                        match read(f) {
                            Ok(b) => texts.push(String::from_utf8_lossy(&b).into_owned()),
                            Err(_) if default => {}
                            Err(e) => return Err(at(format!("{path}.path"), format!("{f}: {e}"))),
                        }
                    }
                    Spec::Hosts(transport::Hosts::new(predefined, &texts))
                }
                DnsServerKind::Udp(a) => {
                    let (r, res) = remote(a)?;
                    Spec::Udp(r, res)
                }
                DnsServerKind::Tcp(a) => {
                    let (r, res) = remote(a)?;
                    Spec::Stream(r, res, None)
                }
                DnsServerKind::Tls { server, tls: t } => {
                    let (r, res) = remote(server)?;
                    let tls = tls(t, &server.server, &[])?;
                    Spec::Stream(r, res, Some(tls))
                }
                DnsServerKind::Https {
                    server,
                    tls: t,
                    path: p,
                    get,
                    headers,
                } => {
                    let (r, res) = remote(server)?;
                    let tls = tls(t, &server.server, &["h2"])?;
                    let host = t.server_name.clone().unwrap_or_else(|| server.server.clone());
                    let host = if host.contains(':') { format!("[{host}]") } else { host };
                    let authority = if server.server_port == 443 {
                        host
                    } else {
                        format!("{host}:{}", server.server_port)
                    };
                    let h = transport::Https::new(r, tls, authority, p, *get, headers).map_err(|e| at(&path, e))?;
                    Spec::Https(Box::new(h), res)
                }
                DnsServerKind::FakeIp {
                    inet4_range,
                    inet6_range,
                } => Spec::FakeIp(Arc::new(FakeIp::new(*inet4_range, *inet6_range))),
                DnsServerKind::Rcode(c) => Spec::Rcode(*c),
            });
        }
        // Resolver chains must end: A resolving its address through B which
        // resolves through A would recurse forever at runtime.
        for (i, spec) in specs.iter().enumerate() {
            let mut seen = vec![i];
            let mut cur = spec;
            while let Some(next) = match cur {
                Spec::Udp(_, r) | Spec::Stream(_, r, _) | Spec::Https(_, r) => r.as_ref().map(|r| r.0),
                _ => None,
            } {
                if seen.contains(&next) {
                    return Err(at(format!("dns.servers[{i}].domain_resolver"), "resolver loop"));
                }
                seen.push(next);
                cur = &specs[next];
            }
        }

        let mut tags: Vec<Arc<str>> = cfg.servers.iter().map(|s| Arc::from(s.tag.as_str())).collect();
        let mut legacy: Vec<(Option<DomainStrategy>, Option<IpNet>)> = cfg
            .servers
            .iter()
            .map(|s| {
                s.legacy
                    .as_ref()
                    .map_or((None, None), |l| (strategy(l.strategy), l.client_subnet))
            })
            .collect();
        if specs.is_empty() {
            // sing-box with no servers resolves through the system.
            let d = Dial::default();
            specs.push(Spec::Local(dialer(&ServerDial {
                tag: "local",
                dial: &d,
                default_outbound: false,
            })));
            tags.push("local".into());
            legacy.push((None, None));
        }

        let final_server = match cfg.final_server() {
            Some(t) => *by_tag
                .get(t)
                .ok_or_else(|| at("dns.final", format!("server not found: {t}")))?,
            None => 0,
        };
        let mut rules = Vec::with_capacity(cfg.rules.len());
        for (i, r) in cfg.rules.iter().enumerate() {
            let path = format!("dns.rules[{i}]");
            let server = |t: &str| {
                by_tag
                    .get(t)
                    .copied()
                    .ok_or_else(|| at(format!("{path}.server"), format!("server not found: {t}")))
            };
            let action = match &r.action {
                DnsRuleAction::Route { server: s, options } => Action::Route {
                    server: server(s)?,
                    options: options.clone(),
                },
                DnsRuleAction::RouteOptions(o) => Action::RouteOptions(o.clone()),
                DnsRuleAction::Reject { method, .. } => Action::Reject {
                    drop: *method == RejectMethod::Drop,
                },
                DnsRuleAction::Predefined(p) => {
                    // Validate records now, not on the first query.
                    let q = msg::query("example.com", TYPE_A).expect("valid name");
                    for rec in p.answer.iter().chain(&p.ns).chain(&p.extra) {
                        msg::predefined_record(rec, &q.queries[0]).map_err(|e| at(&path, e.to_string()))?;
                    }
                    Action::Predefined(p.clone())
                }
            };
            rules.push(Rule {
                matcher: Matcher::compile(&r.rule, &path, sets)?,
                action,
            });
        }

        let inner = Arc::new_cyclic(|weak: &Weak<Inner>| {
            let resolver = |(idx, opts): (usize, QueryOpts)| -> transport::Resolver {
                let weak = weak.clone();
                Arc::new(move |domain: Arc<str>| {
                    let (weak, opts) = (weak.clone(), opts.clone());
                    Box::pin(async move {
                        let inner = weak.upgrade().ok_or_else(|| io::Error::other("DNS router shut down"))?;
                        inner
                            .lookup_server(idx, &domain, &opts, None)
                            .await
                            .map_err(io::Error::from)
                    })
                })
            };
            let mut fakeips = Vec::new();
            let servers = specs
                .into_iter()
                .zip(tags)
                .zip(legacy)
                .map(|((spec, tag), (strategy, client_subnet))| {
                    let mut fakeip = None;
                    let upstream = matches!(spec, Spec::Udp(..) | Spec::Stream(..) | Spec::Https(..));
                    let with = |mut r: Remote, res: Option<(usize, QueryOpts)>| {
                        r.resolver = res.map(resolver);
                        r
                    };
                    let transport: Box<dyn Transport> = match spec {
                        Spec::Local(d) => Box::new(transport::Local::new(d)),
                        Spec::Hosts(h) => Box::new(h),
                        Spec::Udp(r, res) => Box::new(transport::Udp::new(with(r, res))),
                        Spec::Stream(r, res, tls) => Box::new(transport::StreamTransport::new(with(r, res), tls)),
                        Spec::Https(mut h, res) => {
                            h.set_resolver(res.map(resolver));
                            h
                        }
                        Spec::FakeIp(f) => {
                            fakeips.push(f.clone());
                            fakeip = Some(f.clone());
                            Box::new(FakeIpTransport(f))
                        }
                        Spec::Rcode(c) => Box::new(transport::Rcode(c)),
                    };
                    Server {
                        tag,
                        transport,
                        upstream,
                        fakeip,
                        strategy,
                        client_subnet,
                    }
                })
                .collect();
            let capacity = NonZeroUsize::new((cfg.cache_capacity as usize).max(1024)).expect("non-zero");
            Inner {
                servers,
                by_tag: by_tag.clone(),
                final_server,
                rules,
                cache: (!cfg.disable_cache).then(|| Cache::new(cfg.cache_capacity, cfg.disable_expire, cfg.optimistic)),
                inflight: cache::Inflight::default(),
                refreshing: Mutex::new(HashSet::new()),
                strategy: strategy(cfg.strategy),
                timeout: cfg.timeout.unwrap_or(DEFAULT_TIMEOUT),
                client_subnet: cfg.client_subnet,
                fakeips,
                reverse: cfg.reverse_mapping.then(|| Mutex::new(LruCache::new(capacity))),
                failed: Mutex::new(HashMap::new()),
                weak: weak.clone(),
            }
        });
        Ok(Self { inner })
    }

    /// The domain behind a FakeIP address; see [`Dns::fakeip_lookup`].
    pub fn fakeip_lookup(&self, ip: IpAddr) -> Option<Option<Arc<str>>> {
        self.inner.fakeip_lookup(ip)
    }
}

/// `fakeip` server: A/AAAA get an address from the store.
struct FakeIpTransport(Arc<FakeIp>);

impl Transport for FakeIpTransport {
    fn exchange<'a>(&'a self, query: &'a Message) -> BoxFuture<'a, io::Result<Message>> {
        Box::pin(async move {
            let q = query.queries.first().ok_or_else(|| msg::invalid("no question"))?;
            let qtype = u16::from(q.query_type());
            if qtype != TYPE_A && qtype != TYPE_AAAA {
                return Err(io::Error::other("only IP queries are supported by fakeip"));
            }
            let domain = msg::domain_of(q);
            match self.0.allocate(&domain, qtype == TYPE_AAAA) {
                Some(ip) => Ok(msg::addresses(query, &[ip], sbr_config::DEFAULT_TTL)),
                None => Ok(msg::status(query, 0)),
            }
        })
    }
}

impl Inner {
    fn arc(&self) -> Option<Arc<Inner>> {
        self.weak.upgrade()
    }

    fn effective_strategy(&self, server: usize, opts: &QueryOpts) -> Option<DomainStrategy> {
        opts.strategy.or(self.servers[server].strategy).or(self.strategy)
    }

    /// One query to one server, through the cache and in-flight coalescing.
    /// Returns the response (TTLs as stored) and the TTL to present.
    async fn query_server(
        &self,
        idx: usize,
        query: &Message,
        opts: &QueryOpts,
        check: Option<Check<'_>>,
    ) -> Result<(Arc<Message>, u32), XErr> {
        let server = &self.servers[idx];
        let q = query.queries.first().ok_or_else(|| msg::invalid("no question"))?;
        let qtype = u16::from(q.query_type());
        match (qtype, self.effective_strategy(idx, opts)) {
            (TYPE_A, Some(DomainStrategy::Ipv6Only)) | (TYPE_AAAA, Some(DomainStrategy::Ipv4Only)) => {
                return Ok((Arc::new(msg::status(query, 0)), 0));
            }
            _ => {}
        }

        // ECS: the rule's, the server's (legacy), the global one, or the client's own.
        let mut owned = None;
        let subnet = if opts.remove_client_subnet {
            if msg::client_subnet(query).is_some() {
                let mut m = query.clone();
                msg::remove_client_subnet(&mut m);
                owned = Some(m);
            }
            None
        } else {
            match opts.client_subnet.or(server.client_subnet).or(self.client_subnet) {
                Some(s) => {
                    let mut m = query.clone();
                    msg::set_client_subnet(&mut m, s);
                    owned = Some(m);
                    Some(s)
                }
                None => msg::client_subnet(query),
            }
        };
        let send = owned.as_ref().unwrap_or(query);

        let cache = self
            .cache
            .as_ref()
            .filter(|_| !opts.disable_cache && server.fakeip.is_none() && msg::is_simple(query));
        let key = cache.and_then(|_| Key::from_name(idx, q.name(), qtype, u16::from(q.query_class()), subnet));
        let mut leader = None;
        if let (Some(cache), Some(key)) = (cache, &key) {
            loop {
                if let Some(hit) = cache.get(key, Instant::now())
                    && !(hit.stale && opts.disable_optimistic)
                {
                    if hit.stale {
                        self.refresh(idx, key.clone(), send.clone(), opts.clone());
                    }
                    return checked(hit.msg, hit.ttl, check);
                }
                match self.inflight.join(key) {
                    Join::Lead(l) => {
                        leader = Some(l);
                        break;
                    }
                    Join::Wait(rx) => match cache::wait(rx).await {
                        Some(Ok(m)) => {
                            let ttl = msg::response_ttl(&m);
                            return checked(m, ttl, check);
                        }
                        Some(Err((kind, text))) => return Err(XErr::Io(io::Error::new(kind, text.to_string()))),
                        None => continue, // the leader was cancelled: try again
                    },
                }
            }
        }

        let timeout = opts.timeout.unwrap_or(self.timeout);
        let result = self.exchange_with_failover(idx, send, timeout).await;
        let mut resp = match result {
            Ok(r) => r,
            Err(e) => {
                if let Some(l) = leader {
                    l.finish(Err((e.kind(), e.to_string().into())));
                }
                return Err(XErr::Io(e));
            }
        };
        let mut ttl = msg::response_ttl(&resp);
        if let Some(t) = opts.rewrite_ttl {
            ttl = t;
        }
        msg::set_ttl(&mut resp, ttl);
        let resp = Arc::new(resp);
        let rcode = msg::rcode(&resp);
        if let (Some(cache), Some(key)) = (cache, key)
            && (rcode == 0 || rcode == 3)
        {
            cache.put(key, resp.clone(), ttl, Instant::now());
        }
        if let Some(l) = leader {
            l.finish(Ok(resp.clone()));
        }
        checked(resp, ttl, check)
    }

    /// Exchange with `idx`, failing over to the config's other upstream
    /// servers when it errors, times out, or answers SERVFAIL/REFUSED.
    /// sing-box never fails over; a profile whose primary resolver is
    /// unreachable through the current path (e.g. a REALITY server refusing
    /// loopback destinations) then resolves nothing. A failed server is
    /// skipped for a minute so later queries don't each wait for it.
    async fn exchange_with_failover(&self, idx: usize, query: &Message, timeout: Duration) -> io::Result<Message> {
        let failed = |i: usize| self.failed.lock().unwrap().contains_key(&i);
        let mut order = vec![idx];
        if self.servers[idx].upstream {
            let others = (0..self.servers.len())
                .filter(|&i| i != idx && self.servers[i].upstream && !failed(i))
                .collect::<Vec<_>>();
            order.extend(others);
            // A failed server goes last, so queries never wait on it while it
            // is down; a background probe brings it back to the front.
            if failed(idx) && order.len() > 1 {
                order.rotate_left(1);
                self.probe(idx, query);
            }
        }
        // With somewhere to fail over to, don't wait the full timeout first.
        let attempt = if order.len() > 1 {
            timeout.min(FAILOVER_ATTEMPT)
        } else {
            timeout
        };
        let mut last = None;
        for (n, &i) in order.iter().enumerate() {
            let server = &self.servers[i];
            let t = if n + 1 == order.len() { timeout } else { attempt };
            let r = match tokio::time::timeout(t, server.transport.exchange(query)).await {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("dns server {}: timed out", server.tag),
                )),
            };
            match r {
                Ok(resp) if !matches!(msg::rcode(&resp), 2 | 5) || n + 1 == order.len() => {
                    self.failed.lock().unwrap().remove(&i);
                    if i != idx {
                        tracing::debug!(from = %self.servers[idx].tag, to = %server.tag, "dns failover");
                    }
                    return Ok(resp);
                }
                Ok(resp) => {
                    tracing::debug!(server = %server.tag, rcode = msg::rcode(&resp), "dns server failed; trying next");
                    last = Some(Ok(resp));
                }
                Err(e) => {
                    tracing::debug!(server = %server.tag, error = %e, "dns server failed; trying next");
                    last = Some(Err(e));
                }
            }
            if server.upstream && order.len() > 1 {
                self.failed
                    .lock()
                    .unwrap()
                    .entry(i)
                    .or_insert_with(|| Instant::now() + FAILOVER_COOLDOWN);
            }
        }
        last.unwrap_or_else(|| Err(io::Error::other("no dns server")))
    }

    /// Re-try a failed server off the query path, at most once per cooldown.
    fn probe(&self, idx: usize, query: &Message) {
        let now = Instant::now();
        {
            let mut failed = self.failed.lock().unwrap();
            match failed.get_mut(&idx) {
                Some(next) if *next <= now => *next = now + FAILOVER_COOLDOWN,
                _ => return,
            }
        }
        let Some(this) = self.arc() else { return };
        let query = query.clone();
        tokio::spawn(async move {
            let server = &this.servers[idx];
            if let Ok(Ok(resp)) = tokio::time::timeout(this.timeout, server.transport.exchange(&query)).await
                && !matches!(msg::rcode(&resp), 2 | 5)
            {
                tracing::debug!(server = %server.tag, "dns server recovered");
                this.failed.lock().unwrap().remove(&idx);
            }
        });
    }

    /// `optimistic`: refresh a stale entry in the background, once per key.
    fn refresh(&self, idx: usize, key: Key, query: Message, opts: QueryOpts) {
        let Some(this) = self.arc() else { return };
        if !self.refreshing.lock().unwrap().insert(key.clone()) {
            return;
        }
        tokio::spawn(async move {
            let server = &this.servers[idx];
            let timeout = opts.timeout.unwrap_or(this.timeout);
            if let Ok(Ok(mut resp)) = tokio::time::timeout(timeout, server.transport.exchange(&query)).await
                && matches!(msg::rcode(&resp), 0 | 3)
                && let Some(cache) = &this.cache
            {
                let ttl = opts.rewrite_ttl.unwrap_or_else(|| msg::response_ttl(&resp));
                msg::set_ttl(&mut resp, ttl);
                cache.put(key.clone(), Arc::new(resp), ttl, Instant::now());
            }
            this.refreshing.lock().unwrap().remove(&key);
        });
    }

    /// A and/or AAAA for `domain` from one server, ordered for dialing.
    async fn lookup_server(
        &self,
        idx: usize,
        domain: &str,
        opts: &QueryOpts,
        check: Option<Check<'_>>,
    ) -> Result<Vec<IpAddr>, XErr> {
        let strat = self.effective_strategy(idx, opts);
        let (v4, v6) = match strat {
            Some(DomainStrategy::Ipv4Only) => (self.lookup_type(idx, domain, TYPE_A, opts, check).await, Ok(vec![])),
            Some(DomainStrategy::Ipv6Only) => (Ok(vec![]), self.lookup_type(idx, domain, TYPE_AAAA, opts, check).await),
            _ => {
                tokio::join!(
                    self.lookup_type(idx, domain, TYPE_A, opts, check),
                    self.lookup_type(idx, domain, TYPE_AAAA, opts, check)
                )
            }
        };
        let addrs: Vec<IpAddr> = match (v4, v6) {
            (Err(e), Err(_)) => return Err(e),
            (Ok(a), Err(e)) | (Err(e), Ok(a)) if a.is_empty() => return Err(e),
            (a, b) => a.unwrap_or_default().into_iter().chain(b.unwrap_or_default()).collect(),
        };
        if addrs.is_empty() {
            return Err(XErr::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no addresses for {domain}"),
            )));
        }
        Ok(apply_strategy(addrs, strat))
    }

    async fn lookup_type(
        &self,
        idx: usize,
        domain: &str,
        qtype: u16,
        opts: &QueryOpts,
        check: Option<Check<'_>>,
    ) -> Result<Vec<IpAddr>, XErr> {
        let server = &self.servers[idx];
        // Cache fast path: no message is built for a hit.
        if let Some(cache) = &self.cache
            && !opts.disable_cache
            && server.fakeip.is_none()
        {
            let subnet = if opts.remove_client_subnet {
                None
            } else {
                opts.client_subnet.or(server.client_subnet).or(self.client_subnet)
            };
            if let Some(key) = Key::from_str(idx, domain, qtype, subnet)
                && let Some(hit) = cache.get(&key, Instant::now())
                && !(hit.stale && opts.disable_optimistic)
            {
                if hit.stale
                    && let Ok(q) = msg::query(domain, qtype)
                {
                    let mut q = q;
                    if let Some(s) = subnet {
                        msg::set_client_subnet(&mut q, s);
                    }
                    self.refresh(idx, key, q, opts.clone());
                }
                if check.is_some_and(|c| !c(&hit.msg)) {
                    return Err(XErr::Rejected);
                }
                let rcode = msg::rcode(&hit.msg);
                if rcode != 0 {
                    return Err(XErr::Io(rcode_error(rcode)));
                }
                return Ok(filter_family(hit.addrs.iter().copied(), qtype));
            }
        }
        let q = msg::query(domain, qtype)?;
        let (resp, _) = self.query_server(idx, &q, opts, check).await?;
        let rcode = msg::rcode(&resp);
        if rcode != 0 {
            return Err(XErr::Io(rcode_error(rcode)));
        }
        Ok(filter_family(msg::answer_addrs(&resp).into_iter(), qtype))
    }

    /// sing-box `matchDNS` (legacy mode): walk rules from `from`.
    fn match_rules<'a>(
        &'a self,
        meta: &Metadata,
        dq: &DnsQuery,
        from: usize,
        allow_fakeip: bool,
        address_query: bool,
        opts: &mut QueryOpts,
    ) -> (Target<'a>, Option<usize>) {
        for (i, r) in self.rules.iter().enumerate().skip(from) {
            if r.matcher.has_address_limit() && !address_query {
                continue;
            }
            if !r.matcher.pre_match_dns(meta, dq) {
                continue;
            }
            match &r.action {
                Action::Route { server, options } => {
                    let fake = self.servers[*server].fakeip.is_some();
                    if fake && !allow_fakeip {
                        continue;
                    }
                    opts.apply(options);
                    if fake {
                        opts.disable_cache = true;
                    }
                    let limit = r.matcher.has_address_limit().then_some(&r.matcher);
                    return (Target::Server(*server, limit), Some(i));
                }
                Action::RouteOptions(o) => opts.apply(o),
                Action::Reject { drop } => return (Target::Reject { drop: *drop }, Some(i)),
                Action::Predefined(p) => return (Target::Predefined(p), Some(i)),
            }
        }
        (Target::Server(self.final_server, None), None)
    }

    /// hijack-dns: answer a raw query, walking the rules.
    async fn exchange(&self, raw: &[u8], meta: &Metadata) -> io::Result<Vec<u8>> {
        let req = msg::decode(raw)?;
        let udp = meta.network == Network::Udp;
        let reply = |m: Message| -> io::Result<Vec<u8>> {
            if udp {
                msg::truncate_to(m, msg::udp_size(&req))
            } else {
                msg::encode(&m)
            }
        };
        if req.queries.len() != 1 {
            return reply(msg::status(&req, 1));
        }
        let q = &req.queries[0];
        let qtype = u16::from(q.query_type());
        let domain = msg::domain_of(q);
        // Resolver discovery (DDR) would let clients bypass us.
        if qtype == TYPE_SVCB && domain.starts_with("_dns.") {
            return reply(msg::status(&req, 0));
        }
        let mut m = meta.clone();
        m.destination = Destination::new(Host::Domain(domain.as_str().into()), 0);
        m.sniffed_domain = None;
        m.destination_addresses.clear();
        let dq = DnsQuery {
            query_type: Some(qtype),
            outbound: None,
        };
        let address_query = matches!(qtype, TYPE_A | TYPE_AAAA | TYPE_HTTPS);
        let mut from = 0;
        loop {
            let mut opts = QueryOpts::default();
            let (target, rule) = self.match_rules(&m, &dq, from, true, address_query, &mut opts);
            let (server, limit) = match target {
                Target::Reject { drop: true } => {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "dns query dropped"));
                }
                Target::Reject { drop: false } => {
                    let mut r = msg::status(&req, 5);
                    r.metadata.authoritative = false;
                    return reply(r);
                }
                Target::Predefined(p) => return reply(predefined(&req, p)?),
                Target::Server(s, limit) => (s, limit),
            };
            let check = limit.map(|matcher| {
                let m = &m;
                move |resp: &Message| {
                    let mut mm = m.clone();
                    mm.destination_addresses = msg::answer_addrs(resp);
                    matcher.matches_dns(&mm, &dq)
                }
            });
            let check_ref = check.as_ref().map(|c| c as Check);
            match self.query_server(server, &req, &opts, check_ref).await {
                Ok((resp, ttl)) => {
                    let mut out = (*resp).clone();
                    out.metadata.id = req.metadata.id;
                    msg::set_ttl(&mut out, ttl);
                    if req.edns.is_none() {
                        out.edns = None;
                    }
                    if self.servers[server].fakeip.is_none() {
                        self.record_reverse(&out);
                    }
                    debug!(%domain, qtype, server = %self.servers[server].tag, rcode = msg::rcode(&out), "dns exchange");
                    return reply(out);
                }
                Err(XErr::Rejected) => {
                    from = rule.map_or(self.rules.len(), |i| i + 1);
                }
                Err(XErr::Io(e)) => {
                    debug!(%domain, qtype, server = %self.servers[server].tag, error = %e, "dns exchange failed");
                    return reply(msg::status(&req, 2));
                }
            }
        }
    }

    /// Lookup for dialing, walking the rules (no bound server).
    async fn lookup_rules(
        &self,
        domain: &str,
        caller: Option<DomainStrategy>,
        meta: Option<&Metadata>,
        outbound: Option<&str>,
    ) -> io::Result<Vec<IpAddr>> {
        let domain = domain.trim_end_matches('.');
        let base = QueryOpts {
            strategy: strategy(caller),
            ..QueryOpts::default()
        };
        // sing-box: with fewer than two servers there is nothing to choose.
        if self.rules.is_empty() || self.servers.len() < 2 {
            return Ok(self.lookup_server(self.final_server, domain, &base, None).await?);
        }
        let m = match meta {
            Some(meta) => {
                let mut m = meta.clone();
                m.destination = Destination::new(Host::Domain(domain.into()), 0);
                m.sniffed_domain = None;
                m.destination_addresses.clear();
                m
            }
            None => Metadata::new(
                Arc::from(""),
                "",
                Network::Tcp,
                std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                Destination::new(Host::Domain(domain.into()), 0),
            ),
        };
        let dq = DnsQuery {
            query_type: None,
            outbound,
        };
        let mut from = 0;
        loop {
            let mut opts = base.clone();
            let (target, rule) = self.match_rules(&m, &dq, from, false, true, &mut opts);
            let (server, limit) = match target {
                Target::Reject { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "lookup rejected by DNS rule",
                    ));
                }
                Target::Predefined(p) => {
                    if p.rcode != 0 {
                        return Err(rcode_error(p.rcode));
                    }
                    let q = msg::query(domain, TYPE_A)?;
                    let mut addrs = Vec::new();
                    for rec in &p.answer {
                        let r = msg::predefined_record(rec, &q.queries[0])?;
                        let mut m = Message::query();
                        m.answers.push(r);
                        addrs.extend(msg::answer_addrs(&m));
                    }
                    return Ok(apply_strategy(addrs, opts.strategy.or(self.strategy)));
                }
                Target::Server(s, limit) => (s, limit),
            };
            let check = limit.map(|matcher| {
                let m = &m;
                move |resp: &Message| {
                    let mut mm = m.clone();
                    mm.destination_addresses = msg::answer_addrs(resp);
                    matcher.matches_dns(&mm, &dq)
                }
            });
            let check_ref = check.as_ref().map(|c| c as Check);
            match self.lookup_server(server, domain, &opts, check_ref).await {
                Ok(a) => return Ok(a),
                // sing-box retries later rules on any failure of an address-limited rule.
                Err(e) if limit.is_some() => {
                    debug!(%domain, error = %io::Error::from(e), "address-limited rule skipped");
                    from = rule.map_or(self.rules.len(), |i| i + 1);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn record_reverse(&self, resp: &Message) {
        let Some(rev) = &self.reverse else { return };
        let now = Instant::now();
        let mut rev = rev.lock().unwrap();
        for r in &resp.answers {
            let ip = match &r.data {
                hickory_proto::rr::RData::A(a) => IpAddr::V4(a.0),
                hickory_proto::rr::RData::AAAA(a) => IpAddr::V6(a.0),
                _ => continue,
            };
            let mut name = r.name.to_ascii().to_ascii_lowercase();
            if name.ends_with('.') {
                name.pop();
            }
            rev.put(ip, (name.into(), now + Duration::from_secs(r.ttl as u64)));
        }
    }

    fn reverse_lookup(&self, ip: IpAddr) -> Option<Arc<str>> {
        let mut rev = self.reverse.as_ref()?.lock().unwrap();
        let ip = ip.to_canonical();
        let (name, expire) = rev.get(&ip)?;
        if Instant::now() >= *expire {
            rev.pop(&ip);
            return None;
        }
        Some(name.clone())
    }

    fn fakeip_lookup(&self, ip: IpAddr) -> Option<Option<Arc<str>>> {
        self.fakeips.iter().find(|f| f.contains(ip)).map(|f| f.lookup(ip))
    }
}

fn checked(msg: Arc<Message>, ttl: u32, check: Option<Check<'_>>) -> Result<(Arc<Message>, u32), XErr> {
    if let Some(c) = check {
        let rcode = msg::rcode(&msg);
        if (rcode != 0 && rcode != 3) || !c(&msg) {
            return Err(XErr::Rejected);
        }
    }
    Ok((msg, ttl))
}

fn filter_family(addrs: impl Iterator<Item = IpAddr>, qtype: u16) -> Vec<IpAddr> {
    addrs
        .filter(|a| if qtype == TYPE_A { a.is_ipv4() } else { a.is_ipv6() })
        .collect()
}

/// sing-box `RuleActionPredefined.Response`.
fn predefined(req: &Message, p: &Predefined) -> io::Result<Message> {
    let mut m = msg::status(req, p.rcode);
    let q = &req.queries[0];
    for rec in &p.answer {
        m.answers.push(msg::predefined_record(rec, q)?);
    }
    for rec in &p.ns {
        m.authorities.push(msg::predefined_record(rec, q)?);
    }
    for rec in &p.extra {
        m.additionals.push(msg::predefined_record(rec, q)?);
    }
    Ok(m)
}

impl Dns for DnsRouter {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: Option<DomainStrategy>,
    ) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(self.inner.lookup_rules(domain, strategy, None, None))
    }

    fn exchange<'a>(&'a self, query: &'a [u8], meta: &'a Metadata) -> BoxFuture<'a, io::Result<Vec<u8>>> {
        Box::pin(self.inner.exchange(query, meta))
    }

    fn lookup_for<'a>(
        &'a self,
        domain: &'a str,
        strategy: Option<DomainStrategy>,
        meta: &'a Metadata,
    ) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(self.inner.lookup_rules(domain, strategy, Some(meta), None))
    }

    fn bind(&self, spec: &ResolverSpec<'_>) -> Option<Arc<dyn Dns>> {
        if spec.resolver.is_none() && spec.outbound.is_none() {
            return None;
        }
        let (server, opts) = match spec.resolver {
            Some(r) => match self.inner.by_tag.get(&r.server) {
                Some(&i) => (Some(i), QueryOpts::from(&r.options)),
                None => {
                    tracing::warn!(server = %r.server, "domain_resolver: unknown DNS server");
                    (None, QueryOpts::default())
                }
            },
            None => (None, QueryOpts::default()),
        };
        Some(Arc::new(Bound {
            inner: self.inner.clone(),
            server,
            opts,
            outbound: spec.outbound.map(Arc::from),
        }))
    }

    fn fakeip_lookup(&self, ip: IpAddr) -> Option<Option<Arc<str>>> {
        self.inner.fakeip_lookup(ip)
    }

    fn reverse_lookup(&self, ip: IpAddr) -> Option<Arc<str>> {
        self.inner.reverse_lookup(ip)
    }
}

/// A resolver bound to a `domain_resolver` and/or an outbound tag.
struct Bound {
    inner: Arc<Inner>,
    server: Option<usize>,
    opts: QueryOpts,
    outbound: Option<Arc<str>>,
}

impl Dns for Bound {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
        strategy: Option<DomainStrategy>,
    ) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            match self.server {
                Some(idx) => {
                    let mut opts = self.opts.clone();
                    // The resolver's own strategy wins over the deprecated dial `domain_strategy`.
                    if opts.strategy.is_none() {
                        opts.strategy = self::strategy(strategy);
                    }
                    let domain = domain.trim_end_matches('.');
                    Ok(self.inner.lookup_server(idx, domain, &opts, None).await?)
                }
                None => {
                    self.inner
                        .lookup_rules(domain, strategy, None, self.outbound.as_deref())
                        .await
                }
            }
        })
    }

    fn exchange<'a>(&'a self, query: &'a [u8], meta: &'a Metadata) -> BoxFuture<'a, io::Result<Vec<u8>>> {
        Box::pin(self.inner.exchange(query, meta))
    }

    fn bind(&self, spec: &ResolverSpec<'_>) -> Option<Arc<dyn Dns>> {
        DnsRouter {
            inner: self.inner.clone(),
        }
        .bind(spec)
    }

    fn fakeip_lookup(&self, ip: IpAddr) -> Option<Option<Arc<str>>> {
        self.inner.fakeip_lookup(ip)
    }

    fn reverse_lookup(&self, ip: IpAddr) -> Option<Arc<str>> {
        self.inner.reverse_lookup(ip)
    }
}

#[cfg(test)]
mod tests;
