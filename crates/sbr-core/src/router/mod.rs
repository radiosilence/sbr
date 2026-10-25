//! Rule evaluation with sing-box semantics.
//!
//! A default rule's fields fall into four OR-groups (source address, source
//! port, destination address, destination port); a rule matches when every
//! populated group has at least one hit and every remaining field matches.
//! A `rule_set` whose body is a single plain rule merges its groups into the
//! outer rule's, so `{"rule_set": "geosite-x", "port": 443}` behaves the way
//! people expect.
//!
//! Rule-set contents are hot-swappable ([`Router::update_rule_set`]): each
//! set lives behind an `ArcSwap`, so remote rule-set refreshes publish a new
//! compiled set atomically while matching stays lock-free.

mod describe;
mod sets;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use sbr_config::{
    DomainStrategy, LogicalMode, Matchers, Protocol, RejectMethod, Rule, RuleAction, RuleKind, RuleSet, RuleSetSource,
};

use crate::addr::is_private;
use crate::session::{Metadata, Network};
pub use describe::RuleInfo;
pub use sets::{DomainSet, IpSet, PortSet};

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("{0}: invalid domain_regex: {1}")]
    Regex(String, regex::Error),
    #[error("rule-set {0}: {1}")]
    RuleSet(String, String),
    #[error("unknown outbound {0}")]
    Outbound(String),
}

/// A compiled rule action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Final. Index into the engine's outbound table.
    Route {
        outbound: usize,
        options: RouteOptions,
    },
    /// Final.
    Reject {
        drop: bool,
        no_drop: bool,
    },
    /// Final.
    HijackDns,
    RouteOptions(RouteOptions),
    /// Empty `sniffers` means "all".
    Sniff {
        sniffers: Vec<Protocol>,
        timeout: Option<std::time::Duration>,
    },
    Resolve {
        server: Option<String>,
        strategy: Option<DomainStrategy>,
    },
}

impl Action {
    pub fn is_final(&self) -> bool {
        matches!(self, Action::Route { .. } | Action::Reject { .. } | Action::HijackDns)
    }
}

/// Resolved `route-options`; later options override earlier ones field by field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteOptions {
    pub override_address: Option<crate::Host>,
    pub override_port: Option<u16>,
    pub udp_disable_domain_unmapping: bool,
    pub udp_connect: bool,
    pub udp_timeout: Option<std::time::Duration>,
    pub tls_fragment: bool,
    pub tls_record_fragment: bool,
    pub tls_fragment_fallback_delay: Option<std::time::Duration>,
}

impl RouteOptions {
    fn compile(o: &sbr_config::RouteOptionsAction) -> Self {
        Self {
            override_address: o
                .override_address
                .as_deref()
                .map(|a| crate::Destination::from_host_port(a, 0).host),
            override_port: o.override_port,
            udp_disable_domain_unmapping: o.udp_disable_domain_unmapping,
            udp_connect: o.udp_connect,
            udp_timeout: o.udp_timeout,
            tls_fragment: o.tls_fragment,
            tls_record_fragment: o.tls_record_fragment,
            tls_fragment_fallback_delay: o.tls_fragment_fallback_delay,
        }
    }

    pub fn merge(&mut self, o: &RouteOptions) {
        if o.override_address.is_some() {
            self.override_address.clone_from(&o.override_address);
        }
        if o.override_port.is_some() {
            self.override_port = o.override_port;
        }
        self.udp_disable_domain_unmapping |= o.udp_disable_domain_unmapping;
        self.udp_connect |= o.udp_connect;
        if o.udp_timeout.is_some() {
            self.udp_timeout = o.udp_timeout;
        }
        self.tls_fragment |= o.tls_fragment;
        self.tls_record_fragment |= o.tls_record_fragment;
        if o.tls_fragment_fallback_delay.is_some() {
            self.tls_fragment_fallback_delay = o.tls_fragment_fallback_delay;
        }
    }

    /// Where to actually connect.
    pub fn apply(&self, dest: &crate::Destination) -> crate::Destination {
        crate::Destination {
            host: self.override_address.clone().unwrap_or_else(|| dest.host.clone()),
            port: self.override_port.unwrap_or(dest.port),
        }
    }
}

pub struct Router {
    rules: Vec<(Node, Action)>,
    /// Parallel to `rules`: what the Clash API shows.
    info: Vec<RuleInfo>,
    final_outbound: usize,
    sets: HashMap<String, Arc<SetSlot>>,
    clash_mode: Arc<ClashMode>,
}

/// One rule-set's current contents.
type SetSlot = ArcSwap<CompiledSet>;

impl Router {
    /// `outbound` maps tags to the caller's outbound indices. `load` reads
    /// local rule-set files (kept injectable so tests and iOS can supply
    /// bytes from wherever they live). Remote rule-sets start empty (they
    /// match nothing) until [`Router::update_rule_set`] fills them.
    pub fn new(
        rules: &[Rule],
        rule_sets: &[RuleSet],
        final_tag: &str,
        outbound: impl Fn(&str) -> Option<usize>,
        load: impl Fn(&str) -> std::io::Result<Vec<u8>>,
    ) -> Result<Self, BuildError> {
        let mut sets: HashMap<String, Arc<SetSlot>> = HashMap::new();
        for rs in rule_sets {
            let rules = match &rs.source {
                RuleSetSource::Inline(r) => r.clone(),
                RuleSetSource::Local { path, format } => {
                    let data = load(path).map_err(|e| BuildError::RuleSet(rs.tag.clone(), format!("{path}: {e}")))?;
                    sbr_config::parse_rule_set(&data, *format)
                        .map_err(|e| BuildError::RuleSet(rs.tag.clone(), e.to_string()))?
                }
                RuleSetSource::Remote(_) => Vec::new(),
            };
            let set = CompiledSet::compile(&rs.tag, &rules, &sets)?;
            sets.insert(rs.tag.clone(), Arc::new(ArcSwap::from_pointee(set)));
        }

        let resolve = |tag: &str| outbound(tag).ok_or_else(|| BuildError::Outbound(tag.to_owned()));
        let mut compiled = Vec::with_capacity(rules.len());
        let mut info = Vec::with_capacity(rules.len());
        for (i, r) in rules.iter().enumerate() {
            let action = match &r.action {
                RuleAction::Route { outbound, options } => Action::Route {
                    outbound: resolve(outbound)?,
                    options: RouteOptions::compile(options),
                },
                RuleAction::Reject { method, no_drop } => Action::Reject {
                    drop: *method == RejectMethod::Drop,
                    no_drop: *no_drop,
                },
                RuleAction::HijackDns => Action::HijackDns,
                RuleAction::RouteOptions(o) => Action::RouteOptions(RouteOptions::compile(o)),
                RuleAction::Sniff { sniffers, timeout } => Action::Sniff {
                    sniffers: sniffers.clone(),
                    timeout: *timeout,
                },
                RuleAction::Resolve { server, strategy } => Action::Resolve {
                    server: server.clone(),
                    strategy: *strategy,
                },
                RuleAction::None => continue,
            };
            compiled.push((Node::compile(r, &format!("route.rules[{i}]"), &sets)?, action));
            info.push(RuleInfo::new(r));
        }
        Ok(Self {
            rules: compiled,
            info,
            final_outbound: resolve(final_tag)?,
            sets,
            clash_mode: Arc::new(ClashMode::new(None, ClashMode::modes_in(rules))),
        })
    }

    /// Set the Clash API `default_mode` (sing-box default: `Rule`).
    pub fn with_default_mode(mut self, mode: Option<&str>, rules: &[Rule]) -> Self {
        self.clash_mode = Arc::new(ClashMode::new(mode, ClashMode::modes_in(rules)));
        self
    }

    pub fn clash_mode(&self) -> &Arc<ClashMode> {
        &self.clash_mode
    }

    /// Atomically replace a rule-set's contents. Connections being routed
    /// right now finish against whichever version they loaded.
    pub fn update_rule_set(&self, tag: &str, rules: &[Rule]) -> Result<(), BuildError> {
        let slot = self
            .sets
            .get(tag)
            .ok_or_else(|| BuildError::RuleSet(tag.to_owned(), "not found".into()))?;
        let set = CompiledSet::compile(tag, rules, &self.sets)?;
        slot.store(Arc::new(set));
        Ok(())
    }

    /// Rule `index` (as returned by [`Router::next`]) for display.
    pub fn rule_info(&self, index: usize) -> Option<&RuleInfo> {
        self.info.get(index)
    }

    pub fn rules_info(&self) -> &[RuleInfo] {
        &self.info
    }

    /// The first rule at or after `from` that matches, with its index.
    /// Callers run non-final actions and continue from `index + 1`.
    pub fn next(&self, meta: &Metadata, from: usize) -> Option<(usize, &Action)> {
        let mode = self.clash_mode.current.load();
        let ctx = Ctx {
            ip_cidr_match_source: false,
            clash_mode: &mode.lower,
        };
        self.rules
            .iter()
            .enumerate()
            .skip(from)
            .find(|(_, (n, _))| n.matches(meta, ctx))
            .map(|(i, (_, a))| (i, a))
    }

    /// `route.final`, or the first outbound.
    pub fn final_outbound(&self) -> usize {
        self.final_outbound
    }

    /// Evaluate to a final action without performing any side effects
    /// (sniff/resolve are skipped, route-options are folded in).
    pub fn route(&self, meta: &Metadata) -> Action {
        let mut opts = RouteOptions::default();
        let mut i = 0;
        while let Some((idx, action)) = self.next(meta, i) {
            i = idx + 1;
            match action {
                Action::RouteOptions(o) => opts.merge(o),
                Action::Route { outbound, options } => {
                    opts.merge(options);
                    return Action::Route {
                        outbound: *outbound,
                        options: opts,
                    };
                }
                a if a.is_final() => return a.clone(),
                _ => {}
            }
        }
        Action::Route {
            outbound: self.final_outbound,
            options: opts,
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[derive(Clone, Copy)]
struct Ctx<'a> {
    /// Set inside a rule-set referenced with `rule_set_ip_cidr_match_source`.
    ip_cidr_match_source: bool,
    /// The current Clash mode, lowercased.
    clash_mode: &'a str,
}

struct CompiledSet {
    nodes: Vec<Node>,
    mergeable: bool,
}

impl CompiledSet {
    fn compile(tag: &str, rules: &[Rule], sets: &HashMap<String, Arc<SetSlot>>) -> Result<Self, BuildError> {
        let nodes = rules
            .iter()
            .enumerate()
            .map(|(i, r)| Node::compile(r, &format!("rule_set[{tag}].rules[{i}]"), sets))
            .collect::<Result<Vec<_>, _>>()?;
        let mergeable = matches!(nodes.as_slice(), [Node::Default(d)] if !d.invert && d.rule_set.is_none());
        Ok(Self { nodes, mergeable })
    }
}

/// The Clash API mode shared by the API, the router's `clash_mode` matcher
/// and (later) DNS rules. Matching reads it lock-free.
pub struct ClashMode {
    list: Vec<String>,
    current: ArcSwap<ModeName>,
}

struct ModeName {
    display: String,
    lower: String,
}

impl ClashMode {
    /// sing-box `clashmode.NewManager`: the default (`Rule` unless set) is
    /// always selectable.
    pub fn new(default: Option<&str>, mut list: Vec<String>) -> Self {
        let default = default.filter(|d| !d.is_empty()).unwrap_or("Rule").to_owned();
        if !list.contains(&default) {
            list.insert(0, default.clone());
        }
        Self {
            list,
            current: ArcSwap::from_pointee(ModeName {
                lower: default.to_lowercase(),
                display: default,
            }),
        }
    }

    /// sing-box `CalculateModeList` over route rules: custom modes sorted,
    /// then `Rule`, `Global`, `Direct` in that order when used.
    pub fn modes_in(rules: &[Rule]) -> Vec<String> {
        fn walk(r: &Rule, out: &mut Vec<String>) {
            match &r.kind {
                RuleKind::Default(m) => out.extend(m.clash_mode.iter().cloned()),
                RuleKind::Logical { rules, .. } => rules.iter().for_each(|r| walk(r, out)),
            }
        }
        let mut found = Vec::new();
        rules.iter().for_each(|r| walk(r, &mut found));
        const PREDEFINED: [&str; 3] = ["Rule", "Global", "Direct"];
        let mut list: Vec<String> = found
            .iter()
            .filter(|m| !PREDEFINED.contains(&m.as_str()))
            .cloned()
            .collect();
        list.sort();
        list.dedup();
        list.extend(
            PREDEFINED
                .iter()
                .filter(|p| found.iter().any(|m| m == *p))
                .map(|p| p.to_string()),
        );
        list
    }

    pub fn current(&self) -> String {
        self.current.load().display.clone()
    }

    pub fn list(&self) -> &[String] {
        &self.list
    }

    /// Switch mode; unknown modes are ignored (exact match first, then
    /// case-insensitive). Returns the new mode if it changed.
    pub fn set(&self, mode: &str) -> Option<String> {
        let found = self
            .list
            .iter()
            .find(|m| *m == mode)
            .or_else(|| self.list.iter().find(|m| m.eq_ignore_ascii_case(mode)))?;
        if self.current.load().display == *found {
            return None;
        }
        self.current.store(Arc::new(ModeName {
            display: found.clone(),
            lower: found.to_lowercase(),
        }));
        Some(found.clone())
    }
}

enum Node {
    Default(Box<DefaultRule>),
    Logical {
        mode: LogicalMode,
        rules: Vec<Node>,
        invert: bool,
    },
}

#[derive(Default)]
struct DefaultRule {
    invert: bool,
    empty: bool,
    inbound: HashSet<Box<str>>,
    auth_user: HashSet<Box<str>>,
    network: Vec<Network>,
    protocol: Vec<Protocol>,
    ip_version: Option<u8>,
    source_ip: IpSet,
    source_ip_is_private: bool,
    source_port: PortSet,
    domain: DomainSet,
    dest_ip: IpSet,
    dest_ip_is_private: bool,
    dest_port: PortSet,
    rule_set: Option<(Vec<Arc<SetSlot>>, bool)>,
    /// Lowercased.
    clash_mode: Option<Box<str>>,
}

const SRC_ADDR: u8 = 1;
const SRC_PORT: u8 = 2;
const DST_ADDR: u8 = 4;
const DST_PORT: u8 = 8;

#[derive(Clone, Copy, Default)]
struct Groups {
    required: u8,
    satisfied: u8,
}

impl Groups {
    fn done(self) -> bool {
        self.required & !self.satisfied == 0
    }
    fn merge(self, o: Groups) -> Groups {
        Groups {
            required: self.required | o.required,
            satisfied: self.satisfied | o.satisfied,
        }
    }
    fn add(&mut self, bit: u8, hit: impl FnOnce() -> bool) {
        self.required |= bit;
        if self.satisfied & bit == 0 && hit() {
            self.satisfied |= bit;
        }
    }
}

impl Node {
    fn compile(r: &Rule, path: &str, sets: &HashMap<String, Arc<SetSlot>>) -> Result<Node, BuildError> {
        Ok(match &r.kind {
            RuleKind::Default(m) => Node::Default(Box::new(DefaultRule::compile(m, r.invert, path, sets)?)),
            RuleKind::Logical { mode, rules } => Node::Logical {
                mode: *mode,
                invert: r.invert,
                rules: rules
                    .iter()
                    .enumerate()
                    .map(|(i, r)| Node::compile(r, &format!("{path}.rules[{i}]"), sets))
                    .collect::<Result<_, _>>()?,
            },
        })
    }

    fn matches(&self, meta: &Metadata, ctx: Ctx) -> bool {
        match self {
            Node::Default(d) => d.matches(meta, ctx),
            Node::Logical { mode, rules, invert } => {
                let hit = match mode {
                    LogicalMode::And => rules.iter().all(|r| r.matches(meta, ctx)),
                    LogicalMode::Or => rules.iter().any(|r| r.matches(meta, ctx)),
                };
                hit != *invert
            }
        }
    }
}

impl DefaultRule {
    fn compile(
        m: &Matchers,
        invert: bool,
        path: &str,
        sets: &HashMap<String, Arc<SetSlot>>,
    ) -> Result<Self, BuildError> {
        let rule_set = if m.rule_set.is_empty() {
            None
        } else {
            let list = m
                .rule_set
                .iter()
                .map(|t| {
                    sets.get(t)
                        .cloned()
                        .ok_or_else(|| BuildError::RuleSet(t.clone(), "not found".into()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Some((list, m.rule_set_ip_cidr_match_source))
        };
        let r = DefaultRule {
            invert,
            empty: false,
            inbound: m.inbound.iter().map(|s| s.as_str().into()).collect(),
            auth_user: m.auth_user.iter().map(|s| s.as_str().into()).collect(),
            network: m.network.clone(),
            protocol: m.protocol.clone(),
            ip_version: m.ip_version,
            source_ip: IpSet::new(&m.source_ip_cidr),
            source_ip_is_private: m.source_ip_is_private,
            source_port: PortSet::new(&m.source_port, &m.source_port_range),
            domain: DomainSet::new(&m.domain, &m.domain_suffix, &m.domain_keyword, &m.domain_regex)
                .map_err(|e| BuildError::Regex(path.to_owned(), e))?,
            dest_ip: IpSet::new(&m.ip_cidr),
            dest_ip_is_private: m.ip_is_private,
            dest_port: PortSet::new(&m.port, &m.port_range),
            rule_set,
            clash_mode: m.clash_mode.as_deref().map(|c| c.to_lowercase().into()),
        };
        let empty = r.inbound.is_empty()
            && r.auth_user.is_empty()
            && r.network.is_empty()
            && r.protocol.is_empty()
            && r.ip_version.is_none()
            && r.source_ip.is_empty()
            && !r.source_ip_is_private
            && r.source_port.is_empty()
            && r.domain.is_empty()
            && r.dest_ip.is_empty()
            && !r.dest_ip_is_private
            && r.dest_port.is_empty()
            && r.rule_set.is_none()
            && r.clash_mode.is_none();
        Ok(DefaultRule { empty, ..r })
    }

    fn has_dest_ip(&self) -> bool {
        !self.dest_ip.is_empty() || self.dest_ip_is_private
    }

    fn ip_hit(&self, ip: std::net::IpAddr) -> bool {
        self.dest_ip.contains(ip) || (self.dest_ip_is_private && is_private(ip))
    }

    /// The AND-ed, non-grouped fields.
    fn items_match(&self, meta: &Metadata, ctx: Ctx) -> bool {
        self.clash_mode.as_deref().is_none_or(|m| m == ctx.clash_mode)
            && (self.inbound.is_empty() || self.inbound.contains(&*meta.inbound))
            && (self.network.is_empty() || self.network.contains(&meta.network))
            && (self.protocol.is_empty() || meta.protocol.is_some_and(|p| self.protocol.contains(&p)))
            && (self.auth_user.is_empty() || meta.user.as_deref().is_some_and(|u| self.auth_user.contains(u)))
            && self.ip_version.is_none_or(|v| match meta.destination.ip() {
                Some(std::net::IpAddr::V4(_)) => v == 4,
                Some(std::net::IpAddr::V6(_)) => v == 6,
                None => false,
            })
    }

    fn groups(&self, meta: &Metadata, ctx: Ctx) -> Groups {
        let mut g = Groups::default();
        let src_ip = meta.source.ip();
        if !self.source_ip.is_empty() || self.source_ip_is_private {
            g.add(SRC_ADDR, || {
                self.source_ip.contains(src_ip) || (self.source_ip_is_private && is_private(src_ip))
            });
        }
        if ctx.ip_cidr_match_source && self.has_dest_ip() {
            g.add(SRC_ADDR, || self.ip_hit(src_ip));
        }
        if !self.source_port.is_empty() {
            g.add(SRC_PORT, || self.source_port.contains(meta.source.port()));
        }
        if !self.domain.is_empty() {
            g.add(DST_ADDR, || meta.domain().is_some_and(|d| self.domain.matches(d)));
        }
        if !ctx.ip_cidr_match_source && self.has_dest_ip() {
            g.add(DST_ADDR, || meta.destination_ips().any(|ip| self.ip_hit(ip)));
        }
        if !self.dest_port.is_empty() {
            g.add(DST_PORT, || self.dest_port.contains(meta.destination.port));
        }
        g
    }

    fn matches(&self, meta: &Metadata, ctx: Ctx) -> bool {
        if self.empty {
            return !self.invert;
        }
        self.matches_inner(meta, ctx) != self.invert
    }

    fn matches_inner(&self, meta: &Metadata, ctx: Ctx) -> bool {
        if !self.items_match(meta, ctx) {
            return false;
        }
        let outer = self.groups(meta, ctx);
        let Some((sets, match_source)) = &self.rule_set else {
            return outer.done();
        };
        let nested = Ctx {
            ip_cidr_match_source: *match_source,
            ..ctx
        };
        sets.iter().any(|slot| {
            let set = slot.load();
            if set.mergeable {
                let Node::Default(branch) = &set.nodes[0] else {
                    unreachable!()
                };
                branch.items_match(meta, nested) && outer.merge(branch.groups(meta, nested)).done()
            } else {
                outer.done() && set.nodes.iter().any(|n| n.matches(meta, nested))
            }
        })
    }
}

#[cfg(test)]
mod tests;
