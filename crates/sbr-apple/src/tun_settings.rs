//! `NEPacketTunnelNetworkSettings`, derived from the config's `tun` inbound.
//!
//! Lives in Rust rather than Swift so it reuses the strict config parser
//! (comments, legacy `inet4_address` fields) and is unit-tested off-Mac.
//! The rules follow sing-box's libbox platform interface:
//!
//! - `address` → interface addresses (IPv4 as address + mask, IPv6 as
//!   address + prefix length).
//! - IPv6 with `auto_route` but no IPv6 address: the interface gets
//!   [`UNROUTED_IPV6`] and the same routes, so IPv6 enters the tunnel instead
//!   of leaving by the physical interface on a dual-stack network. The engine
//!   has no IPv6 address to translate to and refuses those flows (TCP reset,
//!   ICMPv6 unreachable), so clients fall back to IPv4 at once.
//! - `auto_route` → included routes are `route_address` of that family, or
//!   the default route when empty; `route_exclude_address` → excluded routes.
//!   Without `auto_route` only the interface subnets reach the tunnel, routed
//!   explicitly because NetworkExtension adds no route on its own.
//! - DNS (only with `auto_route`): the address right after the first IPv4
//!   interface address (172.19.0.1/30 → 172.19.0.2), matching all domains,
//!   so system DNS enters the TUN where `hijack-dns` answers it. sing-box
//!   requires a /31 or wider IPv4 prefix for this; so do we, falling back to
//!   IPv6 the same way.

use std::net::IpAddr;

use ipnet::IpNet;
use sbr_engine::sbr_config::{InboundKind, Options, TunInbound};
use serde_json::{Value, json};

/// sing-box's default TUN MTU.
const DEFAULT_MTU: u32 = 9000;
/// The interface address for IPv6 that the engine does not carry, from a
/// fixed ULA prefix (`fd73:6272::/48`, "sbr") that no config is likely to use.
/// SbrKit's `Sbr.unroutedIPv6Address` repeats it.
const UNROUTED_IPV6: &str = "fd73:6272::1/126";

pub fn network_settings(options: &Options) -> Result<Value, String> {
    let tun = options
        .inbounds
        .iter()
        .find_map(|i| match &i.kind {
            InboundKind::Tun(t) => Some(t),
            _ => None,
        })
        .ok_or("config has no tun inbound")?;
    Ok(build(tun))
}

fn build(t: &TunInbound) -> Value {
    let unrouted: IpNet = UNROUTED_IPV6.parse().unwrap();
    let family = |v4: bool| -> Option<Value> {
        let mut addrs: Vec<&IpNet> = t.address.iter().filter(|a| a.addr().is_ipv4() == v4).collect();
        if addrs.is_empty() && !v4 && t.auto_route {
            addrs.push(&unrouted);
        }
        if addrs.is_empty() {
            return None;
        }
        let of = |list: &[IpNet]| -> Vec<IpNet> { list.iter().filter(|n| n.addr().is_ipv4() == v4).copied().collect() };
        let (included, excluded) = if t.auto_route {
            let mut inc = of(&t.route_address);
            if inc.is_empty() {
                inc.push(if v4 { "0.0.0.0/0" } else { "::/0" }.parse().unwrap());
            }
            (inc, of(&t.route_exclude_address))
        } else {
            // Without auto_route only the interface's own subnets reach the
            // tunnel; NetworkExtension routes nothing it isn't told to.
            (addrs.iter().map(|a| a.trunc()).collect(), Vec::new())
        };
        Some(json!({
            "addresses": addrs.iter().map(|a| a.addr().to_string()).collect::<Vec<_>>(),
            "prefixes": addrs.iter().map(|a| a.prefix_len()).collect::<Vec<_>>(),
            "subnet_masks": addrs.iter().map(|a| a.netmask().to_string()).collect::<Vec<_>>(),
            "included_routes": included.iter().map(route).collect::<Vec<_>>(),
            "excluded_routes": excluded.iter().map(route).collect::<Vec<_>>(),
        }))
    };
    let dns = t.auto_route.then(|| dns_server(t)).flatten();
    json!({
        "mtu": t.mtu.unwrap_or(DEFAULT_MTU),
        "ipv4": family(true),
        "ipv6": family(false),
        "dns_servers": dns.map(|d| vec![d.to_string()]).unwrap_or_default(),
        "auto_route": t.auto_route,
        "strict_route": t.strict_route,
    })
}

/// Network address (canonical: 10.1.2.3/8 → 10.0.0.0), prefix and mask.
fn route(n: &IpNet) -> Value {
    let n = n.trunc();
    json!({
        "address": n.addr().to_string(),
        "prefix": n.prefix_len(),
        "subnet_mask": n.netmask().to_string(),
    })
}

fn dns_server(t: &TunInbound) -> Option<IpAddr> {
    let next = |v4: bool| {
        t.address
            .iter()
            .find(|a| a.addr().is_ipv4() == v4)
            .filter(|a| a.prefix_len() < a.max_prefix_len())
            .and_then(|a| {
                let n = match a.addr() {
                    IpAddr::V4(ip) => IpAddr::V4(u32::from(ip).checked_add(1)?.into()),
                    IpAddr::V6(ip) => IpAddr::V6(u128::from(ip).checked_add(1)?.into()),
                };
                a.contains(&n).then_some(n)
            })
    };
    next(true).or_else(|| next(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(tun: &str) -> Value {
        let cfg =
            format!(r#"{{"inbounds":[{{"type":"tun","tag":"tun-in",{tun}}}],"outbounds":[{{"type":"direct"}}]}}"#);
        network_settings(&Options::parse(&cfg).unwrap()).unwrap()
    }

    #[test]
    fn auto_route_dual_stack() {
        let s = settings(
            r#"
            // comments are fine, like sing-box
            "address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"mtu":1500,"auto_route":true,
            "route_exclude_address":["192.168.0.0/16","fc00::/7"]"#,
        );
        assert_eq!(s["mtu"], 1500);
        assert_eq!(s["ipv4"]["addresses"], json!(["172.19.0.1"]));
        assert_eq!(s["ipv4"]["subnet_masks"], json!(["255.255.255.252"]));
        assert_eq!(
            s["ipv4"]["included_routes"],
            json!([{"address":"0.0.0.0","prefix":0,"subnet_mask":"0.0.0.0"}])
        );
        assert_eq!(
            s["ipv4"]["excluded_routes"],
            json!([{"address":"192.168.0.0","prefix":16,"subnet_mask":"255.255.0.0"}])
        );
        assert_eq!(s["ipv6"]["addresses"], json!(["fdfe:dcba:9876::1"]));
        assert_eq!(s["ipv6"]["prefixes"], json!([126]));
        assert_eq!(s["ipv6"]["included_routes"][0]["address"], "::");
        assert_eq!(s["ipv6"]["excluded_routes"][0]["prefix"], 7);
        assert_eq!(s["dns_servers"], json!(["172.19.0.2"]));
    }

    #[test]
    fn route_address_and_legacy_fields() {
        let s = settings(r#""inet4_address":"10.0.0.1/24","auto_route":true,"route_address":["1.2.3.4/8","8.8.8.8"]"#);
        assert_eq!(s["mtu"], 9000);
        assert_eq!(s["ipv6"]["addresses"], json!(["fd73:6272::1"]));
        assert_eq!(
            s["ipv6"]["included_routes"],
            json!([{"address":"::","prefix":0,"subnet_mask":"::"}])
        );
        assert_eq!(
            s["ipv4"]["included_routes"],
            json!([
                {"address":"1.0.0.0","prefix":8,"subnet_mask":"255.0.0.0"},
                {"address":"8.8.8.8","prefix":32,"subnet_mask":"255.255.255.255"}
            ])
        );
        assert_eq!(s["dns_servers"], json!(["10.0.0.2"]));
    }

    #[test]
    fn no_auto_route_routes_only_the_interface_subnet() {
        let s = settings(r#""address":["172.19.0.1/30"]"#);
        assert_eq!(s["ipv4"]["included_routes"][0]["address"], "172.19.0.0");
        assert_eq!(s["ipv4"]["included_routes"].as_array().unwrap().len(), 1);
        assert_eq!(s["dns_servers"], json!([]));
        assert_eq!(s["ipv6"], Value::Null, "nothing to leak without auto_route");
        // A /32 leaves no room for a DNS address; IPv6 takes over.
        let s = settings(r#""address":["172.19.0.1/32","fdfe::1/126"],"auto_route":true"#);
        assert_eq!(s["dns_servers"], json!(["fdfe::2"]));
    }

    #[test]
    fn ipv4_only_auto_route_still_claims_ipv6() {
        let s = settings(r#""address":["172.19.0.1/30"],"auto_route":true,"route_exclude_address":["fc00::/7"]"#);
        assert_eq!(s["ipv6"]["addresses"], json!(["fd73:6272::1"]));
        assert_eq!(s["ipv6"]["prefixes"], json!([126]));
        assert_eq!(s["ipv6"]["included_routes"][0]["prefix"], 0);
        assert_eq!(s["ipv6"]["excluded_routes"][0]["prefix"], 7);
        assert_eq!(s["dns_servers"], json!(["172.19.0.2"]));
    }

    #[test]
    fn needs_a_tun_inbound() {
        let o = Options::parse(r#"{"outbounds":[{"type":"direct"}]}"#).unwrap();
        assert!(network_settings(&o).is_err());
    }
}
