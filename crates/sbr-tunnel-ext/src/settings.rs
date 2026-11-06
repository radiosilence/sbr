//! `NEPacketTunnelNetworkSettings` from the plan `sbr-apple` derives from the
//! config's `tun` inbound (see `crates/sbr-apple/src/tun_settings.rs` for the
//! rules): interface addresses, MTU, included and excluded routes, and DNS
//! pointed into the tunnel for every domain.

use objc2::AllocAnyThread;
use objc2::rc::Retained;
use objc2_foundation::{NSArray, NSNumber, NSString};
use objc2_network_extension::{
    NEDNSSettings, NEIPv4Route, NEIPv4Settings, NEIPv6Route, NEIPv6Settings, NEPacketTunnelNetworkSettings,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Route {
    address: String,
    prefix: u32,
    subnet_mask: String,
}

#[derive(Deserialize)]
struct Family {
    addresses: Vec<String>,
    prefixes: Vec<u32>,
    subnet_masks: Vec<String>,
    included_routes: Vec<Route>,
    excluded_routes: Vec<Route>,
}

#[derive(Deserialize)]
struct Plan {
    mtu: u32,
    ipv4: Option<Family>,
    ipv6: Option<Family>,
    dns_servers: Vec<String>,
}

fn strings(v: &[String]) -> Retained<NSArray<NSString>> {
    let v: Vec<Retained<NSString>> = v.iter().map(|s| NSString::from_str(s)).collect();
    NSArray::from_retained_slice(&v)
}

pub fn network_settings(config: &str) -> Result<Retained<NEPacketTunnelNetworkSettings>, String> {
    let plan: Plan =
        serde_json::from_value(sbr_apple::api::tun_network_settings(config)?).map_err(|e| e.to_string())?;
    // SAFETY: plain NetworkExtension value objects.
    unsafe {
        let settings = NEPacketTunnelNetworkSettings::initWithTunnelRemoteAddress(
            NEPacketTunnelNetworkSettings::alloc(),
            &NSString::from_str("127.0.0.1"),
        );
        settings.setMTU(Some(&NSNumber::new_u32(plan.mtu)));
        if let Some(v4) = plan.ipv4 {
            let ip = NEIPv4Settings::initWithAddresses_subnetMasks(
                NEIPv4Settings::alloc(),
                &strings(&v4.addresses),
                &strings(&v4.subnet_masks),
            );
            let route = |r: &Route| {
                NEIPv4Route::initWithDestinationAddress_subnetMask(
                    NEIPv4Route::alloc(),
                    &NSString::from_str(&r.address),
                    &NSString::from_str(&r.subnet_mask),
                )
            };
            let included: Vec<_> = v4
                .included_routes
                .iter()
                .map(|r| {
                    if r.prefix == 0 {
                        NEIPv4Route::defaultRoute()
                    } else {
                        route(r)
                    }
                })
                .collect();
            let excluded: Vec<_> = v4.excluded_routes.iter().map(route).collect();
            ip.setIncludedRoutes(Some(&NSArray::from_retained_slice(&included)));
            ip.setExcludedRoutes(Some(&NSArray::from_retained_slice(&excluded)));
            settings.setIPv4Settings(Some(&ip));
        }
        if let Some(v6) = plan.ipv6 {
            let prefixes: Vec<_> = v6.prefixes.iter().map(|p| NSNumber::new_u32(*p)).collect();
            let ip = NEIPv6Settings::initWithAddresses_networkPrefixLengths(
                NEIPv6Settings::alloc(),
                &strings(&v6.addresses),
                &NSArray::from_retained_slice(&prefixes),
            );
            let route = |r: &Route| {
                NEIPv6Route::initWithDestinationAddress_networkPrefixLength(
                    NEIPv6Route::alloc(),
                    &NSString::from_str(&r.address),
                    &NSNumber::new_u32(r.prefix),
                )
            };
            let included: Vec<_> = v6
                .included_routes
                .iter()
                .map(|r| {
                    if r.prefix == 0 {
                        NEIPv6Route::defaultRoute()
                    } else {
                        route(r)
                    }
                })
                .collect();
            let excluded: Vec<_> = v6.excluded_routes.iter().map(route).collect();
            ip.setIncludedRoutes(Some(&NSArray::from_retained_slice(&included)));
            ip.setExcludedRoutes(Some(&NSArray::from_retained_slice(&excluded)));
            settings.setIPv6Settings(Some(&ip));
        }
        if !plan.dns_servers.is_empty() {
            let dns = NEDNSSettings::initWithServers(NEDNSSettings::alloc(), &strings(&plan.dns_servers));
            // Every query, not just a search domain, goes to the tunnel.
            dns.setMatchDomains(Some(&strings(&[String::new()])));
            dns.setMatchDomainsNoSearch(true);
            settings.setDNSSettings(Some(&dns));
        }
        Ok(settings)
    }
}
