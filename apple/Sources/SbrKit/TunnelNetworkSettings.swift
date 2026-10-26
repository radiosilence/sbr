import Foundation
import NetworkExtension
import SbrCore

/// The shape `sbr_tun_network_settings` returns (see sbr.h).
struct TunNetworkPlan: Decodable {
    struct Route: Decodable {
        let address: String
        let prefix: Int
        let subnet_mask: String
    }

    struct Family: Decodable {
        let addresses: [String]
        let prefixes: [Int]
        let subnet_masks: [String]
        let included_routes: [Route]
        let excluded_routes: [Route]
    }

    let mtu: Int
    let ipv4: Family?
    let ipv6: Family?
    let dns_servers: [String]
    let auto_route: Bool
    let strict_route: Bool
}

extension Sbr {
    /// Network settings derived from the config's `tun` inbound, with
    /// sing-box semantics: `address` → interface addresses, `mtu`,
    /// `auto_route` → default routes (or `route_address`),
    /// `route_exclude_address` → excluded routes, and DNS pointed at the
    /// address after the tun's first IPv4 address (match-all) so system DNS
    /// enters the tunnel where `hijack-dns` answers it.
    ///
    /// With `auto_route` and no IPv6 address in the config, the tunnel still
    /// claims `::/0` on `unroutedIPv6Address`: the engine has no IPv6 address
    /// to carry it on and refuses those flows, so clients fall back to IPv4
    /// through the tunnel instead of leaving by the physical interface.
    ///
    /// `strict_route` has no per-route equivalent here; see
    /// `Sbr.applyLeakProtection(to:enabled:allowLocalNetwork:)` for the
    /// provider-level switches.
    public static func tunnelNetworkSettings(
        config: String,
        tunnelRemoteAddress: String = "127.0.0.1"
    ) throws -> NEPacketTunnelNetworkSettings {
        var err: UnsafeMutablePointer<CChar>?
        let json = takeString(sbr_tun_network_settings(config, &err))
        if let message = takeString(err) { throw SbrError(message) }
        guard let json else { throw SbrError("sbr_tun_network_settings failed") }
        let plan = try JSONDecoder().decode(TunNetworkPlan.self, from: Data(json.utf8))

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelRemoteAddress)
        settings.mtu = NSNumber(value: plan.mtu)
        if let v4 = plan.ipv4 {
            let ip = NEIPv4Settings(addresses: v4.addresses, subnetMasks: v4.subnet_masks)
            ip.includedRoutes = v4.included_routes.map {
                $0.prefix == 0 ? .default() : NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.subnet_mask)
            }
            ip.excludedRoutes = v4.excluded_routes.map {
                NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.subnet_mask)
            }
            settings.ipv4Settings = ip
        }
        if let v6 = plan.ipv6 {
            let ip = NEIPv6Settings(addresses: v6.addresses, networkPrefixLengths: v6.prefixes.map { NSNumber(value: $0) })
            ip.includedRoutes = v6.included_routes.map {
                $0.prefix == 0
                    ? .default()
                    : NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefix))
            }
            ip.excludedRoutes = v6.excluded_routes.map {
                NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefix))
            }
            settings.ipv6Settings = ip
        }
        if !plan.dns_servers.isEmpty {
            let dns = NEDNSSettings(servers: plan.dns_servers)
            // Every query, not just a search domain, goes to the tunnel.
            dns.matchDomains = [""]
            dns.matchDomainsNoSearch = true
            settings.dnsSettings = dns
        }
        return settings
    }

    /// The tun address `tunnelNetworkSettings` uses for IPv6 the engine
    /// does not carry (`UNROUTED_IPV6` in crates/sbr-apple/src/tun_settings.rs).
    public static let unroutedIPv6Address = "fd73:6272::1"

    /// The config's `tun` inbound sets `strict_route`. False when the config
    /// has no tun inbound or doesn't parse.
    public static func strictRoute(config: String) -> Bool {
        var err: UnsafeMutablePointer<CChar>?
        let json = takeString(sbr_tun_network_settings(config, &err))
        _ = takeString(err)
        guard let json, let plan = try? JSONDecoder().decode(TunNetworkPlan.self, from: Data(json.utf8)) else {
            return false
        }
        return plan.strict_route
    }
}

extension Sbr {
    /// Leak protection, the NE form of sing-box's `strict_route`.
    ///
    /// `includeAllNetworks` sends everything through the tunnel, connections
    /// opened before it came up included, and blocks traffic while the tunnel
    /// is down. `excludeLocalNetworks` stays off unless `allowLocalNetwork`:
    /// it exempts whatever the current network calls local, which is how
    /// TunnelCrack's LocalNet attack takes public ranges out of the tunnel.
    /// `enforceRoutes` makes the tunnel's routes win over more specific ones
    /// the network pushes (DHCP option 121, TunnelVision).
    ///
    /// tvOS has only `enforceRoutes`. Off by default: it also breaks AirDrop,
    /// CarPlay and other local traffic, and an app update with it on can leave
    /// the device offline (see apple/README.md).
    public static func applyLeakProtection(
        to proto: NETunnelProviderProtocol,
        enabled: Bool,
        allowLocalNetwork: Bool = false
    ) {
        #if !os(tvOS)
        proto.includeAllNetworks = enabled
        proto.excludeLocalNetworks = enabled && allowLocalNetwork
        #endif
        proto.enforceRoutes = enabled
    }
}
