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
    /// claims `::/0` on a ULA address: the engine has no IPv6 stack for it, so
    /// IPv6 flows fail (and clients fall back to IPv4 through the tunnel)
    /// instead of leaving by the physical interface.
    ///
    /// `strict_route` has no per-route equivalent here; see
    /// `Sbr.applyLeakProtection(to:)` for the provider-level switches.
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
        } else if plan.auto_route {
            let ip = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [126])
            ip.includedRoutes = [.default()]
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
}

extension Sbr {
    /// Route everything through the tunnel, including connections that
    /// predate it, and refuse the "local network" exemption that TunnelCrack's
    /// LocalNet attack abuses. Off by default until it's proven on devices:
    /// some VPNs have seen their own extension's sockets stall under it.
    public static func applyLeakProtection(to proto: NETunnelProviderProtocol, enabled: Bool) {
        #if !os(tvOS)
        proto.includeAllNetworks = enabled
        proto.excludeLocalNetworks = false
        proto.enforceRoutes = enabled
        #endif
    }
}
