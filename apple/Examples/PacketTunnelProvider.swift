// Interim Network Extension wiring until the TUN inbound lands: run sbr's
// mixed inbound on loopback inside the extension and point the system HTTP(S)
// proxy at it. URLSession/Safari/WebKit honour this; raw-socket apps don't.
// That gap is exactly what the TUN inbound closes.
import NetworkExtension
import SbrKit

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var core: Sbr?

    override func startTunnel(options: [String: NSObject]?) async throws {
        guard let config = (protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["config"] as? String else {
            throw SbrError(description: "missing config")
        }
        let groupDir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.example.sbr")
        core = try Sbr(config: config, baseDirectory: groupDir)

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let proxy = NEProxySettings()
        let server = NEProxyServer(address: "127.0.0.1", port: 2080) // must match the mixed inbound
        proxy.httpEnabled = true
        proxy.httpServer = server
        proxy.httpsEnabled = true
        proxy.httpsServer = server
        proxy.matchDomains = [""] // all domains
        settings.proxySettings = proxy
        try await setTunnelNetworkSettings(settings)
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        core?.stop()
        core = nil
    }
}
