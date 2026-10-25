import Foundation
import NetworkExtension
import SbrKit

@MainActor
final class TunnelModel: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var groups: [SbrGroup] = []
    @Published private(set) var stats: SbrStats?
    @Published private(set) var uploadRate: Double = 0 // bytes/s
    @Published private(set) var downloadRate: Double = 0
    @Published private(set) var testing: Set<String> = []
    @Published var errorMessage: String?
    /// "Block traffic outside the tunnel": `includeAllNetworks`. Applied the
    /// next time the tunnel connects.
    @Published var strict = UserDefaults.standard.bool(forKey: "strict") {
        didSet {
            UserDefaults.standard.set(strict, forKey: "strict")
            Task { try? await self.install() }
        }
    }

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    private var session: NETunnelProviderSession? { manager?.connection as? NETunnelProviderSession }

    var isOn: Bool { [.connected, .connecting, .reasserting].contains(status) }
    var isConnected: Bool { status == .connected }

    func load() async {
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = all.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == AppConfig.tunnelBundleIdentifier
            }
            observeStatus()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func setOn(_ on: Bool) async {
        do {
            if manager == nil { try await install() }
            guard let manager else { return }
            if on {
                if !manager.isEnabled {
                    manager.isEnabled = true
                    try await manager.saveToPreferences()
                    try await manager.loadFromPreferences()
                }
                try manager.connection.startVPNTunnel()
            } else {
                manager.connection.stopVPNTunnel()
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// The active profile changed on disk: hot-reload a running tunnel.
    func reload() async {
        guard isConnected, let session else { return }
        do {
            groups = try await session.send(.reload).groups ?? groups
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func select(group: String, member: String) async {
        guard let session else { return }
        do {
            groups = try await session.send(.select(group: group, member: member)).groups ?? groups
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Latency-test a group. Results arrive through polling; the spinner
    /// clears when the group's numbers change or after a few seconds.
    func urlTest(group: String) async {
        guard let session, !testing.contains(group) else { return }
        testing.insert(group)
        let before = groups.first { $0.tag == group }
        _ = try? await session.send(.urlTest(group: group))
        for _ in 0..<20 {
            try? await Task.sleep(nanoseconds: 300_000_000)
            if let g = try? await session.send(.groups).groups {
                groups = g
                if g.first(where: { $0.tag == group }) != before { break }
            }
        }
        testing.remove(group)
    }

    /// Poll the tunnel once a second while visible and connected. The
    /// extension only wakes for these messages, so a backgrounded app costs
    /// it nothing.
    func poll() async {
        var last: (stats: SbrStats, at: Date)?
        while !Task.isCancelled {
            if isConnected, let session {
                if let s = try? await session.send(.stats).stats {
                    let now = Date()
                    if let last {
                        let dt = max(now.timeIntervalSince(last.at), 0.001)
                        uploadRate = Double(s.uplinkBytes &- last.stats.uplinkBytes) / dt
                        downloadRate = Double(s.downlinkBytes &- last.stats.downlinkBytes) / dt
                    }
                    last = (s, now)
                    stats = s
                }
                if let g = try? await session.send(.groups).groups { groups = g }
            } else {
                last = nil
                uploadRate = 0
                downloadRate = 0
            }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
    }

    private func install() async throws {
        #if SBR_SYSTEM_EXTENSION
        try await SystemExtensionActivator.activate(identifier: AppConfig.tunnelBundleIdentifier)
        #endif
        let m = manager ?? NETunnelProviderManager()
        let proto = (m.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppConfig.tunnelBundleIdentifier
        proto.serverAddress = "sbr"
        // The tunnel reads config.json from the App Group container.
        proto.providerConfiguration = [SbrProviderKey.appGroup: AppConfig.appGroup]
        Sbr.applyLeakProtection(to: proto, enabled: strict)
        m.protocolConfiguration = proto
        m.localizedDescription = "sbr"
        m.isEnabled = true
        try await m.saveToPreferences()
        // A freshly saved manager must be reloaded before it can start.
        try await m.loadFromPreferences()
        manager = m
        observeStatus()
    }

    private func observeStatus() {
        if let statusObserver { NotificationCenter.default.removeObserver(statusObserver) }
        guard let connection = manager?.connection else { return }
        status = connection.status
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: connection, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.status = connection.status
                if connection.status != .connected { self.groups = [] }
            }
        }
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .invalid: "not installed"
        case .disconnected: "off"
        case .connecting: "connecting"
        case .connected: "on"
        case .reasserting: "reconnecting"
        case .disconnecting: "disconnecting"
        @unknown default: "unknown"
        }
    }
}
