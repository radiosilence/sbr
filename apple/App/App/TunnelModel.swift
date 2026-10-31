import Foundation
import NetworkExtension
import SbrKit
#if os(macOS)
import ServiceManagement
#endif

@MainActor
final class TunnelModel: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var groups: [SbrGroup] = []
    @Published private(set) var stats: SbrStats?
    @Published private(set) var uploadRate: Double = 0 // bytes/s
    @Published private(set) var downloadRate: Double = 0
    /// Share of one core the tunnel used over the last poll, 0…1+.
    @Published private(set) var cpuShare: Double = 0
    @Published private(set) var testing: Set<String> = []
    @Published var errorMessage: String?
    /// Why the tunnel last stopped without being asked to, from the system.
    @Published private(set) var lastStop: String?
    /// The system extension is waiting for the user to allow it in System
    /// Settings. Always false outside the Developer ID build.
    @Published private(set) var needsApproval = false
    /// "Block traffic outside the tunnel": `Sbr.applyLeakProtection`. Follows
    /// the profile's `strict_route` until the user sets it. Applied the next
    /// time the tunnel connects.
    var strict: Bool {
        get { strictChoice ?? profileStrict }
        set {
            strictChoice = newValue
            UserDefaults.standard.set(newValue, forKey: "strict")
            Task { try? await self.install() }
        }
    }

    @Published private var strictChoice = UserDefaults.standard.object(forKey: "strict") as? Bool
    @Published private var profileStrict = false

    /// Under `strict`, let traffic to the local network bypass the tunnel
    /// (`excludeLocalNetworks`), for AirPlay, printers and LAN media servers.
    @Published var allowLocalNetwork = UserDefaults.standard.bool(forKey: "allowLocalNetwork") {
        didSet {
            UserDefaults.standard.set(allowLocalNetwork, forKey: "allowLocalNetwork")
            Task { try? await self.install() }
        }
    }

    /// Connect on demand everywhere except `trustedNetworks` (Wi-Fi SSIDs).
    @Published var autoConnect = UserDefaults.standard.bool(forKey: "autoConnect") {
        didSet {
            UserDefaults.standard.set(autoConnect, forKey: "autoConnect")
            Task { try? await self.install(onDemand: self.autoConnect) }
        }
    }

    @Published var trustedNetworks = UserDefaults.standard.stringArray(forKey: "trustedNetworks") ?? [] {
        didSet {
            UserDefaults.standard.set(trustedNetworks, forKey: "trustedNetworks")
            Task { try? await self.install() }
        }
    }

    /// Debug-level engine logs in the logs tab, for diagnosing a profile.
    /// Run the tunnel on sbr's userspace TCP stack (the default) rather than
    /// the kernel's, which iOS stops under sustained load. Applied by
    /// reconnecting.
    @Published var userspaceTCP = UserDefaults.standard.object(forKey: "tcpStackUserspace") as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(userspaceTCP, forKey: "tcpStackUserspace")
            Task {
                try? await self.install()
                if self.isOn, let manager = self.manager {
                    manager.connection.stopVPNTunnel()
                    try? await Task.sleep(nanoseconds: 1_500_000_000)
                    try? manager.connection.startVPNTunnel()
                }
            }
        }
    }

    @Published var verbose = UserDefaults.standard.bool(forKey: "verbose") {
        didSet {
            UserDefaults.standard.set(verbose, forKey: "verbose")
            Task {
                try? await self.install()
                if self.isConnected, let session = self.session {
                    _ = try? await session.send(.reload(config: self.config, remote: self.remote, logLevel: self.logLevel,
                                                         rules: self.rules))
                }
            }
        }
    }

    /// Personal routing rules, put into whatever profile runs.
    @Published private(set) var rules = SbrPersonalRules.decode(UserDefaults.standard.data(forKey: "personalRules"))

    /// Outbounds a personal rule can name in the active profile.
    var routeChoices: [String] { config.map(SbrPersonalRules.choices) ?? [] }

    /// Route `domain` and its subdomains through `outbound`, replacing any
    /// rule for the same domain. Checked against the active profile first.
    func addRule(domain: String, outbound: String) async {
        guard let domain = SbrPersonalRule.normalize(domain) else {
            errorMessage = "not a domain"
            return
        }
        var next = rules.filter { $0.domains != [domain] }
        next.insert(SbrPersonalRule(domains: [domain], outbound: outbound), at: 0)
        if let config, let problem = Sbr.check(config: SbrPersonalRules.apply(next, to: config).config) {
            errorMessage = problem
            return
        }
        await setRules(next)
    }

    func removeRule(_ rule: SbrPersonalRule) async {
        await setRules(rules.filter { $0.id != rule.id })
    }

    private func setRules(_ next: [SbrPersonalRule]) async {
        rules = next
        UserDefaults.standard.set(SbrPersonalRules.encode(next), forKey: "personalRules")
        guard manager != nil, config != nil else { return }
        do {
            try await install()
            if isConnected, let session {
                groups = try await session.send(.reload(config: config, remote: remote, logLevel: logLevel, rules: next))
                    .groups ?? groups
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private var manager: NETunnelProviderManager?
    /// The last install failed part-way, for example while the system
    /// extension awaited approval, so the saved VPN configuration may name an
    /// older profile and the next connect saves it again.
    private var installFailed = false
    /// The active profile's config, carried in the VPN configuration.
    private var config: String?
    /// Where it came from, for the tunnel to refresh it itself.
    private var remote: SbrRemoteProfile?
    /// Its Keychain item, which the tunnel reads it from on start.
    private var stored: SbrStoredProfile?
    private var statusObserver: NSObjectProtocol?

    private var session: NETunnelProviderSession? { manager?.connection as? NETunnelProviderSession }

    var isOn: Bool { [.connected, .connecting, .reasserting].contains(status) }
    var isConnected: Bool { status == .connected }

    #if SBR_SYSTEM_EXTENSION
    init() {
        SystemExtensionActivator.approvalChanged = { [weak self] in
            self?.needsApproval = SystemExtensionActivator.awaitingApproval
        }
    }
    #endif

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
            if manager == nil || (on && installFailed) { try await install() }
            guard let manager else { return }
            try await TunnelControl.setOn(on, manager)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// The active profile changed: point the VPN configuration at it (so a
    /// restart uses it) and hot-reload a running tunnel.
    func apply(config: String?, remote: SbrRemoteProfile?, stored: SbrStoredProfile?) async {
        guard config != self.config || remote != self.remote || stored != self.stored else { return }
        self.config = config
        self.remote = remote
        self.stored = stored
        profileStrict = config.map(Sbr.strictRoute) ?? false
        guard manager != nil, config != nil else { return }
        do {
            try await install()
            if isConnected, let session {
                groups = try await session.send(.reload(config: config, remote: remote, logLevel: logLevel, rules: rules))
                    .groups ?? groups
            }
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

    /// The tunnel's recent log, kept on disk so it survives the tunnel (and
    /// this app) going away: the lines before a failure are the useful ones.
    @Published private(set) var logs: [String] = TunnelModel.loadLogs()

    private static var logsURL: URL? {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?
            .appendingPathComponent("tunnel-logs.json")
    }

    private static func loadLogs() -> [String] {
        guard let url = logsURL, let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder().decode([String].self, from: data)) ?? []
    }

    /// Poll the extension's recent logs while the logs tab is visible.
    /// The tunnel's CPU time so far, in microseconds.
    func cpuTime() async -> UInt64? {
        try? await session?.send(.stats).stats?.cpuTimeMicros
    }

    func pollLogs() async {
        while !Task.isCancelled {
            if isConnected, let session, let l = try? await session.send(.logs).logs, l != logs {
                logs = l
                if let url = Self.logsURL, let data = try? JSONEncoder().encode(l) {
                    try? data.write(to: url, options: .atomic)
                }
            }
            try? await Task.sleep(nanoseconds: 2_000_000_000)
        }
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
                        cpuShare = Double(s.cpuTimeMicros &- last.stats.cpuTimeMicros) / 1e6 / dt
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

    /// The remote profile as the running tunnel last downloaded it, if it
    /// refreshed it since the app last looked.
    func tunnelProfile() async -> SbrProfileSnapshot? {
        guard isConnected, let session else { return nil }
        return try? await session.send(.profile).profile
    }

    /// A connection with its rate over the last poll and when bytes last moved.
    struct LiveConnection: Identifiable, Hashable {
        var connection: SbrConnection
        var uploadRate: Double = 0
        var downloadRate: Double = 0
        var lastActive: Date
        var id: String { connection.id }
    }

    @Published private(set) var connections: [LiveConnection] = []
    @Published private(set) var connectionsTotal = 0

    /// Poll the tunnel's connections once a second while the connections
    /// tab is visible. Rows sort by when bytes last moved, newest first.
    func pollConnections() async {
        var previous: [String: LiveConnection] = [:]
        var lastAt = Date()
        while !Task.isCancelled {
            if isConnected, let session, let snapshot = try? await session.send(.connections).connections {
                let now = Date()
                let dt = max(now.timeIntervalSince(lastAt), 0.001)
                lastAt = now
                let rows = snapshot.connections.map { c in
                    guard let p = previous[c.id] else {
                        return LiveConnection(connection: c, lastActive: c.startDate)
                    }
                    let up = c.upload &- p.connection.upload, down = c.download &- p.connection.download
                    return LiveConnection(
                        connection: c,
                        uploadRate: Double(up) / dt,
                        downloadRate: Double(down) / dt,
                        lastActive: up + down > 0 ? now : p.lastActive
                    )
                }
                previous = Dictionary(rows.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
                connections = rows.sorted { ($0.lastActive, $0.connection.start) > ($1.lastActive, $1.connection.start) }
                connectionsTotal = snapshot.total
            } else if !isConnected {
                previous = [:]
                connections = []
                connectionsTotal = 0
            }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
    }

    func closeConnection(id: String) async {
        guard let session else { return }
        connections.removeAll { $0.id == id }
        do {
            _ = try await session.send(.closeConnection(id: id))
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// With `verbose`, the tunnel raises the profile's log level to debug,
    /// including in profiles it downloads itself.
    private var logLevel: String? { verbose ? "debug" : nil }

    /// Save the VPN configuration. `onDemand` arms or disarms auto-connect;
    /// nil keeps whatever a manual connect or disconnect last left it as.
    private func install(onDemand: Bool? = nil) async throws {
        guard config != nil else { throw SbrError("no profile selected") }
        installFailed = true
        #if SBR_SYSTEM_EXTENSION
        try await SystemExtensionActivator.activate(identifier: AppConfig.tunnelBundleIdentifier)
        #endif
        let m = manager ?? NETunnelProviderManager()
        // An intent may have changed it from another process since.
        if manager != nil { try? await m.loadFromPreferences() }
        let proto = (m.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppConfig.tunnelBundleIdentifier
        proto.serverAddress = "sbr"
        #if SBR_SYSTEM_EXTENSION
        // A system extension runs as root, outside the user's Keychain.
        var pc: [String: Any] = [SbrProviderKey.config: config ?? ""]
        if let remote { pc[SbrProviderKey.remote] = try JSONEncoder().encode(remote) }
        #else
        guard let stored else { throw SbrError("the profile is not in the Keychain") }
        var pc: [String: Any] = [SbrProviderKey.stored: try JSONEncoder().encode(stored)]
        #endif
        if let logLevel { pc[SbrProviderKey.logLevel] = logLevel }
        pc[SbrProviderKey.personalRules] = SbrPersonalRules.encode(rules)
        pc[SbrProviderKey.tunStack] = userspaceTCP ? "gvisor" : "system"
        proto.providerConfiguration = pc
        Sbr.applyLeakProtection(to: proto, enabled: strict, allowLocalNetwork: allowLocalNetwork)
        m.protocolConfiguration = proto
        m.localizedDescription = "sbr"
        m.isEnabled = true
        m.onDemandRules = autoConnect ? OnDemand.rules(trusted: trustedNetworks) : nil
        m.isOnDemandEnabled = autoConnect && (onDemand ?? (manager == nil || m.isOnDemandEnabled))
        try await m.saveToPreferences()
        // A freshly saved manager must be reloaded before it can start.
        try await m.loadFromPreferences()
        manager = m
        installFailed = false
        observeStatus()
    }

    /// Remove the VPN configuration and everything the app remembers about
    /// it: settings, personal rules, trusted networks and the saved logs. A
    /// running tunnel first deletes its own files (`SbrRequest.erase`).
    func erase() async {
        config = nil
        remote = nil
        stored = nil
        if isConnected, let session { _ = try? await session.send(.erase) }
        for m in (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? [] {
            m.connection.stopVPNTunnel()
            do {
                try await m.removeFromPreferences()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
        #if os(macOS)
        if [.enabled, .requiresApproval].contains(SMAppService.mainApp.status) {
            do {
                try await SMAppService.mainApp.unregister()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
        #endif
        if let statusObserver { NotificationCenter.default.removeObserver(statusObserver) }
        statusObserver = nil
        manager = nil
        installFailed = false
        status = .invalid
        groups = []
        stats = nil
        connections = []
        connectionsTotal = 0
        lastStop = nil
        rules = []
        trustedNetworks = []
        strictChoice = nil
        profileStrict = false
        allowLocalNetwork = false
        logs = []
        if let url = Self.logsURL { try? FileManager.default.removeItem(at: url) }
        URLCache.shared.removeAllCachedResponses()
        if let domain = Bundle.main.bundleIdentifier { UserDefaults.standard.removePersistentDomain(forName: domain) }
        TunnelControl.reloadControl()
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
                let previous = self.status
                self.status = connection.status
                TunnelControl.reloadControl()
                if connection.status != .connected { self.groups = [] }
                if connection.status == .connecting { self.lastStop = nil }
                if connection.status == .disconnected, previous != .disconnecting, previous != .disconnected {
                    self.lastStop = await Self.disconnectReason(connection)
                }
            }
        }
    }
}

extension TunnelModel {
    /// The system's account of an unrequested stop: the extension crashed,
    /// was killed for memory, another VPN took over, and so on.
    static func disconnectReason(_ connection: NEVPNConnection) async -> String {
        let error: Error? = await withCheckedContinuation { c in
            connection.fetchLastDisconnectError { c.resume(returning: $0) }
        }
        guard let error else { return "stopped unexpectedly" }
        let ns = error as NSError
        return "stopped: \(ns.localizedDescription.lowercased()) (\(ns.domain) \(ns.code))"
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
