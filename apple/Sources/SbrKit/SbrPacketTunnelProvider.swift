import Foundation
import Network
import NetworkExtension
import os

/// A complete packet tunnel: subclass it (an empty subclass is enough) and
/// name the subclass as the extension's principal / provider class.
///
/// Start-up: read the sing-box config (`providerConfiguration["config"]`, or
/// `config.json` in the App Group named by `providerConfiguration["appGroup"]`),
/// derive `NEPacketTunnelNetworkSettings` from its `tun` inbound, apply them,
/// find the utun fd NetworkExtension created and start sbr on it. Path
/// changes and wake-ups reset path-bound state; app messages
/// (`SbrRequest`) expose groups, selection, stats, connections and reload.
///
/// With `providerConfiguration["remote"]` set, the tunnel refreshes that
/// profile itself on its interval: downloaded through its own outbounds
/// (`Sbr.fetchProfile`), validated, then hot-reloaded. A profile that fails
/// validation leaves the running config untouched. The last good download is
/// kept in the extension's container, survives restarts, and is what
/// `SbrRequest.profile` returns for the app to store.
open class SbrPacketTunnelProvider: NEPacketTunnelProvider {
    private static let subsystem = Bundle.main.bundleIdentifier ?? "sbr"
    public let logger = Logger(subsystem: SbrPacketTunnelProvider.subsystem, category: "tunnel")

    private let lock = NSLock()
    private var _core: Sbr?
    private var pathMonitor: NWPathMonitor?
    private let pathQueue = DispatchQueue(label: "sbr.path-monitor")
    private var lastPath: String? // only touched on pathQueue
    // Guarded by `lock`.
    private var remote: SbrRemoteProfile?
    private var logLevel: String?
    private var refreshTask: Task<Void, Never>?

    /// The running core, if any.
    public var core: Sbr? {
        lock.lock()
        defer { lock.unlock() }
        return _core
    }

    private func swapCore(_ new: Sbr?) -> Sbr? {
        lock.lock()
        defer { lock.unlock() }
        let old = _core
        _core = new
        return old
    }

    private var providerConfiguration: [String: Any] {
        (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
    }

    /// The App Group container, when the configuration names one. Relative
    /// paths in the config (rule-sets) resolve against it.
    open var appGroupDirectory: URL? {
        (providerConfiguration[SbrProviderKey.appGroup] as? String).flatMap { SbrConfigStore(appGroup: $0).directory }
    }

    /// The extension's own Application Support directory: where relative
    /// paths in the config (cache_file, local rule-sets) live when no App
    /// Group is configured.
    static var privateDirectory: URL? {
        guard let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        else { return nil }
        let sbr = dir.appendingPathComponent("sbr", isDirectory: true)
        try? FileManager.default.createDirectory(at: sbr, withIntermediateDirectories: true)
        return sbr
    }

    /// Override to load the config from somewhere else (Keychain, a server).
    open func loadConfiguration() throws -> String {
        if let inline = providerConfiguration[SbrProviderKey.config] as? String {
            return inline
        }
        if let group = providerConfiguration[SbrProviderKey.appGroup] as? String {
            return try SbrConfigStore(appGroup: group).load()
        }
        throw SbrError("no config: set providerConfiguration[\"config\"] or [\"appGroup\"]")
    }

    /// Override to tune the core (threads, buffers, connection cap). The TUN
    /// fd and, if unset, the base directory are filled in by the provider.
    open var coreOptions: Sbr.Options { Sbr.Options() }

    /// Set to true to see destinations in Console without a debug profile.
    open var publicLogMessages: Bool { false }

    override open func startTunnel(options: [String: NSObject]?) async throws {
        Sbr.forwardLogs(to: Logger(subsystem: Self.subsystem, category: "core"), publicMessages: publicLogMessages)
        logger.info("starting sbr \(Sbr.version, privacy: .public)")
        reportPreviousSession()
        do {
            let saved = Self.savedState(providerConfiguration)
            let (text, remote) = Self.newest(try loadConfiguration(), remote: saved.remote)
            setState(remote: remote, logLevel: saved.logLevel)
            let config = Self.withLogLevel(text, saved.logLevel, stack: tunStack)
            try await setTunnelNetworkSettings(try Sbr.tunnelNetworkSettings(config: config))
            // The utun exists once the settings are applied.
            guard let fd = Sbr.findTunFileDescriptor() else { throw SbrError("utun file descriptor not found") }
            var opts = coreOptions
            opts.tunFileDescriptor = fd
            if opts.baseDirectory == nil { opts.baseDirectory = appGroupDirectory ?? Self.privateDirectory }
            _ = swapCore(try Sbr(config: config, options: opts))
            startPathMonitor()
            scheduleRefresh()
            startHeartbeat()
            logger.info("tunnel up on fd \(fd)")
        } catch {
            logger.error("start failed: \(error.localizedDescription, privacy: .private)")
            SbrRecentLogs.shared.append(.error, "start failed: \(error.localizedDescription)")
            throw error
        }
    }

    override open func stopTunnel(with reason: NEProviderStopReason) async {
        logger.info("stopping (reason \(reason.rawValue))")
        heartbeat?.cancel()
        heartbeat = nil
        if let url = Self.heartbeatURL { try? FileManager.default.removeItem(at: url) }
        // The system stopping us (rather than the user, sleep or an update)
        // reads as "plugin failed" in the app; keep the reason for next start.
        if ![.userInitiated, .providerDisabled, .configurationDisabled, .configurationRemoved, .sleep, .appUpdate,
             .userLogout, .userSwitch].contains(reason)
        {
            let mb = Double(core?.stats().memoryFootprint ?? 0) / 1_048_576
            Self.recordEnd(String(format: "stopped by the system: %@ (reason %d) with %.1f MB in use",
                                  Self.describe(reason), reason.rawValue, mb))
        }
        pathMonitor?.cancel()
        pathMonitor = nil
        setState(remote: nil, logLevel: nil)
        scheduleRefresh()
        swapCore(nil)?.stop()
    }

    override open func handleAppMessage(_ messageData: Data) async -> Data? {
        let response: SbrResponse
        do {
            let request = try JSONDecoder().decode(SbrRequest.self, from: messageData)
            response = try await handle(request)
        } catch {
            response = SbrResponse(error: error.localizedDescription)
        }
        return try? JSONEncoder().encode(response)
    }

    /// Override to add requests; call super for the built-in ones.
    open func handle(_ request: SbrRequest) async throws -> SbrResponse {
        if case .logs = request { return SbrResponse(logs: SbrRecentLogs.shared.snapshot()) }
        if case .profile = request {
            let current = state.remote
            return SbrResponse(profile: Self.loadSnapshot().flatMap { $0.url == current?.url ? $0 : nil })
        }
        guard let core else { throw SbrError("sbr is not running") }
        switch request {
        case .groups:
            return SbrResponse(groups: core.groups())
        case let .select(group, member):
            guard core.select(group: group, member: member) else {
                throw SbrError("no member \(member) in group \(group)")
            }
            return SbrResponse(groups: core.groups())
        case let .urlTest(group):
            core.urlTest(group: group)
            return SbrResponse(groups: core.groups())
        case .stats:
            return SbrResponse(stats: core.stats())
        case .connections:
            return SbrResponse(connections: core.connections())
        case let .closeConnection(id):
            core.closeConnection(id: id)
            return SbrResponse(connections: core.connections())
        case .logs:
            return SbrResponse(logs: SbrRecentLogs.shared.snapshot())
        case .profile:
            return SbrResponse()
        case let .reload(config, remote, logLevel):
            let saved = config == nil ? Self.savedState(providerConfiguration) : (remote: remote, logLevel: logLevel)
            // A copy the tunnel downloaded after the app's wins: the app may
            // not have picked it up yet.
            let (text, newest) = Self.newest(try config ?? loadConfiguration(), remote: saved.remote)
            try await run(text, logLevel: saved.logLevel)
            setState(remote: newest, logLevel: saved.logLevel)
            scheduleRefresh()
            return SbrResponse(groups: core.groups())
        }
    }

    /// Run `config` on the core: validated first, a no-op when unchanged, and
    /// new interface settings applied when its tun inbound asks for them.
    private func run(_ config: String, logLevel: String?) async throws {
        guard let core else { throw SbrError("sbr is not running") }
        let config = Self.withLogLevel(config, logLevel, stack: tunStack)
        if try core.apply(config: config) == .needsNetworkSettings {
            try await setTunnelNetworkSettings(try Sbr.tunnelNetworkSettings(config: config))
            try core.reload(config: config)
        }
    }

    // MARK: Remote profile refresh

    private var state: (remote: SbrRemoteProfile?, logLevel: String?) {
        lock.lock()
        defer { lock.unlock() }
        return (remote, logLevel)
    }

    private func setState(remote: SbrRemoteProfile?, logLevel: String?) {
        lock.lock()
        defer { lock.unlock() }
        self.remote = remote
        self.logLevel = logLevel
    }

    /// Re-arm the refresh timer from the profile's `updated` time: one sleep,
    /// no polling. `retryIn` overrides it after a failed attempt.
    private func scheduleRefresh(retryIn: TimeInterval? = nil) {
        lock.lock()
        defer { lock.unlock() }
        refreshTask?.cancel()
        refreshTask = nil
        guard let remote else { return }
        let interval = Double(max(remote.refreshMinutes, 5)) * 60
        let due = retryIn ?? (remote.updated ?? .distantPast).addingTimeInterval(interval).timeIntervalSinceNow
        refreshTask = Task { [weak self] in
            if due > 0 { try? await Task.sleep(nanoseconds: UInt64(due * 1_000_000_000)) }
            guard !Task.isCancelled, let self else { return }
            await self.refreshRemote()
        }
    }

    private func refreshRemote() async {
        guard let core, let remote = state.remote else { return }
        let text: String
        do {
            text = try await core.fetchProfile(url: remote.url)
        } catch {
            logger.error("profile refresh failed: \(error.localizedDescription, privacy: .private)")
            SbrRecentLogs.shared.append(.warn, "profile refresh failed: \(error.localizedDescription)")
            scheduleRefresh(retryIn: 5 * 60)
            return
        }
        do {
            try await run(text, logLevel: state.logLevel)
        } catch {
            // The error can quote the profile; keep it out of the app's log view.
            logger.error("downloaded profile rejected: \(error.localizedDescription, privacy: .private)")
            SbrRecentLogs.shared.append(.warn, "downloaded profile is invalid; keeping the running one")
            scheduleRefresh(retryIn: 5 * 60)
            return
        }
        let now = Date()
        Self.saveSnapshot(SbrProfileSnapshot(url: remote.url, text: text, updated: now))
        lock.lock()
        if self.remote?.url == remote.url { self.remote?.updated = now }
        lock.unlock()
        logger.info("profile refreshed")
        SbrRecentLogs.shared.append(.info, "profile refreshed")
        scheduleRefresh()
    }

    private static func savedState(_ pc: [String: Any]) -> (remote: SbrRemoteProfile?, logLevel: String?) {
        let remote = (pc[SbrProviderKey.remote] as? Data).flatMap {
            try? JSONDecoder().decode(SbrRemoteProfile.self, from: $0)
        }
        return (remote, pc[SbrProviderKey.logLevel] as? String)
    }

    /// `config` for `remote`, or the tunnel's own later download of it.
    private static func newest(_ config: String, remote: SbrRemoteProfile?) -> (String, SbrRemoteProfile?) {
        guard var remote, let snap = loadSnapshot(), snap.url == remote.url,
              snap.updated > (remote.updated ?? .distantPast)
        else { return (config, remote) }
        remote.updated = snap.updated
        return (snap.text, remote)
    }

    /// The config with its `log.level` replaced; unchanged if `level` is nil
    /// or the config isn't plain JSON.
    static func withLogLevel(_ config: String, _ level: String?, stack: String? = nil) -> String {
        guard level != nil || stack != nil,
              var root = (try? JSONSerialization.jsonObject(with: Data(config.utf8))) as? [String: Any]
        else { return config }
        if let level {
            var log = root["log"] as? [String: Any] ?? [:]
            log["level"] = level
            root["log"] = log
        }
        if let stack, var inbounds = root["inbounds"] as? [[String: Any]] {
            for i in inbounds.indices where inbounds[i]["type"] as? String == "tun" {
                inbounds[i]["stack"] = stack
            }
            root["inbounds"] = inbounds
        }
        guard let data = try? JSONSerialization.data(withJSONObject: root) else { return config }
        return String(decoding: data, as: UTF8.self)
    }

    private static var snapshotURL: URL? { privateDirectory?.appendingPathComponent("remote-profile.json") }

    private static func loadSnapshot() -> SbrProfileSnapshot? {
        guard let url = snapshotURL, let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(SbrProfileSnapshot.self, from: data)
    }

    /// Holds server credentials: protected until first unlock, out of backups.
    private static func saveSnapshot(_ snapshot: SbrProfileSnapshot) {
        guard var url = snapshotURL, let data = try? JSONEncoder().encode(snapshot) else { return }
        try? data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }

    /// The device is going to sleep. An idle sbr arms no timers, so there's
    /// nothing to pause; return promptly so sleep isn't delayed.
    override open func sleep() async {
        logger.debug("sleep")
    }

    /// Back from sleep: NAT mappings for UDP flows have likely expired and
    /// the path may differ, so drop path-bound state like a network change.
    override open func wake() {
        logger.debug("wake")
        core?.networkChanged()
        // The refresh sleep may have been suspended along with the extension.
        scheduleRefresh()
    }

    // MARK: Previous-session report

    private var heartbeat: Task<Void, Never>?
    private static var crashURL: URL? { privateDirectory?.appendingPathComponent("crash.log") }
    private static var heartbeatURL: URL? { privateDirectory?.appendingPathComponent("heartbeat") }

    /// The last process's crash breadcrumbs, or, if it left none but never
    /// stopped cleanly, its last heartbeat: a memory kill leaves no other trace.
    private func reportPreviousSession() {
        let fm = FileManager.default
        var abnormal = false
        if let url = Self.endURL, let end = try? String(contentsOf: url, encoding: .utf8) {
            SbrRecentLogs.shared.append(.error, "previous session \(end)")
            try? fm.removeItem(at: url)
            abnormal = true
        }
        if let url = Self.crashURL {
            let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            let lines = text.split(separator: "\n").suffix(5)
            for line in lines {
                SbrRecentLogs.shared.append(.error, "previous session: \(line)")
            }
            try? fm.removeItem(at: url)
            Sbr.setCrashFile(url)
            abnormal = abnormal || !lines.isEmpty
        }
        if let url = Self.heartbeatURL, let beat = try? String(contentsOf: url, encoding: .utf8) {
            if !abnormal {
                SbrRecentLogs.shared.append(.warn, "previous session ended without stopping; last seen \(beat)")
            }
            try? fm.removeItem(at: url)
            abnormal = true
        }
        // What the tunnel was doing just before, oldest first.
        if let url = Self.recentURL {
            if abnormal, let text = try? String(contentsOf: url, encoding: .utf8) {
                for line in text.split(separator: "\n") {
                    SbrRecentLogs.shared.append(.info, "prev │ \(line)")
                }
            }
            try? fm.removeItem(at: url)
        }
    }

    private static var endURL: URL? { privateDirectory?.appendingPathComponent("end") }
    private static var recentURL: URL? { privateDirectory?.appendingPathComponent("recent.log") }

    private static func recordEnd(_ text: String) {
        guard let url = endURL else { return }
        try? text.write(to: url, atomically: true, encoding: .utf8)
        saveRecent()
    }

    /// The last 40 log lines, so an abnormal end can show its lead-up.
    private static func saveRecent() {
        guard let url = recentURL else { return }
        let lines = SbrRecentLogs.shared.snapshot().suffix(40)
        try? lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
    }

    private static func describe(_ r: NEProviderStopReason) -> String {
        switch r {
        case .providerFailed: "provider failed"
        case .noNetworkAvailable: "no network"
        case .unrecoverableNetworkChange: "unrecoverable network change"
        case .authenticationCanceled: "authentication cancelled"
        case .configurationFailed: "configuration failed"
        case .idleTimeout: "idle timeout"
        case .superceded: "another vpn took over"
        case .connectionFailed: "connection failed"
        case .internalError: "internal error"
        default: "other"
        }
    }

    /// Every 10 s: the time and memory in use, overwritten in place.
    private func startHeartbeat() {
        heartbeat?.cancel()
        heartbeat = Task { [weak self] in
            let clock = ISO8601DateFormatter()
            while !Task.isCancelled {
                if let self, let url = Self.heartbeatURL, let core = self.core {
                    let mb = Double(core.stats().memoryFootprint) / 1_048_576
                    let beat = String(format: "%@ with %.1f MB in use", clock.string(from: Date()), mb)
                    try? beat.write(to: url, atomically: true, encoding: .utf8)
                    Self.saveRecent()
                }
                try? await Task.sleep(nanoseconds: 10_000_000_000)
            }
        }
    }

    private var tunStack: String? {
        (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?[SbrProviderKey.tunStack] as? String
    }

    private var includeAllNetworks: Bool {
        #if os(tvOS)
        false
        #else
        (protocolConfiguration as? NETunnelProviderProtocol)?.includeAllNetworks ?? false
        #endif
    }

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            // Our own utun shows up as `.other`; only physical paths matter.
            let interfaces = path.availableInterfaces.filter { $0.type != .other }.map(\.name)
            let signature = path.status == .satisfied ? interfaces.joined(separator: ",") : "unsatisfied"
            defer { self.lastPath = signature }
            // With includeAllNetworks the extension's own sockets aren't
            // reliably exempt from its tunnel, so pin them to the physical
            // path, as desktop auto_route does.
            if self.includeAllNetworks, path.status == .satisfied {
                Sbr.setDefaultInterface(interfaces.first)
                if self.lastPath == nil { self.core?.networkChanged() }
            }
            guard let last = self.lastPath, last != signature else { return } // first report, or no change
            self.logger.info("network changed: \(last, privacy: .public) -> \(signature, privacy: .public)")
            if path.status == .satisfied { self.core?.networkChanged() }
        }
        monitor.start(queue: pathQueue)
        pathMonitor = monitor
    }
}
