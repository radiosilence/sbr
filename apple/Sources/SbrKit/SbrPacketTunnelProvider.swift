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
/// (`SbrRequest`) expose groups, selection, stats and reload.
open class SbrPacketTunnelProvider: NEPacketTunnelProvider {
    private static let subsystem = Bundle.main.bundleIdentifier ?? "sbr"
    public let logger = Logger(subsystem: SbrPacketTunnelProvider.subsystem, category: "tunnel")

    private let lock = NSLock()
    private var _core: Sbr?
    private var pathMonitor: NWPathMonitor?
    private let pathQueue = DispatchQueue(label: "sbr.path-monitor")
    private var lastPath: String? // only touched on pathQueue

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
        do {
            let config = try loadConfiguration()
            try await setTunnelNetworkSettings(try Sbr.tunnelNetworkSettings(config: config))
            // The utun exists once the settings are applied.
            guard let fd = Sbr.findTunFileDescriptor() else { throw SbrError("utun file descriptor not found") }
            var opts = coreOptions
            opts.tunFileDescriptor = fd
            if opts.baseDirectory == nil { opts.baseDirectory = appGroupDirectory ?? Self.privateDirectory }
            _ = swapCore(try Sbr(config: config, options: opts))
            startPathMonitor()
            logger.info("tunnel up on fd \(fd)")
        } catch {
            logger.error("start failed: \(error.localizedDescription, privacy: .private)")
            SbrRecentLogs.shared.append(.error, "start failed: \(error.localizedDescription)")
            throw error
        }
    }

    override open func stopTunnel(with reason: NEProviderStopReason) async {
        logger.info("stopping (reason \(reason.rawValue))")
        pathMonitor?.cancel()
        pathMonitor = nil
        swapCore(nil)?.stop()
    }

    override open func handleAppMessage(_ messageData: Data) async -> Data? {
        let response: SbrResponse
        do {
            let request = try JSONDecoder().decode(SbrRequest.self, from: messageData)
            response = try handle(request)
        } catch {
            response = SbrResponse(error: error.localizedDescription)
        }
        return try? JSONEncoder().encode(response)
    }

    /// Override to add requests; call super for the built-in ones.
    open func handle(_ request: SbrRequest) throws -> SbrResponse {
        if case .logs = request { return SbrResponse(logs: SbrRecentLogs.shared.snapshot()) }
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
        case .logs:
            return SbrResponse(logs: SbrRecentLogs.shared.snapshot())
        case let .reload(config):
            // Interface settings come from the tun inbound; if those changed,
            // the app should restart the tunnel instead.
            try core.reload(config: try config ?? loadConfiguration())
            return SbrResponse(groups: core.groups())
        }
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
    }

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            // Our own utun shows up as `.other`; only physical paths matter.
            let interfaces = path.availableInterfaces.filter { $0.type != .other }.map(\.name)
            let signature = path.status == .satisfied ? interfaces.joined(separator: ",") : "unsatisfied"
            defer { self.lastPath = signature }
            guard let last = self.lastPath, last != signature else { return } // first report, or no change
            self.logger.info("network changed: \(last, privacy: .public) -> \(signature, privacy: .public)")
            if path.status == .satisfied { self.core?.networkChanged() }
        }
        monitor.start(queue: pathQueue)
        pathMonitor = monitor
    }
}
