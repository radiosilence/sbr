import Foundation
import SbrCore

public struct SbrError: Error, LocalizedError, CustomStringConvertible, Sendable {
    public let description: String
    public init(_ description: String) { self.description = description }
    public var errorDescription: String? { description }
}

public struct SbrGroup: Codable, Sendable, Hashable, Identifiable {
    public struct Member: Codable, Sendable, Hashable, Identifiable {
        public let tag: String
        public let type: String
        /// Last measured latency in milliseconds; nil when untested.
        public let delay: Int?
        /// Set when failover has dropped this member: why (`frozen`, `reset`,
        /// `closed`, `no_response`, `connect`) and seconds until it is retried.
        public let degraded: Bool?
        public let reason: String?
        public let retryIn: Int?
        public var id: String { tag }

        enum CodingKeys: String, CodingKey {
            case tag, type, delay, degraded, reason
            case retryIn = "retry_in"
        }
        public var isGroup: Bool { type == "selector" || type == "urltest" }
    }

    public let tag: String
    /// `selector` (picked by hand) or `urltest` (picks the fastest itself).
    public let type: String
    public let selected: String
    /// The leaf outbound traffic resolves to through nested groups.
    public let now: String
    public let delay: Int?
    public let members: [Member]
    public var id: String { tag }
    public var isSelectable: Bool { type == "selector" }
}

public struct SbrStats: Codable, Sendable, Hashable {
    /// Bytes jetsam charges the process (phys_footprint).
    public var memoryFootprint: UInt64
    /// Bytes left before jetsam (iOS/tvOS); 0 on macOS.
    public var memoryAvailable: UInt64
    public var activeConnections: UInt64
    public var udpSessions: UInt64
    /// Bytes relayed since start, live.
    public var uplinkBytes: UInt64
    public var downlinkBytes: UInt64
}

/// A running sbr core. Thread-safe; stopped by `stop()` or on release.
public final class Sbr: @unchecked Sendable {
    public struct Options: Sendable {
        /// Resolves relative paths in the config (local rule-sets).
        public var baseDirectory: URL?
        /// The utun fd from `Sbr.findTunFileDescriptor()`; nil for no TUN.
        public var tunFileDescriptor: Int32?
        /// 0: platform default (1 on iOS/tvOS). 1: single-threaded runtime.
        public var threads: Int32
        /// Per-direction relay buffer; 0: default (16 KiB iOS/tvOS, 64 KiB macOS).
        public var relayBufferBytes: UInt32
        /// Connection cap; nil: default (512 on iOS/tvOS, none on macOS); 0: none.
        public var maxConnections: UInt32?

        public init(
            baseDirectory: URL? = nil,
            tunFileDescriptor: Int32? = nil,
            threads: Int32 = 0,
            relayBufferBytes: UInt32 = 0,
            maxConnections: UInt32? = nil
        ) {
            self.baseDirectory = baseDirectory
            self.tunFileDescriptor = tunFileDescriptor
            self.threads = threads
            self.relayBufferBytes = relayBufferBytes
            self.maxConnections = maxConnections
        }
    }

    private let lock = NSLock()
    private var handle: OpaquePointer?

    public static var version: String { String(cString: sbr_version()) }

    /// nil when the config is valid, otherwise the error (with its JSON path).
    public static func check(config: String) -> String? {
        takeString(sbr_check(config))
    }

    /// The utun fd NetworkExtension opened for this process. Call after
    /// `setTunnelNetworkSettings` has completed.
    public static func findTunFileDescriptor() -> Int32? {
        let fd = sbr_find_tun_fd()
        return fd >= 0 ? fd : nil
    }

    public init(config: String, options: Options = Options()) throws {
        var o = sbr_start_options_default()
        o.tun_fd = options.tunFileDescriptor ?? -1
        o.threads = options.threads
        o.relay_buffer = options.relayBufferBytes
        if let m = options.maxConnections { o.max_connections = m }
        var err: UnsafeMutablePointer<CChar>?
        let h = withOptionalCString(options.baseDirectory?.path) { dir -> OpaquePointer? in
            o.base_dir = dir
            return sbr_start_ex(config, &o, &err)
        }
        if let message = Self.takeString(err) { throw SbrError(message) }
        guard let h else { throw SbrError("sbr_start_ex failed") }
        handle = h
    }

    deinit { stop() }

    /// Tear down every connection and the runtime. Blocks until done.
    public func stop() {
        lock.lock()
        defer { lock.unlock() }
        if let h = handle { sbr_stop(h) }
        handle = nil
    }

    /// Swap in a new config, keeping the TUN fd. An invalid config leaves
    /// the current one running.
    public func reload(config: String) throws {
        try withHandle { h in
            if let message = Self.takeString(sbr_reload(h, config)) { throw SbrError(message) }
        }
    }

    public enum Applied: Int32, Sendable {
        /// The same text is already running.
        case unchanged = 0
        case reloaded = 1
        /// Valid, but its tun inbound wants different interface settings:
        /// apply `tunnelNetworkSettings(config:)`, then `reload(config:)`.
        case needsNetworkSettings = 2
    }

    /// Run `config` unless it is already running. Validated first: an
    /// invalid config throws and leaves the current one running.
    public func apply(config: String) throws -> Applied {
        try withHandle { h in
            var err: UnsafeMutablePointer<CChar>?
            let r = sbr_apply_profile(h, config, &err)
            if let message = Self.takeString(err) { throw SbrError(message) }
            guard let applied = Applied(rawValue: r) else { throw SbrError("sbr_apply_profile failed") }
            return applied
        }
    }

    /// Download a remote profile (https only) through the running config's
    /// route rules, so it leaves through the tunnel's outbounds rather than
    /// the physical network, with no identifying headers. Not validated:
    /// hand the text to `apply(config:)`.
    public func fetchProfile(url: URL) async throws -> String {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
            let box = Unmanaged.passRetained(FetchBox(cont)).toOpaque()
            let started = (try? withHandle { h in
                sbr_fetch_profile(h, url.absoluteString, { context, profile, error in
                    guard let context else { return }
                    let box = Unmanaged<FetchBox>.fromOpaque(context).takeRetainedValue()
                    if let profile {
                        box.cont.resume(returning: String(cString: profile))
                    } else {
                        box.cont.resume(throwing: SbrError(error.map { String(cString: $0) } ?? "download failed"))
                    }
                }, box)
            }) ?? 0
            if started == 0 {
                Unmanaged<FetchBox>.fromOpaque(box).release()
                cont.resume(throwing: SbrError(
                    url.scheme?.lowercased() == "https" ? "sbr is not running" : "profile links must use https"
                ))
            }
        }
    }

    @discardableResult
    public func select(group: String, member: String) -> Bool {
        (try? withHandle { sbr_select($0, group, member) == 1 }) ?? false
    }

    public func groups() -> [SbrGroup] {
        guard let json = try? withHandle({ Self.takeString(sbr_groups($0)) }) ?? nil else { return [] }
        return (try? JSONDecoder().decode([SbrGroup].self, from: Data(json.utf8))) ?? []
    }

    /// Start a latency test of a group; results show up in `groups()`.
    @discardableResult
    public func urlTest(group: String) -> Bool {
        (try? withHandle { sbr_url_test($0, group) == 1 }) ?? false
    }

    public func stats() -> SbrStats {
        var s = SbrRuntimeStats()
        lock.lock()
        sbr_runtime_stats(handle, &s) // NULL handle: memory figures only
        lock.unlock()
        return SbrStats(
            memoryFootprint: s.memory_footprint,
            memoryAvailable: s.memory_available,
            activeConnections: s.active_connections,
            udpSessions: s.udp_sessions,
            uplinkBytes: s.uplink_bytes,
            downlinkBytes: s.downlink_bytes
        )
    }

    /// Pin sbr's own sockets to a physical interface (`en0`, `pdp_ip0`), or
    /// unpin with nil. Process-wide.
    public static func setDefaultInterface(_ name: String?) {
        sbr_set_default_interface(name)
    }

    /// The default network path changed: drop state bound to the old one.
    public func networkChanged() {
        try? withHandle { sbr_network_changed($0) }
    }

    func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard let h = handle else { throw SbrError("sbr is stopped") }
        return try body(h)
    }

    static func takeString(_ p: UnsafeMutablePointer<CChar>?) -> String? {
        guard let p else { return nil }
        defer { sbr_string_free(p) }
        return String(cString: p)
    }
}

/// The continuation handed to `sbr_fetch_profile`, which calls back exactly
/// once; the callback takes the retain.
private final class FetchBox {
    let cont: CheckedContinuation<String, Error>
    init(_ cont: CheckedContinuation<String, Error>) { self.cont = cont }
}

private func withOptionalCString<R>(_ s: String?, _ body: (UnsafePointer<CChar>?) throws -> R) rethrows -> R {
    guard let s else { return try body(nil) }
    return try s.withCString(body)
}
