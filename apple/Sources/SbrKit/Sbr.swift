import Foundation
import SbrCore

public struct SbrError: Error, LocalizedError, CustomStringConvertible, Sendable {
    public let description: String
    public init(_ description: String) { self.description = description }
    public var errorDescription: String? { description }
}

public struct SbrGroup: Codable, Sendable, Hashable, Identifiable {
    public let tag: String
    public let type: String
    public let selected: String
    public let members: [String]
    public var id: String { tag }
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

    @discardableResult
    public func select(group: String, member: String) -> Bool {
        (try? withHandle { sbr_select($0, group, member) == 1 }) ?? false
    }

    public func groups() -> [SbrGroup] {
        guard let json = try? withHandle({ Self.takeString(sbr_groups($0)) }) ?? nil else { return [] }
        return (try? JSONDecoder().decode([SbrGroup].self, from: Data(json.utf8))) ?? []
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

    /// The default network path changed: drop state bound to the old one.
    public func networkChanged() {
        try? withHandle { sbr_network_changed($0) }
    }

    private func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
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

private func withOptionalCString<R>(_ s: String?, _ body: (UnsafePointer<CChar>?) throws -> R) rethrows -> R {
    guard let s else { return try body(nil) }
    return try s.withCString(body)
}
