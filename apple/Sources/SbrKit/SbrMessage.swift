import Foundation
import NetworkExtension

/// App → tunnel requests over `NETunnelProviderSession.sendProviderMessage`.
public enum SbrRequest: Codable, Sendable {
    case groups
    case select(group: String, member: String)
    /// Start a latency test of a group; poll `.groups` for the results.
    case urlTest(group: String)
    case stats
    /// The newest open connections (at most 200).
    case connections
    /// Close one connection; answers with the connections left.
    case closeConnection(id: String)
    /// The extension's recent log lines (memory only).
    case logs
    /// Run this config (a no-op when it is already running), or re-read the
    /// saved one when nil. The app also saves it into `providerConfiguration`
    /// so a restart uses it. With a config, `remote` and `logLevel` replace
    /// the tunnel's: nil `remote` stops background refresh. `rules` replaces
    /// the personal rules; connections to domains whose route changed close.
    case reload(config: String?, remote: SbrRemoteProfile? = nil, logLevel: String? = nil,
                rules: [SbrPersonalRule]? = nil)
    /// The remote profile the tunnel last downloaded itself, if any.
    case profile
}

/// A remote profile the tunnel keeps fresh by itself. The URL usually
/// carries credentials: never log it.
public struct SbrRemoteProfile: Codable, Sendable, Hashable {
    public var url: URL
    /// sing-box's `auto_update_interval`: 60 by default.
    public var refreshMinutes: Int
    /// When the config handed to the tunnel was downloaded.
    public var updated: Date?

    public init(url: URL, refreshMinutes: Int = 60, updated: Date? = nil) {
        self.url = url
        self.refreshMinutes = refreshMinutes
        self.updated = updated
    }
}

/// A remote profile as the tunnel downloaded and validated it.
public struct SbrProfileSnapshot: Codable, Sendable, Hashable {
    public var url: URL
    public var text: String
    public var updated: Date

    public init(url: URL, text: String, updated: Date) {
        self.url = url
        self.text = text
        self.updated = updated
    }
}

public struct SbrResponse: Codable, Sendable {
    public var groups: [SbrGroup]?
    public var stats: SbrStats?
    public var logs: [String]?
    public var profile: SbrProfileSnapshot?
    public var connections: SbrConnections?
    public var error: String?

    public init(
        groups: [SbrGroup]? = nil,
        stats: SbrStats? = nil,
        logs: [String]? = nil,
        profile: SbrProfileSnapshot? = nil,
        connections: SbrConnections? = nil,
        error: String? = nil
    ) {
        self.groups = groups
        self.stats = stats
        self.logs = logs
        self.profile = profile
        self.connections = connections
        self.error = error
    }
}

extension NETunnelProviderSession {
    /// Ask the running tunnel something. Throws if it isn't running or
    /// doesn't answer.
    public func send(_ request: SbrRequest) async throws -> SbrResponse {
        let data = try JSONEncoder().encode(request)
        let reply: Data = try await withCheckedThrowingContinuation { cont in
            do {
                try sendProviderMessage(data) { reply in
                    if let reply {
                        cont.resume(returning: reply)
                    } else {
                        cont.resume(throwing: SbrError("the tunnel did not answer"))
                    }
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
        let response = try JSONDecoder().decode(SbrResponse.self, from: reply)
        if let error = response.error { throw SbrError(error) }
        return response
    }
}
