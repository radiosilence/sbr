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
    /// Reload with this config, or re-read the saved one when nil. The app
    /// also saves it into `providerConfiguration` so a restart uses it.
    case reload(config: String?)
}

public struct SbrResponse: Codable, Sendable {
    public var groups: [SbrGroup]?
    public var stats: SbrStats?
    public var logs: [String]?
    public var connections: SbrConnections?
    public var error: String?

    public init(
        groups: [SbrGroup]? = nil,
        stats: SbrStats? = nil,
        logs: [String]? = nil,
        connections: SbrConnections? = nil,
        error: String? = nil
    ) {
        self.groups = groups
        self.stats = stats
        self.logs = logs
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
