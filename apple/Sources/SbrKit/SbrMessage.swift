import Foundation
import NetworkExtension

/// App → tunnel requests over `NETunnelProviderSession.sendProviderMessage`.
public enum SbrRequest: Codable, Sendable {
    case groups
    case select(group: String, member: String)
    case stats
    /// Re-read the config (App Group / providerConfiguration) and reload.
    case reload
}

public struct SbrResponse: Codable, Sendable {
    public var groups: [SbrGroup]?
    public var stats: SbrStats?
    public var error: String?

    public init(groups: [SbrGroup]? = nil, stats: SbrStats? = nil, error: String? = nil) {
        self.groups = groups
        self.stats = stats
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
