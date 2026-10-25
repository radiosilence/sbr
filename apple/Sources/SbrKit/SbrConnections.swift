import Foundation
import SbrCore

/// The tunnel's open connections, newest first (`sbr_connections`).
public struct SbrConnections: Codable, Sendable, Hashable {
    /// Every open connection; `connections` lists at most 200 of them.
    public var total: Int
    /// Bytes since start, including closed connections.
    public var uploadTotal: UInt64
    public var downloadTotal: UInt64
    public var connections: [SbrConnection]

    enum CodingKeys: String, CodingKey {
        case total, connections
        case uploadTotal = "upload_total"
        case downloadTotal = "download_total"
    }
}

/// One TCP stream or UDP session.
public struct SbrConnection: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    /// `tcp` or `udp`.
    public let network: String
    /// `type/tag`, e.g. `tun/tun-in`.
    public let inbound: String
    public let source: String
    /// The address as requested: `host:port`.
    public let destination: String
    /// The requested or sniffed domain.
    public let domain: String?
    /// The resolved address, when known.
    public let ip: String?
    /// The sniffed protocol (`tls`, `http`, `quic`, ...).
    public let sniffedProtocol: String?
    /// Outbound tags from the leaf that carries the traffic to the one the
    /// rule chose.
    public let chain: [String]
    /// `payload => action`, or `final`.
    public let rule: String
    public let upload: UInt64
    public let download: UInt64
    /// Unix milliseconds.
    public let start: Int64

    enum CodingKeys: String, CodingKey {
        case id, network, inbound, source, destination, domain, ip, chain, rule, upload, download, start
        case sniffedProtocol = "protocol"
    }

    public var startDate: Date { Date(timeIntervalSince1970: Double(start) / 1000) }

    /// What to call it: the domain, else the address.
    public var host: String { domain ?? ip ?? destination }
}

extension Sbr {
    /// The newest open connections, at most `limit` (capped at 200).
    public func connections(limit: UInt32 = 200) -> SbrConnections? {
        guard let json = try? withHandle({ Self.takeString(sbr_connections($0, limit)) }) ?? nil else { return nil }
        return try? JSONDecoder().decode(SbrConnections.self, from: Data(json.utf8))
    }

    /// Close a connection by its `id`; false if it had already gone.
    @discardableResult
    public func closeConnection(id: String) -> Bool {
        (try? withHandle { sbr_close_connection($0, id) == 1 }) ?? false
    }
}
