import Foundation
import SbrCore

public struct SbrError: Error, CustomStringConvertible {
    public let description: String
}

public struct SbrGroup: Decodable, Sendable {
    public let tag: String
    public let type: String
    public let selected: String
    public let members: [String]
}

/// A running sbr core. Thread-safe; stop it by releasing it or calling `stop()`.
public final class Sbr: @unchecked Sendable {
    private var handle: OpaquePointer?

    /// Returns nil when the config is valid, otherwise the error (with JSON path).
    public static func check(config: String) -> String? {
        guard let p = sbr_check(config) else { return nil }
        defer { sbr_string_free(p) }
        return String(cString: p)
    }

    public init(config: String, baseDirectory: URL? = nil) throws {
        var err: UnsafeMutablePointer<CChar>?
        let h = sbr_start(config, baseDirectory?.path, &err)
        if let err {
            defer { sbr_string_free(err) }
            throw SbrError(description: String(cString: err))
        }
        handle = h
    }

    deinit { stop() }

    public func stop() {
        if let h = handle { sbr_stop(h) }
        handle = nil
    }

    @discardableResult
    public func select(group: String, member: String) -> Bool {
        guard let h = handle else { return false }
        return sbr_select(h, group, member) == 1
    }

    public func groups() -> [SbrGroup] {
        guard let h = handle, let p = sbr_groups(h) else { return [] }
        defer { sbr_string_free(p) }
        return (try? JSONDecoder().decode([SbrGroup].self, from: Data(String(cString: p).utf8))) ?? []
    }

    public func stats() -> (up: UInt64, down: UInt64, active: UInt64) {
        var up: UInt64 = 0, down: UInt64 = 0, active: UInt64 = 0
        if let h = handle { sbr_stats(h, &up, &down, &active) }
        return (up, down, active)
    }
}
