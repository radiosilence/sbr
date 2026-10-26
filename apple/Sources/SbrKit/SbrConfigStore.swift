import Foundation

/// Keys SbrKit reads from `NETunnelProviderProtocol.providerConfiguration`.
public enum SbrProviderKey {
    /// JSON-encoded `SbrStoredProfile`: the config, and the remote URL it is
    /// refreshed from, are read from the Keychain. Preferred, since the
    /// system keeps `providerConfiguration` on disk with the VPN preferences.
    public static let stored = "stored"
    /// Inline sing-box JSON, stored by the system with the VPN preferences.
    /// For a provider that cannot reach the app's Keychain, such as a macOS
    /// system extension, which runs as root.
    public static let config = "config"
    /// The tun inbound's `stack`, overriding the profile: `"gvisor"` for sbr's
    /// userspace TCP, `"system"` for the kernel's; absent leaves the profile's.
    public static let tunStack = "tunStack"
    /// App Group identifier whose container holds `config.json` (preferred:
    /// no size concerns, and rule-set files can sit next to it).
    public static let appGroup = "appGroup"
    /// JSON-encoded `SbrRemoteProfile`: the URL `config` came from, which the
    /// tunnel refreshes it from on its own.
    public static let remote = "remote"
    /// Replaces the config's `log.level` (for example "debug"), including in
    /// profiles the tunnel downloads itself.
    public static let logLevel = "logLevel"
    /// JSON-encoded `[SbrPersonalRule]`, put into every config the tunnel
    /// runs, including profiles it downloads itself.
    public static let personalRules = "personalRules"
}

/// The config file shared between the app and its tunnel extension through
/// an App Group container.
public struct SbrConfigStore: Sendable {
    public let appGroup: String
    public var fileName = "config.json"

    public init(appGroup: String) {
        self.appGroup = appGroup
    }

    /// The App Group container; also the base directory for relative paths
    /// in the config (local rule-sets).
    public var directory: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
    }

    public var configURL: URL? { directory?.appendingPathComponent(fileName) }

    public func load() throws -> String {
        guard let url = configURL else { throw SbrError("App Group \(appGroup) is not available (entitlement missing?)") }
        do {
            return try String(contentsOf: url, encoding: .utf8)
        } catch {
            throw SbrError("no config at \(url.path): \(error.localizedDescription)")
        }
    }

    /// Atomic write. Readable after first unlock, so on-demand / always-on
    /// tunnels can start before the user unlocks again.
    public func save(_ config: String) throws {
        guard let url = configURL else { throw SbrError("App Group \(appGroup) is not available (entitlement missing?)") }
        try Data(config.utf8).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
