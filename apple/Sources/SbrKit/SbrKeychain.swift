import Foundation
import Security

/// Generic-password items in one Keychain access group, shared by the app and
/// its tunnel extension. Items are readable after the first unlock (so an
/// on-demand tunnel can start), never synchronised, and never leave the
/// device: they are not restored from a backup onto another one.
public struct SbrKeychain: Sendable {
    /// `<team prefix>.<identifier>`, as in the `keychain-access-groups`
    /// entitlement. Nil uses the process's default group.
    public let accessGroup: String?
    public let service: String
    /// The data protection Keychain, which honours access groups and
    /// accessibility on macOS. Off only for tests in an unsigned process.
    public var dataProtection = true

    public init(accessGroup: String?, service: String = "sbr") {
        self.accessGroup = accessGroup
        self.service = service
    }

    public func data(_ account: String) throws -> Data? {
        var query = base(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status, "read")
        return result as? Data
    }

    public func set(_ data: Data, for account: String) throws {
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(base(account) as CFDictionary, attributes as CFDictionary)
        if status != errSecItemNotFound { return try check(status, "update") }
        try check(SecItemAdd(base(account).merging(attributes) { $1 } as CFDictionary, nil), "add")
    }

    public func remove(_ account: String) throws {
        let status = SecItemDelete(base(account) as CFDictionary)
        if status != errSecItemNotFound { try check(status, "delete") }
    }

    /// Every account in this service and group.
    public func accounts() throws -> [String] {
        var query = base(nil)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        try check(status, "list")
        return (result as? [[String: Any]] ?? []).compactMap { $0[kSecAttrAccount as String] as? String }
    }

    /// Delete every item in this service and group.
    public func removeAll() throws {
        #if os(macOS)
        // The file-based macOS Keychain deletes one match per call.
        if !dataProtection {
            for account in try accounts() { try remove(account) }
            return
        }
        #endif
        let status = SecItemDelete(base(nil) as CFDictionary)
        if status != errSecItemNotFound { try check(status, "delete") }
    }

    public func value<T: Decodable>(_ type: T.Type, _ account: String) throws -> T? {
        try data(account).map { try JSONDecoder().decode(T.self, from: $0) }
    }

    public func set(value: some Encodable, for account: String) throws {
        try set(JSONEncoder().encode(value), for: account)
    }

    private func base(_ account: String?) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: false,
        ]
        if let account { q[kSecAttrAccount as String] = account }
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        if dataProtection { q[kSecUseDataProtectionKeychain as String] = true }
        return q
    }

    private func check(_ status: OSStatus, _ op: String) throws {
        guard status != errSecSuccess else { return }
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
        throw SbrError("keychain \(op) failed: \(message)")
    }
}

/// What makes a profile usable, and so what a seized device must not give up:
/// the config (servers, credentials, keys) and the link it came from, which
/// is itself a bearer credential. Stored whole in the Keychain.
public struct SbrProfileSecret: Codable, Sendable, Hashable {
    /// Nil while a remote profile waits to be downloaded again.
    public var config: String?
    public var url: URL?

    public init(config: String?, url: URL?) {
        self.config = config
        self.url = url
    }

    public static func account(_ id: String) -> String { "profile.\(id)" }
}

/// `providerConfiguration[SbrProviderKey.stored]`: which Keychain item holds
/// the tunnel's profile. Nothing secret, so the VPN preferences (which the
/// system keeps on disk) carry no server or credential.
public struct SbrStoredProfile: Codable, Sendable, Hashable {
    public var accessGroup: String
    public var id: String
    /// For a remote profile: its refresh interval and when the stored config
    /// was downloaded.
    public var refreshMinutes: Int
    public var updated: Date?

    public init(accessGroup: String, id: String, refreshMinutes: Int = 60, updated: Date? = nil) {
        self.accessGroup = accessGroup
        self.id = id
        self.refreshMinutes = refreshMinutes
        self.updated = updated
    }

    public var keychain: SbrKeychain { SbrKeychain(accessGroup: accessGroup) }

    public func secret() throws -> SbrProfileSecret {
        guard let secret = try keychain.value(SbrProfileSecret.self, SbrProfileSecret.account(id)) else {
            throw SbrError("the profile is not in the Keychain")
        }
        return secret
    }
}
