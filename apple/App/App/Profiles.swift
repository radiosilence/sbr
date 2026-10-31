import Foundation
import SbrKit

/// A sing-box config the user can switch to. Remote profiles keep their URL.
/// The active one is refreshed by the running tunnel itself (see
/// `SbrPacketTunnelProvider`); the rest, and the active one while the tunnel
/// is off, refresh when the app comes to the front and they're stale.
struct Profile: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String
    /// A bearer link: stored with the config in the profile's Keychain item,
    /// never encoded into the index. Decoded only from a pre-Keychain index.
    var remoteURL: URL?
    var updated: Date?
    /// sing-box's default remote-profile interval.
    var autoUpdateMinutes = 60

    var isStale: Bool {
        guard remoteURL != nil else { return false }
        guard let updated else { return true }
        return Date().timeIntervalSince(updated) > Double(autoUpdateMinutes) * 60
    }

    private enum CodingKeys: String, CodingKey { case id, name, remoteURL, updated, autoUpdateMinutes }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encodeIfPresent(updated, forKey: .updated)
        try c.encode(autoUpdateMinutes, forKey: .autoUpdateMinutes)
    }
}

/// What a sing-box / sbr import link asks for.
struct ProfileLink {
    var url: URL
    var name: String?

    /// `sing-box://import-remote-profile?url=<encoded>#<name>` (and the same
    /// under `sbr://`), or a bare http(s) URL to a JSON profile.
    init?(_ link: URL) {
        switch link.scheme?.lowercased() {
        case "sing-box", "sbr":
            guard link.host == "import-remote-profile",
                  let raw = URLComponents(url: link, resolvingAgainstBaseURL: false)?
                  .queryItems?.first(where: { $0.name == "url" })?.value,
                  let url = URL(string: raw), url.scheme?.lowercased() == "https"
            else { return nil }
            self.url = url
            self.name = link.fragment?.removingPercentEncoding
        case "https":
            self.url = link
            self.name = link.fragment?.removingPercentEncoding
        default:
            return nil
        }
    }
}

/// Profiles live in the Keychain, in the access group the app shares with
/// its tunnel: an index of names and refresh times, and per profile an
/// `SbrProfileSecret` holding the whole config and its remote URL. Items are
/// device-only and readable after first unlock, so they never reach iCloud or
/// a computer backup, or a device restored from one. The tunnel reads the
/// active profile's item itself (`SbrStoredProfile`), so the VPN preferences
/// carry no credentials. It keeps its own download of the active profile,
/// which the app asks for over the provider message channel (`adopt`).
@MainActor
final class ProfileStore: ObservableObject {
    @Published private(set) var profiles: [Profile] = []
    @Published private(set) var activeID: UUID?
    @Published private(set) var refreshing: Set<UUID> = []
    /// The active profile's config, for the tunnel.
    @Published private(set) var activeText: String? {
        didSet { if activeText != oldValue { activeWarnings = activeText.map(Sbr.warnings) ?? [] } }
    }
    /// `Sbr.warnings` for the active profile.
    @Published private(set) var activeWarnings: [String] = []

    private let keychain = SbrKeychain(accessGroup: AppConfig.keychainGroup)
    private static let indexAccount = "index"

    private struct Index: Codable {
        var profiles: [Profile]
        var active: UUID?
    }

    var active: Profile? { profiles.first { $0.id == activeID } }

    /// The active profile's source, for the tunnel to refresh it from.
    var activeRemote: SbrRemoteProfile? {
        guard let p = active, let url = p.remoteURL else { return nil }
        return SbrRemoteProfile(url: url, refreshMinutes: p.autoUpdateMinutes, updated: p.updated)
    }

    /// The Keychain item for the active profile, which the tunnel reads.
    var activeStored: SbrStoredProfile? {
        guard let p = active, let group = AppConfig.keychainGroup else { return nil }
        return SbrStoredProfile(accessGroup: group, id: p.id.uuidString, refreshMinutes: p.autoUpdateMinutes,
                                updated: p.updated)
    }

    func load() {
        migrate()
        guard let index = try? keychain.value(Index.self, Self.indexAccount) else { return }
        profiles = index.profiles.map { p in
            var p = p
            p.remoteURL = (try? secret(p.id))?.url
            return p
        }
        activeID = index.active
        activeText = active.flatMap { try? text(of: $0) }
    }

    /// Download again any remote profile whose config is missing: one whose
    /// purged tvOS cache file left only its URL to move to the Keychain.
    func restore() async {
        for p in profiles where p.remoteURL != nil && (try? text(of: p)) == nil {
            guard let url = p.remoteURL, let text = try? await fetch(url) else { continue }
            guard (try? write(p, text: text)) != nil else { continue }
            if p.id == activeID { activeText = text }
        }
    }

    /// Download a remote profile, validate it with the tunnel's own parser,
    /// and add it. Returns the new profile.
    @discardableResult
    func add(remote url: URL, name: String?) async throws -> Profile {
        let text = try await fetch(url)
        var profile = Profile(name: name ?? Self.defaultName(for: url), remoteURL: url, updated: Date())
        if let existing = profiles.first(where: { $0.remoteURL == url }) {
            profile.id = existing.id
            profile.name = name ?? existing.name
        }
        try write(profile, text: text)
        return profile
    }

    /// A pasted, scanned or typed link: `sing-box://`, `sbr://` or https.
    @discardableResult
    func add(link raw: String) async throws -> Profile {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed), let link = ProfileLink(url) else {
            throw SbrError("that isn't a profile link. it should start with https://, sing-box:// or sbr://")
        }
        return try await add(remote: link.url, name: link.name)
    }

    /// A profile file picked with the system file importer.
    @discardableResult
    func add(file url: URL) throws -> Profile {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let text = try String(contentsOf: url, encoding: .utf8)
        return try add(text: text, name: url.deletingPathExtension().lastPathComponent)
    }

    @discardableResult
    func add(text: String, name: String) throws -> Profile {
        let profile = Profile(name: name)
        try write(profile, text: text)
        return profile
    }

    func text(of profile: Profile) throws -> String {
        guard let config = try secret(profile.id)?.config else { throw SbrError("this profile has not been downloaded") }
        return config
    }

    /// Make `profile` the one the tunnel runs.
    func activate(_ profile: Profile) throws {
        activeText = try text(of: profile)
        activeID = profile.id
        try saveIndex()
    }

    func remove(_ profile: Profile) {
        try? keychain.remove(SbrProfileSecret.account(profile.id.uuidString))
        profiles.removeAll { $0.id == profile.id }
        if activeID == profile.id {
            // The tunnel's own download of it.
            try? keychain.remove(SbrProfileSnapshot.account)
            activeID = nil
            activeText = nil
        }
        try? saveIndex()
    }

    /// Re-download one remote profile. Returns true when the active profile's
    /// content changed (the caller reloads a running tunnel).
    @discardableResult
    func refresh(_ profile: Profile) async throws -> Bool {
        guard let url = profile.remoteURL else { return false }
        refreshing.insert(profile.id)
        defer { refreshing.remove(profile.id) }
        let text = try await fetch(url)
        let before = try? self.text(of: profile)
        var updated = profile
        updated.updated = Date()
        try write(updated, text: text)
        guard profile.id == activeID, before != text else { return false }
        activeText = text
        return true
    }

    /// Refresh every stale remote profile but `except` (the active one while
    /// the tunnel refreshes it). Run when the app comes to the front: no
    /// background timers.
    func refreshStale(except: UUID? = nil) async -> Bool {
        var activeChanged = false
        for p in profiles where p.isStale && p.id != except {
            if (try? await refresh(p)) == true { activeChanged = true }
        }
        return activeChanged
    }

    /// Store the tunnel's own download of the active profile when it is newer
    /// than ours. Validated again before it is written.
    func adopt(_ snapshot: SbrProfileSnapshot) {
        guard var p = active, p.remoteURL == snapshot.url,
              snapshot.updated > (p.updated ?? .distantPast)
        else { return }
        p.updated = snapshot.updated
        guard (try? write(p, text: snapshot.text)) != nil else { return }
        if activeText != snapshot.text { activeText = snapshot.text }
    }

    /// No disk cache (the response carries credentials), no cookies, and no
    /// User-Agent: CFNetwork's default names the app and its build.
    private static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.httpAdditionalHeaders = ["User-Agent": ""]
        c.urlCache = nil
        c.httpCookieStorage = nil
        c.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return URLSession(configuration: c)
    }()

    private func fetch(_ url: URL) async throws -> String {
        guard url.scheme?.lowercased() == "https" else { throw SbrError("profile links must use https") }
        let (data, response) = try await Self.session.data(from: url)
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw SbrError("download failed: HTTP \(http.statusCode)")
        }
        return String(decoding: data, as: UTF8.self)
    }

    private func write(_ profile: Profile, text: String) throws {
        if let problem = Sbr.check(config: text) { throw SbrError("this profile can't be used: \(problem)") }
        try keychain.set(value: SbrProfileSecret(config: text, url: profile.remoteURL),
                         for: SbrProfileSecret.account(profile.id.uuidString))
        if let i = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[i] = profile
        } else {
            profiles.append(profile)
        }
        if activeID == nil { try activate(profile) } else { try saveIndex() }
    }

    private func saveIndex() throws {
        try keychain.set(value: Index(profiles: profiles, active: activeID), for: Self.indexAccount)
    }

    private func secret(_ id: UUID) throws -> SbrProfileSecret? {
        try keychain.value(SbrProfileSecret.self, SbrProfileSecret.account(id.uuidString))
    }

    /// Delete every profile and everything else in the shared Keychain group
    /// (the tunnel's downloaded copy included).
    func eraseAll() throws {
        try keychain.removeAll()
        if let legacyDir { try? FileManager.default.removeItem(at: legacyDir) }
        profiles = []
        activeID = nil
        activeText = nil
        refreshing = []
    }

    // MARK: Pre-Keychain storage

    /// Where profiles were files: `index.json` and one JSON file per profile,
    /// in Application Support, or on tvOS in the caches directory with the
    /// index also in UserDefaults.
    private var legacyDir: URL? {
        #if os(tvOS)
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
        #else
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        #endif
        return base?.appendingPathComponent("profiles", isDirectory: true)
    }

    private static let legacyDefaultsKey = "profileIndex"

    /// Move file-based profiles into the Keychain, then delete the files. A
    /// remote profile whose file the system purged keeps its URL, for
    /// `restore`. On failure the files stay, and the next launch retries.
    private func migrate() {
        var data = legacyDir.flatMap { try? Data(contentsOf: $0.appendingPathComponent("index.json")) }
        #if os(tvOS)
        data = data ?? UserDefaults.standard.data(forKey: Self.legacyDefaultsKey)
        #endif
        guard let data, let legacy = try? JSONDecoder().decode(Index.self, from: data) else { return }
        do {
            var index = try keychain.value(Index.self, Self.indexAccount) ?? Index(profiles: [], active: nil)
            for p in legacy.profiles where !index.profiles.contains(where: { $0.id == p.id }) {
                let file = legacyDir?.appendingPathComponent("\(p.id.uuidString).json")
                let text = file.flatMap { try? String(contentsOf: $0, encoding: .utf8) }
                guard text != nil || p.remoteURL != nil else { continue }
                try keychain.set(value: SbrProfileSecret(config: text, url: p.remoteURL),
                                 for: SbrProfileSecret.account(p.id.uuidString))
                index.profiles.append(p)
            }
            if index.active == nil, index.profiles.contains(where: { $0.id == legacy.active }) {
                index.active = legacy.active
            }
            try keychain.set(value: index, for: Self.indexAccount)
        } catch {
            return
        }
        if let legacyDir { try? FileManager.default.removeItem(at: legacyDir) }
        UserDefaults.standard.removeObject(forKey: Self.legacyDefaultsKey)
    }

    private static func defaultName(for url: URL) -> String {
        if let fragment = url.fragment, !fragment.isEmpty { return fragment }
        return url.host ?? "profile"
    }
}
