import Foundation
import SbrKit

/// A sing-box config the user can switch to. Remote profiles keep their URL
/// and refresh themselves when the app comes to the front and they're stale.
struct Profile: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String
    var remoteURL: URL?
    var updated: Date?
    /// sing-box's default remote-profile interval.
    var autoUpdateMinutes = 60

    var isStale: Bool {
        guard remoteURL != nil else { return false }
        guard let updated else { return true }
        return Date().timeIntervalSince(updated) > Double(autoUpdateMinutes) * 60
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
                  let url = URL(string: raw), url.scheme?.hasPrefix("http") == true
            else { return nil }
            self.url = url
            self.name = link.fragment?.removingPercentEncoding
        case "http", "https":
            self.url = link
            self.name = link.fragment?.removingPercentEncoding
        default:
            return nil
        }
    }
}

/// Profiles live in the app's own container (`Application Support/profiles`:
/// `index.json` plus one JSON file per profile), protected until first
/// unlock. The tunnel never reads them: the app hands it the active
/// profile's text inside the VPN configuration (see `TunnelModel.apply`), so
/// no shared container holds every profile's credentials.
@MainActor
final class ProfileStore: ObservableObject {
    @Published private(set) var profiles: [Profile] = []
    @Published private(set) var activeID: UUID?
    @Published private(set) var refreshing: Set<UUID> = []
    /// The active profile's config, for the tunnel.
    @Published private(set) var activeText: String?

    private var dir: URL? {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("profiles", isDirectory: true)
    }
    private var indexURL: URL? { dir?.appendingPathComponent("index.json") }

    private struct Index: Codable {
        var profiles: [Profile]
        var active: UUID?
    }

    var active: Profile? { profiles.first { $0.id == activeID } }

    func load() {
        guard let indexURL, let data = try? Data(contentsOf: indexURL),
              let index = try? JSONDecoder().decode(Index.self, from: data)
        else { return }
        profiles = index.profiles
        activeID = index.active
        activeText = active.flatMap { try? text(of: $0) }
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

    @discardableResult
    func add(text: String, name: String) throws -> Profile {
        let profile = Profile(name: name)
        try write(profile, text: text)
        return profile
    }

    func text(of profile: Profile) throws -> String {
        guard let url = file(profile.id) else { throw SbrError("no storage directory") }
        return try String(contentsOf: url, encoding: .utf8)
    }

    /// Make `profile` the one the tunnel runs.
    func activate(_ profile: Profile) throws {
        activeText = try text(of: profile)
        activeID = profile.id
        try saveIndex()
    }

    func remove(_ profile: Profile) {
        if let url = file(profile.id) { try? FileManager.default.removeItem(at: url) }
        profiles.removeAll { $0.id == profile.id }
        if activeID == profile.id {
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

    /// Refresh every stale remote profile. Run when the app comes to the
    /// front: no background timers.
    func refreshStale() async -> Bool {
        var activeChanged = false
        for p in profiles where p.isStale {
            if (try? await refresh(p)) == true { activeChanged = true }
        }
        return activeChanged
    }

    private func fetch(_ url: URL) async throws -> String {
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("sbr/\(Sbr.version)", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw SbrError("download failed: HTTP \(http.statusCode)")
        }
        return String(decoding: data, as: UTF8.self)
    }

    private func write(_ profile: Profile, text: String) throws {
        guard let dir, let url = file(profile.id) else { throw SbrError("no storage directory") }
        if let problem = Sbr.check(config: text) { throw SbrError(problem) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        if let i = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[i] = profile
        } else {
            profiles.append(profile)
        }
        if activeID == nil { try activate(profile) } else { try saveIndex() }
    }

    private func saveIndex() throws {
        guard let dir, let indexURL else { return }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(Index(profiles: profiles, active: activeID))
        try data.write(to: indexURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    private func file(_ id: UUID) -> URL? { dir?.appendingPathComponent("\(id.uuidString).json") }

    private static func defaultName(for url: URL) -> String {
        if let fragment = url.fragment, !fragment.isEmpty { return fragment }
        return url.host ?? "profile"
    }
}
