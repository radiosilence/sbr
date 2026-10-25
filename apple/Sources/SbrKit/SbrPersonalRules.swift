import Foundation

/// A route the user keeps on top of whatever profile runs: these domains go
/// through `outbound`. The app stores them and hands them to the tunnel
/// (`SbrProviderKey.personalRules`), which puts them into every config it
/// runs, including the profiles it downloads itself.
public struct SbrPersonalRule: Codable, Sendable, Hashable, Identifiable {
    public var id: UUID
    /// What a rule made from a template is called; nil for a single domain.
    public var name: String?
    public var domains: [String]
    /// Match the domains and their subdomains (`domain_suffix`), or the
    /// domains exactly (`domain`).
    public var subdomains: Bool
    /// An outbound or group tag in the profile.
    public var outbound: String
    public var enabled: Bool

    public init(
        id: UUID = UUID(),
        name: String? = nil,
        domains: [String],
        subdomains: Bool = true,
        outbound: String,
        enabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.domains = domains
        self.subdomains = subdomains
        self.outbound = outbound
        self.enabled = enabled
    }

    /// The sing-box route rule.
    public var routeRule: [String: Any] {
        [subdomains ? "domain_suffix" : "domain": domains, "action": "route", "outbound": outbound]
    }

    /// `input` as a rule matches it: lowercased, without a scheme, path,
    /// port or trailing dot. Nil when what is left is not a host name.
    public static func normalize(_ input: String) -> String? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
        if let i = s.firstIndex(where: { "/?#".contains($0) }) { s = String(s[..<i]) }
        if let i = s.lastIndex(of: ":") { s = String(s[..<i]) }
        while s.hasPrefix("*.") || s.hasPrefix(".") { s.removeFirst(s.hasPrefix(".") ? 1 : 2) }
        while s.hasSuffix(".") { s.removeLast() }
        let labels = s.split(separator: ".", omittingEmptySubsequences: false)
        guard !s.isEmpty, s.count <= 253, labels.allSatisfy({ label in
            !label.isEmpty && label.count <= 63 && label.first != "-" && label.last != "-"
                && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
        }) else { return nil }
        return s
    }
}

public enum SbrPersonalRules {
    public static func encode(_ rules: [SbrPersonalRule]) -> Data {
        (try? JSONEncoder().encode(rules)) ?? Data("[]".utf8)
    }

    /// Empty for nil or unreadable data.
    public static func decode(_ data: Data?) -> [SbrPersonalRule] {
        data.flatMap { try? JSONDecoder().decode([SbrPersonalRule].self, from: $0) } ?? []
    }

    /// Every outbound and endpoint tag in a config.
    public static func tags(_ root: [String: Any]) -> Set<String> {
        let all = (root["outbounds"] as? [[String: Any]] ?? []) + (root["endpoints"] as? [[String: Any]] ?? [])
        return Set(all.compactMap { $0["tag"] as? String })
    }

    /// What a rule can route through: the members of the config's selector
    /// groups, then the groups themselves, in profile order.
    public static func choices(config: String) -> [String] {
        guard let root = (try? JSONSerialization.jsonObject(with: Data(config.utf8))) as? [String: Any] else { return [] }
        let selectors = (root["outbounds"] as? [[String: Any]] ?? []).filter { $0["type"] as? String == "selector" }
        var seen = Set<String>()
        let members = selectors.flatMap { $0["outbounds"] as? [String] ?? [] }
        let groups = selectors.compactMap { $0["tag"] as? String }
        return (members + groups).filter { seen.insert($0).inserted }
    }

    /// Put the enabled rules into `root.route.rules`, in order, after the
    /// last `sniff` or `hijack-dns` rule so they see sniffed domains and DNS
    /// is still answered. Returns the rules left out because the config has
    /// no outbound by that tag.
    @discardableResult
    public static func insert(_ rules: [SbrPersonalRule], into root: inout [String: Any]) -> [SbrPersonalRule] {
        let enabled = rules.filter { $0.enabled && !$0.domains.isEmpty }
        guard !enabled.isEmpty else { return [] }
        let tags = tags(root)
        let usable = enabled.filter { tags.contains($0.outbound) }
        let skipped = enabled.filter { !tags.contains($0.outbound) }
        guard !usable.isEmpty else { return skipped }
        var route = root["route"] as? [String: Any] ?? [:]
        var existing = route["rules"] as? [[String: Any]] ?? []
        let at = existing.lastIndex { ["sniff", "hijack-dns"].contains($0["action"] as? String) }.map { $0 + 1 } ?? 0
        existing.insert(contentsOf: usable.map(\.routeRule), at: at)
        route["rules"] = existing
        root["route"] = route
        return skipped
    }

    /// `config` with `rules` inserted, and the rules left out. Unchanged if
    /// there is nothing to insert or the config is not plain JSON.
    public static func apply(_ rules: [SbrPersonalRule], to config: String) -> (config: String, skipped: [SbrPersonalRule]) {
        guard rules.contains(where: \.enabled),
              var root = (try? JSONSerialization.jsonObject(with: Data(config.utf8))) as? [String: Any]
        else { return (config, []) }
        let skipped = insert(rules, into: &root)
        guard let data = try? JSONSerialization.data(withJSONObject: root) else { return (config, skipped) }
        return (String(decoding: data, as: UTF8.self), skipped)
    }

    /// The domains whose routing differs between two rule lists, so their
    /// open connections can be closed and reopened on the new route.
    public static func changedDomains(from old: [SbrPersonalRule], to new: [SbrPersonalRule]) -> [(domain: String, subdomains: Bool)] {
        func entries(_ rules: [SbrPersonalRule]) -> Set<Entry> {
            Set(rules.filter(\.enabled).flatMap { r in
                r.domains.map { Entry(domain: $0, subdomains: r.subdomains, outbound: r.outbound) }
            })
        }
        let a = entries(old), b = entries(new)
        var seen = Set<String>()
        return a.symmetricDifference(b)
            .sorted { ($0.domain, $0.outbound) < ($1.domain, $1.outbound) }
            .compactMap { e in
                seen.insert("\(e.subdomains) \(e.domain)").inserted ? (e.domain, e.subdomains) : nil
            }
    }

    private struct Entry: Hashable {
        var domain: String
        var subdomains: Bool
        var outbound: String
    }
}
