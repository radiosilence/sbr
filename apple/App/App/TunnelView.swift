import SbrKit
import SwiftUI

struct TunnelView: View {
    @EnvironmentObject private var tunnel: TunnelModel
    @EnvironmentObject private var profiles: ProfileStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                header
                if tunnel.isConnected {
                    rates
                    ForEach(shownGroups) { group in
                        GroupSection(group: group, lookup: groupsByTag)
                    }
                }
                #if !os(tvOS)
                SectionHeader("protection")
                Toggle(isOn: $tunnel.strict) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("block traffic outside the tunnel").font(.sbr(.control))
                        Text("includes connections opened before connecting. takes effect on reconnect.")
                            .font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
                    }
                }
                .tint(.sbrAccent)
                AutoConnectSection()
                #endif
            }
            .padding(.horizontal, Theme.Space.xl)
            .padding(.bottom, Theme.Space.xxl)
        }
        // Groups, latency and traffic come from the tunnel, polled only while
        // this tab is on screen.
        .task { await tunnel.poll() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: Theme.Space.s) {
            Text("sbr").font(.sbr(.display)).foregroundStyle(Color.sbrStrong)
                .padding(.top, Theme.Space.xl)
            Text("\(profiles.active?.name ?? "no profile") · build \(Self.build)")
                .font(.sbr(.meta)).foregroundStyle(Color.sbrMuted)
            HStack(alignment: .firstTextBaseline, spacing: Theme.Space.m) {
                Circle()
                    .fill(tunnel.isConnected ? Color.sbrAccent : Color.sbrRule)
                    .frame(width: 8, height: 8)
                Text(tunnel.status.label).font(.sbr(.title)).foregroundStyle(Color.sbrStrong)
                Spacer()
                Button(tunnel.isOn ? "disconnect" : "connect") {
                    Task { await tunnel.setOn(!tunnel.isOn) }
                }
                .sbrButton(tunnel.isOn ? .bordered : .prominent)
                .disabled(profiles.active == nil)
                .sensoryFeedback(.impact(weight: .light), trigger: tunnel.isOn)
            }
            .padding(.top, Theme.Space.l)
            .animation(Theme.settle, value: tunnel.status)
            if let route { routeLine(route) }
        }
    }

    /// Where traffic goes right now: the leaf of the route's outermost
    /// selector, with its latency.
    private var route: (tag: String, delay: Int?)? {
        guard let g = shownGroups.first else { return nil }
        return (g.now, groupsByTag[g.now]?.delay ?? leafDelay(g.now))
    }

    private func leafDelay(_ tag: String) -> Int? {
        for g in tunnel.groups {
            if let m = g.members.first(where: { $0.tag == tag }) { return m.delay }
        }
        return nil
    }

    private func routeLine(_ r: (tag: String, delay: Int?)) -> some View {
        HStack(spacing: Theme.Space.s) {
            Text("via").foregroundStyle(Color.sbrMuted)
            Text(r.tag).foregroundStyle(Color.sbrInk).lineLimit(1).truncationMode(.middle)
            Spacer()
            if let d = r.delay { Text("\(d) ms").foregroundStyle(Color.sbrAccent) }
        }
        .font(.sbr(.meta))
    }

    private var rates: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader("traffic")
            HStack(spacing: Theme.Space.xl) {
                rate("up", tunnel.uploadRate)
                rate("down", tunnel.downloadRate)
                Spacer()
            }
            if let s = tunnel.stats {
                Text("\(s.activeConnections) tcp · \(s.udpSessions) udp · \(Self.bytes(Double(s.memoryFootprint))) mem")
                    .font(.sbr(.fine)).foregroundStyle(Color.sbrMuted).padding(.top, Theme.Space.s)
            }
        }
    }

    private func rate(_ label: String, _ bytesPerSecond: Double) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
            Text(Self.bits(bytesPerSecond)).font(.sbr(.title)).foregroundStyle(Color.sbrStrong)
                .contentTransition(.numericText())
                .animation(Theme.fast, value: bytesPerSecond)
        }
    }

    /// Selectors you can steer, outermost first; urltests are reached
    /// through them. One-member selectors are aliases and stay hidden.
    private var shownGroups: [SbrGroup] {
        let selectors = tunnel.groups.filter { $0.isSelectable && $0.members.count > 1 }
        let nested = Set(tunnel.groups.flatMap { $0.members.map(\.tag) })
        // Roots (not a member of anything else) first, e.g. exit-select before entry-select.
        return selectors.sorted { a, b in
            let ra = !nested.contains(a.tag), rb = !nested.contains(b.tag)
            return ra && !rb
        }
    }

    private var groupsByTag: [String: SbrGroup] {
        Dictionary(tunnel.groups.map { ($0.tag, $0) }, uniquingKeysWith: { a, _ in a })
    }

    static let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"

    static func bytes(_ n: Double) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .binary)
    }

    /// Network speeds read in bits, like the speed test the user compares against.
    static func bits(_ bytesPerSecond: Double) -> String {
        let b = bytesPerSecond * 8
        switch b {
        case ..<1_000: return "0 kb/s"
        case ..<1_000_000: return String(format: "%.0f kb/s", b / 1_000)
        case ..<1_000_000_000: return String(format: "%.1f mb/s", b / 1_000_000)
        default: return String(format: "%.2f gb/s", b / 1_000_000_000)
        }
    }
}

/// One selector: its members as rows, the chosen one marked by a leading
/// accent rule. Members that are themselves groups (an `auto` urltest) show
/// what they resolved to. Latency on the right; the fastest in accent.
struct GroupSection: View {
    let group: SbrGroup
    let lookup: [String: SbrGroup]
    @EnvironmentObject private var tunnel: TunnelModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader(group.tag) {
                if tunnel.testing.contains(group.tag) {
                    Text("testing").font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
                } else {
                    Button("test") { Task { await tunnel.urlTest(group: group.tag) } }
                        .sbrButton(.text)
                }
            }
            ForEach(Array(group.members.enumerated()), id: \.element.id) { i, m in
                if i > 0 { RowRule() }
                row(m)
            }
        }
    }

    /// Why failover dropped a path, in plain words.
    static func blocked(_ m: SbrGroup.Member) -> String {
        let why = switch m.reason {
        case "frozen": "stalls mid-transfer"
        case "reset": "reset after connecting"
        case "closed": "closed before any data"
        case "no_response": "no response"
        case "connect": "can't connect"
        default: "unavailable"
        }
        guard let s = m.retryIn else { return "blocked: \(why)" }
        return "blocked: \(why) · retry in \(s >= 60 ? "\(s / 60)m" : "\(s)s")"
    }

    private var fastest: String? {
        group.members.filter { $0.delay != nil }.min { ($0.delay ?? .max) < ($1.delay ?? .max) }?.tag
    }

    private func row(_ m: SbrGroup.Member) -> some View {
        let selected = m.tag == group.selected
        let inner = lookup[m.tag]
        let delay = inner?.delay ?? m.delay
        return Button {
            Task { await tunnel.select(group: group.tag, member: m.tag) }
        } label: {
            HStack(spacing: Theme.Space.m) {
                Rectangle().fill(selected ? Color.sbrAccent : .clear).frame(width: 2)
                VStack(alignment: .leading, spacing: 2) {
                    Text(m.tag)
                        .font(.sbr(.control))
                        .foregroundStyle(selected ? Color.sbrStrong : Color.sbrInk)
                        .lineLimit(1).truncationMode(.middle)
                    if let inner {
                        Text("→ \(inner.now)").font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
                            .lineLimit(1).truncationMode(.middle)
                    }
                    if m.degraded == true {
                        Text(Self.blocked(m)).font(.sbr(.fine)).foregroundStyle(Color.sbrBad).lineLimit(1)
                    }
                }
                Spacer()
                Text(m.degraded == true ? "×" : delay.map { "\($0) ms" } ?? "—")
                    .font(.sbr(.meta))
                    .foregroundStyle(m.degraded == true ? Color.sbrBad : m.tag == fastest ? Color.sbrAccent : Color.sbrMuted)
            }
            .padding(.vertical, Theme.Space.m)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .animation(Theme.fast, value: group.selected)
    }
}
