import SbrKit
import SwiftUI

/// The tunnel's open connections, most recently active first: where each
/// goes, the outbounds it takes and how fast it is moving. Tap for details;
/// swipe (or long-press) to close one.
struct ConnectionsView: View {
    @EnvironmentObject private var tunnel: TunnelModel
    @State private var filter = ""
    @State private var detail: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            List {
                ForEach(shown) { live in
                    ConnectionRow(live: live) { detail = live.id }
                        .listRowInsets(EdgeInsets(top: 0, leading: Theme.Space.xl, bottom: 0, trailing: Theme.Space.xl))
                        .listRowBackground(Color.sbrBg)
                        .sbrHideListSeparator()
                        .contextMenu {
                            Button("close connection", role: .destructive) { close(live.id) }
                        }
                        #if !os(tvOS)
                        .swipeActions(edge: .trailing) {
                            Button("close", role: .destructive) { close(live.id) }
                                .tint(.sbrBad)
                        }
                        #endif
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .environment(\.defaultMinListRowHeight, 0)
            .animation(Theme.normal, value: shown.map(\.id))
        }
        .background(Color.sbrBg)
        .sheet(item: Binding(get: { detail.map(DetailID.init) }, set: { detail = $0?.id })) { d in
            ConnectionDetail(id: d.id)
                .environmentObject(tunnel)
        }
        .task { await tunnel.pollConnections() }
    }

    private struct DetailID: Identifiable { let id: String }

    private var header: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("connections").font(.sbr(.display)).foregroundStyle(Color.sbrStrong)
                .padding(.top, Theme.Space.xl)
                .padding(.bottom, Theme.Space.s)
            Text(summary).font(.sbr(.meta)).foregroundStyle(Color.sbrMuted)
                .contentTransition(.numericText())
            TextField("filter", text: $filter)
                .font(.sbr(.control))
                .textFieldStyle(.plain)
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.never)
                #endif
                .padding(.vertical, Theme.Space.s)
                .overlay(alignment: .bottom) {
                    Rectangle().fill(filter.isEmpty ? Color.sbrRule : Color.sbrAccent).frame(height: Theme.hairline)
                }
                .padding(.top, Theme.Space.l)
                .padding(.bottom, Theme.Space.s)
            if !tunnel.isConnected {
                Text("connect to see the tunnel's connections.")
                    .font(.sbr(.meta)).foregroundStyle(Color.sbrMuted).padding(.top, Theme.Space.m)
            } else if shown.isEmpty {
                Text(filter.isEmpty ? "nothing open." : "nothing matches.")
                    .font(.sbr(.meta)).foregroundStyle(Color.sbrMuted).padding(.top, Theme.Space.m)
            }
        }
        .padding(.horizontal, Theme.Space.xl)
    }

    private var summary: String {
        guard tunnel.isConnected else { return "off" }
        let listed = tunnel.connections.count
        let count = tunnel.connectionsTotal > listed ? "newest \(listed) of \(tunnel.connectionsTotal)" : "\(listed) open"
        let up = tunnel.connections.reduce(0) { $0 + $1.uploadRate }
        let down = tunnel.connections.reduce(0) { $0 + $1.downloadRate }
        return "\(count) · ↑ \(TunnelView.bits(up)) ↓ \(TunnelView.bits(down))"
    }

    /// Every word of the filter must appear in the host, destination, route,
    /// rule, inbound or network.
    private var shown: [TunnelModel.LiveConnection] {
        let words = filter.lowercased().split(whereSeparator: \.isWhitespace)
        guard !words.isEmpty else { return tunnel.connections }
        return tunnel.connections.filter { live in
            let c = live.connection
            let text = ([c.host, c.destination, c.ip ?? "", c.rule, c.inbound, c.network, c.sniffedProtocol ?? ""] + c.chain)
                .joined(separator: " ").lowercased()
            return words.allSatisfy { text.contains($0) }
        }
    }

    private func close(_ id: String) {
        Task { await tunnel.closeConnection(id: id) }
    }

    /// The route as it reads: the outbound the rule chose, through to the leaf.
    static func route(_ c: SbrConnection) -> String {
        c.chain.isEmpty ? "—" : c.chain.reversed().joined(separator: " → ")
    }

    static func age(since date: Date, now: Date = Date()) -> String {
        let s = max(Int(now.timeIntervalSince(date)), 0)
        switch s {
        case ..<60: return "\(s)s"
        case ..<3600: return "\(s / 60)m"
        case ..<86400: return "\(s / 3600)h \(s % 3600 / 60)m"
        default: return "\(s / 86400)d \(s % 86400 / 3600)h"
        }
    }
}

/// Host and live rate on top; route, then network, totals and age below.
/// A leading accent rule marks connections that moved bytes in the last poll.
private struct ConnectionRow: View {
    let live: TunnelModel.LiveConnection
    let open: () -> Void

    private var active: Bool { live.uploadRate + live.downloadRate > 0 }

    var body: some View {
        let c = live.connection
        Button(action: open) {
            VStack(spacing: 0) {
                HStack(spacing: Theme.Space.m) {
                    Rectangle().fill(active ? Color.sbrAccent : .clear).frame(width: 2)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(alignment: .firstTextBaseline) {
                            Text(c.host)
                                .font(.sbr(.control))
                                .foregroundStyle(Color.sbrStrong)
                                .lineLimit(1).truncationMode(.middle)
                            Spacer(minLength: Theme.Space.s)
                            if active {
                                Text("↑ \(TunnelView.bits(live.uploadRate)) ↓ \(TunnelView.bits(live.downloadRate))")
                                    .font(.sbr(.fine)).foregroundStyle(Color.sbrAccent)
                                    .lineLimit(1)
                            }
                        }
                        Text(ConnectionsView.route(c))
                            .font(.sbr(.fine)).foregroundStyle(Color.sbrInk)
                            .lineLimit(1).truncationMode(.middle)
                        Text(
                            "\(c.network) · ↑ \(TunnelView.bytes(Double(c.upload))) ↓ \(TunnelView.bytes(Double(c.download))) · \(ConnectionsView.age(since: c.startDate))"
                        )
                        .font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
                        .lineLimit(1)
                    }
                }
                .padding(.vertical, Theme.Space.m)
                RowRule()
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Everything known about one connection, kept live by the list's polling.
private struct ConnectionDetail: View {
    let id: String
    @EnvironmentObject private var tunnel: TunnelModel
    @Environment(\.dismiss) private var dismiss
    /// Kept so the sheet still reads after the connection closes.
    @State private var last: TunnelModel.LiveConnection?

    private var live: TunnelModel.LiveConnection? { tunnel.connections.first { $0.id == id } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .firstTextBaseline) {
                    Text(live == nil ? "closed" : "open")
                        .font(.sbr(.fine))
                        .foregroundStyle(live == nil ? Color.sbrMuted : Color.sbrAccent)
                    Spacer()
                    Button("done") { dismiss() }.sbrButton(.text)
                }
                .padding(.top, Theme.Space.m)
                if let shown = live ?? last {
                    content(shown)
                }
            }
            .padding(.horizontal, Theme.Space.xl)
            .padding(.bottom, Theme.Space.xxl)
        }
        .background(Color.sbrBg.ignoresSafeArea())
        .foregroundStyle(Color.sbrInk)
        .tint(.sbrAccent)
        .font(.sbr(.body))
        .onAppear { last = live }
        .onChange(of: live) { _, new in if let new { last = new } }
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 480)
        #endif
    }

    @ViewBuilder
    private func content(_ live: TunnelModel.LiveConnection) -> some View {
        let c = live.connection
        Text(c.host).font(.sbr(.title)).foregroundStyle(Color.sbrStrong)
            .sbrSelectable()
            .padding(.top, Theme.Space.s)
        Text(ConnectionsView.route(c)).font(.sbr(.meta)).foregroundStyle(Color.sbrInk)
            .padding(.top, Theme.Space.s)

        SectionHeader("traffic")
        HStack(spacing: Theme.Space.xl) {
            figure("up", TunnelView.bits(live.uploadRate), TunnelView.bytes(Double(c.upload)))
            figure("down", TunnelView.bits(live.downloadRate), TunnelView.bytes(Double(c.download)))
            Spacer()
        }

        SectionHeader("connection")
        field("destination", c.destination)
        if let ip = c.ip { field("address", ip) }
        if let d = c.domain { field("domain", d) }
        field("network", c.network)
        if let p = c.sniffedProtocol { field("protocol", p) }
        field("inbound", c.inbound)
        field("source", c.source)
        field("rule", c.rule)
        field("started", "\(c.startDate.formatted(date: .omitted, time: .standard)) · \(ConnectionsView.age(since: c.startDate)) ago")
        field("id", c.id)

        if self.live != nil {
            Button("close connection") {
                Task {
                    await tunnel.closeConnection(id: c.id)
                    dismiss()
                }
            }
            .sbrButton(.bordered)
            .padding(.top, Theme.Space.xl)
        }
    }

    private func figure(_ label: String, _ rate: String, _ total: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
            Text(rate).font(.sbr(.title)).foregroundStyle(Color.sbrStrong)
                .contentTransition(.numericText())
            Text(total).font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
        }
    }

    private func field(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: Theme.Space.m) {
                Text(label).font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
                    .frame(width: 96, alignment: .leading)
                Text(value).font(.sbr(.meta)).foregroundStyle(Color.sbrInk)
                    .sbrSelectable()
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.vertical, Theme.Space.s)
            RowRule()
        }
    }
}

private extension View {
    /// Rows draw their own hairline; the system separator is off where it exists.
    @ViewBuilder func sbrHideListSeparator() -> some View {
        #if os(tvOS)
        self
        #else
        listRowSeparator(.hidden)
        #endif
    }
}
