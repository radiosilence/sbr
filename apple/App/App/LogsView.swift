import SwiftUI

/// The tunnel's recent log lines, newest first. They come from the
/// extension's memory and are shown here only.
struct LogsView: View {
    @EnvironmentObject private var tunnel: TunnelModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text("logs").font(.sbr(.display)).foregroundStyle(Color.sbrStrong)
                    .padding(.top, Theme.Space.xl)
                    .padding(.bottom, Theme.Space.m)
                HStack(spacing: Theme.Space.l) {
                    Toggle(isOn: $tunnel.verbose) {
                        Text("verbose").font(.sbr(.control))
                    }
                    .tint(.sbrAccent)
                    #if !os(tvOS)
                    ShareLink(item: tunnel.logs.joined(separator: "\n")) {
                        Text("share").font(.sbr(.control))
                    }
                    .disabled(tunnel.logs.isEmpty)
                    #endif
                }
                .padding(.bottom, Theme.Space.m)
                DiagnoseSection()
                if tunnel.logs.isEmpty {
                    Text(tunnel.isConnected ? "nothing yet." : "connect to see the tunnel's logs.")
                        .font(.sbr(.meta)).foregroundStyle(Color.sbrMuted)
                }
                ForEach(Array(tunnel.logs.reversed().enumerated()), id: \.offset) { _, line in
                    Text(line)
                        .font(.sbr(.fine))
                        .foregroundStyle(line.contains("ERROR") || line.contains(" error ") ? Color.sbrBad : line.contains("WARN") || line.contains(" warn ") ? Color.sbrInk : Color.sbrMuted)
                        .sbrSelectable()
                        .padding(.vertical, 3)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(.horizontal, Theme.Space.xl)
            .padding(.bottom, Theme.Space.xxl)
        }
        .task { await tunnel.pollLogs() }
    }
}
