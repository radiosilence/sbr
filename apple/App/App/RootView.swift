import SwiftUI

enum Tab: String, CaseIterable {
    case tunnel, connections, profiles, logs
}

/// kōan's phone shell: content on the flat ground, and a flat tab row with
/// lowercase labels and a hairline accent underline instead of a system bar.
struct RootView: View {
    @EnvironmentObject private var tunnel: TunnelModel
    @State private var tab: Tab = .tunnel
    @Namespace private var underline

    var body: some View {
        VStack(spacing: 0) {
            Group {
                switch tab {
                case .tunnel: TunnelView()
                case .connections: ConnectionsView()
                case .profiles: ProfilesView()
                case .logs: LogsView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            #if os(tvOS)
            // Without sections, tvOS only moves focus up from a tab to a
            // control roughly above it, which a lone button often isn't.
            .focusSection()
            #endif
            tabBar
            #if os(tvOS)
            .focusSection()
            #endif
        }
        .background(Color.sbrBg.ignoresSafeArea())
        .foregroundStyle(Color.sbrInk)
        .tint(.sbrAccent)
        .font(.sbr(.body))
        .alert(
            "error",
            isPresented: Binding(get: { tunnel.errorMessage != nil }, set: { if !$0 { tunnel.errorMessage = nil } })
        ) {
            Button("ok", role: .cancel) {}
        } message: {
            Text(tunnel.errorMessage ?? "")
        }
    }

    private var tabBar: some View {
        VStack(spacing: 0) {
            RowRule()
            HStack {
                ForEach(Tab.allCases, id: \.self) { t in
                    Button {
                        tab = t
                    } label: {
                        Text(t.rawValue)
                            .font(.sbr(.fine))
                            .foregroundStyle(tab == t ? Color.sbrAccent : Color.sbrMuted)
                            .padding(.bottom, 3)
                            .overlay(alignment: .bottom) {
                                if tab == t {
                                    Rectangle().fill(Color.sbrAccent).frame(height: Theme.hairline)
                                        .matchedGeometryEffect(id: "underline", in: underline)
                                }
                            }
                            .frame(maxWidth: .infinity, minHeight: 49)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
            .animation(Theme.normal, value: tab)
        }
        .background(Color.sbrBg)
    }
}
