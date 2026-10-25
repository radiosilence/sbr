import NetworkExtension
import SwiftUI

enum OnDemand {
    /// Off on trusted Wi-Fi, on everywhere else (other Wi-Fi, cellular,
    /// wired). Rules are evaluated in order; the first match wins.
    static func rules(trusted: [String]) -> [NEOnDemandRule] {
        var rules: [NEOnDemandRule] = []
        if !trusted.isEmpty {
            let off = NEOnDemandRuleDisconnect()
            off.interfaceTypeMatch = .wiFi
            off.ssidMatch = trusted
            rules.append(off)
        }
        let on = NEOnDemandRuleConnect()
        on.interfaceTypeMatch = .any
        rules.append(on)
        return rules
    }

    /// The joined Wi-Fi network's name. iOS answers apps holding the Access
    /// WiFi Information entitlement that have installed a VPN configuration,
    /// without location permission; elsewhere names are typed in.
    static func currentSSID() async -> String? {
        #if os(iOS)
        await NEHotspotNetwork.fetchCurrent()?.ssid
        #else
        nil
        #endif
    }
}

struct AutoConnectSection: View {
    @EnvironmentObject private var tunnel: TunnelModel
    @State private var draft = ""
    @State private var current: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Toggle(isOn: $tunnel.autoConnect) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("auto-connect").font(.sbr(.control))
                    Text("connects on cellular and on wi-fi not listed below; disconnects on listed networks. disconnecting by hand keeps it off until you connect again.")
                        .font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
                }
            }
            .tint(.sbrAccent)
            .padding(.top, Theme.Space.l)

            if tunnel.autoConnect {
                SectionHeader("trusted networks") {
                    if let current, !tunnel.trustedNetworks.contains(current) {
                        Button("add \(current)") { add(current) }.sbrButton(.text)
                    }
                }
                ForEach(tunnel.trustedNetworks, id: \.self) { ssid in
                    HStack {
                        Text(ssid).font(.sbr(.control)).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button("remove") { tunnel.trustedNetworks.removeAll { $0 == ssid } }.sbrButton(.text)
                    }
                    RowRule()
                }
                TextField("wi-fi name", text: $draft)
                    .textFieldStyle(.plain)
                    .font(.sbr(.control))
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                    .onSubmit { add(draft) }
                    .frame(minHeight: 44)
                Text("names are matched exactly, including case.")
                    .font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
            }
        }
        .animation(Theme.normal, value: tunnel.autoConnect)
        .task(id: tunnel.autoConnect) {
            if tunnel.autoConnect { current = await OnDemand.currentSSID() }
        }
    }

    private func add(_ ssid: String) {
        let s = ssid.trimmingCharacters(in: .whitespaces)
        if !s.isEmpty, !tunnel.trustedNetworks.contains(s) { tunnel.trustedNetworks.append(s) }
        draft = ""
    }
}
