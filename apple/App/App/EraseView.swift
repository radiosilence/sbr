import SwiftUI

/// One action that leaves nothing of sbr's on the device but the app itself:
/// profiles and their credentials, the VPN configuration, settings, caches
/// and logs.
struct EraseSection: View {
    @EnvironmentObject private var tunnel: TunnelModel
    @EnvironmentObject private var profiles: ProfileStore
    @State private var confirming = false

    var body: some View {
        SectionHeader("erase")
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            Text("removes every profile and its credentials, the vpn configuration, settings and logs from this device. the app stays installed, and the system keeps its own record of vpn connections.")
                .font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
            Button("erase everything") { confirming = true }
                .sbrButton(.bordered)
        }
        .confirmationDialog("erase everything?", isPresented: $confirming, titleVisibility: .visible) {
            Button("erase", role: .destructive) { Task { await erase() } }
            Button("cancel", role: .cancel) {}
        } message: {
            Text("profiles can't be recovered. you'll need their links or files to add them again.")
        }
    }

    private func erase() async {
        await tunnel.erase()
        do {
            try profiles.eraseAll()
        } catch {
            tunnel.errorMessage = error.localizedDescription
        }
    }
}
