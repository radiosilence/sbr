import SbrKit
import SwiftUI

@main
struct SbrApp: App {
    @StateObject private var tunnel = TunnelModel()
    @StateObject private var profiles = ProfileStore()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        Theme.registerFont()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(tunnel)
                .environmentObject(profiles)
                .task {
                    profiles.load()
                    await tunnel.load()
                    await tunnel.apply(config: profiles.activeText, remote: profiles.activeRemote)
                    await syncProfiles()
                }
                .onChange(of: profiles.activeText) { _, text in
                    Task { await tunnel.apply(config: text, remote: profiles.activeRemote) }
                }
                .onChange(of: profiles.activeRemote) { _, remote in
                    Task { await tunnel.apply(config: profiles.activeText, remote: remote) }
                }
                .onOpenURL { url in
                    guard let link = ProfileLink(url) else { return }
                    Task { await importLink(link) }
                }
                .onChange(of: scenePhase) { _, phase in
                    guard phase == .active else { return }
                    Task { await syncProfiles() }
                }
        }
    }

    /// A running tunnel refreshes the active remote profile itself, through
    /// its own outbounds: take its copy rather than downloading another.
    private func syncProfiles() async {
        if let snapshot = await tunnel.tunnelProfile() { profiles.adopt(snapshot) }
        _ = await profiles.refreshStale(except: tunnel.isConnected ? profiles.activeID : nil)
    }

    private func importLink(_ link: ProfileLink) async {
        do {
            try await profiles.add(remote: link.url, name: link.name)
        } catch {
            tunnel.errorMessage = error.localizedDescription
        }
    }
}

/// Per-target values injected through Info.plist by project.yml.
enum AppConfig {
    static let tunnelBundleIdentifier = Bundle.main.object(forInfoDictionaryKey: "SbrTunnelBundleIdentifier") as? String ?? ""
}
