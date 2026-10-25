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
                }
                .onOpenURL { url in
                    guard let link = ProfileLink(url) else { return }
                    Task { await importLink(link) }
                }
                .onChange(of: scenePhase) { _, phase in
                    guard phase == .active else { return }
                    Task {
                        if await profiles.refreshStale() { await tunnel.reload() }
                    }
                }
        }
    }

    private func importLink(_ link: ProfileLink) async {
        do {
            let p = try await profiles.add(remote: link.url, name: link.name)
            if profiles.activeID == p.id { await tunnel.reload() }
        } catch {
            tunnel.errorMessage = error.localizedDescription
        }
    }
}

/// Per-target values injected through Info.plist by project.yml.
enum AppConfig {
    static let appGroup = Bundle.main.object(forInfoDictionaryKey: "SbrAppGroup") as? String ?? ""
    static let tunnelBundleIdentifier = Bundle.main.object(forInfoDictionaryKey: "SbrTunnelBundleIdentifier") as? String ?? ""
}
