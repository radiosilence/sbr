import SbrKit
import SwiftUI

@main
struct SbrApp: App {
    @StateObject private var tunnel = TunnelModel()
    @StateObject private var profiles = ProfileStore()
    #if os(iOS)
    @StateObject private var inbox = PairInbox()
    #endif
    @Environment(\.scenePhase) private var scenePhase
    /// A link opened from elsewhere, waiting for the user to confirm: opening
    /// it downloads from its host, before any tunnel is up.
    @State private var pendingLink: ProfileLink?

    init() {
        Theme.registerFont()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(tunnel)
                .environmentObject(profiles)
                #if os(iOS)
                .environmentObject(inbox)
                .sheet(item: $inbox.invite) { SendToTVSheet(invite: $0).environmentObject(profiles) }
                #endif
                .task {
                    profiles.load()
                    await profiles.restore()
                    await tunnel.load()
                    await tunnel.apply(config: profiles.activeText, remote: profiles.activeRemote,
                                       stored: profiles.activeStored)
                    await syncProfiles()
                }
                .onChange(of: profiles.activeText) { _, text in
                    Task { await tunnel.apply(config: text, remote: profiles.activeRemote, stored: profiles.activeStored) }
                }
                .onChange(of: profiles.activeRemote) { _, remote in
                    Task { await tunnel.apply(config: profiles.activeText, remote: remote, stored: profiles.activeStored) }
                }
                .onOpenURL { url in
                    #if os(iOS)
                    if let invite = Pairing.Invite(url) {
                        inbox.invite = invite
                        return
                    }
                    #endif
                    guard let link = ProfileLink(url) else { return }
                    pendingLink = link
                }
                .alert("download this profile?", isPresented: Binding(
                    get: { pendingLink != nil },
                    set: { if !$0 { pendingLink = nil } }
                ), presenting: pendingLink) { link in
                    Button("download") { Task { await importLink(link) } }
                    Button("cancel", role: .cancel) {}
                } message: { link in
                    Text("sbr will connect to \(link.url.host ?? "an unknown host") directly, outside any tunnel. Only continue if you trust this link.")
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
    /// The Keychain access group shared with the tunnel (`keychain-access-groups`).
    static let keychainGroup = (Bundle.main.object(forInfoDictionaryKey: "SbrKeychainGroup") as? String)
        .flatMap { $0.isEmpty ? nil : $0 }
}
