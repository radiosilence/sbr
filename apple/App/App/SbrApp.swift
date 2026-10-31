import SbrKit
import SwiftUI

@main
struct SbrApp: App {
    #if os(macOS)
    @NSApplicationDelegateAdaptor private var delegate: AppDelegate
    #else
    @StateObject private var tunnel = TunnelModel()
    @StateObject private var profiles = ProfileStore()
    @Environment(\.scenePhase) private var scenePhase
    #endif
    #if os(iOS)
    @StateObject private var inbox = PairInbox()
    #endif

    init() {
        Theme.registerFont()
    }

    var body: some Scene {
        #if os(macOS)
        MenuBarExtra {
            MenuBarContent(delegate: delegate)
                .environmentObject(delegate.tunnel)
                .environmentObject(delegate.profiles)
        } label: {
            MenuBarLabel(delegate: delegate)
                .environmentObject(delegate.tunnel)
        }
        Window("sbr", id: MainWindow.id) {
            RootView()
                .environmentObject(delegate.tunnel)
                .environmentObject(delegate.profiles)
                .mainWindow(delegate)
        }
        .launchHidden()
        #else
        WindowGroup {
            RootView()
                .environmentObject(tunnel)
                .environmentObject(profiles)
                #if os(iOS)
                .environmentObject(inbox)
                .sheet(item: $inbox.invite) { SendToTVSheet(invite: $0).environmentObject(profiles) }
                #endif
                .task {
                    await AppFlow.start(tunnel: tunnel, profiles: profiles)
                    await AppFlow.sync(tunnel: tunnel, profiles: profiles)
                }
                .onChange(of: profiles.activeText) { _, _ in
                    Task { await AppFlow.applyActive(tunnel: tunnel, profiles: profiles) }
                }
                .onChange(of: profiles.activeRemote) { _, _ in
                    Task { await AppFlow.applyActive(tunnel: tunnel, profiles: profiles) }
                }
                .onOpenURL { url in
                    #if os(iOS)
                    if let invite = Pairing.Invite(url) {
                        inbox.invite = invite
                        return
                    }
                    #endif
                    guard let link = ProfileLink(url) else { return }
                    Task { await AppFlow.importLink(link, tunnel: tunnel, profiles: profiles) }
                }
                .onChange(of: scenePhase) { _, phase in
                    guard phase == .active else { return }
                    Task { await AppFlow.sync(tunnel: tunnel, profiles: profiles) }
                }
        }
        #endif
    }
}

/// What the app does with its models outside any one view, shared by the
/// iOS/tvOS scene and the macOS app delegate.
@MainActor
enum AppFlow {
    static func start(tunnel: TunnelModel, profiles: ProfileStore) async {
        profiles.load()
        await profiles.restore()
        await tunnel.load()
        await applyActive(tunnel: tunnel, profiles: profiles)
    }

    static func applyActive(tunnel: TunnelModel, profiles: ProfileStore) async {
        await tunnel.apply(config: profiles.activeText, remote: profiles.activeRemote, stored: profiles.activeStored)
    }

    /// A running tunnel refreshes the active remote profile itself, through
    /// its own outbounds: take its copy rather than downloading another.
    static func sync(tunnel: TunnelModel, profiles: ProfileStore) async {
        if let snapshot = await tunnel.tunnelProfile() { profiles.adopt(snapshot) }
        _ = await profiles.refreshStale(except: tunnel.isConnected ? profiles.activeID : nil)
    }

    static func importLink(_ link: ProfileLink, tunnel: TunnelModel, profiles: ProfileStore) async {
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
