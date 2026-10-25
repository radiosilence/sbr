import SwiftUI

@main
struct SbrDemoApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

/// Per-target values injected through Info.plist by project.yml.
enum AppConfig {
    static let appGroup = Bundle.main.object(forInfoDictionaryKey: "SbrAppGroup") as? String ?? ""
    static let tunnelBundleIdentifier = Bundle.main.object(forInfoDictionaryKey: "SbrTunnelBundleIdentifier") as? String ?? ""
}
