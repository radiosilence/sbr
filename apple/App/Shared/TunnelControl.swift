import Foundation
import NetworkExtension
#if os(iOS)
import WidgetKit
#endif

/// Starts and stops the installed tunnel. Shared by the app and its App
/// Intents, which may run in the widget extension, so it depends on nothing
/// but NetworkExtension and the saved VPN configuration.
///
/// Auto-connect is recorded on the configuration itself: it is on when the
/// configuration carries on-demand rules. `isOnDemandEnabled` is whether
/// those rules are armed right now; a manual disconnect disarms them, as the
/// system would otherwise reconnect at once, and a manual connect re-arms them.
enum TunnelControl {
    static let controlKind = "cc.blit.sbr.tunnel"

    static let tunnelBundleIdentifier =
        Bundle.main.object(forInfoDictionaryKey: "SbrTunnelBundleIdentifier") as? String ?? ""

    static func manager() async throws -> NETunnelProviderManager? {
        try await NETunnelProviderManager.loadAllFromPreferences().first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == tunnelBundleIdentifier
        }
    }

    static func isOn() async -> Bool {
        guard let m = try? await manager() else { return false }
        return [.connected, .connecting, .reasserting].contains(m.connection.status)
    }

    static func setOn(_ on: Bool) async throws {
        guard let m = try await manager() else { throw ControlError.notInstalled }
        try await setOn(on, m)
    }

    static func setOn(_ on: Bool, _ m: NETunnelProviderManager) async throws {
        if on {
            let auto = !(m.onDemandRules ?? []).isEmpty
            if !m.isEnabled || m.isOnDemandEnabled != auto {
                m.isEnabled = true
                m.isOnDemandEnabled = auto
                try await m.saveToPreferences()
                try await m.loadFromPreferences()
            }
            try m.connection.startVPNTunnel()
        } else {
            if m.isOnDemandEnabled {
                m.isOnDemandEnabled = false
                try await m.saveToPreferences()
            }
            m.connection.stopVPNTunnel()
        }
        reloadControl()
    }

    /// Ask Control Center to re-read the toggle's state.
    static func reloadControl() {
        #if os(iOS)
        if #available(iOS 18, *) { ControlCenter.shared.reloadControls(ofKind: controlKind) }
        #endif
    }

    enum ControlError: Error, LocalizedError {
        case notInstalled
        var errorDescription: String? { "open sbr and choose a profile first" }
    }
}
