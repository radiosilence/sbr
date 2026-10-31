#if os(macOS)
import AppKit
import Combine
import NetworkExtension
import ServiceManagement
import SwiftUI

/// On macOS sbr lives in the menu bar. The delegate owns the models, so the
/// tunnel and profiles are loaded at launch, including at login, whether or
/// not the window is ever opened.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let tunnel = TunnelModel()
    let profiles = ProfileStore()
    let window = MainWindow()
    private lazy var started = Task {
        await AppFlow.start(tunnel: tunnel, profiles: profiles)
        // The active profile can change with the window closed: from the
        // menu, or when a remote profile refreshes. objectWillChange fires
        // before the change lands, hence the hop; apply ignores the fires
        // that leave the active profile as it was.
        tracking = profiles.objectWillChange
            .receive(on: DispatchQueue.main)
            .sink { [unowned self] _ in
                Task { await AppFlow.applyActive(tunnel: tunnel, profiles: profiles) }
            }
        // After the subscription, so a profile this refreshes is applied.
        await AppFlow.sync(tunnel: tunnel, profiles: profiles)
    }
    private var tracking: AnyCancellable?

    /// Everything that acts on the tunnel or profiles waits for launch to
    /// have loaded them.
    func ready() async { await started.value }

    func applicationWillFinishLaunching(_ notification: Notification) {
        // Set before launch finishes, so the Dock icon never appears; the
        // window brings it back while it is open.
        NSApp.setActivationPolicy(.accessory)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        _ = started
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        let links = urls.compactMap(ProfileLink.init)
        guard !links.isEmpty else { return }
        Task {
            await ready()
            for link in links where confirm(link) {
                await AppFlow.importLink(link, tunnel: tunnel, profiles: profiles)
            }
            window.open()
        }
    }

    private func confirm(_ link: ProfileLink) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = AppFlow.confirmTitle
        alert.informativeText = AppFlow.confirmMessage(link)
        alert.addButton(withTitle: "Download")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }

    /// Opening the app again from Finder or Spotlight shows the window.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        window.open()
        return false
    }
}

/// The main window, opened from outside SwiftUI (the delegate) through the
/// action a SwiftUI view hands it. A request that arrives before any view
/// has done so is kept until one does.
@MainActor
final class MainWindow {
    static let id = "main"
    private var openAction: OpenWindowAction?
    private var requested = false

    func attach(_ action: OpenWindowAction) {
        openAction = action
        if requested { open() }
    }

    func open() {
        guard let openAction else {
            requested = true
            return
        }
        requested = false
        openAction(id: Self.id)
        NSApp.activate()
    }
}

extension View {
    /// The app is in the Dock and the app switcher only while its window is open.
    func mainWindow(_ delegate: AppDelegate) -> some View {
        onAppear {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate()
            Task {
                await delegate.ready()
                await AppFlow.sync(tunnel: delegate.tunnel, profiles: delegate.profiles)
            }
        }
        .onDisappear { NSApp.setActivationPolicy(.accessory) }
    }
}

extension Scene {
    /// Open only when asked: not at launch, and not restored from last time.
    func launchHidden() -> some Scene {
        defaultLaunchBehavior(.suppressed).restorationBehavior(.disabled)
    }
}

/// The status item: the arch, lit while the tunnel is up.
struct MenuBarLabel: View {
    let delegate: AppDelegate
    @EnvironmentObject private var tunnel: TunnelModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(tunnel.isConnected ? "MenuBarOn" : "MenuBarOff")
            .accessibilityLabel(tunnel.isConnected ? "sbr, connected" : "sbr, disconnected")
            .onAppear { delegate.window.attach(openWindow) }
    }
}

struct MenuBarContent: View {
    let delegate: AppDelegate
    @EnvironmentObject private var tunnel: TunnelModel
    @EnvironmentObject private var profiles: ProfileStore
    @Environment(\.openWindow) private var openWindow
    /// SMAppService.Status is not observable. The menu re-reads it whenever
    /// the tunnel model changes, and this forces a re-read after the toggle.
    @State private var loginItemRevision = 0

    var body: some View {
        if let error = tunnel.errorMessage {
            Text("Error: \(Self.brief(error))")
        }
        Text(statusLine)
        if tunnel.needsApproval {
            Button("Allow sbr in System Settings…") {
                NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
            }
        }
        Button(tunnel.isOn ? "Disconnect" : "Connect") {
            Task { await act { await tunnel.setOn(!tunnel.isOn) } }
        }
        .disabled(!tunnel.isOn && profiles.active == nil)
        if !profiles.profiles.isEmpty {
            Picker("Profile", selection: Binding(
                get: { profiles.activeID },
                set: { id in
                    guard let p = profiles.profiles.first(where: { $0.id == id }) else { return }
                    Task { await act { try profiles.activate(p) } }
                }
            )) {
                ForEach(profiles.profiles) { Text($0.name).tag(Optional($0.id)) }
            }
        }
        Divider()
        Button("Open sbr") { open() }
            .keyboardShortcut("o")
        loginItem
        Divider()
        Button("Quit sbr") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    /// The menu is as wide as its widest item; the window's alert has the rest.
    private static func brief(_ message: String) -> String {
        let line = message.prefix { !$0.isNewline }
        return line.count > 60 ? String(line.prefix(59)) + "…" : String(line)
    }

    private var statusLine: String {
        let state = tunnel.status.label
        guard let name = profiles.active?.name else { return state }
        return "\(state) · \(name)"
    }

    private func open() {
        delegate.window.attach(openWindow)
        delegate.window.open()
    }

    /// Runs a menu action, and shows the window if it failed: the error alert
    /// lives there, and the menu has already closed.
    private func act(_ action: () async throws -> Void) async {
        await delegate.ready()
        tunnel.errorMessage = nil
        do {
            try await action()
        } catch {
            tunnel.errorMessage = error.localizedDescription
        }
        if tunnel.errorMessage != nil { open() }
    }

    @ViewBuilder private var loginItem: some View {
        let _ = loginItemRevision
        let status = SMAppService.mainApp.status
        if let reason = loginItemUnavailable {
            Toggle("Launch at Login (\(reason))", isOn: .constant(false)).disabled(true)
        } else if status == .requiresApproval {
            Button("Launch at Login: Allow in System Settings…") { SMAppService.openSystemSettingsLoginItems() }
        } else {
            Toggle("Launch at Login", isOn: Binding(
                get: { status == .enabled },
                set: { on in
                    Task {
                        do {
                            if on {
                                try SMAppService.mainApp.register()
                            } else if SMAppService.mainApp.status == .enabled {
                                try await SMAppService.mainApp.unregister()
                            }
                        } catch {
                            tunnel.errorMessage = error.localizedDescription
                        }
                        loginItemRevision += 1
                    }
                }
            ))
        }
    }

    /// SMAppService registers the app where it is now. The Developer ID
    /// build can only activate its system extension from /Applications, so
    /// from anywhere else (such as the mounted disk image) it would register
    /// a path that stops working.
    private var loginItemUnavailable: String? {
        #if SBR_SYSTEM_EXTENSION
        let path = Bundle.main.bundleURL.resolvingSymlinksInPath().standardizedFileURL.path
        return path.hasPrefix("/Applications/") ? nil : "move sbr to Applications"
        #else
        return nil
        #endif
    }
}
#endif
