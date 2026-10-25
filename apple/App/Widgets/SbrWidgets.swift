import AppIntents
import SwiftUI
import WidgetKit

@main
struct SbrWidgets: WidgetBundle {
    var body: some Widget {
        TunnelToggle()
    }
}

/// Control Center, Lock Screen and Action button toggle for the tunnel.
struct TunnelToggle: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: TunnelControl.controlKind, provider: Value()) { on in
            ControlWidgetToggle("sbr", isOn: on, action: SetTunnelIntent()) { on in
                Label(on ? "on" : "off", systemImage: on ? "lock.shield.fill" : "lock.shield")
            }
        }
        .displayName("sbr tunnel")
        .description("connect or disconnect the tunnel.")
    }

    struct Value: ControlValueProvider {
        var previewValue: Bool { false }
        func currentValue() async throws -> Bool { await TunnelControl.isOn() }
    }
}
