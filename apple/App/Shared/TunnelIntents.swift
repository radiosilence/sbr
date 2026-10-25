import AppIntents

struct ConnectIntent: AppIntent {
    static let title: LocalizedStringResource = "Connect"
    static let description = IntentDescription("Start the sbr tunnel with the active profile.")

    func perform() async throws -> some IntentResult {
        try await TunnelControl.setOn(true)
        return .result()
    }
}

struct DisconnectIntent: AppIntent {
    static let title: LocalizedStringResource = "Disconnect"
    static let description = IntentDescription(
        "Stop the sbr tunnel. With auto-connect on, it stays off until you connect again."
    )

    func perform() async throws -> some IntentResult {
        try await TunnelControl.setOn(false)
        return .result()
    }
}

struct ToggleTunnelIntent: AppIntent {
    static let title: LocalizedStringResource = "Toggle Tunnel"
    static let description = IntentDescription("Connect sbr if it is off, otherwise disconnect it.")

    func perform() async throws -> some IntentResult & ReturnsValue<Bool> {
        let on = !(await TunnelControl.isOn())
        try await TunnelControl.setOn(on)
        return .result(value: on)
    }
}

/// The Control Center and Lock Screen toggle's action.
struct SetTunnelIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Set Tunnel"
    static let isDiscoverable = false

    @Parameter(title: "On")
    var value: Bool

    func perform() async throws -> some IntentResult {
        try await TunnelControl.setOn(value)
        return .result()
    }
}
