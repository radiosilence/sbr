import AppIntents
import NetworkExtension
import SbrKit

/// Pick a selector group's outbound from Shortcuts. Talks to the running
/// tunnel, so it needs the tunnel connected.
struct SelectOutboundIntent: AppIntent {
    static let title: LocalizedStringResource = "Select Outbound"
    static let description = IntentDescription(
        "Choose the outbound a selector group routes through. The tunnel must be connected."
    )

    @Parameter(title: "Group", optionsProvider: GroupOptions())
    var group: String

    @Parameter(title: "Outbound", optionsProvider: MemberOptions())
    var member: String

    static var parameterSummary: some ParameterSummary {
        Summary("Select \(\.$member) in \(\.$group)")
    }

    func perform() async throws -> some IntentResult {
        let session = try await Self.session()
        let groups = try await session.send(.groups).groups ?? []
        guard let g = groups.first(where: { $0.tag == group && $0.isSelectable }) else {
            throw SbrError("no selector group named \(group)")
        }
        guard g.members.contains(where: { $0.tag == member }) else {
            throw SbrError("\(group) has no outbound named \(member)")
        }
        _ = try await session.send(.select(group: group, member: member))
        return .result()
    }

    static func session() async throws -> NETunnelProviderSession {
        guard let m = try await TunnelControl.manager() else { throw TunnelControl.ControlError.notInstalled }
        guard m.connection.status == .connected, let session = m.connection as? NETunnelProviderSession else {
            throw SbrError("sbr is not connected")
        }
        return session
    }

    static func selectors() async throws -> [SbrGroup] {
        try await session().send(.groups).groups?.filter(\.isSelectable) ?? []
    }
}

struct GroupOptions: DynamicOptionsProvider {
    func results() async throws -> [String] {
        try await SelectOutboundIntent.selectors().map(\.tag)
    }
}

struct MemberOptions: DynamicOptionsProvider {
    @IntentParameterDependency<SelectOutboundIntent>(\.$group) var intent

    func results() async throws -> [String] {
        let selectors = try await SelectOutboundIntent.selectors()
        if let group = intent?.group {
            return selectors.first { $0.tag == group }?.members.map(\.tag) ?? []
        }
        return Array(Set(selectors.flatMap { $0.members.map(\.tag) })).sorted()
    }
}

struct SbrShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: ConnectIntent(),
            phrases: ["Connect \(.applicationName)", "Turn on \(.applicationName)"],
            shortTitle: "Connect",
            systemImageName: "lock.shield.fill"
        )
        AppShortcut(
            intent: DisconnectIntent(),
            phrases: ["Disconnect \(.applicationName)", "Turn off \(.applicationName)"],
            shortTitle: "Disconnect",
            systemImageName: "lock.shield"
        )
        AppShortcut(
            intent: ToggleTunnelIntent(),
            phrases: ["Toggle \(.applicationName)"],
            shortTitle: "Toggle",
            systemImageName: "arrow.left.arrow.right"
        )
        AppShortcut(
            intent: SelectOutboundIntent(),
            phrases: ["Select an outbound in \(.applicationName)"],
            shortTitle: "Select Outbound",
            systemImageName: "point.3.connected.trianglepath.dotted"
        )
    }
}
