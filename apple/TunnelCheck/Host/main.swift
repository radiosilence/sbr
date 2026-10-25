// Command-line driver for the tunnel check (see ../README.md).
//
//   SbrTunnelCheck up [seconds] < config.json   install/update, start, wait for connected
//   SbrTunnelCheck down [seconds]                stop and wait for disconnected
//   SbrTunnelCheck status | logs | stats
//   SbrTunnelCheck remove                         delete the VPN configuration
//
// The configuration is kept between runs (macOS asks once before an app adds
// its first VPN configuration) but is never left connected by the script.
import Foundation
import NetworkExtension
import SbrKit

let description = "sbr tunnel check"
let providerBundleID = (Bundle.main.bundleIdentifier ?? "cc.blit.sbr.check") + ".tunnel"

func say(_ line: String) {
    FileHandle.standardError.write(Data("tunnel-check: \(line)\n".utf8))
}

func fail(_ line: String) -> Never {
    say(line)
    exit(1)
}

func existing() async throws -> NETunnelProviderManager? {
    try await NETunnelProviderManager.loadAllFromPreferences().first { $0.localizedDescription == description }
}

func name(_ status: NEVPNStatus) -> String {
    switch status {
    case .invalid: "invalid"
    case .disconnected: "disconnected"
    case .connecting: "connecting"
    case .connected: "connected"
    case .reasserting: "reasserting"
    case .disconnecting: "disconnecting"
    @unknown default: "unknown(\(status.rawValue))"
    }
}

/// Polls: this is a test driver, and polling avoids depending on the run
/// loop that delivers NEVPNStatusDidChange.
func wait(_ connection: NEVPNConnection, until done: (NEVPNStatus) -> Bool, seconds: Double) async -> NEVPNStatus {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if done(connection.status) { break }
        try? await Task.sleep(nanoseconds: 50_000_000)
    }
    return connection.status
}

func lastError(_ connection: NEVPNConnection) async -> String {
    do {
        try await connection.fetchLastDisconnectError()
        return "no disconnect error recorded"
    } catch {
        return error.localizedDescription
    }
}

func up(seconds: Double) async throws {
    let config = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
    guard !config.isEmpty else { fail("up: no config on stdin") }
    let manager = try await existing() ?? NETunnelProviderManager()
    let proto = NETunnelProviderProtocol()
    proto.providerBundleIdentifier = providerBundleID
    proto.serverAddress = "127.0.0.1"
    proto.providerConfiguration = [SbrProviderKey.config: config]
    proto.disconnectOnSleep = true
    manager.protocolConfiguration = proto
    manager.localizedDescription = description
    manager.isEnabled = true
    manager.isOnDemandEnabled = false
    say("saving configuration (the first save asks the user to allow it)")
    try await manager.saveToPreferences()
    try await manager.loadFromPreferences()
    let connection = manager.connection
    if connection.status != .disconnected && connection.status != .invalid {
        connection.stopVPNTunnel()
        _ = await wait(connection, until: { $0 == .disconnected }, seconds: 10)
    }
    try connection.startVPNTunnel()
    var sawStart = false
    let status = await wait(connection, until: {
        if $0 == .connecting { sawStart = true }
        return $0 == .connected || (sawStart && $0 == .disconnected)
    }, seconds: seconds)
    guard status == .connected else {
        connection.stopVPNTunnel()
        fail("up: tunnel is \(name(status)) after \(Int(seconds)) s: \(await lastError(connection))")
    }
    say("connected")
}

func down(seconds: Double) async throws {
    guard let manager = try await existing() else { return }
    let connection = manager.connection
    connection.stopVPNTunnel()
    let status = await wait(connection, until: { $0 == .disconnected || $0 == .invalid }, seconds: seconds)
    guard status == .disconnected || status == .invalid else { fail("down: tunnel still \(name(status))") }
    say("disconnected")
}

func session() async throws -> NETunnelProviderSession {
    guard let manager = try await existing(), let session = manager.connection as? NETunnelProviderSession else {
        fail("no configuration installed")
    }
    return session
}

let args = CommandLine.arguments.dropFirst()
let seconds = args.dropFirst().first.flatMap(Double.init)
do {
    switch args.first {
    case "up":
        try await up(seconds: seconds ?? 30)
    case "down":
        try await down(seconds: seconds ?? 15)
    case "status":
        print(try await existing().map { name($0.connection.status) } ?? "not installed")
    case "logs":
        for line in try await session().send(.logs).logs ?? [] {
            print(line)
        }
    case "stats":
        let stats = try await session().send(.stats).stats
        print(String(decoding: try JSONEncoder().encode(stats), as: UTF8.self))
    case "remove":
        try await existing()?.removeFromPreferences()
        say("removed")
    default:
        fail("usage: SbrTunnelCheck up|down [seconds] | status | logs | stats | remove")
    }
} catch {
    fail("\(args.first ?? ""): \(error.localizedDescription)")
}
exit(0)
