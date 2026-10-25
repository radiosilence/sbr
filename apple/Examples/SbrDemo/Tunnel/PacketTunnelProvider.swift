import SbrKit

/// Everything lives in SbrKit's base class: config from the App Group, network
/// settings from the tun inbound, utun fd, path monitoring, app messages.
/// Override `coreOptions`, `loadConfiguration()` or `handle(_:)` to customise.
final class PacketTunnelProvider: SbrPacketTunnelProvider {}
