# SbrDemo

A minimal SwiftUI client for sbr on iOS 15+, macOS 12+ and tvOS 17+: import a
sing-box config, install and toggle the VPN, pick selector members, watch
traffic. The tunnel extension is an empty subclass of SbrKit's
`SbrPacketTunnelProvider`.

> Written on Linux and not yet built with Xcode. Expect small fixes on the
> first build; please send them back.

## 1. Build the core

```sh
cd apple
./build-xcframework.sh            # SBR_SKIP_TVOS=1 if you have no nightly toolchain
```

This produces `apple/SbrCore.xcframework`, which the `SbrKit` package wraps.

## 2. Generate the Xcode project

```sh
brew install xcodegen
cd apple/Examples/SbrDemo
# Change SBR_BUNDLE_ID in project.yml to a prefix you own, then:
SBR_TEAM_ID=ABCDE12345 xcodegen generate
open SbrDemo.xcodeproj
```

`project.yml` declares four targets:

| target | platforms | what |
|---|---|---|
| `SbrDemo` | iOS, macOS, tvOS | the app |
| `SbrTunnel` | iOS, macOS, tvOS | packet tunnel **app extension**, embedded in `SbrDemo` |
| `SbrDemoMac` | macOS | the same app for Developer ID distribution |
| `SbrTunnelSystemExtension` | macOS | the tunnel as a **system extension**, embedded in `SbrDemoMac` |

On macOS, pick one style. The app extension is the Mac App Store route. The system extension
is required for Developer ID (outside the store); it is activated on first
use, and the user approves it in System Settings › Privacy & Security.

## 3. Capabilities

The entitlements files are already written. Your App ID (in the developer
portal, or via automatic signing) needs:

- **Network Extensions**, with `packet-tunnel-provider`, or
  `packet-tunnel-provider-systemextension` for the Developer ID flavour.
- **App Groups**: `group.<SBR_BUNDLE_ID>` on iOS/tvOS, and
  `<TEAM_ID>.<SBR_BUNDLE_ID>` on macOS. The same group goes on the app and
  its tunnel.
- macOS Developer ID only: **System Extension**.

Packet tunnels don't run in the iOS or tvOS simulators. Use a device.

## 4. Use it

1. Run `SbrDemo` on a device.
2. **Config**: paste JSON (iOS/macOS clipboard button, or the text field on tvOS),
   import a file (iOS/macOS), or download it from a URL. The app validates the config
   with the same parser the tunnel uses (`Sbr.check`), and errors name the
   JSON path. The config is written to `config.json` in the App Group.
3. The first import installs the VPN profile. iOS asks to *Allow VPN
   Configurations*.
4. **Tunnel** toggle: connects through `NETunnelProviderManager`.
5. While connected, the app polls the tunnel once a second over the
   provider message channel (`SbrRequest.stats` / `.groups`). It shows live
   up/down rates, totals, connection counts and the extension's memory footprint.
   Tap a member of a `selector` group to switch (`SbrRequest.select`).
6. Importing a new config while connected hot-reloads it (`SbrRequest.reload`).
   If the `tun` inbound's addresses or routes changed, toggle the tunnel off and on so
   the new interface settings apply.

The config needs a `tun` inbound. Its fields become the tunnel's network
settings:

```json
{
  "log": { "level": "info" },
  "inbounds": [{
    "type": "tun", "tag": "tun-in",
    "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
    "mtu": 9000, "auto_route": true,
    "route_exclude_address": ["192.168.0.0/16"]
  }],
  "outbounds": [
    { "type": "selector", "tag": "proxy", "outbounds": ["ss", "direct"] },
    { "type": "shadowsocks", "tag": "ss", "server": "203.0.113.1", "server_port": 8388,
      "method": "aes-128-gcm", "password": "change-me" },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [{ "port": 53, "action": "hijack-dns" }],
    "final": "proxy"
  }
}
```

With `auto_route`, all traffic enters the tunnel except `route_exclude_address`. System
DNS points at `172.19.0.2`, the address after the tun's, so the port-53 `hijack-dns`
rule answers it.

## Logs

The tunnel logs to the unified log under its bundle ID, with categories
`tunnel` (the provider) and `core` (sbr):

```sh
log stream --predicate 'subsystem BEGINSWITH "io.sbr.demo"' --level debug
```

Core messages are `private` by default, because they contain destinations. Override
`publicLogMessages` in `PacketTunnelProvider` to see them without a
logging profile.
