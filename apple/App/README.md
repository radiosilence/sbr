# sbr app

The sbr client for iOS 17+, macOS 14+ and tvOS 17+. It runs sing-box profiles in
a packet tunnel extension (an empty subclass of SbrKit's
`SbrPacketTunnelProvider`) and follows kōan's design language: Geist Mono,
lowercase interface text, square corners, hairlines and a single mint accent
(see `koan/docs/design/koan-theme.md`).

## Build

```sh
cd apple
./build-xcframework.sh              # SBR_SKIP_TVOS=1 without a nightly toolchain
cd App
mise exec -- xcodegen generate      # team: DEVELOPMENT_TEAM in project.yml
open Sbr.xcodeproj
```

| target | platforms | what |
|---|---|---|
| `Sbr` | iOS, macOS, tvOS | the app |
| `SbrTunnel` | iOS, macOS, tvOS | packet tunnel **app extension**, embedded in `Sbr` |
| `SbrMac` | macOS | the same app for Developer ID distribution |
| `SbrTunnelSystemExtension` | macOS | the tunnel as a **system extension**, embedded in `SbrMac` |

The App Store and TestFlight route uses the app extension on every platform.
Developer ID distribution outside the store needs the system extension, which
the user approves once in System Settings › Privacy & Security.

Both bundle IDs need the **Network Extensions** and **App Groups**
capabilities. The group is `group.cc.blit.sbr` on iOS and tvOS, and
`<TEAM_ID>.cc.blit.sbr` on macOS. Packet tunnels do not run in simulators.

The icon is drawn by `apple/tools/make-icon.swift`; re-run it to regenerate
`AppIcon.appiconset/icon-1024.png`.

## Profiles

A profile is a sing-box config. Remote profiles keep their URL and re-download
when the app comes to the front after `autoUpdateMinutes` (60, as in sing-box).
The app sets no background timers for this. Profiles can be added from:

- a `sing-box://import-remote-profile?url=<encoded>#<name>` link, which is
  sing-box's own format. `sbr://` is accepted the same way, and both schemes
  open the app;
- an `https://` URL pasted into the profiles tab;
- a JSON file.

Every profile is validated with the tunnel's parser (`Sbr.check`) before it is
saved, so an unsupported field is reported with its JSON path at import, not at
connect time. Profiles live in the App Group under `profiles/`. The active one
is copied to `config.json`, which the tunnel reads, and switching profiles
hot-reloads a running tunnel. If the `tun` inbound's addresses or routes
changed, reconnect so the new interface settings apply.

## Groups

While connected, the tunnel tab lists every `selector` group with more than one
member; one-member selectors are aliases and stay hidden. Each row shows the
member, what a nested group (such as an `auto` urltest) currently resolves to,
and its last measured latency, with the fastest in the accent colour. **test**
runs a latency test of that group and of any urltest groups inside it
(`SbrRequest.urlTest`, which calls `sbr_url_test`).

The header shows where traffic currently goes: the leaf of the outermost
selector and its latency.

## Logs

The tunnel logs to the unified log under its bundle ID, with categories
`tunnel` (the provider) and `core` (sbr):

```sh
log stream --predicate 'subsystem BEGINSWITH "cc.blit.sbr"' --level debug
```

Core messages are `private` by default, because they contain destinations.
Override `publicLogMessages` in `PacketTunnelProvider` to see them without a
logging profile.
