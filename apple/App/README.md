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
| `SbrWidgets` | iOS 18+ | Control Center and Lock Screen toggle (`cc.blit.sbr.widgets`), embedded in `Sbr` |

The App Store and TestFlight route uses the app extension on every platform.
Developer ID distribution outside the store needs the system extension, which
the user approves once in System Settings › Privacy & Security.

Both bundle IDs need the **Network Extensions** and **App Groups**
capabilities. The group is `group.cc.blit.sbr` on iOS and tvOS, and
`<TEAM_ID>.cc.blit.sbr` on macOS. On iOS the app ID also needs **Access WiFi
Information**, and `cc.blit.sbr.widgets` needs **Network Extensions**, since
the toggle loads and starts the VPN configuration itself. Packet tunnels do not
run in simulators.

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

## Personal rules

Long-pressing a connection offers "always route <domain> via…" with every
member of the profile's selectors, then the selectors themselves. The rule
matches the domain and its subdomains (`domain_suffix`) and survives profile
switches and refreshes: the app keeps the rules and passes them to the tunnel
(`SbrProviderKey.personalRules`), which inserts them into every config it runs,
including profiles it downloads itself, after the last `sniff` or `hijack-dns`
rule so sniffed domains match. A rule naming an outbound a refreshed profile no
longer has is skipped with a warning in the logs tab. When rules change, the
tunnel closes open connections to the affected domains so they reconnect on the
new route. The profiles tab lists the rules for deleting.

## Blocking traffic outside the tunnel

**Block traffic outside the tunnel** is SbrKit's leak protection (see
`apple/README.md`, "Leak protection"). It follows the active profile's
`strict_route` until the user changes it, and is off for profiles without it,
because it stops AirDrop, CarPlay, AirPlay and LAN servers and can leave the
device offline during an app update. On iOS and macOS, **allow local network**
under it lets local traffic bypass the tunnel again. tvOS gets only the route
enforcement, so a LAN server stays reachable there only through a
`route_exclude_address` entry in the profile. Changes apply on reconnect.

## Auto-connect

With auto-connect on, the VPN configuration carries on-demand rules: disconnect
on the trusted Wi-Fi networks, connect on every other interface. Disconnecting
by hand, from the app, Shortcuts or Control Center, disarms the rules
(`isOnDemandEnabled`), because the system would otherwise reconnect at once;
connecting by hand arms them again. On a trusted network that means a manual
connect is undone by the disconnect rule, so turn auto-connect off to use the
tunnel there.

On iOS, **add <network>** trusts the joined Wi-Fi. `NEHotspotNetwork` reports
it to an app with the Access WiFi Information entitlement that has installed a
VPN configuration, so no location permission is asked for. macOS gives SSIDs
only to apps with location access, so there networks are typed in.

## Shortcuts and Control Center

App Intents: **Connect**, **Disconnect**, **Toggle Tunnel** and **Select
Outbound** (a selector group and one of its members, offered from the running
tunnel). The Control Center toggle uses the same code (`Shared/`), which needs
only the saved VPN configuration and so also runs in the widget extension.

## Connections

The connections tab is the native counterpart of a Clash dashboard's
connections page. While it is on screen the app polls the tunnel once a second
(`SbrRequest.connections`, which calls `sbr_connections`) and derives each
connection's rate from the change since the previous poll. Rows sort by when
bytes last moved, so idle keep-alives sink below live transfers. The snapshot
holds at most the 200 newest connections, which keeps the message small inside
the extension's ~50 MB; the header says when more are open than are listed.

Tap a row for its destination, sniffed domain and protocol, rule and route.
Swipe it, long-press it or use the button in its details to close it
(`SbrRequest.closeConnection`, which calls `sbr_close_connection`). The filter
matches every word against the host, address, route, rule, inbound and network.

## Logs

The tunnel logs to the unified log under its bundle ID, with categories
`tunnel` (the provider) and `core` (sbr):

```sh
log stream --predicate 'subsystem BEGINSWITH "cc.blit.sbr"' --level debug
```

Core messages are `private` by default, because they contain destinations.
Override `publicLogMessages` in `PacketTunnelProvider` to see them without a
logging profile.
