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
`<TEAM_ID>.cc.blit.sbr` on macOS. The app and its tunnel share the Keychain
access group `<TEAM_ID>.cc.blit.sbr` (`<TEAM_ID>.cc.blit.sbr.mac` for
`SbrMac`); groups under the team prefix are allowed by every provisioning
profile, so this needs no capability in the developer portal. On iOS the app ID also needs **Access WiFi
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
connect time. Switching profiles hot-reloads a running tunnel. If the `tun`
inbound's addresses or routes changed, reconnect so the new interface settings
apply.

A profile's config names its servers and carries their credentials, and a
remote profile's URL fetches the same, so both are kept in the Keychain rather
than in files: one item per profile holding the config and URL, and one for
the index of names and refresh times. Items are
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and not synchronisable, so
they stay out of iCloud backups and iCloud Keychain and cannot be restored onto
another device. The tunnel reads the active profile's item when it starts; the
VPN configuration names the item but holds no credentials. `SbrMac` is the
exception: its system extension runs as root, outside the user's Keychain, so
it still receives the config inline in the VPN configuration. Profiles stored
as files by earlier builds move into the Keychain on first launch and the files
are deleted. On tvOS, a remote profile whose cached file the system had already
purged keeps only its URL and is downloaded again.

## Erase everything

**erase everything** on the tunnel tab, after a confirmation, deletes every
Keychain item in the group (profiles, the index and the tunnel's downloaded
copy), stops and removes the VPN configuration, clears the app's settings,
personal rules, trusted networks and saved logs, and, if the tunnel is
connected, has it delete its own files (cache file, rule-set cache, session
logs). The app stays installed. Keychain items outlive deleting the app on iOS,
so erase before deleting it. What erasing leaves behind is listed in
`docs/threat-model.md` under "Device seizure".

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
