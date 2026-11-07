# Changelog

## 0.3.0

### Added

- **Connections, logs and settings in the GPUI app.** The connections page polls only while it shows, with per-connection rates, closing by connection or domain, and personal rules added from a connection. The logs page keeps the last session's lines on disk. The settings page holds auto-connect, leak protection, the TCP stack, verbose logs, a reduced diagnose (DNS, HTTPS, exit address, IPv6 and WebRTC exposure) and erase, confirmed with koan-kit's question sheet.
- **Profiles in the GPUI app.** sbr-gui reads and writes profiles in the Keychain items the Swift app used, so an existing install keeps its profiles and settings, and installs the VPN configuration (on-demand rules, trusted Wi-Fi, leak protection, personal rules). Configs are checked and remote profiles downloaded by sbr-apple directly, with the tunnel's anonymous HTTP client.

### Changed

- **The iOS and macOS app is rewritten in Rust with GPUI and kōan's koan-kit, and requires iOS 26 and macOS 26.** The tvOS app keeps SwiftUI. The new app draws its throughput graph, gauges and bars on the GPU between polls, so they move at the display's rate while the page itself is drawn only as figures arrive. It reads the Keychain items and VPN configuration the Swift app wrote, so an existing install keeps its profiles. Not carried over: scanning a profile's QR code, sending a profile to an Apple TV, the macOS app's Shortcuts actions, and the diagnose page's QUIC, bulk-download and system-resolver checks.
- **The packet tunnel provider is Rust.** `SbrTunnelProvider` (`crates/sbr-tunnel-ext`) replaces SbrKit's `SbrPacketTunnelProvider` in the iOS, tvOS and macOS app extension and the macOS system extension, calling the core directly instead of through the C ABI, with the same app messages, Keychain items and files. `build-xcframework.sh` also builds `SbrTunnel.xcframework`, which the extensions link; SbrKit no longer has a provider class.

## 0.2.9

### Fixed

- **The macOS app no longer uses a quarter of a core while its window is open.** The traffic and connection rates animated each change with a rolling-digit transition, which SwiftUI renders on the CPU by redrawing the text layer every frame; at one update a second this kept the app at 25–35% CPU. The figures now change in place, and unchanged groups and stats from the poll are no longer republished.

## 0.2.8

### Added

- **Automatic fragmentation also reacts to silence.** A ClientHello with no answer for 6 s now counts as a cut, as a reset does, so filters that drop blocked flows instead of resetting them (Egypt's often do) turn fragmentation on; such a handshake used to wait out the 15 s timeout and fail.
- **`urltest` retries a failed connect on the next member.** When the selected member cannot connect, the connection is made once more through the member the group would pick without it, and the group switches there if that works, instead of failing every connection until the next check.

### Tests

- **SSH tests start their sshd reliably.** The test sshd is restarted on a fresh port when another test takes the one it was given, instead of the test failing with "connection refused".

## 0.2.7

### Changed

- **One Homebrew tap.** Install from `radiosilence/tap`, which holds every radiosilence formula and cask; `brew update` moves installs from the old per-project tap.

## 0.2.6

### Fixed

- **Failed connects no longer block a working proxy.** A burst of failed connects through a member now triggers a probe and blocks the member only if that fails, as a burst of early closes already did; dead destinations had been enough to mark a working proxy "blocked: can't connect".
- **macOS: the network extension activates after a reinstall.** The app now carries its own notarisation ticket, so macOS can verify the system extension of a copy put back from the Bin, where it used to fail with "code signature invalid". When verification still fails, sbr says to reinstall from the disk image.

## 0.2.5

### Fixed

- **tvOS: focus reaches connect from a group.** Moving up from a group's test button lands on connect/disconnect instead of stopping.

## 0.2.4

### Internal

- **TestFlight gets tvOS builds.** Every push to `main` that passes uploads the tvOS app alongside the iOS one; tvOS builds had only been uploaded by hand.

## 0.2.3

### Breaking

- **The SSH outbound no longer supports RSA keys.** RSA client keys, RSA `host_key` pins and RSA `host_key_algorithms` are rejected when the profile loads, and RSA host keys are not negotiated. Support relied on the `rsa` crate, whose private-key operations are not constant-time (RUSTSEC-2023-0071, no fixed release). Use an ed25519 or ECDSA key; a server offering only an RSA host key cannot be reached.

### Internal

- **Faster xcframework builds.** tvOS builds on stable Rust with its prebuilt std instead of nightly `-Zbuild-std`, the unused Intel simulator slices are gone, and every target builds in one cargo invocation so their LTO passes overlap.
- **Builds use the latest stable Rust.** `rust-version` is removed from the manifests, so dependency resolution targets the toolchain in use instead of holding crates back for an old compiler.

## 0.2.2

### Added

- **Homebrew cask.** `brew install --cask radiosilence/sbr/sbr` installs the Mac app; each release moves the cask to its disk image once the image is notarised.
- **Mac app icon and disk image layout.** The Developer ID macOS app has an icon drawn for macOS's unmasked tile, and its disk image opens to a laid-out window with the app beside an Applications link, instead of a bare folder.

### Changed

- **Mac menu bar in title case.** The menu bar menu uses macOS capitalisation ("Open sbr", "Launch at Login") instead of the app's lowercase style, which stays for the window.

### Fixed

- **The Mac app's tunnel activates.** The Developer ID app's system extension now declares `CFBundlePackageType` `SYSX`, without which macOS refused to activate it ("does not appear to belong to any extension categories") and the app could not connect.

### Internal

- **One macOS runner per run.** The macOS tests and the Apple build share one job instead of holding two macOS runners, and a release push skips that job, since its pull request ran it, leaving the release build as its only macOS job while the checks run.

## 0.2.1

### Security

- **Deleting the active profile clears it from the VPN configuration.** The macOS system extension build kept the deleted profile there inline, credentials included, and anything that started the tunnel connected with it.

### Fixed

- **DNS servers detoured through a `direct` outbound get the cleartext warning.** They leave the tunnel exactly as servers without a detour do.
- **SSH connections no longer leak channels or fail after a cancelled connect.** A channel the server confirms after its connect was cancelled is closed; a dial carries on, and keeps its timeout, when the connect that started it is cancelled; a dial overtaken by a network change hands its connects to a fresh one; the idle close no longer closes a connection a new channel has just picked.
- **Leak protection no longer starts the tunnel by itself.** Changing a setting before the first connect could arm the on-demand rule; it now arms only while the tunnel is on. A failed erase of the tunnel's files is reported instead of passing silently.
- **WireGuard TCP connections no longer keep fixed buffers committed.** They run on sbr's userspace TCP, whose buffers hold memory only for bytes in flight or unread. On iOS the WireGuard outbound's TCP buffers are capped at 8 MiB in total, where each connection previously kept up to 512 KiB with no overall limit. Loss inside the tunnel is repaired with SACK-based recovery, which smoltcp lacks.
- **tvOS builds again.** tvOS and watchOS prohibit `sigaltstack`, which the alternate signal stacks from #27 called unconditionally; there they are skipped.

### Tests

- **The direct-detour DNS warning test expects both warnings.** #36 merged before its test change.

### Internal

- **Faster releases.** The macOS release build starts alongside the checks rather than after them, the disk image is notarised once, after the release is published, instead of the app and then the image beforehand, and release pull requests no longer hold two macOS runners for a signing check. A release cancels pending pull request runs and superseded runs on main to free macOS runners.

## 0.2.0

### Added

- **macOS menu bar app.** sbr runs from the menu bar on macOS: connect, switch profiles and launch at login without opening a window. macOS 15 or later is required.
- **Signed macOS releases.** Each release publishes a notarised disk image of the Developer ID build, with its system extension, on GitHub.
- **Config warnings in the app.** `sbr_check_warnings` returns a config's warnings and the app lists the active profile's, including new ones for DNS servers that resolve outside the tunnel: `local`, and plain UDP/TCP without a detour.
- **sing-mux multiplexing.** `multiplex` on vless, vmess, trojan and shadowsocks, over smux, yamux or h2mux, with padding, UDP and the Brutal speed exchange. Set `max_connections` to share sessions between concurrent streams.
- **SSH outbound.** sing-box's `ssh` outbound, with pinned host keys and an OpenSSH 9.9 banner and algorithm order. One connection per outbound carries a channel per stream; an idle connection costs no wakeups.

### Security

- **urltest probes send no User-Agent.** Behind REALITY, the probe's `sbr/<version>` reached the site the server fronts for.
- **Deleting the active profile removes what the tunnel kept.** The tunnel stops and its cache, rule-sets, logs and downloaded copy of the profile are deleted. Erase everything also deletes the tunnel's files when it is off.
- **Remote profile links ask before downloading.** The confirmation names the host, and the download sends no User-Agent, which named the app.
- **Leak protection restarts a stopped tunnel.** With leak protection on, an on-demand rule brings back a tunnel the system stopped, instead of leaving traffic outside it.

### Changed

- **`SbrConfigStore` keeps `config.json` out of backups.** It holds server credentials.

### Fixed

- **Connecting the Developer ID macOS build no longer hangs while its system extension awaits approval.** It reports that approval is needed and links to the settings pane.
- **A failed VPN configuration save no longer leaves the previous profile in place.** The next connect saves it again, and a running tunnel takes the new profile and rules either way.

### Tests

- **A flaky urltest idle test.** It counted probes before one already in flight had landed.

### Internal

- **`just release` and `just changelog`.** The release and changelog commands run through just, as in kōan.
