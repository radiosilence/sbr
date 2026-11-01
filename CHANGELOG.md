# Changelog

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
