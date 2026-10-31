# Changelog

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
