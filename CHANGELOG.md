# Changelog

## Unreleased

### Added

- `ssh` outbound: OpenSSH banner and algorithm order, pinned host keys, one connection per outbound with a channel per stream (README, "SSH and sing-mux").
- `multiplex` (sing-mux: smux, yamux, h2mux, padding, Brutal speed exchange) on vless, vmess, trojan and shadowsocks.
- `sbr_check_warnings` in the C API; the app lists the active profile's warnings.
- Config warnings for DNS servers that resolve outside the tunnel with a `tun` inbound: `local`, and plain UDP/TCP without a detour.

### Changed

- Opening a remote profile link asks first and names the host it downloads from; the download sends no User-Agent.
- Deleting the active profile stops the tunnel and deletes the extension's cache, rule-sets, logs and its copy of the profile.
- Erase everything also deletes the extension's files when the tunnel is off.
- With leak protection on, an on-demand rule restarts a tunnel the system stopped.
- urltest data probes send no User-Agent.
- `SbrConfigStore` keeps `config.json` out of backups.
