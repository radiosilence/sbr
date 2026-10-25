# Tunnel check

An automated end-to-end check of sbr inside a real macOS packet tunnel:

```sh
mise run test:apple-tunnel        # or apple/TunnelCheck/tunnel-check.sh
```

Every other test runs sbr on a Linux TUN, a root-owned utun, or behind SOCKS.
None of them runs inside a Network Extension, where the process's own sockets
are scoped to the physical interface and never enter the tunnel. That
difference shipped a build in which no TCP connection through the iOS tunnel
completed (fixed by binding the system stack's listener with `IP_BOUND_IF`).
A root `sbr run` on a utun does not reproduce it; only an NE does, so this
check runs one.

## What runs

`SbrTunnelCheck.app` is a windowless host app with the shipping
`PacketTunnelProvider` (`apple/App/Tunnel`) embedded as a packet tunnel app
extension. Its bundle IDs (`cc.blit.sbr.check`, `.tunnel`) are separate from
the real app's, so it never touches that app's VPN configuration. SbrKit is
compiled from `apple/Sources/SbrKit` and linked against the release
`libsbr_apple.a` for the host architecture, so the check neither needs nor
rebuilds `apple/SbrCore.xcframework`.

The script passes the test config inline (`providerConfiguration["config"]`),
starts the tunnel, runs the checks and always stops it on exit. The tun
inbound has `auto_route: false` and owns only `198.19.250.0/24`: no default
route and no DNS settings are pushed, and the script fails if either changes.
Test destinations are addresses in that subnet that route rules rewrite:

| check | path |
|---|---|
| route | `198.19.250.0/24` is on a utun; default route and system DNS untouched |
| TCP | HTTPS fetch (`--resolve` to `.20`, rewritten to the site's real IP), `direct` outbound: the NE's own egress |
| DNS | `dig @198.19.250.2`: `hijack-dns`, then UDP to 1.1.1.1 |
| UDP | echo of 1, 1200 and 4000 bytes (fragmented at MTU 1280) through a `socks` outbound to a local `sbr` |
| UDP | STUN binding request to `stun.cloudflare.com:3478`, `direct` |
| bulk | 32 MiB, sha256-checked, over `direct` to loopback (the TUN stack alone) and through the socks hop, each at least 20 MB/s |

The local servers (HTTP, UDP echo, `sbr run` with a `mixed` inbound) listen on
loopback only. The tun matches the user's profile where it matters: MTU 1280,
`stack: mixed`.

## Signing and the one-time approval

Running an NE needs a development-signed app. The build uses automatic
signing with `-allowProvisioningUpdates -allowProvisioningDeviceRegistration`
and the App Store Connect API key in `~/.appstoreconnect/private_keys/`
(override with `APPLE_API_KEY_PATH`, `APPLE_API_KEY_ID`,
`APPLE_API_ISSUER_ID`), which registers the Mac and creates the App IDs and
profiles on first build.

The first `up` adds a VPN configuration named "sbr tunnel check", and macOS
asks the logged-in user to allow it. Until someone clicks Allow, the script
fails with a message saying so. The configuration is kept afterwards, so later
runs are unattended. `SbrTunnelCheck remove` deletes it.

## Driver

`build/dd/Build/Products/Debug/SbrTunnelCheck.app/Contents/MacOS/SbrTunnelCheck`:

- `up [seconds] < config.json`: install or update the configuration, start it,
  wait until connected;
- `down [seconds]`, `status`, `remove`;
- `logs`, `stats`: the extension's in-memory log tail and counters
  (`SbrRequest.logs`, `.stats`).

The unified log has the rest:
`log stream --predicate 'subsystem BEGINSWITH "cc.blit.sbr.check"' --level debug`.
