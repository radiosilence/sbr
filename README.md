# sbr

A [sing-box](https://github.com/SagerNet/sing-box)-compatible proxy core in Rust, built to be embedded in iOS and macOS apps.

```
sbr run -c config.json        # same flags, same config as sing-box
sbr check -c config.json
```

## Why Rust core + thin Swift shell (and not pure Swift)

- **The iOS Network Extension memory ceiling is the main problem.** Packet tunnel extensions are jetsam-killed at roughly 50 MB. Go's GC'd heap plus goroutine stacks is the reason sing-box on iOS needs constant tuning. A Rust core has no GC, deterministic buffers, and costs about 32 KB per relayed connection by default in the extension (`sbr-apple`).
- **Ecosystem.** Tokio, rustls/aws-lc (hardware AES-GCM on Apple silicon), quinn (QUIC for hysteria2/tuic) and smoltcp all exist and are fast. In Swift, every protocol would be written from scratch on top of Network.framework, and the code would only run on Apple platforms.
- **One core, everywhere.** The same crate runs as a Linux server, a macOS CLI, and inside a `NEPacketTunnelProvider` behind a C ABI. Swift stays responsible for what only Swift can do: NetworkExtension, UI and Keychain.

## Layout

| crate | what |
|---|---|
| `sbr-config` | sing-box JSON model. Strict like sing-box: unknown fields are errors, reported with the exact JSON path. Anything sing-box accepts that sbr hasn't implemented is **rejected**, never silently ignored, unless it can't change where traffic goes. Those cases are reported as warnings. |
| `sbr-core` | Session metadata, the router (sing-box match semantics, see below), Happy Eyeballs dialer, relay. No protocol code. |
| `sbr-engine` | Inbounds, outbounds, runtime (`Instance`). |
| `sbr` | CLI, flag-compatible with `sing-box run/check/version`. |
| `sbr-apple` | C ABI (`include/sbr.h`) + `staticlib` for an xcframework. |
| `apple/` | `SbrKit` Swift package, `build-xcframework.sh`, example `PacketTunnelProvider`. **Untested: written on Linux, not compiled with Xcode yet.** |

## Routing semantics

These match sing-box's `rule_abstract.go`. A default rule's fields fall into four OR-groups: source address, source port, destination address (domain\* + `ip_cidr`/`ip_is_private`), and destination port. Within a group, any hit counts. Every populated group must hit, and the remaining fields (`inbound`, `network`, `auth_user`, `ip_version`) are AND-ed on top. A `rule_set` whose body is one plain rule **merges** its groups into the outer rule's groups. `rule_set_ip_cidr_match_source` moves the set's CIDRs into the source group. `domain_suffix` follows sing-box: `"a.com"` matches `a.com` and its subdomains, `".a.com"` matches subdomains only. Tests for all of this are in `crates/sbr-core/src/router/tests.rs`.

Lookups are built for large rule-sets: hash sets per label for domains, Aho-Corasick for keywords, `RegexSet` for regexes, and merged sorted ranges with binary search for CIDRs.

## Compatibility today

| | supported | not yet (rejected with a path) |
|---|---|---|
| inbounds | `mixed`, `socks` (5), `http`, users/auth | **`tun`**, socks4, UDP associate, TLS on http, everything else |
| outbounds | `direct`, `block`, `socks` (5), `http` (CONNECT), `shadowsocks` (AEAD + 2022), `selector`, `urltest`\*, `detour` chains | vmess, vless (+reality), trojan, hysteria2, tuic, wireguard, anytls, shadowtls, naive, ssh, tor, … |
| route | all default-rule fields above, logical and/or, invert, actions `route` / `reject` (default, drop) / `sniff`\*\*, inline + local *source* rule-sets | binary `.srs`, remote rule-sets, `protocol`/sniffing, `process_*`, `wifi_*`, `hijack-dns`, `resolve`, `route-options` |
| dns | system resolver (warns) | the whole `dns` section |
| experimental | ignored with warning | clash API, cache file |

\* `urltest` doesn't probe yet. It is pinned to the first member.
\*\* `sniff` is a no-op. The current inbounds already carry the requested domain.

## Benchmark

`cargo run --release -p sbr-engine --example throughput -- 4 5 /path/to/sing-box`

This feeds **the same config file** to both cores. Setup: 4 streams of loopback upload on a 4-vCPU Linux VM, with client, proxy, sink and the test SS server all sharing those cores. Three runs:

| path | sbr | sing-box (HEAD, 2026-10-24) |
|---|---|---|
| socks → direct | 30–33 Gbit/s | 34–37 Gbit/s |
| socks → shadowsocks-2022 → server | 16.7–17.4 Gbit/s | 15.7–16.2 Gbit/s |

sing-box wins plain TCP relay **on Linux** because its `bufio` uses `splice(2)` zero-copy. Darwin has no splice, so on Apple targets that path is copy-vs-copy. sbr wins on encrypted relay. This is a single synthetic loopback test, so treat it as a smoke signal, not a verdict.

## Known upstream issue worked around

`shadowsocks` 1.25 `ProxyClientStream` assumes the first write (address header + payload) fits in one AEAD chunk. A larger first write is reported as fully written while only part of it is sent: a `debug_assert!` in debug builds, silent data loss in release builds. `FirstWriteCap` in `outbound/shadowsocks.rs` caps the first write. This should be reported upstream.

## Roadmap (in order of what unblocks the iOS app)

1. **TUN inbound.** Takes the utun fd from `NEPacketTunnelProvider` (`packetFlow`'s socket). Two stacks, like sing-box:
   - `system`: rewrite TCP SYNs to a local listener and let the kernel run TCP. This is the fast path and works on macOS and iOS.
   - a userspace stack (smoltcp) for when `system` can't be used.
   UDP NAT table, then FakeIP.
2. **DNS.** The `dns` section: servers (udp/tcp/tls/https/quic), rules, cache, `hijack-dns`, FakeIP.
3. **TLS layer** (rustls + aws-lc-rs, uTLS-style ClientHello fingerprints) → trojan, vless, vmess, http/socks over TLS. Then **reality**.
4. **QUIC** (quinn) → hysteria2, tuic.
5. **wireguard** (boringtun or gotatun).
6. Binary `.srs` rule-sets and remote rule-sets. Real-world configs depend on these heavily.
7. `urltest` probing, clash API (dashboards and the iOS app UI use it).
8. Linux `splice(2)` fast path for raw TCP↔TCP.

What "drop-in compatible" means here: sing-box is about 174k lines of Go before counting its `sing-*` libraries, so sbr is not trying to clone everything. The target is the protocol and config subset that real iOS/macOS client configs use. Everything outside that subset fails loudly at `check`, never at 2 a.m.
