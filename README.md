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

Which censors and surveillance programmes sbr is designed against, and what it still lacks, is in [`docs/threat-model.md`](docs/threat-model.md).

## Layout

| crate | what |
|---|---|
| `sbr-config` | sing-box JSON model. Strict like sing-box: unknown fields are errors, reported with the exact JSON path. Anything sing-box accepts that sbr hasn't implemented is **rejected**, never silently ignored, unless it can't change where traffic goes. Those cases are reported as warnings. |
| `sbr-core` | Session metadata, the router (sing-box match semantics, see below), Happy Eyeballs dialer, relay. No protocol code. |
| `sbr-dns` | The `dns` section: DNS servers and transports, DNS rules, cache, FakeIP. |
| `sbr-engine` | Inbounds, outbounds, runtime (`Instance`). |
| `sbr` | CLI, flag-compatible with `sing-box run/check/version`. |
| `sbr-reality` | REALITY TLS 1.3 client with uTLS-equivalent ClientHello fingerprints (used by `tls.reality`). |
| `sbr-apple` | C ABI (`include/sbr.h`) + `staticlib` for an xcframework: TUN fd adoption, log callback, reload, memory stats, network-change hook. |
| `apple/` | `SbrKit` Swift package (`Sbr`, `SbrPacketTunnelProvider`), `build-xcframework.sh` (iOS, macOS, Catalyst, tvOS), SwiftUI sample app. See [`apple/README.md`](apple/README.md). **The Swift code is syntax-checked only: written on Linux, not compiled with Xcode yet.** |

## Routing semantics

These match sing-box's `rule_abstract.go`. A default rule's fields fall into four OR-groups: source address, source port, destination address (domain\* + `ip_cidr`/`ip_is_private`), and destination port. Within a group, any hit counts. Every populated group must hit, and the remaining fields (`inbound`, `network`, `auth_user`, `ip_version`) are AND-ed on top. A `rule_set` whose body is one plain rule **merges** its groups into the outer rule's groups. `rule_set_ip_cidr_match_source` moves the set's CIDRs into the source group. `domain_suffix` follows sing-box: `"a.com"` matches `a.com` and its subdomains, `".a.com"` matches subdomains only. Tests for all of this are in `crates/sbr-core/src/router/tests.rs`.

Lookups are built for large rule-sets: hash sets per label for domains, Aho-Corasick for keywords, `RegexSet` for regexes, and merged sorted ranges with binary search for CIDRs.

## Compatibility today

| | supported | not yet (rejected with a path) |
|---|---|---|
| inbounds | `mixed`, `socks` (5), `http`, users/auth | **`tun`**, socks4, UDP associate, TLS on http, everything else |
| outbounds | `direct`, `block`, `socks` (4/4a/5, UDP associate, UoT), `http` (CONNECT, over TLS too), `trojan`, `vless` (+ `xtls-rprx-vision`, REALITY), `vmess` (AEAD), `shadowsocks` (AEAD + 2022, TCP + UDP, UoT v1/v2), `shadowtls` (v1/v2/v3), `anytls`, `hysteria2` (salamander, port hopping, Brutal), `tuic` (v5, all UDP relay modes, 0-RTT), `selector`, `urltest`\*, `detour` chains, `interrupt_exist_connections` | `multiplex` (sing-mux), VMess legacy (`alter_id` > 0, `aes-128-cfb`), `packet_encoding: packetaddr`, `quic` v2ray transport, HTTP/2-3 proxies, hysteria2 gecko obfs / realm, naive, ssh, tor, SIP003 plugins, … |
| endpoints | `wireguard` (userspace: boringtun + smoltcp, as an outbound) | `system: true`, flows opened by the peer, tailscale |
| route | all default-rule fields above, `clash_mode`, logical and/or, invert, actions `route` / `reject` (default, drop) / `sniff`\*\*, inline / local / remote rule-sets, source and binary (`.srs` v1–5) | `protocol`/sniffing, `process_*`, `wifi_*`, `hijack-dns`, `resolve`, `route-options`, rule-set `http_client` |
| dns | servers `local`, `hosts`, `udp` (TC→TCP), `tcp` (pipelined), `tls`, `https` (HTTP/2, POST/GET), `fakeip`, legacy `address` URLs incl. `rcode://`; `detour`/`domain_resolver` on servers, outbounds and `route.default_domain_resolver`; rules with all route matchers plus `query_type`, `outbound`, `ip_accept_any` and legacy address filtering; actions `route`, `route-options`, `reject`, `predefined`; cache (TTL, `cache_capacity`, `disable_expire`, `optimistic`, coalescing), `strategy`, `client_subnet`, `reverse_mapping` | servers `quic`, `h3`, `dhcp`, `mdns`, `tailscale`, `resolved`; `evaluate`/`respond`/response matching (1.14); uTLS/reality/ECH/pinning on DNS TLS |
| experimental | `clash_api`, `cache_file` (`v2ray_api`, `debug` ignored with a warning) | |

\* `urltest` probes like sing-box (`interval`, `tolerance`, `idle_timeout`, nested groups), with one deliberate difference, below.
\*\* `sniff` is a no-op. The current inbounds already carry the requested domain.

## sbr never phones home

sbr only contacts endpoints your config names. Where sing-box has a built-in third-party default, sbr differs:

- **`urltest` without `url`**: sing-box probes `https://www.gstatic.com/generate_204`. sbr instead measures the TCP handshake to each member's *own server* (through that member's dialer and `detour`); `hysteria2` and `tuic` report their QUIC connection's RTT estimate instead, and a `wireguard` endpoint the round trip of its last handshake (one is made if none completed in the last two minutes). This ranks servers by network distance but doesn't prove the proxy protocol works end to end; set `url` to an endpoint you control (any URL answering `HEAD`, e.g. a `204` route on your own server) for that. Members without a server (`direct`, `block`) aren't measured in that mode.
- **Clash API delay tests** (`/proxies/{name}/delay`, `/group/{name}/delay`): dashboards send `gstatic.com` by default. sbr only fetches a `url` that the config itself names as some `urltest` group's `url`; otherwise it measures the handshake as above.
- **`external_ui`**: served from the local directory only. sing-box downloads a GitHub-hosted dashboard when the directory is empty; sbr downloads only if `external_ui_download_url` is set.

Remote rule-sets are explicit config, so they are fetched (over HTTPS with the Mozilla root store, through `download_detour` or `route.final`) and cached: in `experimental.cache_file` when enabled, else in `rule-set-cache/` under the working/base directory. A cached copy is used when offline. To own your rule-sets, compile and host them yourself:

```
sbr rule-set compile geosite-mine.json            # -> geosite-mine.srs (same format sing-box writes)
scp geosite-mine.srs me@my.host:/var/www/rules/   # any static web server will do
```

```json
{ "type": "remote", "tag": "mine", "url": "https://my.host/rules/geosite-mine.srs", "update_interval": "1d" }
```

Refreshes send `If-None-Match`, so a server that sets `ETag` (nginx and caddy do for static files) answers with a cheap `304`. `sbr rule-set decompile|match|format` mirror the sing-box subcommands.

## Clash API

`experimental.clash_api` serves what yacd, metacubexd and zashboard use: `/version`, `/configs` (GET, PATCH `mode`), `/proxies[/{name}[/delay]]` (PUT selects), `/group[/{name}[/delay]]`, `/rules`, `/connections` (GET or WebSocket, DELETE all or one), `/traffic`, `/memory`, `/logs?level=` (WebSocket or streamed), `/dns/query` (A/AAAA), `/cache/fakeip/flush`, and `external_ui` under `/ui/`. `secret` is a bearer token (`?token=` for WebSockets); CORS follows `access_control_allow_origin` and `access_control_allow_private_network`. Closing a connection aborts its relay. `memory` is the process footprint (`phys_footprint` on Apple, RSS on Linux).

Connection tracking costs one small allocation per connection and a non-atomic counter update per relayed chunk (each counter has a single writer), so it is always on.

`cache_file` is a `redb` database (not file-compatible with sing-box's bbolt `cache.db`): selector choices, the Clash mode and remote rule-sets persist across restarts, namespaced by `cache_id`.

## Benchmark

`cargo run --release -p sbr-engine --example throughput -- 4 5 /path/to/sing-box`

This feeds **the same config file** to both cores. Setup: 4 streams of loopback upload on a 4-vCPU Linux VM, with client, proxy, sink and the test SS server all sharing those cores. Three runs:

| path | sbr | sing-box (HEAD, 2026-10-24) |
|---|---|---|
| socks → direct | 30–33 Gbit/s | 34–37 Gbit/s |
| socks → shadowsocks-2022 → server | 16.7–17.4 Gbit/s | 15.7–16.2 Gbit/s |

WireGuard (`cargo run --release -p sbr-engine --example wg_throughput -- /path/to/sing-box-with_wireguard [streams] [seconds]`): sbr and sing-box as clients of the same sing-box peer, same 4-vCPU box, loopback:

| streams | sbr up / down | sing-box up / down |
|---|---|---|
| 1 | 1.9 / 1.8–2.0 Gbit/s | 2.0–2.1 / 2.3 Gbit/s |
| 4 | 2.7 / 4.1 Gbit/s | 2.3 / 1.7 Gbit/s |

`cargo run --release -p sbr-engine --example quic_throughput -- /path/to/sing-box 4 5` runs both cores as hysteria2 **clients** (same config file, separate processes) against one sing-box hysteria2 server; CPU is from `/proc/<pid>/stat`. Three runs:

| hysteria2 client, 4 streams upload | throughput | client CPU per GB |
|---|---|---|
| sbr (quinn, BBR) | 1.10–2.02 Gbit/s | 3.8–4.3 s |
| sing-box (quic-go, BBR) | 0.98–1.23 Gbit/s | 4.6–5.2 s |

`cargo run --release -p sbr-engine --example proxy_bench -- /path/to/sing-box 4 5` runs both cores as **clients** (same config, socks inbound) against one sing-box server, upload and download. Three runs, Gbit/s, same 4-vCPU box shared with other builds, so the spread is wide:

| client path | sbr up | sing-box up | sbr down | sing-box down |
|---|---|---|---|---|
| vless + tls | 7.2–14.0 | 6.9–12.8 | 7.4–12.2 | 6.4–12.8 |
| trojan + tls | 7.0–8.6 | 6.7–12.4 | 6.7–7.9 | 6.2–12.4 |
| vmess aes-128-gcm | 6.9–7.4 | 6.4–11.2 | 6.1–11.9 | 6.4–11.8 |

No clear winner at this noise level. rustls reads ciphertext 4 KiB at a time and shrinks its buffer whenever it empties, so sbr puts a 20 KiB read-ahead under it (one socket read per record).

sing-box wins plain TCP relay **on Linux** because its `bufio` uses `splice(2)` zero-copy. Darwin has no splice, so on Apple targets that path is copy-vs-copy. sbr wins on encrypted relay. This is a single synthetic loopback test, so treat it as a smoke signal, not a verdict.

## TLS and V2Ray transports

The outbound `tls` object is rustls + aws-lc-rs (`crates/sbr-engine/src/tls`): `server_name`, `disable_sni`, `insecure`, `alpn`, `min_version`/`max_version` (rustls speaks 1.2 and 1.3 only), `certificate`/`certificate_path` (replaces the web PKI roots, like sing-box), `certificate_sha256` and `certificate_public_key_sha256` pins, client certificates, `handshake_timeout`, `fragment`/`record_fragment` (one split inside the SNI's first label, as sing-box effectively does; on Linux it waits for the ACK via `TCP_INFO`, elsewhere it sleeps `fragment_fallback_delay`), and `ech` with a static `config` (no DNS lookup of ECH configs, no retry with server-provided configs). `reality` goes through `sbr-reality` with its browser fingerprints.

**`utls` without `reality` is not a browser fingerprint.** rustls cannot emit Chrome's ClientHello; sbr accepts `utls.enabled` and only borrows what is cheap (ALPN `h2, http/1.1` when none is set, AES-128-GCM first). The ClientHello is rustls', which a censor can tell apart from Chrome's. Use REALITY where that matters.

Transports: `ws` (incl. early data in the path or a header), `httpupgrade`, `grpc` (the "gun" framing over one pooled HTTP/2 connection per outbound, h2c without TLS) and `http` (HTTP/2 over TLS, HTTP/1.1 without). gRPC/HTTP `idle_timeout`/`ping_timeout` are parsed but no health pings are sent (no idle timers).

Interop is tested against real sing-box servers (`crates/sbr-engine/tests/singbox.rs`): every protocol over every transport with and without TLS, 1 MiB round trips plus UDP, Vision with TLS 1.3 inside (direct mode), REALITY with and without Vision, and each TLS option. The trojan + `httpupgrade` pair is excluded: sing-box's httpupgrade server flushes `101` before hijacking, so Go's HTTP server can swallow the first byte of the tunnel and its trojan server rejects the short read. That is a server-side race any client hits.

Vision skips sing-box's 5 ms sleep before the first raw write; rustls is fed one TLS record per wakeup until the server's switch to direct, so no inner bytes ever reach the outer TLS.

## Known upstream issue worked around

`shadowsocks` 1.25 `ProxyClientStream` assumes the first write (address header + payload) fits in one AEAD chunk. A larger first write is reported as fully written while only part of it is sent: a `debug_assert!` in debug builds, silent data loss in release builds. `FirstWriteCap` in `outbound/shadowsocks.rs` caps the first write. This should be reported upstream.

## Roadmap (in order of what unblocks the iOS app)

1. **TUN inbound.** Takes the utun fd from `NEPacketTunnelProvider` (`packetFlow`'s socket). Two stacks, like sing-box:
   - `system`: rewrite TCP SYNs to a local listener and let the kernel run TCP. This is the fast path and works on macOS and iOS.
   - a userspace stack (smoltcp) for when `system` can't be used.
   UDP NAT table, then FakeIP.
2. **DNS.** Done except QUIC-based servers (`quic`, `h3`) and FakeIP persistence in the cache file.
3. ~~**TLS layer** → trojan, vless, vmess, http over TLS, reality~~ (done; `multiplex` next).
4. ~~**QUIC** (quinn) → hysteria2, tuic.~~ Done; see `outbound/quic/`.
5. **wireguard** (boringtun or gotatun).
6. ~~Binary `.srs` rule-sets and remote rule-sets~~ (done).
7. ~~`urltest` probing, clash API~~ (done).
8. Linux `splice(2)` fast path for raw TCP↔TCP.

What "drop-in compatible" means here: sing-box is about 174k lines of Go before counting its `sing-*` libraries, so sbr is not trying to clone everything. The target is the protocol and config subset that real iOS/macOS client configs use. Everything outside that subset fails loudly at `check`, never at 2 a.m.
