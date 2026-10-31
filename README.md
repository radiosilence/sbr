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
| `sbr-reality` | TLS 1.3 client with browser ClientHellos: REALITY, and the default handshake for every other TCP TLS client. |
| `sbr-apple` | C ABI (`include/sbr.h`) + `staticlib` for an xcframework: TUN fd adoption, log callback, reload, remote profile refresh through the tunnel, memory stats, network-change hook. |
| `apple/` | `SbrKit` Swift package (`Sbr`, `SbrPacketTunnelProvider`), `build-xcframework.sh` (iOS, macOS, Catalyst, tvOS), SwiftUI sample app. See [`apple/README.md`](apple/README.md). CI builds the app for iOS, tvOS and macOS. |

## Routing semantics

These match sing-box's `rule_abstract.go`. A default rule's fields fall into four OR-groups: source address, source port, destination address (domain\* + `ip_cidr`/`ip_is_private`), and destination port. Within a group, any hit counts. Every populated group must hit, and the remaining fields (`inbound`, `network`, `auth_user`, `ip_version`) are AND-ed on top. A `rule_set` whose body is one plain rule **merges** its groups into the outer rule's groups. `rule_set_ip_cidr_match_source` moves the set's CIDRs into the source group. `domain_suffix` follows sing-box: `"a.com"` matches `a.com` and its subdomains, `".a.com"` matches subdomains only. Tests for all of this are in `crates/sbr-core/src/router/tests.rs`.

Lookups are built for large rule-sets: hash sets per label for domains, Aho-Corasick for keywords, `RegexSet` for regexes, and merged sorted ranges with binary search for CIDRs.

## Compatibility today

| | supported | not yet (rejected with a path) |
|---|---|---|
| inbounds | `mixed`, `socks` (5), `http`, users/auth | **`tun`**, socks4, UDP associate, TLS on http, everything else |
| outbounds | `direct`, `block`, `socks` (4/4a/5, UDP associate, UoT), `http` (CONNECT, over TLS too), `trojan`, `vless` (+ `xtls-rprx-vision`, REALITY), `vmess` (AEAD), `shadowsocks` (AEAD + 2022, TCP + UDP, UoT v1/v2), `shadowtls` (v1/v2/v3), `anytls`, `hysteria2` (salamander, port hopping, Brutal), `tuic` (v5, all UDP relay modes, 0-RTT), the `xhttp` transport (sbr extension, below), `selector`, `urltest`\*, `detour` chains, `interrupt_exist_connections` | `multiplex` (sing-mux), VMess legacy (`alter_id` > 0, `aes-128-cfb`), `packet_encoding: packetaddr`, `quic` v2ray transport, HTTP/2-3 proxies, hysteria2 gecko obfs / realm, naive, ssh, tor, SIP003 plugins, … |
| endpoints | `wireguard` (userspace: boringtun + smoltcp, as an outbound) | `system: true`, flows opened by the peer, tailscale |
| route | all default-rule fields above, `clash_mode`, logical and/or, invert, actions `route` / `reject` (default, drop) / `sniff`\*\*, inline / local / remote rule-sets, source and binary (`.srs` v1–5) | `protocol`/sniffing, `process_*`, `wifi_*`, `hijack-dns`, `resolve`, `route-options`, rule-set `http_client` |
| dns | servers `local`, `hosts`, `udp` (TC→TCP), `tcp` (pipelined), `tls`, `https` (HTTP/2, POST/GET), `fakeip`, legacy `address` URLs incl. `rcode://`; `detour`/`domain_resolver` on servers, outbounds and `route.default_domain_resolver`; rules with all route matchers plus `query_type`, `outbound`, `ip_accept_any` and legacy address filtering; actions `route`, `route-options`, `reject`, `predefined`; cache (TTL, `cache_capacity`, `disable_expire`, `optimistic`, coalescing), `strategy`, `client_subnet`, `reverse_mapping` | servers `quic`, `h3`, `dhcp`, `mdns`, `tailscale`, `resolved`; `evaluate`/`respond`/response matching (1.14); reality/ECH/pinning on DNS TLS |
| experimental | `clash_api`, `cache_file` (`v2ray_api`, `debug` ignored with a warning) | |

\* `urltest` probes like sing-box (`interval`, `tolerance`, `idle_timeout`, nested groups), with one deliberate difference (below) and one addition: it notices members that complete a handshake but stop carrying data, and drops them ([failover](#failover-that-sees-post-handshake-blocking)).
\*\* `sniff` is a no-op. The current inbounds already carry the requested domain.

## Failover that sees post-handshake blocking

Censors now let connections start and then kill them: Russia's TSPU freezes a flow after about 16–20 KB downstream, Iran resets REALITY after its handshake, the GFW has reset all of TCP/443 for an hour. A TCP handshake or a `HEAD` still succeeds under all of these, so sing-box's `urltest` keeps choosing a dead path until someone switches by hand. sbr adds two checks to every `urltest` member, with no new config fields (a profile stays valid for sing-box):

- **A data probe** after each successful delay probe: it pulls 64 KiB through the member on one connection, well past the freeze threshold. With `url` set it is one `GET` of that URL with `Range: bytes=0-65535`, so point `url` at a file of at least 64 KiB on your own server for the probe to be conclusive (a `204` route still works for delay, but its data probe proves nothing). Without `url`, it asks the member's own server, through the member, for its own address: a REALITY or trojan server hands that to its fallback site, and sbr pipelines `GET /` (TLS, no certificate check) until 64 KiB of responses arrive. Hysteria2 and TUIC members use the server's TCP 443. If your REALITY `dest` is someone else's site, set `url`, or the probe reaches that site from your server. Data that stops for 5 s mid-transfer, or a reset, demotes the member at once; anything else (a server with no fallback, too small a site) is inconclusive and changes nothing.
- **Passive detection** in the relay. A connection reset or closed before the remote sent anything, a request with no reply at all for 8 s, and a failed connect each count against the member; failures from three different destinations within 60 s demote it (one dead website cannot). Closes before any data are weaker evidence, since some servers do that on purpose and a starved relay ends flows the same way: a burst made only of them triggers the group's delay probe and a data probe through the member, and demotes it only if one fails; a passing probe clears the burst. Closes are not counted at all while another connection on the member is receiving data and has moved 64 KiB, or within 60 s of one finishing. Silence for 8 s in the middle of a TLS record, or while the client waits for a reply, looks like a freeze but also like a long poll, so it only triggers a data probe (at most one per 30 s; after a false alarm, none for 5 min). A connection that moves 64 KiB proves the path and clears its record.

A demoted member is skipped by every `urltest` group for 120 s (TSPU's residual blocks last 120–600 s), doubling on each relapse up to 30 min, and comes back only after a probe passes once that time is up. The group switches as soon as a member is demoted, not at its next interval. Connections on the demoted member that are stalled or have received nothing are closed, so apps retry on the new path at once instead of after their own timeouts; connections still moving data are left alone, because the freeze is per flow and those flows are getting through. `interrupt_exist_connections: true` still closes everything through the group on any switch. A network change (`sbr_network_changed`) forgets all of this and re-probes. The state is in the Clash API (`alive`, `degraded`, `reason`, `retry_in` on each proxy) and in `sbr_groups` (see `sbr.h`).

Probing is shaped so it does not identify the client. sing-box probes every member at once on a fixed period; for a profile with six REALITY members on one server that is six TLS handshakes to one address within milliseconds, each with a different SNI, repeated exactly every `interval`. No browser does that, and Russia's 2026 rules reportedly count more than three parallel handshakes to one endpoint. sbr probes members that share a server host one after another, 200–1200 ms apart, and different hosts in parallel; adopts the first member that answers when the group has not picked one yet, instead of waiting for the slowest; and varies each period by up to 20% either way. A member probed within half the interval (by another group, say) is not probed again.

Costs: passive detection is a timestamp per relayed chunk and a timer per connection that runs only while data is moving or a reply is owed, so idle connections cost no wakeups. Data probes run only when the group probes (its interval, while in use) or when traffic looks wrong.

## QUIC ClientHello scrambling

The GFW and Russia's TSPU decrypt QUIC v1 Initial packets, whose keys anyone can derive from the connection ID, and block on the TLS SNI; neither reassembles CRYPTO data across datagrams. `hysteria2` without Salamander and `tuic` therefore scramble the ClientHello by default, as quic-go 0.52+ (and so sing-box, Xray and Hysteria) do: the SNI is cut in half and its two halves travel in different Initial packets. rustls' default key shares make the ClientHello longer than one packet, which is what lets the halves land in separate datagrams; a ClientHello that fits in one packet only gets its CRYPTO frames reordered.

quinn builds Initials itself, so the rewrite is a socket wrapper under quinn (`outbound/quic/initial.rs`) that decrypts the Initials carrying the ClientHello, moves bytes between their CRYPTO frames and re-encrypts them, keeping packet numbers and sizes. quinn is unpatched. `"disable_client_hello_scrambling": true` on the outbound (an sbr extension, named after quic-go's `QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING`) turns it off. With Salamander it never runs, because Salamander already hides the whole packet.

The Initial does not resemble Chrome's: 1200-byte datagrams (Chrome sends 1250), a 20-byte destination and 8-byte source connection ID (Chrome: 8 and 0), rustls' ClientHello and quinn's transport parameters, and no Chrome-style interleaving of PING and PADDING frames between CRYPTO frames. Like the hysteria and quic-go clients it imitates, it is fingerprintable as a non-browser QUIC stack.


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

`experimental.clash_api` serves what yacd, metacubexd and zashboard use: `/version`, `/configs` (GET, PATCH `mode`), `/proxies[/{name}[/delay]]` (PUT selects), `/group[/{name}[/delay]]`, `/rules`, `/connections` (GET or WebSocket, DELETE all or one), `/traffic`, `/memory`, `/logs?level=` (WebSocket or streamed), `/dns/query` (A/AAAA), `/cache/fakeip/flush`, and `external_ui` under `/ui/`. `secret` is a bearer token (`?token=` for WebSockets); CORS follows `access_control_allow_origin` and `access_control_allow_private_network`. Without a `secret`, sbr refuses requests from origins not listed in `access_control_allow_origin` (other than the API's own `/ui`) and requests whose `Host` is a domain other than `localhost`, so a web page cannot read connections or switch the proxy through the browser; sing-box allows every origin in that case. Closing a connection aborts its relay. `memory` is the process footprint (`phys_footprint` on Apple, RSS on Linux).

Connection tracking costs one small allocation per connection and a non-atomic counter update per relayed chunk (each counter has a single writer), so it is always on.

`cache_file` is a `redb` database (not file-compatible with sing-box's bbolt `cache.db`): selector choices, the Clash mode and remote rule-sets persist across restarts, namespaced by `cache_id`.

## Benchmark

`cargo run --release -p sbr-engine --example throughput -- 4 5 /path/to/sing-box`

This feeds **the same config file** to both cores. Setup: 4 streams of loopback upload on a 4-vCPU Linux VM, with client, proxy, sink and the test SS server all sharing those cores. Three runs:

| path | sbr | sing-box (HEAD, 2026-10-24) |
|---|---|---|
| socks → direct | 30–33 Gbit/s | 34–37 Gbit/s |
| socks → shadowsocks-2022 → server | 16.7–17.4 Gbit/s | 15.7–16.2 Gbit/s |

WireGuard (`cargo run --release -p sbr-engine --example wg_throughput -- /path/to/sing-box-with_wireguard [streams] [seconds] [runs]`): sbr and sing-box as clients of the same sing-box peer, same 4-vCPU box, loopback. These numbers predate the connected socket and egress thread; Apple silicon numbers are in `BENCHMARKS.md`:

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

## TUN: two TCP stacks

`stack: system` (and `mixed`, and an unset `stack`) lets the kernel run the TUN's TCP through a NAT onto a local listener. `stack: gvisor` runs sbr's own userspace TCP (`crates/sbr-tun/src/tcp`), which needs no socket on the TUN side and so no kernel routing or interface scoping to get replies back into the tunnel. sing-box's `mixed` means system TCP with gVisor UDP; sbr's UDP path is the same under every value, so `mixed` runs system TCP. Embedders can override the config with `Settings::tun_stack` (an sbr extension); the Apple framework sets it to userspace on iOS and tvOS. Picking a group member by hand through the Apple framework closes the connections running through that group, so the change applies to live traffic at once. [ARCHITECTURE.md](ARCHITECTURE.md#tun-tcp-stacks) explains the design and why it is not smoltcp.

Where the userspace stack behaves differently, on purpose:
- A segment for a connection it does not know, such as one an app opened before the tunnel restarted, gets a reset, so the app reconnects at once. The system stack drops it and the app waits out its own timeouts.
- With the default `defer_handshake`, the app's connect completes only once the outbound has connected, and a failed connect or a `reject` rule resets it, so apps fall back immediately instead of watching an established connection die. A config that sniffs before routing still completes the handshake first, because sniffing needs the app's first bytes. A `reject` with `drop` answers nothing at all, like a black hole.
- Buffers live in the process (the kernel's do not count against an iOS extension). They are elastic, so idle connections hold none, capped per connection (128 KiB each way on iOS, 1 MiB elsewhere) and, on iOS, at 8 MiB for all connections together.

## TUN: fragments

A UDP tunnel nested inside sbr's (OpenVPN or AWS Client VPN over UDP, at the usual MTU 1280) sends datagrams larger than the TUN MTU, so the kernel fragments them. sing-box's kernel `system` stack drops these, which is why such profiles use `stack: mixed`. sbr reassembles them under both TCP stacks: it reassembles IPv4 and IPv6 fragments (`crates/sbr-tun/src/frag.rs`) and fragments its own replies that exceed the MTU, acting as the sending host; that applies to IPv6 too, since sbr is the source of those packets.

The reassembly table holds at most 128 datagrams and 2 MiB, and a datagram not completed within 5 s is discarded. The timeout is checked when fragments arrive rather than by a timer, so an idle table costs no wakeups. Any overlap abandons the datagram (RFC 5722, applied to IPv4 as well); exact duplicates are ignored. TCP fragments, which the kernel does not normally produce at the TUN MTU, are reassembled, translated, and fragmented again under sbr's own IP ID, because every translated flow shares one address pair and the apps' IDs could collide in the kernel's reassembly. IPv6 Hop-by-Hop, Routing (with no segments left) and Destination Options headers are skipped to reach TCP or UDP.

## Roaming between Wi-Fi and cellular

When the default path moves to another network, the extension calls `sbr_network_migrate` (after re-pinning sockets with `sbr_set_default_interface`). Each live hysteria2 connection moves to a fresh UDP socket on the new path, with the same Salamander and port-hopping wrappers, and QUIC connection migration (the server validates the new address) keeps every stream and UDP session on it running: a download or call through hysteria2 continues across the handover. A connection whose server sends nothing to the new socket within 4 s is closed, so the next request dials again over the new path. Everything else is reset as `sbr_network_changed` does: UDP sessions on other outbounds are dropped, and TCP-based outbounds (REALITY, trojan, …) cannot migrate, so their connections fail and apps reconnect. hysteria2 through a `detour` is not migrated. `crates/sbr-engine/tests/upstream_servers.rs::hysteria2_apernet_migration` checks this against apernet hysteria with the old path blackholed.

## TUN on Apple: failing fast and staying out of its own tunnel

A Network Extension's own sockets are scoped to the physical interface and never enter its tunnel. The system stack terminates TCP in a kernel listener on the TUN address, so on Apple platforms that listener is bound to the utun with `IP_BOUND_IF`; otherwise its SYN-ACKs leave by Wi-Fi or cellular and no TCP connection through the tunnel completes, while UDP, written straight to the utun descriptor, keeps working. With `includeAllNetworks` (strict mode, from `strict_route` or the app's toggle) the system does not reliably exempt the extension's sockets, so the extension also pins sbr's outbound sockets to the current physical interface, as `auto_route` does on desktops. With `auto_route` and an IPv4-only `tun`, IPv6 is still routed into the tunnel on an address the engine refuses, so it fails over to IPv4 instead of leaving by the physical interface. apple/README.md, "Leak protection", covers what strict mode changes, its costs and the device test matrix.

Clients should fall back quickly rather than wait out timeouts:

- A UDP flow that is rejected by a rule or whose outbound cannot connect is answered with ICMP or ICMPv6 port unreachable from the remote address, as a router would. A QUIC client then falls back to TCP at once. sing-box's gVisor stack behaves the same way; its kernel stack does not.
- VLESS with the Vision flow refuses UDP/443, as Xray's client does. QUIC inside Vision's TLS-over-TCP is slow and conspicuous, while the browser's TCP fallback is carried by Vision's splice.
- A DNS `strategy` of `ipv4_only` or `ipv6_only` also removes the excluded family's `ipv4hint`/`ipv6hint` from HTTPS and SVCB answers. Safari and Network.framework connect to those hints directly, so filtering only AAAA still handed out IPv6 addresses.

When the extension stops without being asked, the app shows the system's reason. Panics and fatal signals are appended to a file in the extension's container, and a heartbeat records time and memory use every 10 s; the next start reports either the breadcrumbs or the last heartbeat (a memory kill leaves no other trace) in the logs tab. The logs tab's diagnose checks run DNS, TCP, HTTP/3 and a bulk download from the app, through the tunnel like any other app's traffic. While connected they also look for leaks: the exit address and country (Cloudflare's trace, from the host the bulk test already uses), whether the system resolver is the tun's DNS address, and whether an IPv6-only request escapes when the tun has no IPv6. WebRTC is not tested, since a browser's WebRTC follows the same routes as everything else.

## TLS and V2Ray transports

The outbound `tls` object (`crates/sbr-engine/src/tls`): `server_name`, `disable_sni`, `insecure`, `alpn`, `min_version`/`max_version` (1.2 and 1.3 only), `certificate`/`certificate_path` (replaces the web PKI roots, like sing-box), `certificate_sha256` and `certificate_public_key_sha256` pins, client certificates, `handshake_timeout`, `fragment`/`record_fragment` (below), and `ech` (below). `reality` goes through `sbr-reality` with its browser fingerprints. With `reality`, `disable_sni`, `ech` and a `max_version` below 1.3 are refused (sing-box refuses the first two as well; REALITY cannot work with any of them), while `insecure`, `certificate`, pins and client certificates are ignored with a warning, as sing-box ignores them. A client the REALITY server does not accept has been relayed to the cover site, so before failing it requests `/` from `server_name` like the imitated browser (HTTP/2, or HTTP/1.1 if that was negotiated) and reads the response for up to three seconds, as sing-box and Xray do; a client that closes straight after the handshake would stand out.

`ech` takes `config` or `config_path` (sing-box's `ECH CONFIGS` PEM). Without either, sbr looks up the HTTPS record of `query_server_name`, else of the TLS server name, and uses its `ech` parameter, as sing-box does. The query goes through sbr's DNS router, so it follows the profile's DNS servers and rules and never reaches the local network's resolver in cleartext; without a `dns` section there is no router to ask, and the outbound fails rather than fall back to the system resolver. The record is kept for its TTL. When a server rejects the offer and sends `retry_configs` (after a key rotation, say), sbr retries once on a fresh connection with them and keeps them until the record would have expired, so a stale static config recovers without a profile update. Go's crypto/tls, and so a sing-box server, never sends `retry_configs`; CDNs and OpenSSL do. ECH uses rustls' ClientHello, not a browser's, and is refused with `utls` enabled, with REALITY, and on QUIC outbounds.

**Every TCP TLS client sends a browser's ClientHello by default**, `utls` or not: trojan, vless, vmess, http over TLS, the v2ray transports, ShadowTLS's camouflage handshake, AnyTLS and DoH. rustls' own ClientHello is rare on the wire and so cheap to block; sing-box without `utls` sends Go's, which is no better. The handshake is `sbr-reality`'s TLS 1.3 client, with rustls' certificate verifiers (web PKI roots, `certificate`, pins, `insecure`), HelloRetryRequest, certificate compression (brotli, zlib, zstd), ALPS and an empty Certificate for optional client auth. `utls.fingerprint` picks the browser:

| `fingerprint` | ClientHello | JA4 |
|---|---|---|
| `chrome` (default; `chrome_pq`, `chrome_psk*` too) | Chrome 155, captured from the browser | `t13d1517h2_8daaf6152771_cb7bf5808d99` |
| `safari`, `ios` | Apple Network.framework, captured from macOS 27 URLSession (equal to uTLS `HelloSafari_26_3`) | `t13d2013h2_a09f3c656075_7f0f34a4126d` |
| `firefox` | Firefox 148 (uTLS `HelloFirefox_148`, as Xray-core 26.10 sends) | `t13d1715h2_5b57614c22b0_a54fffd0eb61` |
| `random` | one of the three, chosen at start | |

`edge`, `360`, `qq`, `android`, `randomized` and `chrome_padding_psk_shuffle` are refused rather than mapped to another browser. sing-box 1.14.4 and Xray 26.10 both still send Chrome 133 (`t13d1516h2_8daaf6152771_d8a2da3f94cd`) for `chrome`, which current Chrome no longer matches. `ios` deliberately departs from uTLS's iOS 14 profile: it is six years stale and lacks the ML-KEM share that current REALITY servers require.

What the browser handshake does not do, and why it falls back to rustls when the options ask for it: TLS 1.2 (`max_version: "1.2"`; it is offered, as Chrome does, but a server that picks it fails with an error naming the fix), client certificates, and ECH with a real config (rustls implements it; the browser profiles send GREASE ECH). With `utls.enabled: true` those combinations are errors, and `utls.enabled: false` selects rustls explicitly. Sessions are never resumed, so every connection is a full handshake with no PSK; a returning browser would often resume, but tickets would also link connections to each other. DoT keeps rustls unless `utls` is enabled: port 853 identifies it regardless, and no browser speaks it.

QUIC (hysteria2, tuic) still sends quinn's rustls ClientHello. quinn's crypto layer is pluggable (`quinn_proto::crypto::Session`), so `sbr-reality`'s handshake could drive it, but a Chrome-like Initial also needs Chrome's transport parameters, their order and GREASE, and its packet layout, which quinn encodes itself. Salamander hides hysteria2's Initial entirely; TUIC has no such cover.

### ClientHello fragmentation

SNI filters in China, Iran's lighter deployments and most commercial DPI read the server name from the first TCP segment, or the first TLS record, of a connection and reset it if the name is listed. The GFW parses one record at a time and does not reassemble records, so a ClientHello split across records passes it; TCP segmentation helps only when no segment carries the whole name ([Niere et al., CCS 2023](https://doi.org/10.1145/3576915.3624372)). The `tls` keys are sing-box's (1.12+):

- `record_fragment: true` splits the ClientHello into several TLS records. sbr cuts the host name strictly inside every label but the last (`www.example.com` → `w|ww.exa|mple.com`), so neither a record nor a segment carries a whole label of the registered name; sing-box cuts only the first label, anywhere in it. Free: no extra round trips.
- `fragment: true` also sends the ClientHello as two TCP segments, cut at the first of those points. On Linux it waits for the first segment's ACK (`TCP_INFO`); elsewhere it sleeps `fragment_fallback_delay` (default 500 ms) once per handshake.
- `route-options` rules with `tls_fragment` / `tls_record_fragment` / `tls_fragment_fallback_delay` do the same to the first write of a routed connection, which is how a `direct` route can carry an app's own TLS past an SNI filter.

**Automatic mode (sbr extension).** With neither key set, a TLS, REALITY or v2ray-transport outbound starts unfragmented and steps up when a handshake is reset or closed before the server sent a single byte, which is what SNI filtering looks like from the client: first to `record_fragment`, then to both. The failed handshake is retried on a fresh connection at once, so the app sees one slower connection rather than an error. The level is per outbound and lasts until the network changes (`sbr_network_changed`). A server that answers anything at all, even an alert, never triggers it, and a level is never raised past both. `"disable_auto_fragment": true` in `tls` turns it off (sing-box rejects the key); with `fragment` or `record_fragment` configured it is off already. ShadowTLS, AnyTLS and DNS-over-TLS/HTTPS clients do not have it.

**Varied splits (sbr extension).** A censor that sees the same split on every connection can learn it: Iran's DPI reassembles fragments, and China's education network has been reported to block one combination of record and segment splitting ([net4people #550](https://github.com/net4people/bbs/issues/550)). `fragment_split` in `tls`, or `tls_fragment_split` in a `route-options` rule, replaces `fragment` / `record_fragment` (setting both is an error, and sing-box rejects the key) with Xray-like controls, drawn afresh for every connection from the system CSPRNG:

```json
"tls": {"enabled": true, "fragment_split": {"mode": "both", "pieces": "3-6", "delay": "10-30"}}
```

- `mode`: `"record"` (TLS records, one write), `"segment"` (TCP segments of the one record) or `"both"` (each record its own segment; the default).
- `pieces`: how many pieces, 2 to 64; or `length`: bytes of the handshake message per piece, 1 to 16384. Not both. With neither, the cuts are `record_fragment`'s, one inside every label but the last. One cut always falls strictly inside the host name, wherever the others land.
- `delay`: milliseconds between segments, 0 to 10000. Unset, each segment waits for its ACK on Linux and `fragment_fallback_delay` elsewhere, as `fragment` does; every gap pays that wait, so many segments make a slow handshake.

Ranges take Xray's form: `3`, `"3"` or `"3-6"`. It disables the automatic mode for that outbound like the sing-box keys do. AnyTLS honours `fragment`, `record_fragment` and `fragment_split` too; ShadowTLS refuses them, since its server reads the ClientHello from one record.

Tested against a model filter (`crates/sbr-engine/tests/common/sni_censor.rs`) that resets a connection whose first segment reveals the name, either in the first record only or in all records joined (`tests/fragment.rs`), and against Xray-core REALITY behind that filter (`upstream_servers.rs`, `xray_reality_fragmented_client_hello`). `tests/fragment.rs` also records the ClientHello as it arrives, one read per segment, and checks the segment and record boundaries `fragment_split` produced against a rustls server.

Transports: `ws` (incl. early data in the path or a header), `httpupgrade`, `grpc` (the "gun" framing over one pooled HTTP/2 connection per outbound, h2c without TLS), `http` (HTTP/2 over TLS, HTTP/1.1 without) and `xhttp` (below). gRPC/HTTP `idle_timeout`/`ping_timeout` are parsed but no health pings are sent (no idle timers).

### XHTTP (sbr extension)

sing-box has no XHTTP, but the Xray servers sbr targets do, and XHTTP is the Xray-native way to multiplex and to run through a CDN (see `docs/threat-model.md`). sbr adds it as a v2ray `transport` with `"type": "xhttp"` (or `"splithttp"`), usable by `vless`, `trojan` and `vmess`. A sing-box binary rejects such a config. The object takes Xray's `xhttpSettings` field names, defaults and validation unchanged, so settings can be copied from an Xray server or share link:

```json
"transport": {
  "type": "xhttp",
  "path": "/xh",
  "mode": "auto",
  "host": "cdn.example.com",
  "headers": {"User-Agent": "firefox"},
  "xPaddingBytes": "100-1000",
  "scMaxEachPostBytes": "500000-1000000",
  "scMinPostsIntervalMs": 30,
  "xmux": {"maxConnections": "2-4", "hMaxRequestTimes": "600-900", "hMaxReusableSecs": "1800-3000"},
  "downloadSettings": {"server": "203.0.113.7", "server_port": 443, "tls": {"enabled": true}, "transport": {"type": "xhttp", "path": "/xh"}}
}
```

- `mode`: `stream-one` (one request each way in a single exchange), `stream-up` (a `GET` download and a streaming `POST` upload joined by a session ID), `packet-up` (the same `GET`, with the upload cut into numbered `POST`s that survive buffering proxies and CDNs). `auto` is `packet-up`, or over REALITY `stream-one` (`stream-up` with `downloadSettings`), as in Xray.
- HTTP version, as Xray decides it: REALITY is HTTP/2; TLS is HTTP/2 unless `alpn` is exactly `["http/1.1"]` (HTTP/1.1, one connection per stream, `Connection: close`, chunked uploads) or `["h3"]` (HTTP/3 over quinn); no TLS is HTTP/1.1.
- Also accepted: `xPaddingObfsMode`, `xPaddingKey`, `xPaddingHeader`, `xPaddingPlacement`, `xPaddingMethod` (`repeat-x`, `tokenish`), `uplinkHTTPMethod`, `sessionIDPlacement`/`sessionIDKey`/`sessionIDTable`/`sessionIDLength`, `seqPlacement`/`seqKey`, `uplinkDataPlacement`/`uplinkDataKey`/`uplinkChunkSize` (packet-up data in headers or cookies), `noGRPCHeader`, `xmux.maxConcurrency`/`cMaxReuseTimes`/`hKeepAlivePeriod`, and `extra` (everything but `host`, `path` and `mode`, as share links carry it). The server-side fields `noSSEHeader`, `scMaxBufferedPosts`, `scStreamUpServerSecs` and `serverMaxHeaderBytes` are accepted and have no effect on a client, as in Xray.
- Requests carry Xray's browser defaults: a Chrome identity (`User-Agent`, client hints, `Sec-Fetch-*`, `Priority`) unless `headers.User-Agent` is `firefox`, `safari`, `edge`, `curl`, `golang` or a literal string, and padding in `Referer: <url>?x_padding=XXX` unless `xPaddingObfsMode` moves it.

Deviations from Xray:

- `downloadSettings` is sing-box-shaped (`server`, `server_port`, `tls`, and a `transport` that must be `xhttp`) rather than an Xray `streamSettings` object, and the same applies inside `extra`.
- HTTP/2 keep-alive pings are sent only when `xmux.hKeepAlivePeriod` is positive. Xray pings every 45 s by default, which wakes the radio on idle connections. Idle pooled connections are retired after 300 s when the next request picks a connection, not by a timer. HTTP/3 connections keep quinn's 10 s keep-alive while open and close 30 s after their last request.
- No `Accept-Encoding: gzip` is sent (Go adds it and decompresses transparently), and Xray's browser dialer does not exist. The HTTP/2 and QUIC framing is h2's and quinn's, not a browser's; over TLS the ClientHello is rustls' (see above), over REALITY it is the configured uTLS fingerprint.
- As in Xray, a client with `uplinkDataPlacement: cookie` defaults its key to `x_data` while a server with `auto` reads `X-Data`; set `uplinkDataKey` on one side.

Interop is tested against Xray-core 26.10.21 (`crates/sbr-engine/tests/xhttp.rs`, binary from `$SBR_XRAY` or `PATH`): every mode plus `auto` over HTTP/2 with TLS, HTTP/1.1 with TLS, HTTP/2 over REALITY, cleartext HTTP/1.1 and HTTP/3, each with a 1 MiB byte-exact round trip, four parallel 64 KiB streams sharing XMUX slots, and XUDP; non-default session, sequence and padding placements with tokenish padding; packet-up data in headers and in cookies; `extra`; `downloadSettings` (HTTP/1.1 upload, HTTP/2 download); plain VLESS UDP; and a wrong path failing promptly.

`cargo run --release -p sbr-engine --example xhttp_bench -- <xray> [streams] [seconds] [rounds]` compares each mode over REALITY with VLESS + REALITY + Vision on the same Xray server; results are in `BENCHMARKS.md`.

Interop is tested against real sing-box servers (`crates/sbr-engine/tests/singbox.rs`): every protocol over every transport with and without TLS, 1 MiB round trips plus UDP, Vision with TLS 1.3 inside (direct mode), REALITY with and without Vision, and each TLS option. The trojan + `httpupgrade` pair is excluded: sing-box's httpupgrade server flushes `101` before hijacking, so Go's HTTP server can swallow the first byte of the tunnel and its trojan server rejects the short read. That is a server-side race any client hits.

The servers the jaritanet gateway actually runs are tested too (`crates/sbr-engine/tests/upstream_servers.rs`, binaries from `$SBR_XRAY` / `$SBR_HYSTERIA` or `PATH`): Xray-core VLESS + REALITY + Vision with a loopback `dest` behind `xver: 1`, several `serverNames` and a guest blackhole, and apernet hysteria2 on several ports with salamander and `userpass`. They cover 1 MiB round trips, Vision's direct copy, XUDP and plain VLESS UDP, fragmented hy2 datagrams, wrong credentials failing promptly, unauthenticated probes reaching `dest` while sbr clients are connected, and the whole `buildProfile` shape (urltest, both selectors, a Shadowsocks exit detoured through `entry-select`). Server behaviour those tests pin down:

- XTLS/REALITY servers (Xray 26.10) refuse a ClientHello without an X25519MLKEM768 share ahead of X25519. Every sbr profile offers it, `ios` included (Apple's current stack). Xray's and sing-box's own `ios` (uTLS `HelloIOS_14`) has no ML-KEM and is refused by such servers: it reaches `dest` like a probe.
- Xray 26 `freedom` blackholes private, loopback and CGNAT destinations (`100.64.0.0/10` included) for vless inbounds unless `finalRules` allow them, so a profile that sends DNS to `127.0.0.1` or tailnet traffic over a REALITY leaf is refused by the server; over hy2 the same traffic works.
- apernet hysteria2 serialises each downlink UDP message, header included, into a 4096-byte buffer, so a reply payload of more than about 4080 bytes is never delivered.
- With a rustls `dest` that compresses its certificate chain (RFC 8879, which every browser profile offers), sing-box 1.14 and Xray 26.10 REALITY servers never complete the handshake. The tests' handshake targets send uncompressed chains.

Vision skips sing-box's 5 ms sleep before the first raw write; rustls is fed one TLS record per wakeup until the server's switch to direct, so no inner bytes ever reach the outer TLS.

## Known upstream issue worked around

`shadowsocks` 1.25 `ProxyClientStream` assumes the first write (address header + payload) fits in one AEAD chunk. A larger first write is reported as fully written while only part of it is sent: a `debug_assert!` in debug builds, silent data loss in release builds. `FirstWriteCap` in `outbound/shadowsocks.rs` caps the first write. This should be reported upstream.

## CI

Every push and pull request to `main` runs `cargo fmt`, clippy and the tests on Linux and macOS, with the interop tests running against sing-box, Xray and hysteria on macOS, and builds the xcframework and the Apple app. Each push to `main` that passes uploads an iOS build to TestFlight. See [`apple/README.md`](apple/README.md#ci).

## Releases

A change records itself as a fragment under `changelog.d/unreleased/` (see [`changelog.d/README.md`](changelog.d/README.md)), not in `CHANGELOG.md`, so open pull requests never conflict over it. `mise run release patch|minor|major|X.Y.Z` opens the release pull request: it bumps the workspace version and the Apple apps' `MARKETING_VERSION` together, and turns the fragments into that version's changelog section. That pull request also signs and packages the Developer ID macOS app, without notarising it, so a signing problem shows before anything is released.

Merging it is what releases: CI sees the push change the version to one with no GitHub release yet, notarises and staples the macOS app and its disk image, and publishes the release with the disk image, creating the `vX.Y.Z` tag. Nothing else creates tags. A failed release is retried by re-running the failed jobs (a re-run of a failed notarisation job takes up the submission already made), or by running CI/CD by hand on `main` with **release** ticked. It needs the `RELEASE_TOKEN` secret, a token with `contents: write` on this repository, because GitHub does not let the workflow token create a tag on a commit that changes a workflow.

## Website

`site/` is [sbr.blit.cc](https://sbr.blit.cc), including the app's privacy policy: plain HTML and one stylesheet, with the font served from the site itself, so a visit makes no third-party request. The benchmark charts are inline SVG rendered from `site/src/benchmarks.json` by `site/src/charts.py` (`mise run charts` in `site/`); update that file when `BENCHMARKS.md` changes, since CI fails when the committed page differs from what the data renders. `mise run preview` serves it on port 3000. Every push to `main` publishes `ghcr.io/radiosilence/sbr-site:sha-<commit>` (`.github/workflows/site.yml`), which jaritanet deploys.

## Roadmap (in order of what unblocks the iOS app)

1. **TUN inbound.** Takes the utun fd from `NEPacketTunnelProvider` (`packetFlow`'s socket). Two stacks, like sing-box:
   - `system`: rewrite TCP SYNs to a local listener and let the kernel run TCP.
   - `gvisor`: sbr's userspace TCP, independent of kernel routing on the TUN side. Always used on iOS and tvOS, where the system stops a packet-tunnel extension running the kernel-listener path under sustained load.
   UDP NAT table, then FakeIP.
2. **DNS.** Done except QUIC-based servers (`quic`, `h3`) and FakeIP persistence in the cache file.
3. ~~**TLS layer** → trojan, vless, vmess, http over TLS, reality~~ (done; `multiplex` next).
4. ~~**QUIC** (quinn) → hysteria2, tuic.~~ Done; see `outbound/quic/`.
5. **wireguard** (boringtun or gotatun).
6. ~~Binary `.srs` rule-sets and remote rule-sets~~ (done).
7. ~~`urltest` probing, clash API~~ (done).
8. Linux `splice(2)` fast path for raw TCP↔TCP.

What "drop-in compatible" means here: sing-box is about 174k lines of Go before counting its `sing-*` libraries, so sbr is not trying to clone everything. The target is the protocol and config subset that real iOS/macOS client configs use. Everything outside that subset fails loudly at `check`, never at 2 a.m.

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. Use it for anything; keep the copyright notice.
