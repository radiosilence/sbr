# Security audit, October 2026

## Scope

The whole Rust workspace and the Apple app (`apple/`), against four adversaries: a hostile network (on-path, injecting, actively probing), a hostile or compromised proxy server, hostile local apps sending arbitrary packets into the TUN or connecting to local inbounds, and hostile configuration (profiles, remote rule-sets). Device seizure was considered for data at rest. Areas covered: memory safety (every `unsafe` block, the C ABI in `sbr-apple`, the `libc` ioctls and `recvmsg_x`), parsers on attacker input, resource exhaustion against the roughly 50 MB iOS extension limit, cryptographic use, leaks, the Clash API, dependencies, and fuzzing.

`docs/threat-model.md` covers censorship techniques; this document covers implementation weaknesses.

## Method

- Manual review of every crate and of the Swift sources. Each finding was checked against the code; none were exploited against a live deployment.
- `cargo audit` and `cargo deny check advisories bans sources`.
- `cargo fuzz` (`fuzz/`, nightly) on the highest-risk parsers, five minutes per target with ASan:

  | target | covers | executions | crashes |
  |---|---|---|---|
  | `tun_packet` | IPv4/IPv6/TCP/UDP parse, NAT rewrite, fragment reassembly | 5.1 M | 0 |
  | `sniff` | TLS, HTTP, QUIC, DNS and other sniffers | 6.1 M | 0 |
  | `dns_wire` | DNS decoding and the message helpers | 1.7 M | 0 |
  | `srs` | binary rule-set decoder | 2.7 M | 0 |
  | `reality_handshake` | REALITY client against arbitrary server bytes; handshake message parsers | 1.6 M | 0 |

  The default RSS limit hides memory amplification, so the `srs` target was rerun with `-malloc_limit_mb=128` after the fix below. VLESS, VMess and trojan have no fuzz target: their decoders are private to `sbr-engine` and reach only AEAD-protected or length-bounded data. Run a target with `cargo +nightly fuzz run -O <target>`.

## Findings

Severity reflects impact for the intended users: a remote or local denial of service that kills the iOS extension also drops the tunnel, and without leak protection traffic then leaves in the clear.

### High

| finding | status |
|---|---|
| UDP session queues were bounded in packets, not bytes: one local app could queue hundreds of megabytes across 512 sessions while an outbound handshake was pending. | Fixed, 278c359 |
| `hijack-dns` spawned a task per query with no limit, and the upstream ID allocator could loop forever under a mutex once 65,536 queries were pending. | Fixed, 278c359 |
| A small `.srs` file with a chain-shaped domain trie decoded to gigabytes; count fields reserved memory up front; the decompression cap was 256 MiB. | Fixed, a0cfead |
| The FakeIP table grew without bound (an IPv6 /18 never wraps) as a local app resolved unique names. | Fixed, 8c6e93c |
| Without a `secret`, the Clash API allowed every CORS origin and did not check `Host`, so any web page could read connection destinations and switch the proxy off. | Fixed, 9ad0a4d |

### Medium

| finding | status |
|---|---|
| The platform tun fd leaked when start failed, and two `tun` inbounds both adopted it (double close). | Fixed, 9eec6dd |
| WireGuard moved its peer endpoint on a cookie reply, which anyone knowing the server's public key can forge. | Fixed, edf6c58 |
| ShadowTLS v3 accepted any TLS 1.2 ServerHello as authorized. | Fixed (strict mode), edf6c58 |
| AnyTLS: unbounded heartbeat reply tasks; a server-supplied padding scheme could force unbounded uploads. | Fixed, edf6c58 |
| WebSocket pongs accumulated without bound when the server stopped reading. | Fixed, edf6c58 |
| `tls.enabled: false` with `reality`, `utls` or `ech` enabled silently sent the proxy header in cleartext. | Fixed (rejected), edf6c58 |
| DNS cache entries were bounded in count only; an answer with thousands of records was cached whole. | Fixed, 8c6e93c |
| The plain UDP DNS transport accepted answers from any source address. | Fixed, 8c6e93c |
| Remote rule-sets followed https→http redirects and could be 64 MiB in memory on iOS. | Fixed, a0cfead |
| A failed REALITY authentication closes the connection without the HTTP request a browser would send. | #14 |
| VMess AEAD chunk counter wraps after 65,536 chunks (nonce reuse on unencrypted transports). | Fixed without TLS (the stream ends); wraps inside TLS/REALITY like v2ray, 6181872 |
| Outbound handshakes (ShadowTLS, AnyTLS, SOCKS, HTTP CONNECT, WebSocket, httpupgrade) and local inbound handshakes have no deadline. | Fixed (30 s connect deadline in dispatch, 15 s inbound handshake, slot taken at accept), b3b3cc7 |
| TUN TCP NAT port space can be exhausted by one app; the table occupies about 5 MiB per family up front. | #17 |
| QUIC and h2 receive windows, TUIC uni streams and QUIC UDP reassembly exceed the iOS memory budget. | #18 |
| QUIC outbounds trust the platform certificate store; every other path uses bundled roots. | #19 |
| Apple app: profile URL and credentials are backed up and readable after first unlock; profile download cached on disk; link import fetches without confirmation; deleting a profile leaves its secrets. | #10 |
| With no `dns` section, hijacked queries are resolved by the system resolver outside the tunnel; leak protection is opt-in. | #6 |

### Low

| finding | status |
|---|---|
| `lru` 0.16 unsound (RUSTSEC-2026-0253); not reachable in sbr. | Fixed, 9748e97 |
| Oversized UDP payloads wrapped the 16-bit length fields; IPv4 could panic in `fragment()`. | Fixed, 9eec6dd |
| `Device::try_send` and `recv_batch_x` relied on callers for bounds. | Fixed, 9eec6dd |
| gRPC (gun) varint length overflow. | Fixed, edf6c58 |
| TUIC domains over 255 bytes spilled into the port field. | Fixed, edf6c58 |
| ShadowTLS tag comparisons were not constant-time; tlsmini's `insecure` verifier skipped handshake signatures. | Fixed, edf6c58 |
| An invalid TUIC uuid was echoed into errors that reach logs. | Fixed, edf6c58 |
| DNS answers matched by ID only; TTLs unclamped; quadratic `truncate_to`; unbounded `getaddrinfo` pool use. SS-2022 UDP replay window reset; TUIC association ID wrap; SOCKS5 UDP source unchecked; REALITY ignoring some `tls` fields; silent packet-loop panic. | #20 |

## Checked and sound

- REALITY server authentication: HMAC-SHA512 of the ed25519 key under the ECDH-derived auth key, compared in constant time; CertificateVerify and Finished verified; nothing beyond the handshake is sent when authentication fails. Record layer and handshake reassembly are bounded; nonces never repeat within a key.
- rustls paths: `insecure` and pinning still verify handshake signatures; hostnames are checked against `server_name`; ECH fails closed.
- RNG: keys, nonces, session IDs and padding that must be unpredictable come from aws-lc. Non-CSPRNG uses (WebSocket masks, hop ports, Salamander salt) are not secret.
- TUN parsing, rewriting and reassembly: every length and offset checked before use; fragment table bounded in entries, bytes, ranges and time.
- Sniffers, DNS wire parsing and SOCKS/HTTP inbound parsing: bounds-checked and size-limited.
- C ABI: every export catches panics; NULL and invalid UTF-8 handled; strings round-trip through `CString`; the tun fd is duplicated with `F_DUPFD_CLOEXEC`. `sbr_stop` must not race other calls on the same instance; SbrKit serialises them.
- Connection tracking keeps no closed-connection history; the Clash API UI rejects path traversal.
- At the default log level, destinations appear only in rejection and connect-failure messages, which the Apple log forwarding marks private.
- `cargo deny`: no advisories or disallowed sources after the `lru` update; only duplicate versions.

# Follow-up: memory, leaks and performance, 31 October 2026

## Scope and method

The whole Rust workspace again, for memory and resource leaks (tasks, sockets and timers nothing stops; caches and queues bounded in entries but not bytes), per-connection memory against the iOS extension's ~50 MB, hot-path allocation and copies, and memory safety in `unsafe` code and the C ABI. Two reviewers read every crate independently and then each other's half.

- AddressSanitizer (nightly, `aarch64-apple-darwin`) over the test suites of every crate: no reports.
- `crates/sbr-engine/tests/resources.rs`: 200 proxied connections through two instances under a counting allocator: heap per idle connection, what 20 of them still hold after carrying a megabyte each, and tasks, file descriptors and heap after a second identical round, against the first.

## Findings

All fixed in #27 unless marked otherwise.

| finding | area |
|---|---|
| A closed hysteria2, TUIC or xhttp/h3 connection kept its QUIC endpoint until the next dial: UDP socket, driver and port hopper (a re-resolve and rebind every hop interval) ran on an idle device. | QUIC |
| `probe_rtt` opened an unpooled connection per urltest probe and left it open for the idle timeout; under TUIC 0-RTT it reported quinn's initial estimate, not a measurement. | QUIC |
| h2 accepted 16 MiB of response headers and h3 any amount; h3 buffers every non-DATA frame whole before its size check. A frame guard under `h3_quinn` now refuses them. | HTTP/2, HTTP/3 |
| UDP sessions whose outbound connection died stayed alive while the app kept sending, black-holing the flow until it fell silent. | UDP |
| On a write timeout the AnyTLS session closed only after the writer lock was released, so a queued writer could write after a partial frame, which the server would parse as frames. Writes had no deadline at all before this audit. | AnyTLS |
| AnyTLS: a 64 KiB write buffer per stream at open; receive queues capped at 32 frames of up to 64 KiB, not in bytes. | AnyTLS |
| The DNS cache was bounded in entries and records, not bytes: 64 large TXT records under each of a thousand names. | DNS |
| Rule-set regexes compiled with the regex crate's 10 MiB defaults. | Routing |
| The Clash API accepted unlimited connections and never timed out headers (axum sets no hyper timer). | Clash API |
| Without a Rust `main`, nothing ignores SIGPIPE, and the system stack's TUN listener lacked `SO_NOSIGPIPE`, which accepted connections inherit: writing to a connection the app had reset would kill the extension unless the host ignored SIGPIPE. Inferred from the default disposition, not observed on a device. | Apple, TUN |
| Crash breadcrumbs: no alternate signal stack outside a Rust `main`, so a stack overflow left none; the host's handlers were discarded; reinstalling raced writers on the old fd. | Apple |
| The profile fetch callback ran under the instance lock (cancellation) or on the engine thread (result); a host calling back into sbr deadlocked. | C ABI |
| The userspace TCP memory limit could miss a wakeup between its headroom check and registering a waiter (multi-thread runtimes). | TUN |
| xhttp packet-up: 1 MB buffered per uploading stream plus one in flight; unbounded response-drain tasks; no deadline on a post. Idle XMUX slots were retired only by the next connection, so h2 keep-alive pings ran on an idle device. The h2 windows were not reduced on iOS. | xhttp |
| A WireGuard device that stopped never restarted, and its detour readers and connections waited forever. | WireGuard |
| Per-connection or per-packet waste: 16 KiB UDP-over-stream read buffers, VMess's read buffer kept at 64 KiB and a copy per sealed chunk, ShadowTLS v3's 128 KiB ring, a memmove of every UDP reply into the TUN. | Several |
| An oversized datagram ended a UoT or TUIC-UoT UDP session; VMess UDP split long replies into two datagrams. | UDP |
| Health events grew with the retry rate of one dead destination and were sorted on every report. | Health |
| SOCKS5 UDP associations' sockets outlived the association; fetch left its connection driver running on error or timeout. | Inbound, fetch |
| WireGuard's smoltcp rings stay committed at 512 KiB per connection after any long transfer. | Open, #28 |

Left as they are, lower priority:

- Memory: a 64 KiB receive buffer per QUIC socket over a detour (`quic/socket.rs`); WireGuard's detour channel of 1024 datagrams; the WebSocket write buffer kept at its largest frame; VMess's 32 KiB read buffer allocated at connect; the QUIC per-session UDP queue counted in packets.
- Per packet: allocations in TUIC and hysteria2 datagram sends; `PinnedUdp`'s linear scan; the WebSocket read buffer's memset per refill; the userspace TCP's SACK block allocation; the TUN writer's 1 ms retry sleeps on `ENOBUFS`.
- Hardening: the WebSocket reader's `assume_init` relies on the inner reader filling the buffer it was given, without the pointer check `tokio::io::Take` makes.
- Coverage: the protocol decoders reachable from a hostile server (VMess, VLESS, Trojan, TUIC, hysteria2, AnyTLS framing) have no fuzz targets. `resources.rs` measures plain SOCKS through two in-process instances, not the TLS or protocol outbounds, and its per-connection figure includes both instances and the test's echo server.
