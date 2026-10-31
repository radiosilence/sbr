# Architecture and contribution contract

Read this before adding a protocol, inbound or service.

## Crates

- `sbr-config`: sing-box JSON → typed options. **Strict**: every field sing-box knows is either parsed, `tolerate`d (accepted with a warning, only when it cannot change where traffic goes), or rejected with its JSON path. Never silently ignore a field. Use `Obj` (`src/obj.rs`): `opt/get/req/list/string/duration/tolerate/finish`. Shared objects: `tls` (`parse_tls`), v2ray `transport` (`parse_transport`), `multiplex` (`parse_multiplex`), dial fields (`parse_dial`), `server`/`server_port` (`parse_server`).
- `sbr-core`: protocol-free data plane.
  - `Outbound` / `PacketConn` / `Group` traits (`src/outbound.rs`).
  - `Dns` trait (`src/dns.rs`): `lookup` (for dialing) and `exchange` (raw DNS messages, used by `hijack-dns`), plus `bind` (a resolver for one dialer's `domain_resolver`), `fakeip_lookup` and `reverse_lookup`. `SystemDns` is used when the config has no `dns` section.
  - `router::Matcher` / `RuleSets`: rule matching for callers with their own actions (DNS rules); rule-sets are compiled once and shared.
- `sbr-dns`: the `dns` section as a `Dns` (`DnsRouter`): transports (hickory-proto wire format, rustls/aws-lc-rs, h2), rules, cache, FakeIP. Servers dial through `Arc<dyn Outbound>`s the engine supplies (`detour`, or a direct dialer); `sbr-engine/src/dns.rs` is the glue.
  - `Router` (`src/router`): a stepper. `next(meta, from)` returns the next matching rule; the engine performs sniff/resolve/route-options and continues. sing-box group semantics; see the module docs.
  - `sniff` (`src/sniff.rs`), `dial` (Happy Eyeballs TCP, `bind_udp`), `relay`.
- `sbr-engine`: runtime.
  - `dispatch.rs`: `Engine::handle_tcp(meta, impl InboundStream)` does rules → sniff → connect → `ready()`/`fail()` → relay. Inbounds only parse their handshake.
  - `udp.rs`: `Engine::handle_udp(inbound, type, UdpPacket, Arc<dyn UdpWriteBack>)`, a full-cone NAT session per client source, routed on the first packet.
  - `outbound/`: one module per protocol, registered in `outbound/mod.rs::Builder::build`. Protocols reach their server through `Upstream` (system dialer with DNS, or a `detour` outbound), so detour chains work for free.
  - `inbound/`: proxy inbounds; `tun` lives in the `sbr-tun` crate plus `inbound/tun.rs` (see [TUN TCP stacks](#tun-tcp-stacks)).
  - `track.rs`: live connection registry (Clash API, `interrupt_exist_connections`). `handle_tcp` and the UDP session register once connected; closing a connection aborts its relay.
  - `outbound/group.rs`: `selector`, `urltest` and `GroupEnv` (delay history, probes, health glue). New protocols with a `server` should be added to `server_of` in `outbound/mod.rs` so URL-less `urltest` can measure them, and to `probe_target_of` if their servers front a website on their own address.
  - `health.rs`: per-leaf health (the state machine, unit-tested with an injected clock), the relay watcher that reports stalls and resets, and its thresholds. `fetch.rs::data_probe` is the active check.
  - `ruleset.rs` (remote rule-sets), `cache.rs` (`cache_file`; other subsystems get namespaced tables via `CacheFile::table`, e.g. `"fakeip"`), `fetch.rs` (HTTP(S) client through an outbound), `clash/` (Clash API).
- `sbr-config/src/srs.rs`: the binary rule-set codec, byte-compatible with sing-box.
- `sbr-reality`: TLS 1.3 client with browser ClientHellos, generic over the transport: `connect(stream, &RealityConfig)` for REALITY, `connect_tls(stream, &TlsConfig)` for ordinary TLS with a rustls `ServerCertVerifier`. rustls cannot emit browser ClientHellos, and its own is distinctive, so this is the default handshake for every TCP TLS client (`sbr-engine/src/tls`, ShadowTLS, AnyTLS, DoH); `TlsOutbound::browser_fingerprint` decides when rustls is used instead. Profiles must follow browser releases: Chrome and Apple are captured from the real clients, and `tls_tests.rs` pins each profile's JA3/JA4. Interop-tested against a sing-box binary built with `-tags with_utls` (`SBR_SING_BOX`) and against Xray-core (`SBR_XRAY`), whose uTLS profiles are the reference.
- `sbr-apple`: C ABI + staticlib; `include/sbr.h` must match the exports (`tests/c_abi.rs` enforces it). `apple/`: Swift package and sample app; see `apple/README.md` for the power and memory budget.

## Adding an outbound protocol

1. Config: add a variant to `OutboundKind` and an arm in `parse_outbound` (`sbr-config/src/lib.rs`). Put the struct and parser in their own file if they're more than a few fields. Reuse `parse_dial`, `parse_server`, `parse_tls`, `parse_transport`, `parse_multiplex`.
2. Engine: `crates/sbr-engine/src/outbound/<proto>.rs` implementing `sbr_core::Outbound` (`connect`, and `connect_udp` if the protocol carries UDP). Register it in `Builder::build`.
3. Tests: an e2e test against a real server implementation (an in-process server written for the test, or the protocol's reference crate). Byte-exactness matters more than coverage numbers. At least one test must push ≥1 MB through and compare. For a path users depend on, add a `soak_*` test (`tests/common/soak.rs`): 128 MiB with random write sizes and reader stalls, which is what exposes writers that lose bytes or strand them across `Pending`.

## Writing `AsyncWrite` wrappers

Two mistakes have each caused bulk transfers to hang:

- Reporting more than was accepted. After `Pending`, a caller may retry with a *different* (`tokio::io::copy`: longer) buffer. A writer that sealed or framed the first buffer must report that length, not the retry's.
- Leaving bytes buffered with nobody to flush them. tokio-rustls (and REALITY's record layer) returns `Ok` while sealed records still wait for the socket; they go out on the next write or `poll_flush`. Any code that writes and then waits for a reply must flush, and a wrapper's `poll_flush` must reach the stream underneath.

## TUN TCP stacks

`sbr-tun` has two ways to terminate the TUN's TCP. Both feed the same `on_tcp(Accepted)` callback, so dispatch and sniffing do not know which one ran; UDP takes the same path under both (datagrams handed up after fragment reassembly, replies written straight to the fd).

- **System** (`stack.rs`, `nat.rs`): SYNs are rewritten onto a kernel listener on the TUN address and the kernel runs TCP. It costs a header rewrite per packet, but every connection depends on the kernel routing the listener's replies back into the TUN. In an iOS Network Extension the extension's own sockets are scoped to the physical interface; the listener needs `IP_BOUND_IF`, and TCP has still been seen dying on devices after extension restarts while UDP kept working. The NAT table holds only live entries, so it costs nothing before traffic arrives; half-open SYNs are capped (the oldest is evicted), and a connection the engine refuses is reset so its port returns at once instead of after the closed grace period, so one app cannot exhaust the port space.
- **Userspace** (`tcp/`): sbr terminates TCP itself and never opens a socket on the TUN side, so nothing depends on kernel routing or interface scoping there. Outbound connections still use the kernel, as they must.

Under both, the packet loop restarts after a panic (logged at error level) rather than leaving the tunnel silently blackholed, and a packet for an address family the tunnel has no address in is refused with a RST or ICMP port unreachable, so Happy Eyeballs moves to the other family at once.

Which one runs: `stack: gvisor` selects userspace; `system`, `mixed` and an unset `stack` select system. sing-box's `mixed` is system TCP with gVisor UDP, and sbr's UDP path is the same under every value, so `mixed` maps to system TCP. `Settings::tun_stack` overrides the config for embedders (an sbr extension; `sbr-apple` leaves it unset).

### Why a purpose-built TCP

Candidates were smoltcp 0.14 (then used by the WireGuard outbound), netstack-smoltcp and ipstack (wrappers and a minimal TCP built for tun2proxy-style forwarding), lwIP bindings, and writing one. The deciding constraint is the iOS extension's ~50 MB memory ceiling: with the kernel stack, socket buffers are kernel memory and do not count against the extension, but with any userspace stack every byte buffered does.

- smoltcp allocates each socket's ring buffers up front at a fixed size, and pages stay committed once touched, so a few hundred connections that each saw one burst keep their full buffers. Its sender has no SACK-based recovery and a fixed 1 s minimum RTO (a compile-time constant), so a lost tail segment stalls a flow for a second. Its interface walks every socket on each egress poll. It is correct and well tested, which is why the tests use it as the independent peer.
- netstack-smoltcp inherits smoltcp's TCP. ipstack's TCP has a much smaller feature set (no SACK, simplified congestion control and retransmission) and less history under loss. lwIP is mature but C, with its own memory pools to size and a cross-compile for every Apple target.
- A TCP that answers SYNs on a link to the same host is a small subset of TCP: no LISTEN state, no path MTU discovery, no options beyond MSS, window scale, SACK and timestamps. (Active open was added later for the WireGuard outbound; see below.) `tcp/tcb.rs` implements that subset against the RFCs it cites (RFC 9293, 7323, 2018, 6675, 5681, 6582, 6298, 5961), and the rest of the stack is shaped around the memory and power rules:
  - **Elastic buffers** (`tcp/buf.rs`): send and receive queues are chains of pooled chunks, held only while they hold bytes. An idle connection costs no buffer memory whatever its window. Per-connection caps (`TcpConfig::rx_buffer`/`tx_buffer`, 128 KiB each on iOS) bound one flow; `TcpConfig::memory_limit` (8 MiB on iOS) bounds all of them together. At the limit, receive windows stop opening and writes wait. Windows already advertised are reserved against the limit, so connections cannot jointly promise more than it.
  - **No idle wakeups**: one deadline heap; a connection with nothing in flight has no timer. ACKs are sent once per received batch rather than on a delayed-ACK timer, and immediately for out-of-order data, gap fills and FINs.
  - **Recovery without timeouts**: SACK scoreboard and RFC 6675-style pipe accounting, NewReno partial ACKs for peers without SACK, a 200 ms minimum RTO. In the loss tests about nine in ten losses are repaired by fast retransmit.
  - **One task owns all state**: the TUN packet loop runs every state machine; a `Stream` shares only its two byte queues and some flags under a mutex held for copies. There is no lock order to get wrong and no cross-thread segment reordering.
  - **Better failure signals than the kernel path**: a segment for an unknown connection (for example, one opened before the tunnel restarted) gets a RST instead of being dropped, so apps fail over at once. With `TcpConfig::defer_handshake` (on by default) the engine gets each connection on the app's SYN and the SYN-ACK waits for the outbound to connect (`InboundStream::ready`); a failed connect or a rejecting rule resets the app's connect instead of killing an established connection. Trade-off: the app's connect() takes as long as the outbound's, and a config that sniffs before routing must complete the handshake first, since sniffing needs the app's first bytes.

Tests: `tcp/tests.rs` runs the stack against smoltcp on a simulated link with a virtual clock (seeded loss, reordering and duplication, small and zero windows, hundreds of connections, half-close both ways, resets both ways, the memory limit, the deferred handshake, and active opens against smoltcp servers including over a 50 ms round trip at the memory limit); `sbr-tun/tests/user_stack.rs` drives the real packet loop over a socketpair without root; `sbr-engine/tests/tun.rs` runs every end-to-end case against the Linux kernel's TCP on both stacks (root).

### WireGuard outbound

The WireGuard outbound runs its TCP on the same stack (`Tcp::client`), adding the active-open half: SYN-SENT, offering window scale, SACK and timestamps and using whichever the peer echoes. It was on smoltcp sockets, which brought the fixed-ring problem above into the extension: 512 KiB per connection on iOS once a flow had cycled its rings, with no overall cap. On the elastic stack a connection costs only what it has buffered, and `stack::tcp_config` caps the outbound's buffers at 8 MiB on iOS, separate from the TUN stack's 8 MiB.

The trade-off is at the cap. Each connection may always buffer one chunk (4 KiB on iOS) each way, so a WireGuard connection that finds the cap taken by stalled readers (relayed downloads whose app stopped reading) proceeds no slower than about one chunk per round trip, about 40 KB/s at 100 ms, plus whatever window it was offered before the cap filled. smoltcp never throttled: it kept allocating instead. With 256 KiB windows it takes 32 stalled connections to reach the cap.

smoltcp still carries the tunnel's UDP; IP fragments are reassembled before either stack sees them.

## Performance rules

- No per-packet or per-chunk allocation on hot paths when avoidable; reuse buffers.
- No `Mutex` held across `.await`.
- Relay buffers come from `Settings::relay_buffer` (16 KiB on iOS, 64 KiB elsewhere).
- Prefer `aws-lc-rs` for crypto (hardware AES and ChaCha on Apple silicon). Use `rustls` with the `aws_lc_rs` provider for TLS.
- Power: no busy timers. Idle sessions must cost zero wakeups; use deadlines, not polling intervals.

## No third-party endpoints

sbr contacts only endpoints the config names. Never add a built-in default URL (probe targets, downloads, update checks); where sing-box has one, document the deviation in the README.

## Style

- `cargo fmt` (max_width 120), `cargo clippy --workspace --all-targets` clean, `cargo test --workspace` green.
- Comments explain *why*. Match the existing density.

## Untrusted input

Local apps, servers, the network and remote rule-sets are all hostile (`docs/security-audit.md`). A panic or an unbounded allocation kills the iOS extension and with it the tunnel, so every length field is checked before use and every table, queue and buffer driven by input has a cap in bytes, not only in entries. New parsers of untrusted bytes get a target in `fuzz/` (`cargo +nightly fuzz run -O <target>`).

Library defaults are inputs too: h2 accepts 16 MiB of response headers, h3 buffers any frame other than DATA whole (`outbound/quic/h3guard.rs` refuses long ones), the regex crate compiles up to 10 MiB per set, and axum's `serve` has no connection limit or header timeout. Check what a new client, server or parser does by default, not only the settings you change. Every spawned task needs a path that stops it, and every resource it holds (a socket, an endpoint, a buffer) must be released when its owner closes, not when the next user arrives: `tests/resources.rs` checks tasks, file descriptors and heap after a round of connections.
