# Architecture and contribution contract

Read this before adding a protocol, inbound or service.

## Crates

- `sbr-config`: sing-box JSON → typed options. **Strict**: every field sing-box knows is either parsed, `tolerate`d (accepted with a warning, only when it cannot change where traffic goes), or rejected with its JSON path. Never silently ignore a field. Use `Obj` (`src/obj.rs`): `opt/get/req/list/string/duration/tolerate/finish`. Shared objects: `tls` (`parse_tls`), v2ray `transport` (`parse_transport`), `multiplex` (`parse_multiplex`), dial fields (`parse_dial`), `server`/`server_port` (`parse_server`).
- `sbr-core`: protocol-free data plane.
  - `Outbound` / `PacketConn` / `Group` traits (`src/outbound.rs`).
  - `Dns` trait (`src/dns.rs`): `lookup` (for dialing) and `exchange` (raw DNS messages, used by `hijack-dns`). `SystemDns` is the default.
  - `Router` (`src/router`): a stepper. `next(meta, from)` returns the next matching rule; the engine performs sniff/resolve/route-options and continues. sing-box group semantics; see the module docs.
  - `sniff` (`src/sniff.rs`), `dial` (Happy Eyeballs TCP, `bind_udp`), `relay`.
- `sbr-engine`: runtime.
  - `dispatch.rs`: `Engine::handle_tcp(meta, impl InboundStream)` does rules → sniff → connect → `ready()`/`fail()` → relay. Inbounds only parse their handshake.
  - `udp.rs`: `Engine::handle_udp(inbound, type, UdpPacket, Arc<dyn UdpWriteBack>)`, a full-cone NAT session per client source, routed on the first packet.
  - `outbound/`: one module per protocol, registered in `outbound/mod.rs::Builder::build`. Protocols reach their server through `Upstream` (system dialer with DNS, or a `detour` outbound), so detour chains work for free.
  - `inbound/`: proxy inbounds; `tun` lives in the `sbr-tun` crate plus `inbound/tun.rs`.
- `sbr-apple`: C ABI + staticlib. `apple/`: Swift package.

## Adding an outbound protocol

1. Config: add a variant to `OutboundKind` and an arm in `parse_outbound` (`sbr-config/src/lib.rs`). Put the struct and parser in their own file if they're more than a few fields. Reuse `parse_dial`, `parse_server`, `parse_tls`, `parse_transport`, `parse_multiplex`.
2. Engine: `crates/sbr-engine/src/outbound/<proto>.rs` implementing `sbr_core::Outbound` (`connect`, and `connect_udp` if the protocol carries UDP). Register it in `Builder::build`.
3. Tests: an e2e test against a real server implementation (an in-process server written for the test, or the protocol's reference crate). Byte-exactness matters more than coverage numbers. At least one test must push ≥1 MB through and compare.

## Performance rules

- No per-packet or per-chunk allocation on hot paths when avoidable; reuse buffers.
- No `Mutex` held across `.await`.
- Relay buffers come from `Settings::relay_buffer` (16 KiB on iOS, 64 KiB elsewhere).
- Prefer `aws-lc-rs` for crypto (hardware AES and ChaCha on Apple silicon). Use `rustls` with the `aws_lc_rs` provider for TLS.
- Power: no busy timers. Idle sessions must cost zero wakeups; use deadlines, not polling intervals.

## Style

- `cargo fmt` (max_width 120), `cargo clippy --workspace --all-targets` clean, `cargo test --workspace` green.
- Comments explain *why*. Match the existing density.
