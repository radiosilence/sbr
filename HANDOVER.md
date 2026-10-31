# Handover: cloud session → Mac session

Written 2026-10-25 by the cloud session that built sbr so far. Everything is on
`master`, pushed, with no WIP branches. The cloud session has stopped making
changes.

## State

- `cargo test --workspace`: 183 passing; clippy clean. Interop tests run against
  real sing-box servers when the env vars below point at a binary, and skip
  (pass) otherwise.
- Benchmarks vs sing-box on an idle 4-vCPU Linux VM: see `BENCHMARKS.md`.
  sbr wins the encrypted paths (SS-2022 +10–16%, trojan +14–23%, vmess +17–31%,
  vless roughly +5–15%) and TUN (+6–9%). It ties on plain relay and hysteria2
  (with less CPU per GB). It loses **WireGuard upload** (−15–40%: one device task
  vs wireguard-go's multicore crypto), and wins WireGuard download (+52–72%).
- **Nothing has ever run on Apple hardware.** Rust compile-checks pass for iOS,
  iOS sim, macOS, Catalyst and tvOS. The Swift code is
  syntax-checked only: no Xcode build, no device run.

## The user's real setup (read this first)

The user's infra is `radiosilence/jaritanet` (Pulumi/TS). It matters because it
is the actual target:
- **Server**: Xray VLESS+REALITY+Vision on tcp/443 (fallback to Traefik via
  `dest` with xver), and official apernet **Hysteria2** on udp/443, 3478 and 4500 (salamander
  obfs, self-signed cert pinned in the client, `userpass` auth, so the client
  password is `name:password`). Not sing-box servers.
- **Client profile generator**: `packages/vpn/src/singbox.ts::buildProfile`.
  Read its comments: they encode hard-won decisions (MTU 1280, 198.18.0.0/30 tun
  addresses, urltest 10m interval and 30m idle for radio power, `stack: mixed`).
- A profile in exactly that shape passes `sbr check` as of commit `50872a0` (the
  day-unit duration fix; `optimistic.timeout: "3d"` used to fail).

## Next, in priority order

1. **Build and run on the Mac.** `apple/build-xcframework.sh`, then
   `apple/Examples/SbrDemo` (XcodeGen `project.yml`; see `apple/README.md`).
   Expect Swift compile errors. Nothing NetworkExtension-specific has been
   compiled. Verify these on a device:
   - utun fd discovery (`sbr_find_tun_fd`);
   - the `recvmsg_x` batch read path (`crates/sbr-tun/src/device.rs`, Apple
     `platform` module): never executed;
   - `phys_footprint` memory stats; jetsam headroom under load;
   - `NEPacketTunnelNetworkSettings` derived from the tun inbound
     (`sbr_tun_network_settings`).
2. ~~**IP fragment reassembly in the TUN.**~~ Done (`crates/sbr-tun/src/frag.rs`,
   README "TUN system stack: fragments"). The kernel path is covered by
   `tun_udp_fragments_at_small_mtu` in `crates/sbr-engine/tests/tun.rs`, which
   needs root on Linux and has not run yet; test it on a device with a nested
   UDP VPN.
3. **Interop against the user's actual servers.** Add Xray (VLESS+REALITY+
   Vision, with fallback) and apernet hysteria2 (salamander, userpass) as test
   servers next to sing-box. Both build from Go source via proxy.golang.org.
   Then try the real server, with the user's consent and their profile.
4. **Speed** (the user asked for "faster everywhere"):
   - WireGuard upload on Darwin: done (connected socket plus an egress thread;
     see `BENCHMARKS.md`). Linux was not re-measured after that change. There
     the device task does GSO sends, so the egress thread matters less and
     crypto matters more. Parallel AEAD would need boringtun to expose its
     session keys.
   - hysteria2: profile first; quinn GSO is already on. Check Brutal window,
     send buffer and pacing (`outbound/quic/brutal.rs`).
   - Linux-only: `splice(2)` for raw TCP↔TCP relay, and TUN offload
     (`IFF_VNET_HDR` + GSO/GRO). Neither exists on Darwin. On Darwin, measure
     CPU per GB and wakeups (Instruments) instead.
   - Measure with **CPU-seconds per GB**, A/B back-to-back; throughput on a
     shared box lies.
5. **Cleanup**:
   - Fold `outbound/tlsmini.rs` (ShadowTLS/AnyTLS) and `outbound/quic/tls.rs`
     onto the shared `src/tls/` layer. See the notes in the TLS agent's README
     section.
   - FakeIP persistence: the `CacheFile::table("fakeip")` hook exists (TODO in
     `cache.rs`), but `sbr_dns::FakeIp` doesn't call it yet.
   - ~~`urltest` should re-probe on network change~~ Done with issue #4:
     `Engine::network_changed` clears outbound health and re-probes groups
     in use (idle ones on their next use).

## Project rules the user set

- **Everything owned by the user, nothing phones home**: sbr never contacts a
  third-party endpoint unless the config names it. URL-less urltest probes the
  member's own server; the dashboard UI is never auto-downloaded.
- Drop-in sing-box config compatibility: strict parsing, and every unsupported
  field is rejected **with its JSON path**, never silently ignored (only
  routing-neutral knobs are tolerated with a warning).
- Power matters as much as throughput: zero wakeups when idle, no polling
  timers, deadlines only.
- Be critical, not validating (user preference).

## Gotchas

- **Never use `sendmsg_x` on NE utun.** In netif mode it leaks mbufs past 512
  queued packets and can take down device networking (sing-tun's finding). Writes
  stay per-packet.
- `Settings::tun_fd`: the engine takes ownership and closes it. sbr-apple passes
  a `dup()`, so the extension's original survives reloads.
- rustfmt `max_width = 120`; formatting reflows long lines, so patch-by-search
  scripts can silently miss. Compile for Apple after touching `cfg` code (this
  bit us once in `dial.rs`).
- Interop env vars: `SBR_SING_BOX` (sing-box with utls+quic+wireguard),
  `SING_BOX` (QUIC tests). Build one with
  `go build -tags with_quic,with_utls,with_wireguard,with_gvisor ./cmd/sing-box`.
  `SBR_XRAY` and `SBR_HYSTERIA` (Xray-core and apernet hysteria, `brew install
  xray hysteria`) drive `tests/upstream_servers.rs`; Homebrew's `sing-box` has
  every tag the other tests need.
- Known upstream quirks: sing-box's httpupgrade server can eat the first tunnel
  byte (trojan+httpupgrade test excluded); ShadowTLS v2 against a TLS 1.3 camouflage
  server is racy in Go's client too; `shadowsocks` crate 1.25 silently truncates
  oversized first writes and miscounts a write retried after `Pending` (both worked
  around by `WriteFix` in `outbound/shadowsocks.rs`, worth reporting upstream).
- Soak tests (`soak_*`, `#[ignore]`d) push 128 MiB through the user's paths; the
  command is in `crates/sbr-engine/tests/common/soak.rs`.

## Map

`ARCHITECTURE.md` is the contract (crates, how to add a protocol, perf rules).
`README.md` has the compatibility table and deviations from sing-box.
`apple/README.md` has the power and memory budget and the timer audit.
