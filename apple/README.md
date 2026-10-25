# sbr on Apple platforms

| | |
|---|---|
| `crates/sbr-apple` | C ABI (`include/sbr.h`) and staticlib |
| `apple/Sources/SbrKit` | Swift package: the `Sbr` wrapper and the `SbrPacketTunnelProvider` base class |
| `apple/build-xcframework.sh` | builds `SbrCore.xcframework` for iOS, iOS Simulator, macOS, Mac Catalyst, tvOS and tvOS Simulator |
| `apple/check-apple-targets.sh` | `cargo check` for every Apple target, runnable from Linux |
| `apple/Examples/SbrDemo` | SwiftUI sample app and tunnel for iOS, macOS and tvOS (XcodeGen) |

> **Status:** the Rust side is type-checked for every Apple target and its
> C ABI is tested on Linux, including a C program linked against the
> staticlib. The Swift code was written without an Xcode toolchain and has
> only been syntax-checked, not compiled. It has never run on a device.

## SbrKit in a tunnel extension

```swift
import SbrKit
final class PacketTunnelProvider: SbrPacketTunnelProvider {}
```

That is the whole extension. The base class:

1. Loads the sing-box config from `providerConfiguration["config"]`, or from
   `config.json` in the App Group named by `providerConfiguration["appGroup"]`
   (see `SbrConfigStore`).
2. Builds `NEPacketTunnelNetworkSettings` from the config's `tun` inbound with
   `sbr_tun_network_settings`. That function is Rust, so it shares the strict parser and its
   tests:
   - `address` sets the interface addresses (IPv6 settings only when there is an IPv6
     address) and `mtu` sets the MTU (default 9000).
   - `auto_route` adds the default routes, or `route_address` when that is set.
     `route_exclude_address` becomes excluded routes.
   - DNS, with `auto_route`: the address after the first IPv4 interface address
     (`172.19.0.1/30` gives `172.19.0.2`), matching all domains. System DNS then enters the
     tunnel, where a `hijack-dns` rule answers it. These are sing-box libbox semantics.
   - `strict_route` has no per-route equivalent. Set
     `NETunnelProviderProtocol.includeAllNetworks` in the app instead.
3. Calls `setTunnelNetworkSettings`. Then it finds the utun fd that NetworkExtension
   opened (`sbr_find_tun_fd`: scan the fd table and match the
   `UTUN_OPT_IFNAME` name against "utun", like WireGuard-apple and sing-box) and
   starts sbr with that fd.
4. Forwards sbr's logs to `Logger` (`Sbr.forwardLogs`). Messages are private by default.
5. Watches `NWPathMonitor` and calls `sbr_network_changed` when the set of physical
   interfaces changes. `wake()` calls it too, because UDP NAT mappings are likely gone
   after sleep. `sleep()` returns immediately: an idle sbr arms no timers, so there is
   nothing to pause.
6. Answers `SbrRequest` app messages (`groups`, `select`, `stats`, `reload`).
   On the app side, call `NETunnelProviderSession.send(_:)`.

Override `loadConfiguration()`, `coreOptions` (threads, buffer, connection cap)
or `handle(_:)` to customise.

## C ABI

The full contract is in [`sbr.h`](../crates/sbr-apple/include/sbr.h). Every
entry point catches panics, takes NULL safely, and may be called from any thread.

```c
const char     *sbr_version(void);
char           *sbr_check(const char *config_json);
SbrStartOptions sbr_start_options_default(void);
SbrInstance    *sbr_start_ex(const char *config_json, const SbrStartOptions *options, char **error_out);
SbrInstance    *sbr_start(const char *config_json, const char *base_dir, char **error_out);
char           *sbr_reload(SbrInstance *instance, const char *config_json);
void            sbr_stop(SbrInstance *instance);
int32_t         sbr_select(SbrInstance *instance, const char *group, const char *member);
char           *sbr_groups(SbrInstance *instance);
void            sbr_stats(SbrInstance *instance, uint64_t *up, uint64_t *down, uint64_t *active);
void            sbr_runtime_stats(SbrInstance *instance, SbrRuntimeStats *out);
void            sbr_network_changed(SbrInstance *instance);
char           *sbr_tun_network_settings(const char *config_json, char **error_out);
int32_t         sbr_find_tun_fd(void);
void            sbr_set_log_callback(SbrLogCallback callback, void *context);
void            sbr_string_free(char *s);
```

- **TUN fd.** `SbrStartOptions.tun_fd` sets `sbr_engine::Settings::tun_fd`. sbr
  `dup()`s the fd on every start and the engine owns the duplicate, the same as
  sing-box's libbox. The extension's original fd is never closed, so
  `sbr_reload` can start again on the same tunnel.
- **Reload.** The new config is validated first, and a bad config leaves the old one
  running. Then the old instance stops and the new one starts with the same options.
  If that start fails (for example, a port is taken), the instance stays stopped until the
  next successful reload.
- **Network change.** `sbr_network_changed` drops state bound to the old path. Today
  that is UDP NAT sessions; QUIC and WebRTC clients re-establish on their next
  packet. Pooled upstream connections (multiplex, QUIC outbounds) and the DNS
  cache belong here as they land, so the next request dials over the new path.
  Open TCP connections are left alone: they survive if the interface is unchanged, or
  fail fast if it changed.
- **Logs.** One process-wide `tracing` subscriber with a reloadable level, taken
  from the config's `log` section at each start or reload. Disabled levels cost
  nothing at the call site. After `sbr_set_log_callback` returns, the previous
  context is never used again, so Swift releases it right away.

## Power and memory

### Runtime flavour

Measured with `cargo run --release -p sbr-apple --example power`. Each run drives
the engine through the C ABI and counts only sbr's own threads (from
`/proc/self/task/*`). The host is a 4-vCPU Linux VM, and client, proxy and sink
share its cores. The bulk test is one 1 GiB upload through socks → direct with
16 KiB buffers. Three runs:

| flavour | idle 10 s: wakeups | bulk: MiB/s | bulk: voluntary switches (sleeps/wakeups) | bulk: CPU ms |
|---|---|---|---|---|
| current-thread | **0** | 883–1084 | **55–226** | 460–1020 |
| 2 workers | **0** | 797–1010 | 4 842–9 617 | 680–1320 |
| 4 workers | **0** | 933–1041 | 5 871–6 655 | 760–870 |

Involuntary switches (the scheduler preempting a busy thread) were noisy in
every flavour (100 to 18 000), because the VM is oversubscribed. They are not
wakeups.

- **Idle: zero wakeups in every flavour.** A parked Tokio runtime with no timer armed
  sleeps in `epoll_wait` (or `kevent` on Darwin) with no timeout.
- **Bulk: the single-threaded runtime wakes 25–100× less often for the same throughput.**
  Multi-thread workers keep parking and unparking each other as I/O readiness hops
  between them. A phone relays a handful of flows, and its CPU-heavy work (AEAD) is
  per-connection, so one thread is the right default for the extension:
  **`threads = 0` means current-thread on iOS/tvOS** and CPU count (capped at 8) on
  macOS. Set `threads` to 2 or more if one connection's crypto ever becomes the
  bottleneck.

The runtime always runs on its own driver thread, so Swift can call in from
any thread. `spawn_blocking` (getaddrinfo) is capped at 8 threads, against
Tokio's default of 512.

### Timer audit (idle engine)

Nothing in sbr wakes periodically. Every timer is either a deadline on work that is
in flight or a back-off on an error path:

| where | what | verdict |
|---|---|---|
| `crates/sbr-core/src/dial.rs:16,21,67,108` | connect timeout (5 s), Happy Eyeballs attempt delay (250 ms) | one-shot per dial |
| `crates/sbr-core/src/dial.rs:18-19,142-144` | TCP keepalive: idle 300 s, interval 75 s, on every outbound socket | **not a process wakeup**, but the kernel sends probes on idle connections, which wakes the cellular radio. Same default as sing-box. Turn it off per outbound with `disable_tcp_keep_alive` / `tcp_keep_alive`. Reported, not changed |
| `crates/sbr-engine/src/dispatch.rs:18,224` | sniff timeout (300 ms) | one-shot per connection |
| `crates/sbr-engine/src/udp.rs:24-26,170,189,255` | UDP session idle deadline (300 s, 10 s for DNS) | deadline per live session. While replies keep it alive it re-arms once per timeout, not per packet. A rejected session parks for 300 s on one timer |
| `crates/sbr-engine/src/lib.rs:253` | accept loop backs off 50 ms after an error | only on the error path. If `EMFILE` persists, this is a 20 Hz loop. **Reported** to the engine owner; exponential back-off would fix it |
| Tokio blocking pool | idle threads exit after 10 s | one wake per thread after the last DNS lookup, not periodic |
| `crates/sbr-apple` | none (the old `shutdown_timeout` only runs on stop) | — |

### Memory (iOS jetsam limit for a Network Extension is about 50 MB)

- Relay buffers default to 16 KiB per direction on iOS/tvOS, so each TCP connection costs 32 KiB.
- `max_connections` defaults to 512 on iOS/tvOS: at most 16 MB of relay buffers. Past
  the cap, new TCP connections are refused cleanly (SOCKS/HTTP get an error, and TUN will
  get a RST) and new UDP flows are dropped. The same number caps UDP NAT sessions.
- `sbr_runtime_stats` reports `phys_footprint` (`TASK_VM_INFO`, the figure jetsam uses)
  and `os_proc_available_memory()` (headroom before the kill) so the app can show them.
- **Reported:** each UDP session's reader allocates a 64 KiB receive buffer
  (`crates/sbr-engine/src/udp.rs:224`, `vec![0u8; 65535]`). At the 512-session cap that is
  32 MB, more than the TCP budget. Size it from the TUN MTU, or lower the UDP cap on iOS.

## Building

```sh
apple/build-xcframework.sh          # on macOS with Xcode
```

- iOS (arm64), iOS Simulator (arm64 + x86_64), macOS (arm64 + x86_64),
  Mac Catalyst (arm64 + x86_64), tvOS (arm64), tvOS Simulator (arm64 + x86_64).
- tvOS is a Rust tier-3 target with no prebuilt std. The script builds it with
  `cargo +nightly build -Zbuild-std=std,panic_unwind`, so you need
  `rustup toolchain install nightly --component rust-src`. `SBR_SKIP_TVOS=1`
  skips it. `SBR_SKIP_CATALYST=1` skips Catalyst.
- Release builds use fat LTO with one codegen unit. The archives are then stripped
  (`strip -S -x`), and the script prints each slice's size.

From Linux, `apple/check-apple-targets.sh` runs `cargo check` for all of these
targets, with nightly build-std for tvOS. aws-lc-sys and blake3 build C code
that needs an Apple SDK, so on Linux the script swaps in a stand-in compiler
that emits empty objects. The Rust code is fully type-checked; the C code is
only compiled by the real macOS build.
