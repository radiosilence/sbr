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

1. Loads the sing-box config from the Keychain item named by
   `providerConfiguration["stored"]` (an `SbrStoredProfile`, see
   `SbrKeychain`), from `providerConfiguration["config"]`, or from
   `config.json` in the App Group named by `providerConfiguration["appGroup"]`
   (see `SbrConfigStore`). The Keychain is preferred because the system keeps
   `providerConfiguration` on disk with the VPN preferences.
2. Builds `NEPacketTunnelNetworkSettings` from the config's `tun` inbound with
   `sbr_tun_network_settings`. That function is Rust, so it shares the strict parser and its
   tests:
   - `address` sets the interface addresses and `mtu` sets the MTU (default 9000).
   - `auto_route` adds the default routes, or `route_address` when that is set.
     `route_exclude_address` becomes excluded routes. With `auto_route` and no IPv6
     address, the interface still gets IPv6 routes on the ULA `fd73:6272::1/126`; the
     engine has no IPv6 address to carry them on and answers each flow with a TCP reset
     or ICMPv6 unreachable. On a dual-stack network IPv6 would otherwise leave by the
     physical interface; this way clients fall back to IPv4 through the tunnel at once.
   - DNS, with `auto_route`: the address after the first IPv4 interface address
     (`172.19.0.1/30` gives `172.19.0.2`), matching all domains. System DNS then enters the
     tunnel, where a `hijack-dns` rule answers it. These are sing-box libbox semantics.
   - `strict_route` has no per-route equivalent; it is a property of the VPN
     configuration, which the app saves. See [Leak protection](#leak-protection).
3. Calls `setTunnelNetworkSettings`. Then it finds the utun fd that NetworkExtension
   opened (`sbr_find_tun_fd`: scan the fd table and match the
   `UTUN_OPT_IFNAME` name against "utun", like WireGuard-apple and sing-box) and
   starts sbr with that fd.
4. Forwards sbr's logs to `Logger` (`Sbr.forwardLogs`). Messages are private by default.
5. Watches `NWPathMonitor` and calls `sbr_network_migrate` when the set of physical
   interfaces changes. `wake()` calls it too, because UDP NAT mappings are likely gone
   after sleep. `sleep()` returns immediately: an idle sbr arms no timers, so there is
   nothing to pause.
6. Answers `SbrRequest` app messages (`groups`, `select`, `stats`, `connections`,
   `closeConnection`, `reload`, `profile`).
   On the app side, call `NETunnelProviderSession.send(_:)`.
7. Refreshes a remote profile itself when the stored profile's Keychain item
   has a URL, or `providerConfiguration["remote"]` names one (an
   `SbrRemoteProfile`: URL, interval, when the config was downloaded). See
   below.
8. Keeps its working files (cache file, rule-set cache, session logs) in a
   directory excluded from backups and protected until first unlock, and
   deletes them on `SbrRequest.erase`.

### Remote profile refresh

A profile change on the server should reach a running tunnel without the app being
opened, so the extension refreshes the active remote profile on its own interval
(sing-box's default of 60 minutes). The download is done by the core
(`sbr_fetch_profile`), not `URLSession`, because it has to go where the tunnel's
traffic goes: it is routed by the running config's route rules exactly as a TCP
connection arriving on the tun inbound would be, so the profile host sees the
proxy's address rather than the device's, and a network that blocks the host cannot
block the update. A `URLSession` in the extension would leave by the physical
interface, since the provider's own traffic bypasses its tunnel. The request carries
no `User-Agent` or other identifying header.

The text is validated by the same checker as `sbr_check` and applied with
`sbr_apply_profile`: unchanged text restarts nothing, a profile that fails
validation leaves the running config untouched (retried in five minutes), and one
whose tun inbound needs different interface settings gets them applied before the
reload. The last good download is stored beside a stored profile in the Keychain,
or otherwise in the extension's own container (no App Group is needed), and used on
the next start if it is newer than the config the app installed. The app asks for it with `SbrRequest.profile` when it comes to the front
and stores it, so it shows what the tunnel runs. The URL and the profile text are
never logged.

Override `loadConfiguration()`, `coreOptions` (threads, buffer, connection cap)
or `handle(_:)` to customise.

### Leak protection

`Sbr.applyLeakProtection(to:enabled:allowLocalNetwork:)` is the Network Extension form
of `strict_route`. It is a property of the saved VPN configuration rather than of the
tunnel settings, so the app applies it when it saves the configuration. The sbr app
turns it on when the profile's `tun` inbound sets `strict_route`
(`Sbr.strictRoute(config:)`) unless the user has set "block traffic outside the tunnel"
either way. It stays off otherwise because it breaks local traffic.

| property | strict | why |
|---|---|---|
| `includeAllNetworks` | on | Everything enters the tunnel, connections opened before it came up included, and nothing leaves while the tunnel is down. |
| `excludeLocalNetworks` | off; on with "allow local network" | It exempts whatever the current network calls local. TunnelCrack's LocalNet attack declares public ranges local to take them out of the tunnel. |
| `enforceRoutes` | on | The tunnel's routes win over more specific ones the network pushes (DHCP option 121, TunnelVision; LocalNet). |

The tvOS SDK has only `enforceRoutes`, so on tvOS strict mode is that alone. Apple
still exempts DHCP, captive-portal probes, carrier cellular services and, by default,
APNs (`excludeAPNs`, `excludeCellularServices`, left at their defaults), and Proton and
IVPN report Apple-service traffic leaving regardless.

Strict mode stops AirDrop, CarPlay, AirPlay and LAN servers on iOS and macOS. "Allow
local network" restores them at the cost of the LocalNet protection. A narrower
alternative is `route_exclude_address` with the LAN's own prefix in the profile, which
exempts only that range; whether excluded routes are honoured under
`includeAllNetworks` is unverified (see the matrix below).

**The extension's own sockets.** With `includeAllNetworks` the system does not reliably
exempt the extension's sockets from its own tunnel; Mullvad saw them stall. The
provider therefore calls `sbr_set_default_interface` with the first physical interface
`NWPathMonitor` reports, and every outbound socket sbr opens (TCP dials, direct UDP, the
QUIC socket, WireGuard's socket, DNS transports) is bound to it with `IP_BOUND_IF` /
`IPV6_BOUND_IF`. These are BSD sockets; `NWConnection` with `requiredInterface` is not
used. `sendmsg_x` is never used on the utun (see HANDOVER.md).

**Server names.** An outbound's server name is resolved by its `domain_resolver`, else
`route.default_domain_resolver`, else the DNS rules and `dns.final`. A config with no
`dns` section, or whose resolver is `local`, resolves through `getaddrinfo` in the
extension: the physical network's resolver, in cleartext, which a hostile network can
answer with its own address (TunnelCrack ServerIP). `sbr check` warns when a config has
a `tun` inbound and no `dns` section. Give servers IP addresses, or resolve them with an
encrypted resolver addressed by IP.

**App updates.** Mullvad reports that updating the app while a tunnel with
`includeAllNetworks` is up can leave the device with no connectivity: the update stops
the extension, the system keeps blocking, and nothing starts it again. The app's
toggle text tells users to turn strict mode off before updating. To recover, turn the
VPN off in Settings › VPN (or System Settings › VPN on macOS), or remove the sbr
configuration there, or restart the device; then reconnect from the updated app.

**Device test matrix.** None of this has run on a device. Each row needs iOS, and macOS
(app extension and system extension) where marked; tvOS where it applies.

| case | setup | expected |
|---|---|---|
| Dual-stack, IPv4-only profile | Wi-Fi with IPv6, `tun` with only an IPv4 address, `auto_route` | Diagnose's IPv6 check passes; an IPv6-only site fails at once, others load over IPv4 |
| IPv4-only network | Same profile | Normal browsing; no stall from the IPv6 routes |
| Strict: own sockets | Strict on; REALITY, hysteria2 and WireGuard profiles; iOS and macOS | Each connects and carries traffic; the extension log shows outbound sockets bound to `en0` / `pdp_ip0` |
| Strict: earlier connections | Start a long download or SSH session, then connect | It stops or moves into the tunnel; the exit IP of new connections is the proxy's |
| Strict: roaming | Wi-Fi to cellular and back while streaming | Sockets re-pin to the new interface and traffic resumes |
| Tunnel restart | Stop the extension (memory kill, crash, or reconnect) | Strict: nothing leaves while it is down, and an on-demand rule restarts it; off: auto-connect brings it back |
| App update | TestFlight update with strict on | Record whether connectivity returns; check the recovery steps above |
| DHCP option 121 | Test AP pushing a classless route for a public /24 via the AP | Strict: that range still goes through the tunnel; off: record |
| LocalNet | Test AP whose LAN subnet is a public range | Strict: the range stays in the tunnel; "allow local network" on: record the leak |
| LAN access | Apple TV streaming from a LAN server; iPhone AirPlay | Strict breaks it; "allow local network" (iOS/macOS) or `route_exclude_address` with the LAN prefix restores it; tvOS: only `route_exclude_address` |
| No `dns` section | Capture port 53 on the router | Confirm the extension's lookups reach the router's resolver in cleartext, and that `sbr check` warns |
| ServerIP | LAN resolver answers the server's name with another address | With `domain_resolver` over DoH by IP, the tunnel still reaches the real server |

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
int32_t         sbr_apply_profile(SbrInstance *instance, const char *config_json, char **error_out);
int32_t         sbr_fetch_profile(SbrInstance *instance, const char *url, SbrFetchCallback callback, void *context);
void            sbr_stop(SbrInstance *instance);
int32_t         sbr_select(SbrInstance *instance, const char *group, const char *member);
char           *sbr_groups(SbrInstance *instance);
char           *sbr_connections(SbrInstance *instance, uint32_t limit);
int32_t         sbr_close_connection(SbrInstance *instance, const char *id);
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

WireGuard follows the same default. On a multi-thread runtime each endpoint
gets one egress thread that makes the UDP sends, so they overlap with the stack
and the crypto. On current-thread it sends inline. Measured on an M1 Pro, against
a sing-box peer on loopback with the machine shared with other builds: one
thread reaches about 2 Gbit/s of upload at 3.2–3.5 CPU-seconds per GB, and the
multi-thread runtime with the egress thread gets the same throughput at 3.8–4.3.
At these rates the loopback sing-box server is the bottleneck: it uses about
three cores. The single thread is about 85% busy at that rate, so the egress
thread is headroom for macOS on fast links. On a phone it would spend more CPU
per byte for an uplink the radio can't fill.

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
- The TUN's TCP: under `stack: system` the kernel holds those buffers, outside the
  extension's footprint. Under `stack: gvisor` (userspace TCP) they are the extension's:
  128 KiB each way per connection at most, nothing for idle connections, and 8 MiB for all
  connections together (plus at most four 4 KiB chunks per connection), so 512 busy
  connections stay under 16 MiB. `TcpConfig` in `sbr-tun` holds the limits.
- `sbr_runtime_stats` reports `phys_footprint` (`TASK_VM_INFO`, the figure jetsam uses)
  and `os_proc_available_memory()` (headroom before the kill) so the app can show them.
- **Reported:** each UDP session's reader allocates a 64 KiB receive buffer
  (`crates/sbr-engine/src/udp.rs:224`, `vec![0u8; 65535]`). At the 512-session cap that is
  32 MB, more than the TCP budget. Size it from the TUN MTU, or lower the UDP cap on iOS.

## Building

```sh
apple/build-xcframework.sh          # on macOS with Xcode
```

- iOS (arm64), iOS Simulator (arm64), macOS (arm64 + x86_64),
  Mac Catalyst (arm64 + x86_64), tvOS (arm64), tvOS Simulator (arm64), all on
  stable Rust. The simulators are arm64 only, since an Intel simulator needs an
  Intel Mac. `SBR_SKIP_TVOS=1` skips tvOS and `SBR_SKIP_CATALYST=1` skips
  Catalyst.
- Every target builds in one cargo invocation, so the single-threaded final
  LTO passes overlap instead of queueing.
- Release builds use fat LTO with one codegen unit, and the script prints each
  slice's size. The archives are not run through `strip`: it corrupts aws-lc's
  assembly objects and the app then fails to link. Xcode strips the final binary.

From Linux, `apple/check-apple-targets.sh` runs `cargo check` for all of these
targets. aws-lc-sys and blake3 build C code
that needs an Apple SDK, so on Linux the script swaps in a stand-in compiler
that emits empty objects. The Rust code is fully type-checked; the C code is
only compiled by the real macOS build.

## Tunnel check

`mise run test:apple-tunnel` runs sbr inside a real macOS packet tunnel
extension and checks TCP, DNS, UDP and a bulk download through it, without
touching the Mac's default route or DNS. It is the only test that exercises a
Network Extension, whose own sockets bypass its tunnel; CI cannot run it,
because an NE needs a signed app and a one-time approval of its VPN
configuration. See [`TunnelCheck/README.md`](TunnelCheck/README.md).

## TestFlight

```sh
APPLE_API_KEY_PATH=AuthKey.p8 APPLE_API_KEY_ID=... APPLE_API_ISSUER_ID=... \
  apple/testflight.sh ios|tvos [build-number]
```

`testflight.sh` archives the iOS or tvOS app in Release, exports it with
`app-store-connect` and uploads it. Release signs manually with the Apple
Distribution certificate and the platform's App Store profiles ("sbr App
Store", "sbr tunnel App Store" and "sbr widgets App Store" on iOS; "sbr tvOS
App Store" and "sbr tunnel tvOS App Store" on tvOS; `App/project.yml`), so the result does not depend on which Apple ID
Xcode is signed in with. `tools/fetch-profiles.py` installs those profiles from
App Store Connect on a machine that lacks them. The build number defaults to the
UTC time as `YYYYMMDDHHMM`, because App Store Connect accepts only rising build
numbers within a version. The export runs with the system `PATH`, since
Homebrew's `rsync` breaks its copy step.

## CI

`.github/workflows/ci-cd.yml` runs on every push and pull request to `main`:
`cargo fmt`, clippy and the tests on Linux, and the `Apple` job, which runs
everything that needs a Mac on one runner: clippy and the tests (with
sing-box, Xray and hysteria from Homebrew so the interop tests run), then the
xcframework (no Catalyst) and the app unsigned for iOS, tvOS and macOS. A push to `main` that passes then calls `ios.yml`,
which archives the app for iOS and tvOS against that xcframework and uploads both to TestFlight; `ios.yml` can also be run
by hand to retry an upload. A pull request's newer push cancels its older run, and so does a newer push to `main` unless the older one may release. Pull requests
never upload.

A push that changes the workspace version (a merged release pull request),
or a manual run on `main` while that version is unreleased, also runs the
`Release (macOS)` job alongside the checks, in place of the `Apple` job, which
its pull request already ran: it builds the xcframework without Catalyst (and
keeps it for TestFlight), then `apple/macos-release.sh build` archives `SbrMac` and exports
it with Developer ID signing and `package` makes the signed disk image. The
image is built with dmgbuild (`apple/dmg/settings.py`, run through `uvx`),
which writes the Finder window's layout into `.DS_Store` directly rather than
scripting Finder, so it lays out the same on a runner with no logged-in
session. Once
the checks pass, CI/CD publishes the GitHub release with that image, and the
`Notarise` job then runs `notarise-dmg`, replaces the release's copy with
the stapled one, and writes `Casks/sbr.rb` in radiosilence/homebrew-sbr. See the root README's "Releases".

These jobs use these repository secrets, the same names kōan uses:

| secret | value |
|---|---|
| `APPLE_API_KEY_P8` | base64 of the App Store Connect API key (`.p8`) |
| `APPLE_API_KEY_ID`, `APPLE_API_ISSUER_ID` | that key's ID and issuer |
| `IOS_CERTIFICATE_P12` | base64 of the Apple Distribution certificate (`.p12`) |
| `IOS_CERTIFICATE_PASSWORD` | its password |
| `MACOS_CERTIFICATE_P12` | base64 of the Developer ID Application certificate (`.p12`) |
| `MACOS_CERTIFICATE_PASSWORD` | its password |
| `RELEASE_TOKEN` | a token with `contents: write` on this repository and radiosilence/homebrew-sbr, which creates the release and its tag and updates the cask |

Without the key or the certificate, the TestFlight job is skipped. The macOS
release jobs fail instead: a release must not quietly ship without its disk
image.
