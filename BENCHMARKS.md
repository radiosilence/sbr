# Benchmarks

Run 2026-10-26 (b3bb52f and later) in an OrbStack Linux VM with 8 vCPUs on an
Apple M1 Pro, three rounds each. sing-box is the 1.14.4 release build
(linux-arm64). Both cores get the **same config file**; servers are sing-box on
loopback. Gbit/s, min–max over 3 rounds.

| path | sbr | sing-box | verdict |
|---|---|---|---|
| socks → direct | 112.7–128.7 | 155.1–166.0 | **sing-box +20–47%** (`splice(2)` on Linux; Darwin has none) |
| socks → shadowsocks-2022 | 44.8–49.5 | 31.6–45.1 | **sbr ahead** |
| vless + tls, up / down | 38.6–45.2 / 41.5–48.0 | 38.2–42.5 / 39.4–42.3 | sbr ahead in 5 of 6 rounds |
| trojan + tls, up / down | 43.6–45.5 / 42.4–48.4 | 38.6–41.8 / 38.8–41.7 | **sbr +2–25%** |
| vmess aes-128-gcm, up / down | 39.8–43.0 / 39.3–40.1 | 36.8–38.6 / 35.4–36.9 | **sbr +3–17%** |
| hysteria2 upload | 4.19–4.48, 1.47–1.59 CPU-s/GB | 3.08–3.26, 1.49–1.61 | **sbr +29–45%** at the same CPU per GB |
| WireGuard 4 streams, up | 3.02–3.07, 1.53–1.56 CPU-s/GB | 2.05–2.14, 8.21–8.58 | **sbr +41–50%** at a fifth of the CPU |
| WireGuard 4 streams, down | 2.22–2.38, 2.01–2.04 | 1.84–2.09, 6.22–6.44 | **sbr +6–29%** at a third of the CPU |

Takeaways:
- Every encrypted path is sbr's. hysteria2 upload turned from a loss on
  2026-10-25 (2.18–2.35 against 2.35–2.38) once streams were spread over two
  QUIC connections; WireGuard upload turned with the connected-socket send path.
- Plain relay to `direct` is the one loss: sing-box moves bytes between two TCP
  sockets with `splice(2)` without copying them through userspace.

## Through a real server (macOS, home Wi-Fi)

Run 2026-10-26: an M1 Pro on home Wi-Fi, each client a local SOCKS proxy to the
same hysteria2 server (apernet hysteria with Salamander on a Hetzner VM),
downloading `nbg1-speed.hetzner.com/10GB.bin` for 20 s, two rounds. Server CPU
from `kubectl top` (15 s windows, approximate).

| | throughput | client CPU | server CPU |
|---|---|---|---|
| tunnel off | 472–500 Mbit/s | — | — |
| sbr | 566–574 Mbit/s | 51–60% of a core | ~0.56 core |
| sing-box | 515–553 Mbit/s | 87–92% of a core | ~1.4 cores |

Both tunnels beat the direct download because the server reaches the test host
by a better route than the home connection does.

Reproduce: `cargo build --release -p sbr-engine --examples`, then
`throughput 4 5 <sb>`, `tun_bench 4 5 <sb>` (root; both TCP stacks, each direction), `proxy_bench <sb> 4 5`,
`quic_throughput <sb> 4 5`, `wg_throughput <sb> 4 5`.

## TUN: system stack vs userspace TCP

Run 2026-10-25 in an OrbStack Linux VM (8 vCPUs) on an Apple M1 Pro. The host was
shared with other builds (load average about 7), so absolute numbers are loose; the
two stacks ran back to back in each round, which is what the comparison rests on.
`tun_bench 4 5`: four streams for 5 s from apps through the TUN, the engine and
`direct` to a loopback server, three rounds, min–max. "CPU" is whole-machine
CPU-seconds per GB from `/proc/stat`, which also counts the kernel's softirq work
that the system stack's second trip through the kernel TCP costs.

| MTU | path | system Gbit/s | system CPU s/GB | userspace Gbit/s | userspace CPU s/GB |
|---|---|---|---|---|---|
| 9000 | up | 16.0–16.6 | 0.65–0.68 | **22.4–22.8** | **0.47–0.48** |
| 9000 | down | 15.2–15.7 | 0.67–0.70 | **19.1–19.5** | **0.53–0.55** |
| 1280 | up | 6.8–7.0 | 1.35–1.40 | **11.9–12.3** | **0.75–0.78** |
| 1280 | down | 6.6–6.7 | 1.32–1.34 | **9.8–10.2** | **0.95–1.01** |

- The userspace stack is ahead everywhere, by the most at MTU 1280 (the user's
  profile), where per-packet costs dominate: 1.5–1.75× the throughput at about 40%
  less CPU per byte. The system stack sends every segment through the kernel twice
  (app socket to TUN, then TUN to the NAT listener), the userspace stack once.
- Both rates are far above 1 Gbit/s, so a phone's radio, not the stack, is the
  limit. What matters there is CPU per byte, and that favours the userspace stack.
- Not measured: a real Darwin utun. Creating one needs root (or a Network
  Extension), so macOS and iOS numbers wait for a device run. The Darwin batch read
  path (`recvmsg_x`) is exercised by `sbr-tun/tests/user_stack.rs` over a socketpair.

Reproduce (root, Linux): `tun_bench 4 5`, and `SBR_BENCH_MTU=1280 tun_bench 4 5`.

## Against the servers jaritanet runs (macOS)

Run 2026-10-26 on an Apple M1 Pro (8 cores, macOS), loopback, against
Xray-core 26.10.21 and apernet hysteria 2.13.0 with jaritanet-shaped configs;
the clients are sbr and Homebrew sing-box 1.14.4 with the same config file.
4 streams × 5 s, three rounds back to back, min–max. Gbit/s, then client
CPU-seconds per GB. The machine was in use during the run, so absolute figures
are lower than on 2026-10-25; compare the two clients within a row. The
hysteria2 rows are from 49331a3, the rest from 61c5b99.

| path | sbr | sing-box |
|---|---|---|
| REALITY + Vision, plain inner, up / down | 8.94–9.31, 0.64 / 8.37–8.48, 1.16–1.18 | refused |
| REALITY + Vision, TLS inner, up / down | 11.54–11.64, 0.60–0.63 / 5.63–8.53, 1.10–2.04 | refused |
| TLS + Vision, plain inner, up | 9.02–9.19, 0.66–0.67 | 7.68–7.89, 1.28–1.29 |
| TLS + Vision, plain inner, down | 8.21–8.34, 1.10–1.18 | 7.54–7.83, 1.39–1.45 |
| TLS + Vision, TLS inner, up | 11.75–11.98, 0.59–0.62 | 11.66–11.86, 0.69–0.70 |
| TLS + Vision, TLS inner, down | 7.15–9.26, 1.04–1.58 | 6.95–9.52, 1.09–1.78 |
| hysteria2 (salamander), up | 1.31–1.38, 7.40–7.68 | 1.08–1.11, 13.52–13.75 |
| hysteria2 (salamander), down | 0.84–0.85, 13.31–13.47 | 0.87–0.89, 21.05–21.52 |

- sing-box strips X25519MLKEM768 from its REALITY ClientHello, which
  XTLS/REALITY servers have refused since 2026-09-08, so it cannot use the
  REALITY inbound at all. The TLS + Vision inbound (same Vision path, pinned
  certificate) is where the two clients compare.
- Vision: sbr is 5–20% faster on the padded path at 15–49% less CPU per GB;
  with TLS inside (direct copy) the two are level.
- hysteria2: upload was 0.86–0.88 Gbit/s on 2026-10-25, behind sing-box. Two
  changes fixed it. On Darwin, QUIC now sends and receives on a socket
  connected to the server: Darwin routes every unconnected `sendto` afresh and
  has no UDP GSO, and quinn-udp always names a destination. That halved upload
  CPU per GB (15.4–16.2 to 7.4–7.7). Streams are also spread over two QUIC
  connections, because quinn runs one connection's packet processing on one
  task; that matters most on a phone, where one core was the ceiling.
  Download is 3–6% behind in throughput at 37% less CPU per GB.

Reproduce: `upstream_bench <xray> <hysteria> <sing-box> 4 5 3`; `SBR_BENCH_ONLY=hysteria2` runs one case.

## WireGuard on Apple silicon

Run 2026-10-25 on an M1 Pro (6 performance + 2 efficiency cores) running macOS,
with Homebrew sing-box 1.14.4 as the peer and as the comparison client. The
machine was shared with other builds (load average 10–17), so expect wide
spreads. `wg_throughput <sb> <streams> 5 1` was run with
`SBR_BENCH_THREADS=0,1`, alternating the old build, sing-box and the new build
back to back, three rounds each. Each client runs in its own process. Columns
give Gbit/s and client CPU-seconds per GB, min–max. `t1` is the current-thread
runtime (the iOS default) and `t0` the multi-thread default.

| streams | client | up Gbit/s | up CPU s/GB | down Gbit/s | down CPU s/GB |
|---|---|---|---|---|---|
| 1 | sbr t0, before | 0.88–0.91 | 8.2–8.9 | 0.64–0.69 | 7.8–9.3 |
| 1 | sbr t1, before | 0.83–0.92 | 8.0–9.0 | 0.63–0.67 | 7.3–9.3 |
| 1 | sing-box | 0.99–1.79 | 11.4–12.4 | 0.61–0.81 | 12.6–20.0 |
| 1 | **sbr t0, after** | 1.63–1.98 | 3.8–4.1 | 0.67–0.70 | 6.9–7.9 |
| 1 | **sbr t1, after** | 1.98–2.05 | 3.2–3.3 | 0.66–0.74 | 6.7–8.4 |
| 4 | sbr t0, before | 0.68–0.79 | 9.5–12.0 | 0.62–0.77 | 7.3–14.9 |
| 4 | sbr t1, before | 0.66–0.83 | 8.4–9.5 | 0.38–0.60 | 7.4–11.2 |
| 4 | sing-box | 1.23–1.80 | 11.4–11.9 | 0.68–0.81 | 11.1–20.5 |
| 4 | **sbr t0, after** | 1.21–2.69 | 4.1–4.2 | 0.67–0.74 | 6.1–11.6 |
| 4 | **sbr t1, after** | 1.54–2.16 | 3.5–3.6 | 0.44–0.68 | 5.8–7.7 |

- The upload deficit on Darwin was the send path, not the crypto. A profile of
  the old build had about 70% of the device thread in `sendmsg`, against 9% in
  ChaCha20-Poly1305. Darwin routes every unconnected `sendto` afresh: a
  microbenchmark measured 6.8 µs per 1440-byte datagram unconnected and 2.9 µs
  connected. Extra threads sending on one socket gained nothing, because the
  kernel serialises them. Connecting the socket (one peer, no `listen_port`)
  more than doubled upload and halved its CPU per byte.
- The egress thread (multi-thread runtime only) takes the sends off the
  device task. Here it shows mainly in the best runs (2.7 vs 2.2 Gbit/s). The
  loopback sing-box server burns about three cores at 2 Gbit/s and is the
  bottleneck. The single-thread client is about 85% busy at that rate.
- Download is at parity in throughput, limited by the same server's sends, with
  about half sing-box's CPU per byte.
- iOS keeps the current-thread runtime. One thread sustains about 2 Gbit/s at
  the lowest CPU per byte, more than a phone's uplink. See `apple/README.md`.

Rerun 2026-10-26 (61c5b99), same machine in use, three rounds each, Gbit/s and
CPU-s/GB, min–max:

| streams | client | up | down |
|---|---|---|---|
| 1 | sbr t0 | 1.96–1.98, 5.09–5.21 | 0.61, 9.19–9.32 |
| 1 | sbr t1 | 1.90–1.94, 3.93–3.95 | 0.61–0.62, 9.21–9.23 |
| 1 | sing-box | 1.65–1.67, 13.66–14.03 | 0.60–0.61, 27.28–29.37 |
| 4 | sbr t0 | 2.02–2.04, 5.61–5.85 | 0.59–0.60, 12.76–13.72 |
| 4 | sbr t1 | 1.65–1.71, 4.43–4.57 | 0.56–0.58, 9.85–10.40 |
| 4 | sing-box | 1.41–1.57, 13.92–15.61 | 0.60–0.64, 24.98–33.61 |

Download is bound by the loopback sing-box server for every client.

## XHTTP against VLESS + REALITY + Vision (macOS)

Run 2026-10-25 on an Apple M1 Pro (8 cores, shared with other builds),
loopback, one Xray-core 26.10.21 process serving both inbounds over REALITY;
sbr is the client in-process. 4 streams × 5 s, three rounds back to back,
min–max. Gbit/s, then client CPU-seconds per GB. Traffic inside the tunnel
is plain TCP.

| path | up | up CPU/GB | down | down CPU/GB |
|---|---|---|---|---|
| vless + reality + vision | 21.0–25.0 | 0.58–0.69 | 21.7–27.1 | 0.51–0.56 |
| xhttp stream-one (h2) | 9.8–11.4 | 1.19–1.57 | 7.3–14.8 | 0.97–1.12 |
| xhttp stream-up (h2) | 8.3–12.7 | 1.05–1.17 | 5.0–9.6 | 1.06–1.53 |
| xhttp packet-up (h2) | 0.99 | 1.10–1.33 | 8.6–9.7 | 1.09–1.35 |

- XHTTP over HTTP/2 moves 40–55% of Vision's bytes per second and costs about
  twice the client CPU per byte: every byte passes through HTTP/2 framing and
  flow control on both ends, where Vision, after its padded first packets, is
  VLESS inside one TLS stream.
- packet-up upload is capped by the protocol defaults, not by sbr: each
  connection sends at most one `scMaxEachPostBytes` (1 MB) POST per
  `scMinPostsIntervalMs` (30 ms), about 33 MB/s, and four streams give 1 Gbit/s.
  Xray's client has the same cap. Raise the interval or the POST size on both
  ends where upload speed matters more than looking like ordinary requests.
- On a phone uplink none of these rates is the limit; the cost that matters is
  the doubled CPU per byte.

Reproduce: `xhttp_bench <xray> 4 5 3`.
