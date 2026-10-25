# Benchmarks

Run 2026-10-25 on an otherwise idle 4-vCPU Linux VM, three runs each, after all
protocol work merged. sing-box is HEAD (a6952cc) built with
`with_quic,with_utls,with_wireguard,with_gvisor`. Both cores get the **same
config file**; servers are sing-box on loopback. Gbit/s, min–max over 3 runs.

| path | sbr | sing-box | verdict |
|---|---|---|---|
| socks → direct | 36.2–37.3 | 34.8–39.8 | tie (sing-box uses `splice(2)` on Linux; Darwin has none) |
| socks → shadowsocks-2022 | 19.4–19.4 | 16.7–17.7 | **sbr +10–16%** |
| TUN (system stack) → direct | 5.4–5.9 | 5.0–5.5 | **sbr +6–9%** |
| vless + tls, up / down | 13.7–16.9 / 14.4–16.3 | 13.1–14.5 / 13.5–14.6 | **sbr ahead** in 5 of 6 |
| trojan + tls, up / down | 15.5–17.5 / 15.0–16.8 | 13.0–14.4 / 13.3–13.7 | **sbr +14–23%** |
| vmess aes-128-gcm, up / down | 14.7–15.8 / 14.9–15.7 | 12.6–13.3 / 11.8–13.1 | **sbr +17–31%** |
| hysteria2 upload | 2.18–2.35 | 2.35–2.38 | sing-box slightly faster; sbr uses **8–15% less CPU per GB** |
| WireGuard 4 streams, up | 1.97–2.33 | 2.46–2.77 | **sing-box +15–40%** |
| WireGuard 4 streams, down | 4.06–4.60 | 2.55–2.68 | **sbr +52–72%** |

Takeaways:
- Encrypted proxy paths (SS-2022, TLS protocols) are where sbr wins clearly.
- WireGuard upload loses here (Linux, before the Darwin work below).
- hysteria2 throughput is at parity, with lower client CPU per byte.
- TUN CPU numbers aren't comparable: sbr's figure includes the in-process load
  generator and sink.

Reproduce: `cargo build --release -p sbr-engine --examples`, then
`throughput 4 5 <sb>`, `tun_bench 4 5 <sb>` (root), `proxy_bench <sb> 4 5`,
`quic_throughput <sb> 4 5`, `wg_throughput <sb> 4 5`.

## Against the servers jaritanet runs (macOS)

Run 2026-10-25 on an Apple M1 Pro (8 cores, macOS), loopback, against
Xray-core 26.10.21 and apernet hysteria 2.13.0 with jaritanet-shaped configs;
the clients are sbr and Homebrew sing-box 1.14.4 with the same config file.
4 streams × 5 s, three rounds back to back, min–max. Gbit/s, then client
CPU-seconds per GB.

| path | sbr | sing-box |
|---|---|---|
| REALITY + Vision, plain inner, up / down | 20.0–20.6, 0.52 / 17.5–18.4, 0.99 | refused |
| REALITY + Vision, TLS inner, up / down | 19.7–23.0, 0.28 / 12.6–15.8, 0.55–0.72 | refused |
| TLS + Vision, plain inner, up | 20.1–20.5, 0.45 | 18.6–18.9, 0.72 |
| TLS + Vision, plain inner, down | 20.8–21.5, 0.65 | 16.9–17.7, 1.05 |
| TLS + Vision, TLS inner, up | 17.4–28.1, 0.27–0.30 | 18.3–22.2, 0.28 |
| TLS + Vision, TLS inner, down | 11.5–20.5, 0.39–0.54 | 3.4–14.1, 0.74–1.96 |
| hysteria2 (salamander), up | 0.86–0.88, 12.6–12.8 | 1.25–1.32, 9.6–10.3 |
| hysteria2 (salamander), down | 0.88–0.92, 15.6–16.3 | 0.94–0.99, 16.3–16.9 |

- sing-box strips X25519MLKEM768 from its REALITY ClientHello, which
  XTLS/REALITY servers have refused since 2026-09-08, so it cannot use the
  REALITY inbound at all. The TLS + Vision inbound (same Vision path, pinned
  certificate) is where the two clients compare.
- Vision: sbr is ahead or level everywhere and uses 35–40% less CPU per GB
  on the padded path. The TLS-inner rows (direct copy) vary widely between
  rounds for both clients on macOS loopback.
- hysteria2 upload loses: about 32% less throughput and 25% more CPU per GB
  than sing-box against the apernet server. On Linux against a sing-box
  server the two were level; this needs profiling on Darwin (no UDP GSO
  there, so per-datagram send cost and salamander dominate).

Reproduce: `upstream_bench <xray> <hysteria> <sing-box> 4 5 3`.

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
