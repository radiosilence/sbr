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
- WireGuard upload loses: one device task vs wireguard-go's multi-core crypto.
  Next step: parallel encryption workers.
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
