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
