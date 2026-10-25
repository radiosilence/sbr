# China

Written 2026-10-25. This is the China-specific companion to `docs/threat-model.md`: what the Great Firewall (GFW) does to the transports sbr and its reference deployment (`radiosilence/jaritanet`) use, what each side does about it, and what has not been verified. Nothing here has been measured from inside China; see the last section.

## What the GFW does

| technique | since | evidence | confidence |
|---|---|---|---|
| DNS poisoning: forged answers injected for blocked names, on UDP 53 to any resolver. | long-standing | [Hoang et al., GFWatch, USENIX Security 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/hoang) | high |
| IP blocking of servers, usually after they are identified by the techniques below; in Oct 2022 TLS-based proxy servers were blocked by port, then by IP. | long-standing; wave Oct 2022 | [GFW Report](https://gfw.report/blog/blocking_of_tls_based_circumvention_tools/en/) | high |
| SNI filtering of TLS: the SNI is read from the ClientHello and a listed name answered with forged RSTs. The filter parses a single TLS record and does not reassemble records; a TCP split helps only if no segment holds the whole name. | long-standing; measured 2023 | [Niere et al., CCS 2023](https://doi.org/10.1145/3576915.3624372), [Hoang et al., GFWeb, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/hoang) | high |
| Henan's provincial firewall (AS4837) with a blocklist up to ten times the national one, including whole second-level domains; defeated by any TCP option or ClientHello fragmentation. | Aug 2023 | [GFW Report, IEEE S&P 2025](https://gfw.report/publications/sp25/en/) | high |
| ESNI blocked outright, with residual blocking of the (client, server, port) triple for 120–180 s; ECH is blocked indirectly by blocking the encrypted DNS that would deliver its keys. | Jul 2020 | [Bock et al.](https://geneva.cs.umd.edu/posts/china-censors-esni/esni/), [FOCI 2025](https://petsymposium.org/foci/2025/foci-2025-0016.pdf) | high |
| QUIC SNI filtering: QUIC v1 Initials decrypted at scale, SNI matched against its own list, 180 s block of the triple. Only datagrams with source port above destination port are inspected; a ClientHello split across datagrams evades it. | 2024-04-07 | [Zohaib et al., USENIX Security 2025](https://gfw.report/publications/usenixsecurity25/en/) | high |
| Fully-encrypted-traffic heuristic: random-looking first payloads blocked unless they match one of five exemptions (printable prefix, popcount bounds, TLS/HTTP prefix and others); applied to a fraction of connections to selected datacentre ranges. Reported dormant since Mar 2023. | Nov 2021 | [Wu et al., USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi) | high (rules), medium (dormant) |
| Active probing: suspected servers are sent replays and crafted payloads; how a server answers invalid input decides. | 2012 onwards | [Ensafi et al., IMC 2015](https://dl.acm.org/doi/10.1145/2815675.2815690), [Alice et al., IMC 2020](https://gfw.report/publications/imc20/en/) | high |
| TLS-in-TLS detection by packet sizes and timing, effective against Vision; no published evidence of deployment. | technique 2024 | [Xue et al., USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting) | high (technique), low (deployed) |
| Unconditional forged RST+ACK on all TCP/443 for 74 minutes; 22 and 80 unaffected. | 2025-08-20 | [GFW Report](https://gfw.report/blog/gfw_unconditional_rst_20250820/en/), [net4people #511](https://github.com/net4people/bbs/issues/511) | high |
| Geedge Networks / MESA leak: JA3/JA4 signatures combined with certificate issuer, IP range and FQDN; ML flow classifiers; flagging of long-lived high-volume unidentified flows; tagging subscribers as VPN users. | leak Sep 2025 | [GFW Report](https://gfw.report/blog/geedge_and_mesa_leak/en/), [InterSecLab](https://interseclab.org/research/the-internet-coup/) | high (leak), medium (in use) |
| Short international blackouts for individual subscribers after P2P or known-tool use (Henan, Jiangsu). | Feb 2026 | [net4people #583](https://github.com/net4people/bbs/issues/583) | low–medium |

No measurement shows the GFW identifying REALITY itself. The risks to it are indirect: a blocked borrowed SNI, an SNI that does not belong on the server's IP, a probe that gets a certificate that does not match the SNI, volume per IP, and the flow-level classifiers in the Geedge material.

## What sbr and jaritanet do about each

| technique | sbr (client) | jaritanet (server and profile) |
|---|---|---|
| DNS poisoning | Every resolver in the generated profile is detoured through the tunnel; `hijack-dns` keeps the system's DNS inside it. Server addresses are IPs. | `gw-cache` (the gateway's unbound), `cf-doh` and `ts-dns` all detour through `entry-select`. |
| IP blocking | Nothing a client can do beyond failing over to another entry. | Single entry IP today. The CDN-fronted XHTTP entry (scaffolded, off) is the answer that survives an IP block, at a privacy cost (below). |
| SNI filtering (TCP) | Automatic ClientHello fragmentation: an outbound whose handshake is reset before the server answers retries with the ClientHello split across TLS records, then across records and TCP segments, cutting inside every label (README, "ClientHello fragmentation"). Configured `fragment`/`record_fragment` and the `route-options` form for `direct` routes. | The China-blocked borrowed SNIs (`www.google.co.uk`, `vk.com`) leave the default profile; the first REALITY identity is the gateway's own hostname, which is not blocked. |
| SNI/IP and certificate consistency | Browser-exact ClientHellos (Chrome 155 default, JA4 equal to the browser's). | "Steal oneself": the first REALITY server name is a hostname of the gateway with its own Let's Encrypt certificate served by Traefik on the same box, so SNI, IP and certificate agree and a probe using that SNI gets a genuine site. The borrowed names stay as fallbacks and remain inconsistent on a Hetzner IP. |
| ESNI/ECH | Not used. | Not used. |
| QUIC SNI filtering | hysteria2 without Salamander and TUIC split the SNI across Initial packets (README, "QUIC ClientHello scrambling"). | Salamander on every hysteria2 port hides the Initial entirely. |
| FET heuristic | REALITY and hysteria2 are not random-looking TCP; Shadowsocks-2022 and VMess would be. | No Shadowsocks or VMess on the entry. |
| Active probing | n/a | Unauthenticated REALITY connections reach Traefik. With the self-steal name the probe sees a matching certificate; with a borrowed name it sees Traefik's certificate for the gateway's domains, which does not match. hysteria2 with Salamander does not answer unauthenticated packets. |
| TLS-in-TLS | Vision; XHTTP as an alternative transport. | XHTTP inbound scaffolded behind the CDN option only. |
| TCP/443-wide events | Failover to hysteria2 (UDP) and its other ports; health tracking demotes a member whose handshakes fail or whose flows stall. | hysteria2 on UDP 443, 3478 and 4500. REALITY on a second TCP port is recommended (threat model, server recommendation 5) and not done. |
| Flow classifiers, probing as a fingerprint | `urltest` probes members on one host one at a time with random gaps and jitters its period, instead of six handshakes with six SNIs at once on a fixed timer. | Fewer borrowed identities in the profile means fewer distinct SNIs from one client to one IP. |
| Subscriber blackouts | Out of reach. | Out of reach. |

## Not verified

- **Anything from inside China.** Every claim that a path works is from loopback tests against a model filter (`crates/sbr-engine/tests/common/sni_censor.rs`) or real Xray and hysteria servers, never through the GFW.
- **Automatic fragmentation under residual blocking.** If the GFW follows an SNI reset with a residual block of the (client, server, port) triple, as it does for ESNI and QUIC, the immediate retry is reset too and the outbound climbs to segment splitting, which costs `fragment_fallback_delay` (500 ms on Apple platforms) on every later handshake. Whether plain SNI resets carry a residual block today is not established. A level is never lowered until the network changes.
- **Salamander under volume.** High-entropy UDP is what the leaked tooling and Russia's mobile networks target; there is no China measurement of hysteria2 with Salamander at sustained volume.
- **The self-steal identity.** It exists only in the jaritanet pull request; nothing has been deployed or probed.
- **The CDN path.** Scaffolded and off. Cloudflare's addresses are reachable from China but are slow on several ISPs, and the CDN terminates TLS, so it sees the client's address, timing, volume and the request path, plus any inner traffic that is not itself encrypted.
- **Probe URL.** The deployment's `urltest` URL is `generate_204`, so sbr's data probe through each member is inconclusive and only passive detection catches a path that completes its handshake and then stalls. A file of at least 64 KiB on the gateway would make the probe conclusive.
- **sbr on a phone.** The Apple build has not run on a device (HANDOVER.md).

## An in-China probe

The gaps above close only with a vantage point inside the GFW. Hong Kong and Macau are outside it and prove nothing.

**Where.** A mainland cloud VPS (Alibaba Cloud, Tencent Cloud, Huawei Cloud) needs an account with real-name verification against a Chinese ID or a business licence for mainland regions; serving websites additionally needs ICP filing, which a probe that only makes outbound connections does not. The account holder is identifiable and the provider can read the box, so the alternatives are a mainland broadband line or SIM of someone who accepts that risk, or a commercial measurement service. A datacentre vantage point also differs from residential users: some measurements (the FET heuristic, Henan) depend on the destination range or the client's province, so one box is one sample.

**What it runs.** Hourly, from a systemd timer with a random offset of up to 20 minutes so the probes are not periodic:

1. For each path separately (each REALITY server name, each hysteria2 port, the CDN entry if enabled), start `sbr run` with a profile containing only that outbound and a `mixed` inbound, fetch a 1 MiB file from the gateway through it (past any byte-count freeze), and record handshake time, bytes received and the error. Log at `info` so automatic fragmentation steps show up.
2. Controls: a direct fetch of a large domestic site (is the box online), and one outbound with a known-blocked SNI (is SNI filtering active on this path). A path failure means something only when the first control passes.
3. On failure, capture the handshake with `tcpdump` (headers only) so a forged RST (TTL and IP ID differ from the server's) can be told from a drop or a real server error.
4. Push results as metrics to the deployment's VictoriaMetrics (`vmagent` remote write) and alert through the existing Telegram notifier when one path fails twice in a row while the controls pass, or when every path fails.

**Credentials.** A dedicated probe user with its own VLESS UUID, REALITY short ID and hysteria2 password, so the box, which sits in the adversary's jurisdiction, holds nothing that a revocation does not cover. Never an admin credential.

**Cost to the deployment.** About 25 short connections an hour from one Chinese datacentre address to the gateway, which is itself a pattern: keep the volume to the 1 MiB fetch per path, and do not run the probe from the same address as real users.
