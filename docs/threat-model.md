# Threat model: censorship and surveillance

Written 2026-10-25. Censor behaviour changes month to month; re-check anything load-bearing against the linked sources before relying on it.

This document maps what state-level censors and surveillance programmes do to circumvention traffic onto what sbr does today, and lists what sbr and its reference deployment must change. The reference deployment is the one sbr is built for: Xray VLESS+REALITY+Vision on TCP/443 with fallback to a real site, and apernet Hysteria2 with Salamander obfuscation on UDP/443, 3478 and 4500 (`radiosilence/jaritanet`, `packages/vpn/src`).

Confidence:

- **High**: peer-reviewed measurement, a primary vendor or government statement, or several independent reports that agree.
- **Medium**: one credible report, or several community reports without controlled measurement.
- **Low**: a single anecdote, an inference, or a source of doubtful quality.

Most 2025–2026 detail comes from community measurement (net4people/bbs, ntc.party, Habr). It is consistent across sources but varies by ISP, region and even cell tower, so treat every threshold as approximate.

## sbr today, as it bears on this model

| area | state |
|---|---|
| REALITY | `sbr-reality`: own TLS 1.3 client with browser ClientHellos (Chrome 155 and Apple captured from the real clients, Firefox 148), X25519MLKEM768, GREASE and ECH GREASE, Vision. Handles NewSessionTicket. |
| Other TLS | The same client with web PKI verification, by default for trojan/VLESS/VMess/HTTP over TLS, the v2ray transports, ShadowTLS's camouflage handshake, AnyTLS and DoH. rustls (a distinguishable ClientHello) only with `utls.enabled: false`, TLS 1.2, client certificates or ECH, which is static-config only. TLS 1.3 only; no session resumption. |
| ClientHello fragmentation | `tls.fragment` / `record_fragment` and the `route-options` form: records cut inside every label of the SNI but the last, one TCP segment boundary. Applies to REALITY too. With neither key set, an automatic mode turns record and then segment splitting on for an outbound whose handshakes are reset before the server answers (README, "ClientHello fragmentation"). |
| QUIC | quinn for hysteria2 (Salamander, port hopping, Brutal) and TUIC. The ClientHello in the Initial is scrambled like quic-go's: the SNI's halves go in different Initial packets (`disable_client_hello_scrambling` turns it off). |
| Transports | ws, httpupgrade, grpc, http, and XHTTP (all modes, HTTP/1.1, HTTP/2 over TLS or REALITY, HTTP/3) as an sbr extension. No `quic` v2ray transport. |
| Multiplexing | `multiplex` (sing-mux) rejected. |
| Other outbounds | shadowsocks (2022), ShadowTLS v1–3, AnyTLS (padding scheme), WireGuard (plain), socks, http. No ssh, no AmneziaWG, no Tor/Snowflake. |
| Probing | Members on one server host are probed one at a time, 200–1200 ms apart; periods vary ±20%; the first member to answer is adopted at start. |
| Failover | `urltest`, plus health tracking (`crates/sbr-engine/src/health.rs`, README "Failover that sees post-handshake blocking"): a 64 KiB data probe through each member, passive detection of resets, unanswered requests and mid-transfer stalls, and demotion with a 120 s back-off that doubles to 30 min. The data probe is conclusive only with a `url` serving at least 64 KiB, or a server whose fallback site answers on its own address (REALITY, trojan). |
| Apple tunnel | Routes and DNS from the `tun` inbound. `strict_route` maps to `includeAllNetworks`, `enforceRoutes` and `excludeLocalNetworks` off, set by SbrKit; the app's "block traffic outside the tunnel" defaults to the profile's `strict_route` and is otherwise opt-in (`enforceRoutes` only on tvOS). Under it the extension's outbound sockets are bound to the physical interface. With `auto_route`, IPv6 is always routed into the tunnel, on a ULA the engine refuses when the `tun` has no IPv6 address. None of it has been verified on a device (apple/README.md, "Leak protection", has the test matrix). |

## Russia

TSPU boxes, mandated by the 2019 "sovereign internet" law, sit in every ISP's network and are controlled centrally by Roskomnadzor; the DPI software is EcoFilter (RDP.RU). Blocks applied through TSPU are not published in the registry and are often regional or temporary, which is why behaviour differs by ISP ([Mediazona, Apr 2026](https://en.zona.media/article/2026/04/07/russian_internet_censorship_2026), [DEF CON 33 TSPU talk](https://media.defcon.org/DEF%20CON%2033/DEF%20CON%2033%20video%20and%20slides/)). Russia is the most active adversary of sbr's protocol set in 2025–2026.

| technique | evidence | confidence |
|---|---|---|
| OpenVPN and WireGuard handshake signatures blocked, mobile first (Aug 2023), widespread by 2025. AmneziaWG periodically blocked. | [Mediazona 2023](https://en.zona.media/article/2023/08/08/vpn), [Habr Feb 2026](https://habr.com/ru/articles/990236/) | high |
| Shape classifier for TLS tunnelled inside a fully encrypted protocol (Shadowsocks/Outline, VMess), from 2024-04-25: three or more client packets of ≥411 bytes, server sending more often than the client. | [net4people #363](https://github.com/net4people/bbs/issues/363) | high |
| **The 16–20 KB freeze.** TCP to an IP in a foreign datacentre ASN (Hetzner, DigitalOcean, OVH, AWS, Cloudflare, others) is silently black-holed after roughly 15–20 KB server-to-client, later refined to about 25 packets in either direction, UDP included. Exempt: SSH on any port, an SNI whitelist, a destination CIDR whitelist. Genuine HTTPS is frozen too. Cloudflare confirmed it from 2025-06-09 on all major carriers. | [net4people #490](https://github.com/net4people/bbs/issues/490), [Cloudflare](https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/), [checker](https://github.com/hyperion-cs/dpi-checkers) | high |
| Port-443 "connection policing" of REALITY+Vision on home ISPs (from Nov 2025): the tunnel dies once several TLS connections to one endpoint carry data, recovers after about 60 s. Other ports, mux, or XHTTP helped some users. | [net4people #546](https://github.com/net4people/bbs/issues/546) | medium |
| 2026 behavioural module (Feb–Jun 2026 waves): flagged destination ASN combined with JA3/JA4 (stock Go and stale uTLS Chrome profiles suspicious) and more than three parallel handshakes to one SNI → 120–600 s blackhole. REALITY+TCP+Vision reported blocked, gRPC and XHTTP partly, Hysteria2 most resilient. | [Habr 1047442](https://habr.com/ru/articles/1047442/) | medium–low (one author's reconstruction) |
| QUIC v1 Initials decrypted and SNI matched against the TLS blocklist on all UDP ports, outbound, 420 s residual block. QUIC v2 not parsed. | [FOCI 2026](https://www.petsymposium.org/foci/2026/foci-2026-0010.php), [net4people #654](https://github.com/net4people/bbs/issues/654) | high |
| Unidentified UDP to foreign IPs largely blocked on mobile (summer 2025); random-looking payloads dying after a few hundred bytes on MegaFon (Oct 2026). | [TechRadar](https://www.techradar.com/vpn/vpn-services/russias-battle-against-vpns-is-entering-a-new-phase-heres-what-to-expect-in-2026), [net4people #673](https://github.com/net4people/bbs/issues/673) | medium / low |
| ECH to Cloudflare (outer SNI `cloudflare-ech.com`) blocked since 2024-11-06; with the freeze, Cloudflare fronting is heavily degraded. | [Habr 856342](https://habr.com/ru/articles/856342), [net4people #662](https://github.com/net4people/bbs/issues/662) | high |
| Mass IP bans of proxy servers, including REALITY self-steal, concentrated on VPS providers popular with Russians (Aug and Sep 2026). | [net4people #671](https://github.com/net4people/bbs/issues/671) | medium |
| Mobile shutdowns and default-deny whitelists ("белые списки") by CIDR and SNI, 48+ regions by Oct 2025; central Moscow without mobile data for three weeks from 2026-03-07. In an Aug 2026 test only REALITY with a permitted Russian SNI got through, and not every such config. | [Meduza](https://meduza.io/feature/2025/10/16/kak-umiraet-internet-karta-shatdaunov-my-podgotovili-ee-sovmestno-s-proektom-na-svyazi), [net4people #650](https://github.com/net4people/bbs/issues/650) | high (shutdowns), medium (what passes) |
| Client-side VPN detection: from 2026-04-15 major Russian apps were told to restrict users with an active VPN; 22 of 30 popular apps detect it, on iOS by interface enumeration and exit-IP comparison. | [RKS Global](https://rks.global/en/research/vpn-detection/), [net4people #605](https://github.com/net4people/bbs/issues/605) | high |
| Possible TUN-mode classification (Beeline, single report). | [net4people #663](https://github.com/net4people/bbs/issues/663) | low |
| Legal: VPN advertising banned; fines for "searching extremist material" (Sep 2025); Apple removed 1,213 apps at RKN's request in 2025. | [OVD-Info](https://ovd.info/en/express-news/2025/07/31/putin-has-signed-law-introducing-fines-searching-extremist-materials-online), [Meduza](https://meduza.io/en/news/2026/05/25/apple-removed-1-213-apps-at-russia-s-internet-regulator-s-request-in-2025) | high |

**Against sbr.** WireGuard, Shadowsocks-2022, VMess and plain trojan to a foreign VPS should be assumed dead. REALITY survives only when its SNI is on the freeze whitelist (Russian services such as VK, Ozon, Yandex), and even then the port-443 policing and the parallel-handshake rule can kill it; every browser tab opening its own REALITY connection is exactly the pattern that rule counts. Hysteria2 with Salamander avoids the QUIC SNI filter but is "unknown UDP", which mobile networks drop. `urltest` cannot see any of this: the TCP handshake and a `HEAD` both complete under the freeze, so sbr keeps selecting a member that stalls on the first large response. App Store availability in Russia is a distribution risk sbr cannot address in code.

**Mitigations.** A REALITY identity with a whitelisted Russian SNI; a relay inside a whitelisted Russian CIDR chained to the foreign exit (the only reported answer to mobile whitelists); multiplexing so one long-lived connection carries many streams; XHTTP as an Xray-native multiplexed transport; an SSH transport (exempt from the freeze); alternate ports; failover that detects stalls after the handshake; routing Russian domestic services `direct` so they never see the VPN exit.

## Belarus

Two state-controlled international chokepoints (Beltelecom and the National Traffic Exchange Center) carry all external traffic, so Belarus needs no TSPU-style distributed system. DPI was procured around 2018 ([Internet Society Pulse](https://pulse.internetsociety.org/en/shutdowns/belarus/)).

| technique | evidence | confidence |
|---|---|---|
| Aug 2020: in-line DPI at the exchanges, blanket TLS throttling and blocking, DNS spoofing, about three days. Standard VPNs and SSH failed; Psiphon worked. | [Psiphon](https://blog.psiphon.ca/2020/08/20/amid-major-network-disruptions-1.76m-psiphon-users-in-belarus/), [Security Affairs / Qurium](https://securityaffairs.com/posts/belarus-internet-blocking) | high |
| Jan 2025 election: VPN disruption and foreign-traffic restrictions. | [Novaya Gazeta Europe](https://novayagazeta.eu/articles/2025/01/25/v-belarusi-nakanune-vyborov-nachalis-pereboi-v-rabote-vpn-i-nekotorykh-saitov-news) | medium |
| Since 2020: resource blocking under the "extremist" label, blocking of VPN providers' sites, short targeted throttling, and user-side enforcement (phone checks, fines, detention). Mobile data capped at 30 GB/month from Jan 2026. | [Meduza Apr 2026](https://meduza.io/feature/2026/04/06/vy-ne-poverite-no-v-belarusi-vse-rabotaet-bez-vpn-i-telegram-i-yutyub-i-instagram-poluchaetsya-tam-svoboda), [Belsat](https://en.belsat.eu/88725171/security-forces-can-now-disconnect-the-belarusians-from-the-internet-and-mobile) | medium |
| Relation to Russian TSPU: no evidence of TSPU or EcoFilter deployed in Belarus. Spillover through shared CIS carriers is plausible. | none found | low |

**Against sbr.** In normal periods REALITY and Hysteria2 are expected to work; there is little recent technical measurement. The threat is crisis-time blanket TLS and UDP blocking at two switches, and device inspection. A phone check that finds a VPN profile is itself the evidence.

**Mitigations.** Transport diversity with automatic failover (the 2020 survivor, Psiphon, won by trying many transports quickly); configuration secrets kept out of backups and quickly removable; no assumption that any single transport survives a crisis.

## China

| technique | evidence | confidence |
|---|---|---|
| Active probing with replays and crafted payloads, triggered by first-packet length and entropy; server behaviour on invalid input is the classifier. | [GFW Report, IMC 2020](https://gfw.report/publications/imc20/en/) | high |
| Fully-encrypted-traffic heuristic (from Nov 2021): block the first client payload unless it has popcount ≤3.4 or ≥4.6 bits/byte, a printable 6-byte prefix, >50% printable bytes, a run of >20 printable bytes, or a TLS/HTTP prefix. Applied to about 26% of connections, to selected datacentre /20s, all ports. Reported dormant since Mar 2023; the capability is in the leaked Geedge tooling. | [Wu et al., USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi), [artifact appendix](https://www.usenix.net/system/files/usenixsecurity23-appendix-wu-mingshi.pdf) | high (rules), medium (dormant) |
| Oct 2022 blocking of TLS-based tools (trojan, VLESS, V2Ray WS/gRPC), port then IP. | [GFW Report](https://gfw.report/blog/blocking_of_tls_based_circumvention_tools/en/) | high |
| TLS-in-TLS detection that works against Vision and obfs4; padding and multiplexing help only partly. No published evidence the GFW deploys it. | [Xue et al., USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting) | high (technique) |
| SNI and Host blocking; no TCP or TLS-record reassembly, so ClientHello fragmentation works. ESNI blocked since 2020. ECH blocked indirectly by blocking encrypted DNS. | [GFW Report ESNI](https://gfw.report/blog/gfw_esni_blocking/en/), [FOCI 2025](https://petsymposium.org/foci/2025/foci-2025-0016.pdf) | high / medium |
| QUIC SNI censorship since 2024-04-07: QUIC v1 Initial decrypted, SNI matched against a separate list, 180 s block on (src IP, dst IP, dst port). Only packets with source port > destination port are inspected. A leading non-QUIC datagram, an Initial split across datagrams, or a ClientHello split across CRYPTO frames evades it. quic-go, sing-box, Xray and Hysteria 2.6.2 shipped SNI slicing in mid-2025. | [Zohaib et al., USENIX Security 2025](https://gfw.report/publications/usenixsecurity25/en/) | high |
| 20 Aug 2025: unconditional forged RST on all TCP/443 for 74 minutes; other ports unaffected. | [GFW Report](https://gfw.report/blog/gfw_unconditional_rst_20250820/en/) | high |
| Henan regional firewall on AS4837 (since 2023): far larger SNI blocklist, defeated by any TCP option or ClientHello fragmentation. | [GFW Report, IEEE S&P 2025](https://gfw.report/publications/sp25/en/) | high |
| Geedge Networks / MESA leak (Sep 2025): DPI, active probing, JA3/JA4 signatures AND-combined with certificate issuer, UDP payload length, first-packet pattern, IP range and FQDN; ML classifiers; flagging of long-lived high-volume unidentified flows; subscriber tagging as "known VPN user". Exported to Myanmar, Pakistan, Ethiopia, Kazakhstan. | [GFW Report](https://gfw.report/blog/geedge_and_mesa_leak/en/), [InterSecLab](https://interseclab.org/research/the-internet-coup/) | high (leak), medium (capabilities) |
| Temporary international blackouts triggered by P2P or known-tool use (Henan, Jiangsu; Feb 2026). | [net4people #583](https://github.com/net4people/bbs/issues/583) | low–medium |

**REALITY's standing.** No measurement shows China detecting REALITY specifically, and community consensus through 2026 rates VLESS+REALITY+Vision the most reliable TCP option. Documented REALITY blocking is outside China: by volume in Iran ([Xray #2778](https://github.com/XTLS/Xray-core/issues/2778)) and by policy in Russia. An SNI/IP consistency check is not known to be deployed, but the leaked rule language can express one, and nDPI implemented one in Oct 2025 ([ntop](https://www.ntop.org/when-snis-cannot-be-trusted/)). The Aparecium tool (Jun 2025) distinguished REALITY and ShadowTLS v3 servers from OpenSSL ones by their NewSessionTicket behaviour; Xray has since changed its server ([Habr](https://habr.com/ru/post/915396)).

**Against sbr.** REALITY with a browser fingerprint and a plausible, unblocked SNI is the primary path. Hysteria2 with Salamander escapes the QUIC SNI rule but is high-entropy UDP exposed to volume and QoS policy. Hysteria2 without Salamander, and TUIC, carry a decryptable Initial; sbr splits the SNI across Initial packets, which these censors do not reassemble. Shadowsocks-2022 and raw VMess are exactly what the FET heuristic blocks if it returns. Trojan/VMess over TLS with a rustls ClientHello is the weakest TCP option. Anything pinned to TCP/443 fails during events like 20 Aug 2025.

**Mitigations.** Current browser fingerprints; SNIs that are not blocked in China (the deployment's own notes already prefer `www.bing.com`/`www.apple.com` there); a non-443 fallback port; QUIC Initial slicing; high server ports for QUIC; moderate volume per IP and several IPs. `docs/china.md` maps each technique to what sbr and the deployment do, lists what is unverified, and proposes an in-China probe.

## Egypt

| technique | evidence | confidence |
|---|---|---|
| Sandvine PacketLogic on Telecom Egypt injecting redirects (2018) and blocking news and circumvention sites; about a quarter of blocked sites were VPN and proxy tools. | [Citizen Lab "Bad Traffic"](https://citizenlab.ca/2018/03/bad-traffic-sandvines-packetlogic-devices-deploy-government-spyware-turkey-syria/), [OONI/AFTE](https://ooni.org/post/egypt-internet-censorship/) | high (dated) |
| PacketLogic on the Telecom Egypt–Vodafone link redirected a target's plain-HTTP request to a Predator iOS zero-day chain (Sep 2023). | [Citizen Lab "Predator in the Wires"](https://citizenlab.ca/2023/09/predator-in-the-wires-ahmed-eltantawy-targeted-with-predator-spyware-after-announcing-presidential-ambitions/) | high |
| Sandvine announced exit from 56 countries (Sep 2024), Egyptian government service ending Mar 2025; renamed AppLogic Networks. Nothing independent confirms the installed boxes are off. | [TechCrunch](https://techcrunch.com/2024/09/20/internet-surveillance-firm-sandvine-says-its-leaving-56-non-democratic-countries), [Access Now](https://www.accessnow.org/press-release/sandvine-removed-from-u-s-entity-list-access-now-urges-continued-scrutiny/) | high (events), low (capability gone) |
| 562 blocked sites as of Jun 2024; VoIP blocked intermittently since 2015 and still partly in 2025. Law 175/2018 penalises visiting banned sites. | [Freedom House 2024](https://freedomhouse.org/country/egypt/freedom-net/2024), [2025](https://freedomhouse.org/country/egypt/freedom-net/2025) | high |
| WireGuard/OpenVPN protocol blocking: no independent 2023–2026 measurement found. | vendor claims only | low |

**Against sbr.** The demonstrated risk is less protocol blocking than injection into anything that leaves the tunnel in cleartext: captive-portal checks, plain-HTTP fetches by apps before the tunnel is up, traffic iOS sends outside the tunnel. REALITY and Hysteria2 are expected to work; plain WireGuard should be assumed fingerprintable. The deployment's own notes observe that VoIP-blocking regimes kill the STUN port (3478) first and leave 443.

**Mitigations.** A tunnel that captures everything from boot (`includeAllNetworks`, see the Apple section), no plaintext fetches by sbr itself (already true: sbr contacts only configured endpoints, remote rule-sets over HTTPS), Lockdown Mode for high-risk users.

## Saudi Arabia and the Gulf

| technique | evidence | confidence |
|---|---|---|
| Saudi: all traffic through two data-service providers; CST blocklists; HTTP and SNI filtering; WireFilter (Sewar) observed by OONI; Tor and VPN provider sites blocked; WhatsApp calls blocked since 2015. | [Freedom House Saudi 2024](https://freedomhouse.org/country/saudi-arabia/freedom-net/2024) | high |
| Saudi: TLS-handshake resets for blocked services (2026). | [OONI finding](https://explorer.ooni.org/findings/305408501600) | medium |
| UAE: Federal Decree-Law 34/2021 Art. 10 (using a third-party address to commit or hide a crime, AED 500k–2m) and Art. 50 (enabling access to blocked services); prosecutors warned again Dec 2024. VoIP other than licensed apps blocked. du lists circumvention tools as prohibited content. | [Gulf News](https://gulfnews.com/uae/government/uae-public-prosecution-warns-against-illegal-network-circumvention-fines-up-to-dh2-million-1.1734973476355), [Freedom House UAE 2024](https://freedomhouse.org/country/united-arab-emirates/freedom-net/2024) | high |
| Netsweeper at national level in Bahrain, Kuwait, Qatar and the UAE, with a "web proxy" category. | [Citizen Lab "Planet Netsweeper"](https://citizenlab.ca/wp-content/uploads/2025/12/Report108-Planet-Netsweeper.pdf) | high |
| Long prison terms for online speech in Saudi Arabia and the UAE. | [Freedom House Saudi 2025](https://freedomhouse.org/country/saudi-arabia/freedom-net/2025) | high |
| WireGuard or REALITY protocol blocking in the Gulf: no independent 2024–2026 measurement found. | none | low |

**Against sbr.** The network threat is mostly SNI/URL filtering and VoIP blocking, which REALITY and Hysteria2 pass. The larger risk is legal and physical: a device seized at a border or in detention exposes the configuration, server list and credentials, and therefore the server and every other user on it.

**Mitigations.** Secrets in the Keychain, device-only, excluded from backups; a way to wipe profiles quickly; per-user credentials on the server so one seized device can be revoked without reissuing everyone.

## Palantir and data fusion

Palantir is not a censor. The threat is the join: platforms such as Gotham integrate customer-supplied sources (call records, ISP connection logs, licence-plate readers, ad-tech location, commercial netflow) on shared identifiers and time. Examples: ICE's ImmigrationOS contract (Apr 2025) ([TechRadar](https://www.techradar.com/pro/security/palantir-to-develop-immigrationos-for-ice-to-speed-up-deportations)); UK NHS, MoD and police contracts ([Al Jazeera](https://www.aljazeera.com/news/2026/5/12/palantir)).

| technique | evidence | confidence |
|---|---|---|
| Commercial netflow: Team Cymru's Augury sells more than 100 billion flow records a day to US agencies; bought specifically to match connections into a VPN server with connections out. | [Wyden](https://www.wyden.senate.gov/news/press-releases/wyden-government-watchdogs-must-investigate-warrantless-purchases-of-americans-internet-browsing-data-by-federal-agencies), [404 Media](https://404media.co/us-counterintel-buys-netflow-data-team-cymru-track-vpns) | high |
| Ad-tech location (Venntel/Gravy, Fog, Babel Street) keyed on IDFA/MAID, sold to government; FTC order Jan 2025. | [The Record](https://therecord.media/ftc-location-data-brokers-gravy-venntel-mobilewalla) | high |
| Flow correlation: DeepCorr reaches 96% on Tor with about 900 packets; a single-hop proxy is easier because both ends of one server are observable. | [DeepCorr, CCS 2018](https://arxiv.org/pdf/1808.07285) | high |
| VPN fingerprinting at ISP scale (OpenVPN, 34 of 41 "obfuscated" commercial configs). | [Xue et al., USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/xue-diwen) | high |
| Routing attacks that move traffic outside the tunnel: TunnelCrack LocalNet and ServerIP (all iOS apps tested were vulnerable), TunnelVision DHCP option 121 (CVE-2024-3661). | [TunnelCrack](https://tunnelcrack.mathyvanhoef.com/details.html), [TunnelVision](https://thehackernews.com/2024/05/new-tunnelvision-attack-allows.html) | high |
| iOS keeps pre-existing connections and some Apple-service traffic outside the tunnel even with `includeAllNetworks`; the flag also stalls the extension's own sockets and can strand the device during app updates. | [Proton](https://protonvpn.com/blog/apple-ios-vulnerability-disclosure/), [Mullvad, Mar 2025](https://mullvad.net/en/blog/why-we-still-dont-use-includeallnetworks), [IVPN](https://ivpn.net/blog/removal-of-kill-switch-from-our-ios-app-due-to-apple-ip-leak-issue) | high |

**Against sbr.** A self-hosted single-hop server is the easiest case for correlation: the ISP's records show the client talking to one IP, and the hosting provider's netflow shows that IP talking to the destinations. No transport changes that. What sbr controls is leakage: DNS outside the tunnel, IPv6 outside an IPv4-only tunnel, LocalNet/ServerIP/option-121 route manipulation, and traffic sent before the tunnel is up. Device identifiers (IDFA, push tokens, Apple ID) defeat IP-level anonymity and are outside what a tunnel can fix.

**Mitigations.** Leak-proof Apple tunnel settings; DNS answered inside the tunnel (`hijack-dns`, already supported); proxy servers addressed by IP or resolved over an encrypted resolver; an exit separate from the entry (the deployment's tailnet exits already provide this) so entry-side and exit-side flow records belong to different providers; multiplexing and padding to raise the cost of per-flow correlation, with the understanding that they do not defeat it.

## Israel

| technique | evidence | confidence |
|---|---|---|
| Bulk interception: Unit 8200 stored up to about 8,000 TB of intercepted Palestinian calls on Azure; Microsoft cut access in Sep 2025. Collection is "everything, search later". | [NBC News](https://www.nbcnews.com/tech/tech-news/microsoft-ends-israel-military-units-access-cloud-service-rcna233723) | high |
| Infrastructure control in the territories: Palestinian operators depend on Israeli spectrum licences and routing; Gaza mostly 2G, West Bank 3G (4G approved Jan 2026); more than twelve Gaza blackouts since Oct 2023. | [Al-Monitor](https://www.al-monitor.com/originals/2026/01/israel-approves-upgrade-4g-mobile-services-palestinians-west-bank), [TechCrunch](https://techcrunch.com/2024/01/18/web-monitors-say-gaza-week-long-internet-outage-is-longest-yet) | high |
| Biometric identification (Red Wolf, Blue Wolf) at checkpoints. | [Amnesty](https://www.amnesty.org/en/latest/news/2023/05/israel-opt-israeli-authorities-are-using-facial-recognition-technology-to-entrench-apartheid/) | high |
| Israeli-origin device compromise: Paragon Graphite on iOS (CVE-2025-43200), NSO Pegasus, Cellebrite extraction. | [Citizen Lab, Jun 2025](https://citizenlab.ca/2025/06/first-forensic-confirmation-of-paragons-ios-mercenary-spyware-finds-journalists-targeted/) | high |

**Against sbr.** A compromised endpoint defeats any tunnel; device compromise is out of scope beyond recommending Lockdown Mode. Against bulk collection, every transport sbr supports encrypts content with ephemeral keys (REALITY offers X25519MLKEM768, which matters against harvest-now-decrypt-later); metadata and flow records remain. Shutdowns defeat everything.

## United Kingdom

| technique | evidence | confidence |
|---|---|---|
| Online Safety Act age checks from 2025-07-25; VPN sign-ups rose more than 1,400%. Ofcom treats promoting VPNs to evade age checks as non-compliant for platforms; VPN use is legal. Ofcom monitors UK VPN use with a third-party tool. | [The Register](https://www.theregister.com/2025/07/28/uk_vpn_demand_soars/), [ISPreview Nov 2025](https://www.ispreview.co.uk/index.php/2025/11/ofcom-monitoring-uk-vpn-use-due-to-circumvention-of-online-safety-act.html) | high / medium |
| Lords passed a ban on providing VPNs to under-18s (Jan 2026); the Commons removed it, but the Act keeps a delegated power to restrict children's online access by regulation. DSIT consultation (Mar–May 2026) asked whether VPNs should be age-restricted. | [ISPreview](https://www.ispreview.co.uk/index.php/2026/01/house-of-lords-votes-to-ban-uk-children-from-using-internet-vpns.html), [Lords division](https://votes.parliament.uk/Votes/Lords/Division/3503), [TechRadar](https://www.techradar.com/vpn/vpn-privacy-security/no-approach-is-a-silver-bullet-uk-launches-online-safety-consultation-that-could-see-vpns-age-restricted) | high / medium |
| ISP blocking: IWF list via Cleanfeed-style hybrid filtering, High Court s.97A orders by DNS, IP and SNI. No protocol blocking of VPNs. Category filters on public Wi-Fi (FortiGuard and similar) intercept TLS by SNI reputation, which the deployment has already hit. | [ISPreview](https://www.ispreview.co.uk/index.php/2021/10/six-big-uk-isps-ordered-to-block-five-piracy-streaming-websites.html), jaritanet `docs/architecture.md` | high |
| Investigatory Powers Act 2016 and the 2024 amendments: bulk interception, internet connection records retained up to 12 months, technical capability notices, and notification notices for changes such as new encryption. | [IPA 2024](https://legislation.gov.uk/ukpga/2024/9/contents) | high |
| Apple Advanced Data Protection withdrawn for UK users (Feb 2025) after a TCN; a UK-only TCN reported since; Investigatory Powers Tribunal challenge ongoing. | [Malwarebytes, Aug 2026](https://www.malwarebytes.com/blog/news/2026/08/apple-battles-it-out-again-with-uk-over-encrypted-icloud-access), [Privacy International](https://privacyinternational.org/legal-action/pi-apple-tcn-challenge) | high / medium |

**Against sbr.** Network-level blocking in the UK does not touch sbr's protocols; captive and category filters do, and the per-network SNI list in the deployment answers that. Connection records tie a subscriber to the server IP with timing and volume, which feeds the correlation threat above. The likely pressure point is distribution (App Store age gating for VPN apps), and iCloud backups without ADP, which can contain configurations and keys unless the app excludes them.

## Capability matrix

R resists, P partially resists, F fails. Columns: REALITY = VLESS+REALITY+Vision; hy2 = Hysteria2+Salamander; TLS = trojan/VMess over TLS, ws, grpc or httpupgrade; SS = Shadowsocks-2022; STLS = ShadowTLS v3; ATLS = AnyTLS; WG = WireGuard; TUIC = TUIC v5.

| technique | REALITY | hy2 | TLS | SS | STLS | ATLS | WG | TUIC |
|---|---|---|---|---|---|---|---|---|
| SNI blocking | R | R | P | R | R | P | R | F |
| IP blocking | F | F | P | F | F | F | F | F |
| Active probing | R* | R | P | R | P | P | R | P |
| Entropy (FET) heuristic | R | P | R | F | R | R | R | R |
| TLS fingerprint (JA3/JA4) | P | R | P | R | P | P | R | F |
| TLS-in-TLS | P | P | F | P | F | P | P | P |
| QUIC/UDP blocking | R | F | R | R | R | R | F | F |
| Timing/size flow fingerprinting | P | P | F | F | F | P | F | P |
| DNS manipulation | R | R | R | R | R | R | R | R |
| Protocol whitelisting | P | F | F | F | P | F | F | F |
| Throttling (16 KB freeze, ASN) | P | P | F | F | P | F | F | F |
| Shutdowns | F | F | F | F | F | F | F | F |

Reasons:

- **SNI blocking.** REALITY and ShadowTLS present a borrowed SNI chosen per network. Salamander hides the QUIC Initial entirely. TLS and AnyTLS present the server's own name, blocked once listed; fragmentation helps against the GFW, not against Iran's reassembling DPI. TUIC's QUIC v1 Initial is decryptable; sbr splits its SNI across packets, which defeats censors that do not reassemble.
- **IP blocking.** No protocol survives a blocked address. Only the CDN-capable TLS transports (ws, grpc, httpupgrade behind a CDN) can move to addresses the censor is reluctant to block, and Russia blocks those too.
- **Active probing.** REALITY forwards unauthenticated connections to its `dest`. \*In the reference deployment `dest` is a local site that cannot present the borrowed SNIs' certificates, so a probe with a borrowed SNI gets a mismatching certificate; see the server section. Salamander and WireGuard are silent to unauthenticated packets; SS-2022 has a replay filter. TLS-based servers are as good as their fallback configuration. ShadowTLS v3 servers were distinguishable by NewSessionTicket handling (Aparecium). A TUIC server answers any Initial with its own certificate.
- **FET heuristic.** It targets random-looking TCP first packets: SS-2022 is the textbook case. Salamander is random UDP; the published rule is TCP-only, but random UDP is what Russia's mobile networks and the leaked TSG signatures target.
- **TLS fingerprint.** Every TCP TLS client sends a current browser's ClientHello (Chrome 155 by default, JA4 equal to the real browser's), where sing-box and Xray still send uTLS's Chrome 133, the kind of stale profile flagged in Russia in 2026. Partial, not resisting: the ClientHello is only the first message; the rest of the handshake (no resumption, TLS 1.3 only, no HTTP/2 SETTINGS fingerprint behind it) and the profiles' freshness still distinguish sbr from a browser. quinn's QUIC ClientHello (TUIC; hysteria2 without Salamander) is not a browser's.
- **TLS-in-TLS.** Vision removes the double encryption but Xue et al. detect it; AnyTLS's padding and Hysteria's QUIC framing blur sizes without hiding round-trip structure. Plain trojan/VMess over TLS is the case the classifiers were built on.
- **QUIC/UDP blocking.** Any UDP transport fails where UDP to foreign hosts is dropped; the TCP transports are unaffected.
- **Flow fingerprinting.** Nothing in sbr shapes timing. Vision pads early packets only; AnyTLS pads per its scheme; WireGuard's fixed message sizes are trivially classified.
- **DNS manipulation.** Transport-independent. Resists when server addresses are IPs or resolved through an encrypted resolver, and when `hijack-dns` keeps system DNS in the tunnel; fails if the server's hostname is resolved through the local resolver.
- **Protocol whitelisting.** Only a whitelisted SNI (REALITY, ShadowTLS) to a whitelisted CIDR has been seen to pass.
- **Throttling.** The freeze exempts whitelisted SNIs, so REALITY or ShadowTLS with such an SNI survives; Hysteria2 was reported the most resilient on wired lines in 2026, though the 25-packet rule reportedly applies to UDP.

## Gaps, ranked by impact

1. ~~**Censorship-aware failover.**~~ Done (issue #4): data probes past the freeze threshold, passive stall and reset detection, demotion with back-off, re-probing on network change. What remains is deployment: give each `urltest` either a `url` serving at least 64 KiB or members whose servers answer on their own address, and enough members across transports and ports to fail over to. Passive detection cannot tell a frozen plain-HTTP response from a finished one, and does not watch UDP sessions; the data probe covers both.
2. ~~**XHTTP transport.**~~ Done as an sbr extension (README, "XHTTP"). Xray's current transport splits a stream across HTTP requests, multiplexes through XMUX and pads requests; it is the Xray-native answer to the parallel-handshake and per-connection rules. Not done: Xray's browser dialer, and a Chrome-like HTTP/2 or QUIC fingerprint (the TLS-level fingerprint is REALITY's or rustls').
3. **Leak-proof Apple tunnel.** `includeAllNetworks` with the extension's own sockets working (Mullvad's failure mode), an IPv6 route into the tunnel even when the config is IPv4-only, `excludeLocalNetworks` off, server addresses pinned so a malicious resolver or DHCP cannot redirect them (TunnelCrack ServerIP, TunnelVision), and no traffic before the tunnel is up. This is the Egypt injection path and the Palantir correlation path. Implemented but unverified on devices (issue #6; apple/README.md, "Leak protection"). Strict mode is opt-in because it breaks local traffic and, per Mullvad, can strand the device during an app update. Server names still go to the network's resolver when the config has no `dns` section (`sbr check` warns), and nothing reconnects a tunnel the system killed unless auto-connect is on.
4. **Multiplexing.** sing-mux (smux, yamux, h2mux, with padding) for sing-box servers. Collapses many application connections into a few long-lived ones, which addresses the more-than-three-parallel-handshakes rule and the per-connection byte counters, and which Xue et al. name as the most promising TLS-in-TLS countermeasure. Xray servers need XHTTP instead (Vision does not combine with Mux.Cool).
5. **SSH outbound.** SSH is exempt from Russia's freeze on any port and survived the 2026 waves. sing-box has an `ssh` outbound, so this stays within config compatibility.
6. ~~**QUIC Initial hardening.**~~ Done: the SNI is split across CRYPTO frames and Initial packets for hysteria2 without Salamander and for TUIC, as quic-go 0.52 does (README, "QUIC ClientHello scrambling"). Not done: a leading junk datagram, and splitting a ClientHello that fits in one packet across datagrams.
7. **Device-side secret handling.** Profiles and credentials in the Keychain, device-only, excluded from iCloud backup and sync; quick removal. Addresses device seizure (Gulf, Belarus phone checks) and UK iCloud exposure.
8. ~~**ClientHello fragmentation.**~~ Done: record cuts inside every label but the last, the `route-options` form, and an automatic mode (README, "ClientHello fragmentation"). Justification: the GFW parses the SNI from one TLS record and does not reassemble records, so any record split defeats it, while a TCP split defeats it only if no segment carries the whole name ([Niere et al., CCS 2023](https://doi.org/10.1145/3576915.3624372)); the Henan firewall is defeated by any fragmentation ([GFW Report, S&P 2025](https://gfw.report/publications/sp25/en/)). Cutting every label instead of the first keeps the registered domain out of any single record or segment, which matters against a filter that substring-matches each packet rather than parsing the ClientHello. The automatic mode exists because a fragmented ClientHello is itself a rare shape on the wire: it should appear only where a filter has already shown itself, and only for the outbound it hit. Not done: Iran reassembles both records and segments, so none of this helps there; random delays between more than one segment (each costs a wait).
9. ~~**Probe shaping.**~~ Done (README, "Failover that sees post-handshake blocking"). sing-box's `urltest` opens a handshake to every member at once on a fixed period. Against a single-IP deployment with six REALITY identities that is a burst of six SNIs to one address, the parallel-handshake pattern Russia's 2026 module reportedly counts ([Habr 1047442](https://habr.com/ru/articles/1047442/), medium–low confidence), and a strictly periodic flow that a classifier looking for "long-lived unidentified flows" or beacons can key on (the Geedge leak describes flow-level flagging, [GFW Report](https://gfw.report/blog/geedge_and_mesa_leak/en/)). Serialising per host with random gaps and jittering the period costs nothing in power (the same number of wakeups on average) and little in time to first selection, since the first member that answers is adopted.
10. **ECH with DNS-published configs.** Fetch ECH configs from HTTPS records through the tunnel's resolver and honour `retry_configs`. Useful for CDN-fronted TLS transports where ECH is not itself blocked; Russia blocks Cloudflare's ECH, so this is lower priority.

Considered and not ranked as issues:

- **Browser-grade TLS for non-REALITY outbounds** is done for TCP. Fingerprint freshness is an ongoing maintenance task, not a feature: profiles must follow browser releases, and `sbr-reality`'s tests pin the JA4 each one must match.
- **Padding and traffic shaping** beyond what Vision, AnyTLS, XHTTP's `xPaddingBytes` and sing-mux padding provide. Xue et al. ([USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting)) detect TLS-in-TLS through Vision's padding and find random padding alone a weak countermeasure, with multiplexing the most promising; extra client-side padding would also have to be understood by an unmodified Xray server, which it is not. The useful step is multiplexing (gap 4) and XHTTP, which exists.
- **Probing with full handshakes instead of bare TCP connects.** A URL-less delay probe opens a TCP connection to the member's server and closes it without sending anything. A connection to 443 that never sends a ClientHello is unusual but also what a browser's unused preconnect looks like; no censor is known to act on it. The data probe that follows does send a full handshake.
- **CDN and domain fronting** already work with ws, grpc and httpupgrade by configuration. XHTTP (gap 2) is the better CDN transport.
- **Snowflake, meek, WebRTC.** Snowflake needs Tor and its DTLS fingerprint was blocked in Russia from 2026-03-30 ([net4people #603](https://github.com/net4people/bbs/issues/603)); meek-style CDN tunnelling is covered by XHTTP through a CDN.
- **Salamander's weakness** is that it makes the flow random UDP. No published detection exists; the mitigations are port hopping (supported), multiple ports (deployed) and TCP fallbacks.
- **AmneziaWG.** Periodically blocked in Russia by signature, and the deployment does not use WireGuard for circumvention.
- **Hiding the VPN from apps.** iOS exposes the utun interface to every app; routing domestic services `direct` by rule-set is the available answer and needs no code.

## Server-side recommendations for the reference deployment

1. **Make REALITY probes see a matching certificate.** Today `dest` is the local Traefik, so a probe with SNI `www.microsoft.com` gets Traefik's certificate. Put an SNI dispatcher on :443 (own domains to Traefik, everything else to REALITY with an external `dest` that serves the borrowed names), or move the public site to a different IP. The deployment's architecture notes already name this as the fix against a probing adversary; Russia and the leaked Geedge tooling make that adversary current.
2. **Prefer borrowed SNIs whose real service plausibly lives near the server.** A target in the same provider or ASN survives an SNI/IP consistency check; `www.baidu.com` and `vk.com` on a German IP are the strongest anomaly in the list, as the notes say. For Russia, the useful identity is a name on the freeze whitelist, which only works convincingly from an entry inside Russia.
3. **Add an entry node inside a whitelisted Russian CIDR** (Yandex Cloud, VK Cloud, Timeweb, verified with a live SIM against the specific /24), chained to the foreign exit. This is the only reported answer to mobile whitelists and the freeze together.
4. **Set REALITY `limitFallbackUpload` and `limitFallbackDownload`** so the fallback path cannot be used as a free high-volume relay to `dest`, and keep `shortIds` per user group so a seized profile can be revoked.
5. **Listen for REALITY on a second TCP port** (for example 8443 or a high port). The 20 Aug 2025 GFW event and Russia's port-443 policing were both port-specific.
6. **Serve Hysteria2 over a port range** with an nftables redirect into the listener, and give clients `server_ports` with `hop_interval`: QUIC residual blocks key on the destination port. High server ports also keep client packets out of the GFW's source-port-greater-than-destination-port inspection rule when Salamander is off.
7. **Run XHTTP alongside TCP+Vision**, which sbr now supports: `stream-one` over REALITY on the same identities, and `packet-up` behind a CDN on a separate domain as the fallback that survives an IP block.
8. **Offer SSH as a last-resort transport** once sbr supports the outbound: a forwarding-only account with key authentication, no shell.
9. **Plan for IP loss.** Keep standby addresses or a second provider that is not popular with Russian users (the Aug and Sep 2026 bans concentrated on such providers), and spread heavy users across addresses: volume per IP is what got REALITY servers blocked in Iran.
10. **Keep Xray and Hysteria current.** The pinned Xray 26.10.21 post-dates the Xray changes made after Aparecium (reported as 25.12.8), and Hysteria 2.13.0 post-dates QUIC SNI slicing (2.6.2); the update tracking already in place is the control.
11. **Keep server logs minimal** (`loglevel: warning` as now, no access logs). The provider's netflow is outside the deployment's control; logs on the box are not.

## Out of scope

Endpoint compromise (Pegasus, Graphite, Predator, forensic extraction), device identifiers and account-level identity (IDFA, push tokens, Apple ID), global passive adversaries correlating both ends of a single-hop proxy, and complete shutdowns. sbr can reduce what leaks around the tunnel; it cannot make a single-hop proxy anonymous.
