import Foundation
import SbrKit
import SwiftUI

/// End-to-end checks run from the app, so their traffic takes the same path
/// as every other app's: system → tunnel → sbr → server. Each one reports
/// pass/fail, timing and the protocol actually negotiated.
@MainActor
final class Diagnose: ObservableObject {
    struct Check: Identifiable {
        let id: String
        var detail = "…"
        var ok: Bool?
    }

    @Published private(set) var checks: [Check] = []
    @Published private(set) var running = false

    /// The profile's own probe host where possible; the bulk test names its
    /// host on screen because nothing in the profile serves large files.
    private static let probe = URL(string: "https://www.gstatic.com/generate_204")!
    private static let page = URL(string: "https://www.google.com/")!
    private static let bulk = URL(string: "https://speed.cloudflare.com/__down?bytes=50000000")!
    /// The tunnel's CPU time so far, for the bulk test's CPU share.
    var cpuTime: () async -> UInt64? = { nil }
    /// Cloudflare's plain-text trace: the address and country a request
    /// arrived from. The bulk test already uses this host.
    private static let trace = URL(string: "https://speed.cloudflare.com/cdn-cgi/trace")!
    /// The same trace on an IPv6 literal (1.1.1.1's certificate covers it),
    /// so the request has no IPv4 path to fall back to.
    private static let trace6 = URL(string: "https://[2606:4700:4700::1111]/cdn-cgi/trace")!

    /// `config` is the active profile, whose tun inbound says where DNS and
    /// IPv6 should go. The leak checks run only while connected.
    func run(connected: Bool, config: String?) async {
        running = true
        defer { running = false }
        let names = ["dns", "tcp", "quic", "bulk 50 MB (speed.cloudflare.com)"]
        let leaks = ["exit ip (speed.cloudflare.com)", "dns via tunnel", "ipv6 (1.1.1.1)", "webrtc"]
        checks = (names + (connected ? leaks : [])).map { Check(id: $0) }
        await check(0) { try await Self.dns("www.google.com") }
        await check(1) { try await Self.fetch(Self.probe, http3: false) }
        // A Vision path refuses QUIC on purpose, and URLSession races TCP, so
        // TCP here is a note, not a failure.
        await check(2, note: { !$0.hasPrefix("h3") }) { try await Self.fetch(Self.page, http3: true) }
        await check(3) {
            let (cpu0, t0) = (await self.cpuTime(), Date())
            let detail = try await Self.fetch(Self.bulk, http3: false, timeout: 60)
            guard let c0 = cpu0, let c1 = await self.cpuTime() else { return detail }
            let share = Double(c1 &- c0) / 1e6 / max(Date().timeIntervalSince(t0), 0.001)
            return detail + String(format: " · tunnel cpu %.0f%%", share * 100)
        }
        guard connected else { return }

        let plan = config.flatMap { try? Sbr.tunnelNetworkSettings(config: $0) }
        await check(4) {
            let t = try await Self.trace(Self.trace)
            return "\(t.ip) · \(t.loc.lowercased())"
        }
        await verdict(5) { try await Self.dnsLeak(expected: plan?.dnsSettings?.servers ?? []) }
        await verdict(6) {
            // Without a real IPv6 address on the tun, the tunnel claims ::/0
            // only to drop it, so any IPv6 answer came by another route.
            let v6 = plan?.ipv6Settings?.addresses.filter { $0 != Sbr.unroutedIPv6Address } ?? []
            guard let t = try? await Self.trace(Self.trace6, timeout: 5) else {
                return (true, "no ipv6 route, so none leaves outside the tunnel")
            }
            return v6.isEmpty
                ? (false, "reached the internet outside the tunnel as \(t.ip)")
                : (true, "via the tunnel as \(t.ip)")
        }
        let routesAll = plan?.ipv4Settings?.includedRoutes?.contains { $0.destinationAddress == "0.0.0.0" } ?? false
        checks[7].ok = nil
        checks[7].detail = routesAll
            ? "not testable in the app. all traffic is routed through the tunnel, so browsers' webrtc is too"
            : "the profile routes only some addresses through the tunnel, so webrtc may bypass it"
    }

    /// A check that reports a verdict and a plain explanation rather than a
    /// timing.
    private func verdict(_ i: Int, _ body: () async throws -> (Bool, String)) async {
        do {
            let (ok, detail) = try await body()
            checks[i].ok = ok
            checks[i].detail = detail
        } catch {
            checks[i].ok = false
            checks[i].detail = error.localizedDescription.lowercased()
        }
    }

    private static func trace(_ url: URL, timeout: TimeInterval = 10) async throws -> (ip: String, loc: String) {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.httpAdditionalHeaders = ["User-Agent": ""]
        let session = URLSession(configuration: config)
        defer { session.finishTasksAndInvalidate() }
        let (data, _) = try await session.data(from: url)
        var fields: [String: String] = [:]
        for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
            let kv = line.split(separator: "=", maxSplits: 1)
            if kv.count == 2 { fields[String(kv[0])] = String(kv[1]) }
        }
        guard let ip = fields["ip"] else { throw SbrDiagnoseError("unexpected reply") }
        return (ip, fields["loc"] ?? "?")
    }

    /// The system resolver should be the address the tunnel gave it, and a
    /// lookup through it should work.
    private static func dnsLeak(expected: [String]) async throws -> (Bool, String) {
        guard let want = expected.first else { throw SbrDiagnoseError("the profile's tun inbound sets no dns address") }
        guard let first = resolvers().first else { throw SbrDiagnoseError("no system resolver") }
        guard expected.contains(first) else {
            return (false, "the system asks \(first), not the tunnel's \(want)")
        }
        _ = try await dns("example.com")
        return (true, "the system asks the tunnel's \(first), and lookups work")
    }

    /// The system's DNS servers, in order, as libresolv reports them.
    private static func resolvers() -> [String] {
        let state = UnsafeMutablePointer<__res_9_state>.allocate(capacity: 1)
        defer { state.deallocate() }
        memset(state, 0, MemoryLayout<__res_9_state>.size)
        guard res_9_ninit(state) == 0 else { return [] }
        defer { res_9_ndestroy(state) }
        var servers = [res_9_sockaddr_union](repeating: res_9_sockaddr_union(), count: 8)
        let n = Int(res_9_getservers(state, &servers, Int32(servers.count)))
        return servers.prefix(max(n, 0)).map { server in
            var s = server
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            withUnsafePointer(to: &s) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    _ = getnameinfo($0, socklen_t($0.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
                }
            }
            return String(cString: host)
        }
    }

    private func check(_ i: Int, note: (String) -> Bool = { _ in false }, _ body: () async throws -> String) async {
        let start = Date()
        do {
            let detail = try await body()
            let fellBack = note(detail)
            checks[i].ok = fellBack ? nil : true
            checks[i].detail = "\(fellBack ? "tcp, quic not used: " : "")\(detail) · \(Self.ms(start))"
        } catch {
            checks[i].ok = false
            checks[i].detail = "\(error.localizedDescription.lowercased()) · \(Self.ms(start))"
        }
    }

    private static func ms(_ start: Date) -> String {
        "\(Int(Date().timeIntervalSince(start) * 1000)) ms"
    }

    private static func dns(_ host: String) async throws -> String {
        try await Task.detached {
            var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0,
                                 ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
            var res: UnsafeMutablePointer<addrinfo>?
            let rc = getaddrinfo(host, nil, &hints, &res)
            guard rc == 0, let first = res else {
                throw SbrDiagnoseError(String(cString: gai_strerror(rc)))
            }
            defer { freeaddrinfo(first) }
            var count = 0
            var p: UnsafeMutablePointer<addrinfo>? = first
            while let a = p { count += 1; p = a.pointee.ai_next }
            return "\(count) address\(count == 1 ? "" : "es")"
        }.value
    }

    /// A fresh ephemeral session each time, so no connection, cache or
    /// Alt-Svc memory from an earlier run decides the protocol.
    private static func fetch(_ url: URL, http3: Bool, expect: String? = nil, timeout: TimeInterval = 10) async throws -> String {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.httpAdditionalHeaders = ["User-Agent": ""]
        let session = URLSession(configuration: config)
        defer { session.finishTasksAndInvalidate() }
        var request = URLRequest(url: url)
        request.assumesHTTP3Capable = http3
        let collector = Metrics()
        let (data, response) = try await session.data(for: request, delegate: collector)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        let proto = collector.protocolName ?? "?"
        guard (200..<400).contains(status) else { throw SbrDiagnoseError("http \(status) over \(proto)") }
        if let expect, proto != expect { throw SbrDiagnoseError("fell back to \(proto)") }
        if data.count > 1_000_000, let secs = collector.duration, secs > 0 {
            return String(format: "%@ · %.0f mb/s", proto, Double(data.count) * 8 / secs / 1_000_000)
        }
        return "\(proto) \(status)"
    }

    private final class Metrics: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        var protocolName: String?
        var duration: TimeInterval?
        func urlSession(_: URLSession, task _: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
            protocolName = metrics.transactionMetrics.last?.networkProtocolName
            duration = metrics.taskInterval.duration
        }
    }
}

struct SbrDiagnoseError: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}

/// The diagnose block on the logs tab.
struct DiagnoseSection: View {
    @StateObject private var model = Diagnose()
    @EnvironmentObject private var tunnel: TunnelModel
    @EnvironmentObject private var profiles: ProfileStore

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader("diagnose") {
                if model.running {
                    Text("running").font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
                } else {
                    Button("run") {
                        model.cpuTime = { [tunnel] in await tunnel.cpuTime() }
                        Task { await model.run(connected: tunnel.isConnected, config: profiles.activeText) }
                    }
                    .sbrButton(.text)
                }
            }
            if !model.checks.isEmpty, !model.checks.contains(where: { $0.id == "webrtc" }) {
                Text("connect to also test for address, dns and ipv6 leaks.")
                    .font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
            }
            ForEach(model.checks) { c in
                HStack(alignment: .firstTextBaseline, spacing: Theme.Space.m) {
                    Text(c.ok == nil ? (model.running && c.detail == "…" ? "·" : "note") : c.ok! ? "ok" : "fail")
                        .foregroundStyle(c.ok == false ? Color.sbrBad : c.ok == true ? Color.sbrAccent : Color.sbrMuted)
                        .frame(width: 32, alignment: .leading)
                    Text(c.id).foregroundStyle(Color.sbrInk)
                    Spacer()
                    Text(c.detail).foregroundStyle(Color.sbrMuted).lineLimit(3).multilineTextAlignment(.trailing)
                }
                .font(.sbr(.fine))
                .padding(.vertical, Theme.Space.s)
            }
        }
        .padding(.bottom, Theme.Space.m)
    }
}
