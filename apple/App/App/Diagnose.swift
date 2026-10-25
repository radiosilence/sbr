import Foundation
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
    private static let bulk = URL(string: "https://speed.cloudflare.com/__down?bytes=10000000")!

    func run() async {
        running = true
        defer { running = false }
        checks = ["dns", "tcp", "quic", "bulk 10 MB (speed.cloudflare.com)"].map { Check(id: $0) }
        await check(0) { try await Self.dns("www.google.com") }
        await check(1) { try await Self.fetch(Self.probe, http3: false) }
        // A Vision path refuses QUIC on purpose, and URLSession races TCP, so
        // TCP here is a note, not a failure.
        await check(2, note: { !$0.hasPrefix("h3") }) { try await Self.fetch(Self.page, http3: true) }
        await check(3) { try await Self.fetch(Self.bulk, http3: false, timeout: 30) }
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

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader("diagnose") {
                if model.running {
                    Text("running").font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
                } else {
                    Button("run") { Task { await model.run() } }.sbrButton(.text)
                }
            }
            ForEach(model.checks) { c in
                HStack(alignment: .firstTextBaseline, spacing: Theme.Space.m) {
                    Text(c.ok == nil ? (model.running && c.detail == "…" ? "·" : "note") : c.ok! ? "ok" : "fail")
                        .foregroundStyle(c.ok == false ? Color.sbrBad : c.ok == true ? Color.sbrAccent : Color.sbrMuted)
                        .frame(width: 32, alignment: .leading)
                    Text(c.id).foregroundStyle(Color.sbrInk)
                    Spacer()
                    Text(c.detail).foregroundStyle(Color.sbrMuted).lineLimit(2).multilineTextAlignment(.trailing)
                }
                .font(.sbr(.fine))
                .padding(.vertical, Theme.Space.s)
            }
        }
        .padding(.bottom, Theme.Space.m)
    }
}
