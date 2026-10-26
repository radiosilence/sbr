import CryptoKit
import Foundation
import Network
import SbrKit
import Security

/// Sending a profile from a phone to an Apple TV on the same network, with no
/// server between them.
///
/// The TV listens on a Bonjour service and shows a QR code holding the
/// service's name and a fresh 256-bit key. The phone resolves the service and
/// connects with TLS keyed by that key (TLS-PSK), so only someone who has seen
/// the TV's screen can send it anything, and nothing on the network can read
/// the profile. The phone sends one `Payload`; the TV adds it and answers with
/// one line.
enum Pairing {
    static let serviceType = "_sbr-pair._tcp"
    /// A profile is a few hundred KB at most.
    static let maxPayload = 2 << 20

    /// `sbr://pair?service=<bonjour name>&key=<base64url>`
    struct Invite: Identifiable {
        let service: String
        let key: SymmetricKey
        var id: String { service }

        init(service: String, key: SymmetricKey) {
            self.service = service
            self.key = key
        }

        init?(_ url: URL) {
            guard url.scheme?.lowercased() == "sbr", url.host == "pair",
                  let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems,
                  let service = items.first(where: { $0.name == "service" })?.value, !service.isEmpty,
                  let raw = items.first(where: { $0.name == "key" })?.value,
                  let data = Data(base64URL: raw), data.count == 32
            else { return nil }
            self.init(service: service, key: SymmetricKey(data: data))
        }

        init?(_ string: String) {
            guard let url = URL(string: string.trimmingCharacters(in: .whitespacesAndNewlines)) else { return nil }
            self.init(url)
        }

        var link: URL {
            var c = URLComponents()
            c.scheme = "sbr"
            c.host = "pair"
            c.queryItems = [
                URLQueryItem(name: "service", value: service),
                URLQueryItem(name: "key", value: key.withUnsafeBytes { Data($0) }.base64URL),
            ]
            return c.url!
        }
    }

    /// A remote profile travels as its link, so the TV refreshes it itself; a
    /// local one as its text.
    struct Payload: Codable {
        var name: String
        var url: URL?
        var text: String?
    }

    static func parameters(_ key: SymmetricKey) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        let opts = tls.securityProtocolOptions
        let psk = key.withUnsafeBytes { DispatchData(bytes: $0) }
        let identity = Data("sbr-pair".utf8).withUnsafeBytes { DispatchData(bytes: $0) }
        sec_protocol_options_add_pre_shared_key(opts, psk as __DispatchData, identity as __DispatchData)
        sec_protocol_options_append_tls_ciphersuite(opts, tls_ciphersuite_t(rawValue: UInt16(TLS_PSK_WITH_AES_128_GCM_SHA256))!)
        // PSK cipher suites exist only up to TLS 1.2 in Network.framework.
        sec_protocol_options_set_min_tls_protocol_version(opts, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(opts, .TLSv12)
        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        params.includePeerToPeer = true
        return params
    }

    /// Reads until the peer finishes sending, up to `maxPayload`.
    static func receiveAll(_ conn: NWConnection) async throws -> Data {
        var data = Data()
        while true {
            let (chunk, done): (Data?, Bool) = try await withCheckedThrowingContinuation { cont in
                conn.receive(minimumIncompleteLength: 1, maximumLength: 64 << 10) { chunk, _, done, error in
                    if let error { cont.resume(throwing: error) } else { cont.resume(returning: (chunk, done)) }
                }
            }
            if let chunk { data.append(chunk) }
            if data.count > maxPayload { throw SbrError("too much data") }
            if done { return data }
        }
    }

    static func sendAll(_ conn: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    /// Sends `payload` to the TV named in `invite` and returns its answer.
    static func send(_ payload: Payload, to invite: Invite) async throws -> String {
        let endpoint = NWEndpoint.service(name: invite.service, type: serviceType, domain: "local.", interface: nil)
        let conn = NWConnection(to: endpoint, using: parameters(invite.key))
        defer { conn.cancel() }
        try await ready(conn)
        try await sendAll(conn, JSONEncoder().encode(payload))
        let answer = String(decoding: try await receiveAll(conn), as: UTF8.self)
        guard answer.hasPrefix("ok") else { throw SbrError(answer.isEmpty ? "the TV closed the connection" : answer) }
        return answer
    }

    private static func ready(_ conn: NWConnection) async throws {
        let once = Once()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: once.run { cont.resume() }
                case let .failed(e): once.run { cont.resume(throwing: e) }
                case let .waiting(e): once.run { cont.resume(throwing: SbrError("can't reach the TV: \(e.localizedDescription)")) }
                case .cancelled: once.run { cont.resume(throwing: CancellationError()) }
                default: break
                }
            }
            conn.start(queue: .main)
            DispatchQueue.main.asyncAfter(deadline: .now() + 15) {
                once.run { cont.resume(throwing: SbrError("the TV didn't answer. is it on the same network, with its code still showing?")) }
            }
        }
    }
}

/// Runs a closure at most once, from any queue.
private final class Once: @unchecked Sendable {
    private var done = false
    private let lock = NSLock()
    func run(_ f: () -> Void) {
        lock.lock()
        let first = !done
        done = true
        lock.unlock()
        if first { f() }
    }
}

/// The TV's side: a listener that lives while its screen is showing.
@MainActor
final class PairReceiver: ObservableObject {
    @Published private(set) var invite: Pairing.Invite?
    @Published private(set) var status: String?
    private var listener: NWListener?
    /// What to do with a received profile; its error goes back to the phone.
    var onPayload: (Pairing.Payload) async throws -> Void = { _ in }

    func start() {
        guard listener == nil else { return }
        let invite = Pairing.Invite(
            service: "sbr-" + String(UInt16.random(in: .min ... .max), radix: 16),
            key: SymmetricKey(size: .bits256)
        )
        do {
            let l = try NWListener(using: Pairing.parameters(invite.key))
            l.service = NWListener.Service(name: invite.service, type: Pairing.serviceType)
            l.newConnectionHandler = { [weak self] conn in
                Task { @MainActor in await self?.handle(conn) }
            }
            l.stateUpdateHandler = { [weak self] (state: NWListener.State) in
                if case let .failed(e) = state {
                    Task { @MainActor in self?.status = "can't listen: \(e.localizedDescription)" }
                }
            }
            l.start(queue: .main)
            listener = l
            self.invite = invite
        } catch {
            status = "can't listen: \(error.localizedDescription)"
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        invite = nil
    }

    private func handle(_ conn: NWConnection) async {
        conn.start(queue: .main)
        defer { conn.cancel() }
        let answer: String
        do {
            let data = try await Pairing.receiveAll(conn)
            let payload = try JSONDecoder().decode(Pairing.Payload.self, from: data)
            try await onPayload(payload)
            status = "added \(payload.name)"
            answer = "ok"
        } catch {
            status = error.localizedDescription
            answer = error.localizedDescription
        }
        try? await Pairing.sendAll(conn, Data(answer.utf8))
    }
}

extension Data {
    init?(base64URL s: String) {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        b += String(repeating: "=", count: (4 - b.count % 4) % 4)
        self.init(base64Encoded: b)
    }

    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
