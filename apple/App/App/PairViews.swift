import CoreImage.CIFilterBuiltins
import SbrKit
import SwiftUI

extension ProfileStore {
    /// A profile sent from another device (see `Pairing`).
    func add(_ payload: Pairing.Payload) async throws {
        if let url = payload.url {
            try await add(remote: url, name: payload.name)
        } else if let text = payload.text {
            try add(text: text, name: payload.name)
        } else {
            throw SbrError("nothing was sent")
        }
    }
}

#if os(tvOS)
/// The TV's way in: a QR code the phone scans to send a profile over the
/// local network.
struct ReceiveFromPhone: View {
    @EnvironmentObject private var profiles: ProfileStore
    @StateObject private var receiver = PairReceiver()

    var body: some View {
        HStack(alignment: .top, spacing: Theme.Space.xl) {
            if let invite = receiver.invite {
                QRCode(text: invite.link.absoluteString)
                    .frame(width: 320, height: 320)
            }
            VStack(alignment: .leading, spacing: Theme.Space.s) {
                Text("send a profile from your iphone")
                    .font(.sbr(.body)).foregroundStyle(Color.sbrStrong)
                Text("scan this with the iphone's camera. sbr on the phone sends a profile to this apple tv over your network; nothing passes through a server.")
                    .font(.sbr(.meta)).foregroundStyle(Color.sbrMuted)
                    .fixedSize(horizontal: false, vertical: true)
                if let status = receiver.status {
                    Text(status).font(.sbr(.meta)).foregroundStyle(Color.sbrInk)
                }
            }
            .frame(maxWidth: 900, alignment: .leading)
        }
        .onAppear {
            receiver.onPayload = { [profiles] in try await profiles.add($0) }
            receiver.start()
        }
        .onDisappear { receiver.stop() }
    }
}

private struct QRCode: View {
    let text: String

    var body: some View {
        if let image = Self.render(text) {
            Image(decorative: image, scale: 1)
                .interpolation(.none)
                .resizable()
                .padding(Theme.Space.m)
                .background(Color.white)
        }
    }

    private static func render(_ text: String) -> CGImage? {
        let f = CIFilter.qrCodeGenerator()
        f.message = Data(text.utf8)
        f.correctionLevel = "M"
        guard let out = f.outputImage else { return nil }
        return CIContext().createCGImage(out, from: out.extent)
    }
}
#endif

#if os(iOS)
/// The phone's side, opened by scanning a TV's code: pick a profile and send it.
struct SendToTVSheet: View {
    let invite: Pairing.Invite
    @EnvironmentObject private var profiles: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var chosen: UUID?
    @State private var sending = false
    @State private var result: String?
    @State private var failed = false

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            Text("send to apple tv").font(.sbr(.display)).foregroundStyle(Color.sbrStrong)
                .padding(.top, Theme.Space.xl)
            if profiles.profiles.isEmpty {
                Text("add a profile on this phone first.").font(.sbr(.meta)).foregroundStyle(Color.sbrMuted)
            }
            ForEach(profiles.profiles) { p in
                Button { chosen = p.id } label: {
                    HStack(spacing: Theme.Space.m) {
                        Rectangle().fill(p.id == chosen ? Color.sbrAccent : .clear).frame(width: 2)
                        Text(p.name).font(.sbr(.body))
                            .foregroundStyle(p.id == chosen ? Color.sbrStrong : Color.sbrInk)
                        Spacer()
                    }
                    .padding(.vertical, Theme.Space.s)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
            HStack(spacing: Theme.Space.m) {
                Button(sending ? "sending" : "send") { Task { await send() } }
                    .sbrButton(.prominent)
                    .disabled(sending || chosen == nil)
                Button("close") { dismiss() }.sbrButton(.bordered)
            }
            if let result {
                Text(result).font(.sbr(.meta)).foregroundStyle(failed ? Color.sbrBad : Color.sbrInk)
            }
            Text("the profile goes straight to the tv over your local network, encrypted with the key in its code.")
                .font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
            Spacer()
        }
        .padding(.horizontal, Theme.Space.xl)
        .onAppear { chosen = chosen ?? profiles.activeID ?? profiles.profiles.first?.id }
    }

    private func send() async {
        guard let p = profiles.profiles.first(where: { $0.id == chosen }) else { return }
        sending = true
        defer { sending = false }
        do {
            let text = p.remoteURL == nil ? try profiles.text(of: p) : nil
            _ = try await Pairing.send(.init(name: p.name, url: p.remoteURL, text: text), to: invite)
            failed = false
            result = "sent \(p.name)."
        } catch {
            failed = true
            result = error.localizedDescription
        }
    }
}

/// Where a scanned or opened TV code waits for its sheet.
@MainActor
final class PairInbox: ObservableObject {
    @Published var invite: Pairing.Invite?
}
#endif
