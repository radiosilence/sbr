import SwiftUI
#if os(iOS)
import AVFoundation
import VisionKit
#endif

/// The tunnel tab before any profile exists: what sbr is, and the ways to
/// add one. Once a profile is added the tunnel tab's own header, with its
/// connect button, takes over.
struct WelcomeView: View {
    @EnvironmentObject private var profiles: ProfileStore
    @State private var busy = false
    @State private var problem: String?
    @State private var showScanner = false
    @State private var showImporter = false

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.s) {
            Text("sbr").font(.sbr(.display)).foregroundStyle(Color.sbrStrong)
                .padding(.top, Theme.Space.xl)
            Text("a vpn client for sing-box profiles. add the profile your server's operator gave you to begin.")
                .font(.sbr(.meta)).foregroundStyle(Color.sbrMuted)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: Theme.Space.m) {
                #if os(iOS)
                Button("scan a qr code") { showScanner = true }.sbrButton(.prominent)
                #endif
                #if !os(tvOS)
                Button(busy ? "adding" : "paste a link") {
                    Task { await add(Pasteboard.string ?? "") }
                }
                .sbrButton(.bordered)
                #endif
                #if os(macOS)
                Button("open a file") { showImporter = true }.sbrButton(.bordered)
                #endif
                #if os(tvOS)
                Text("add one from the profiles tab.").font(.sbr(.meta)).foregroundStyle(Color.sbrMuted)
                #endif
            }
            .disabled(busy)
            .padding(.top, Theme.Space.xl)
            if let problem {
                Text(problem).font(.sbr(.fine)).foregroundStyle(Color.sbrBad).sbrSelectable()
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, Theme.Space.s)
            }
        }
        #if os(iOS)
        .sheet(isPresented: $showScanner) {
            ScanSheet { scanned in Task { await add(scanned) } }
        }
        #endif
        #if os(macOS)
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [.json, .plainText]) { result in
            do {
                try profiles.add(file: result.get())
            } catch {
                problem = error.localizedDescription
            }
        }
        #endif
    }

    private func add(_ link: String) async {
        busy = true
        defer { busy = false }
        do {
            try await profiles.add(link: link)
        } catch {
            problem = error.localizedDescription
        }
    }
}

enum Pasteboard {
    static var string: String? {
        #if os(iOS)
        UIPasteboard.general.string
        #elseif os(macOS)
        NSPasteboard.general.string(forType: .string)
        #else
        nil
        #endif
    }
}

#if os(iOS)
/// A full-screen camera that hands back the first QR code it reads.
struct ScanSheet: View {
    let found: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var problem: String?
    @State private var ready = false

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.s) {
            HStack(alignment: .firstTextBaseline) {
                Text("scan a qr code").font(.sbr(.title)).foregroundStyle(Color.sbrStrong)
                Spacer()
                Button("cancel") { dismiss() }.sbrButton(.text)
            }
            Text("point the camera at a profile's qr code.").font(.sbr(.meta)).foregroundStyle(Color.sbrMuted)
            if let problem {
                Text(problem).font(.sbr(.meta)).foregroundStyle(Color.sbrBad)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, Theme.Space.l)
                Spacer()
            } else if ready {
                QRScanner { code in
                    dismiss()
                    found(code)
                }
                .overlay(Rectangle().strokeBorder(Color.sbrRule, lineWidth: Theme.hairline))
                .padding(.top, Theme.Space.l)
            } else {
                Spacer()
            }
        }
        .padding(Theme.Space.xl)
        .background(Color.sbrBg.ignoresSafeArea())
        .task {
            guard DataScannerViewController.isSupported else {
                problem = "this device can't scan codes. paste the link instead."
                return
            }
            guard await AVCaptureDevice.requestAccess(for: .video), DataScannerViewController.isAvailable else {
                problem = "sbr can't use the camera. allow it in settings → sbr, or paste the link instead."
                return
            }
            ready = true
        }
    }
}

private struct QRScanner: UIViewControllerRepresentable {
    let found: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context _: Context) {
        if !scanner.isScanning { try? scanner.startScanning() }
    }

    func makeCoordinator() -> Coordinator { Coordinator(found: found) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let found: (String) -> Void
        private var done = false

        init(found: @escaping (String) -> Void) { self.found = found }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems _: [RecognizedItem]) {
            for case let .barcode(code) in items {
                guard !done, let payload = code.payloadStringValue else { continue }
                done = true
                scanner.stopScanning()
                found(payload)
            }
        }
    }
}
#endif
