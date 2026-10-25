import SbrKit
import SwiftUI
import UniformTypeIdentifiers
#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

struct ContentView: View {
    @StateObject private var model = TunnelModel()
    @State private var draft = ""
    @State private var urlText = ""
    @State private var showImporter = false

    var body: some View {
        NavigationView {
            Form {
                tunnelSection
                if model.status == .connected {
                    trafficSection
                    ForEach(model.groups) { group in
                        groupSection(group)
                    }
                }
                configSection
            }
            .navigationTitle("sbr")
        }
        .task { await model.load() }
        .task { await model.poll() }
        .alert(
            "Error",
            isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
        #if !os(tvOS)
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [.json, .plainText]) { result in
            switch result {
            case let .success(url): Task { await model.importConfig(from: url) }
            case let .failure(error): model.errorMessage = error.localizedDescription
            }
        }
        #endif
    }

    private var tunnelSection: some View {
        Section("Tunnel") {
            Toggle(
                model.status.label,
                isOn: Binding(get: { model.isOn }, set: { on in Task { await model.setOn(on) } })
            )
            .disabled(!model.hasConfig)
            if !model.hasConfig {
                Text("Import a sing-box config first.").foregroundColor(.secondary)
            }
        }
    }

    private var trafficSection: some View {
        Section("Traffic") {
            row("Upload", "\(bytes(model.uploadRate))/s")
            row("Download", "\(bytes(model.downloadRate))/s")
            if let s = model.stats {
                row("Total", "↑ \(bytes(Double(s.uplinkBytes)))  ↓ \(bytes(Double(s.downlinkBytes)))")
                row("Connections", "\(s.activeConnections) TCP, \(s.udpSessions) UDP")
                row("Tunnel memory", bytes(Double(s.memoryFootprint)))
            }
        }
    }

    private func groupSection(_ group: SbrGroup) -> some View {
        Section("\(group.tag) (\(group.type))") {
            ForEach(group.members, id: \.self) { member in
                Button {
                    Task { await model.select(group: group.tag, member: member) }
                } label: {
                    HStack {
                        Text(member)
                        Spacer()
                        if member == group.selected { Image(systemName: "checkmark") }
                    }
                }
                // Only selectors can be switched by hand.
                .disabled(group.type != "selector")
            }
        }
    }

    private var configSection: some View {
        Section("Config") {
            #if os(tvOS)
            TextField("Paste sing-box JSON", text: $draft)
            #else
            TextEditor(text: $draft)
                .font(.system(.footnote, design: .monospaced))
                .frame(minHeight: 120)
            #endif
            Button("Use this config") { Task { await model.importConfig(draft) } }
                .disabled(draft.isEmpty)
            #if os(iOS)
            Button("Paste from clipboard") { draft = UIPasteboard.general.string ?? "" }
            #elseif os(macOS)
            Button("Paste from clipboard") { draft = NSPasteboard.general.string(forType: .string) ?? "" }
            #endif
            #if !os(tvOS)
            Button("Import file…") { showImporter = true }
            #endif
            TextField("https://… (config URL)", text: $urlText)
            Button("Download") {
                if let url = URL(string: urlText) { Task { await model.importConfig(from: url) } }
            }
            .disabled(URL(string: urlText)?.scheme?.hasPrefix("http") != true)
        }
    }

    private func row(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value).foregroundColor(.secondary).monospacedDigit()
        }
    }

    private func bytes(_ n: Double) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .binary)
    }
}
