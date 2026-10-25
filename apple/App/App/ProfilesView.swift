import SbrKit
import SwiftUI
import UniformTypeIdentifiers

struct ProfilesView: View {
    @EnvironmentObject private var profiles: ProfileStore
    @EnvironmentObject private var tunnel: TunnelModel
    @State private var link = ""
    @State private var busy = false
    @State private var problem: String?
    @State private var showImporter = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text("profiles").font(.sbr(.display)).foregroundStyle(Color.sbrStrong)
                    .padding(.top, Theme.Space.xl)
                if profiles.profiles.isEmpty {
                    Text("add a sing-box profile link or file to begin.")
                        .font(.sbr(.meta)).foregroundStyle(Color.sbrMuted).padding(.top, Theme.Space.s)
                }
                ForEach(Array(profiles.profiles.enumerated()), id: \.element.id) { i, p in
                    if i > 0 { RowRule() }
                    row(p)
                }
                add
                personalRules
            }
            .padding(.horizontal, Theme.Space.xl)
            .padding(.bottom, Theme.Space.xxl)
        }
        #if !os(tvOS)
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [.json, .plainText]) { result in
            Task { await importFile(result) }
        }
        #endif
    }

    private func row(_ p: Profile) -> some View {
        let active = p.id == profiles.activeID
        return Button {
            Task { await activate(p) }
        } label: {
            HStack(spacing: Theme.Space.m) {
                Rectangle().fill(active ? Color.sbrAccent : .clear).frame(width: 2)
                VStack(alignment: .leading, spacing: 2) {
                    Text(p.name).font(.sbr(.body)).foregroundStyle(active ? Color.sbrStrong : Color.sbrInk)
                        .lineLimit(1)
                    Text(subtitle(p)).font(.sbr(.fine)).foregroundStyle(Color.sbrMuted).lineLimit(1)
                }
                Spacer()
                if profiles.refreshing.contains(p.id) {
                    Text("updating").font(.sbr(.fine)).foregroundStyle(Color.sbrMuted)
                }
            }
            .padding(.vertical, Theme.Space.m)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .contextMenu {
            if p.remoteURL != nil {
                Button("update now") { Task { await refresh(p) } }
            }
            Button("delete", role: .destructive) { profiles.remove(p) }
        }
    }

    private func subtitle(_ p: Profile) -> String {
        guard let url = p.remoteURL else { return "local" }
        // The host only: profile URLs usually carry a secret path.
        let host = url.host ?? "remote"
        guard let updated = p.updated else { return host }
        return "\(host) · updated \(updated.formatted(.relative(presentation: .named)))"
    }

    /// Domains routed through a chosen outbound whatever the profile says;
    /// added from a connection's long-press menu.
    @ViewBuilder private var personalRules: some View {
        SectionHeader("rules")
        if tunnel.rules.isEmpty {
            Text("long-press a connection to always route its domain via an exit.")
                .font(.sbr(.meta)).foregroundStyle(Color.sbrMuted)
        }
        ForEach(Array(tunnel.rules.enumerated()), id: \.element.id) { i, r in
            if i > 0 { RowRule() }
            HStack(spacing: Theme.Space.m) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(r.domains.joined(separator: " ")).font(.sbr(.body)).foregroundStyle(Color.sbrInk)
                        .lineLimit(1).truncationMode(.middle)
                    Text("via \(r.outbound)").font(.sbr(.fine)).foregroundStyle(Color.sbrMuted).lineLimit(1)
                }
                Spacer()
                Button("delete") { Task { await tunnel.removeRule(r) } }.sbrButton(.text)
            }
            .padding(.vertical, Theme.Space.s)
        }
    }

    private var add: some View {
        VStack(alignment: .leading, spacing: Theme.Space.s) {
            SectionHeader("add")
            TextField("https://… or sing-box://import-remote-profile…", text: $link)
                .font(.sbr(.control))
                .textFieldStyle(.plain)
                #if os(iOS)
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
                #endif
                .autocorrectionDisabled()
                .padding(Theme.Space.m)
                .overlay(Rectangle().strokeBorder(Color.sbrRule, lineWidth: Theme.hairline))
                .onSubmit { Task { await addLink() } }
            HStack(spacing: Theme.Space.m) {
                Button(busy ? "adding" : "add") { Task { await addLink() } }
                    .sbrButton(.prominent)
                    .disabled(busy || link.isEmpty)
                #if os(iOS)
                Button("paste") {
                    link = UIPasteboard.general.string ?? ""
                    Task { await addLink() }
                }
                .sbrButton(.bordered)
                #endif
                #if !os(tvOS)
                Button("file") { showImporter = true }.sbrButton(.bordered)
                #endif
            }
            if let problem {
                Text(problem).font(.sbr(.fine)).foregroundStyle(Color.sbrBad).sbrSelectable()
            }
        }
    }

    private func addLink() async {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed), let parsed = ProfileLink(url) else {
            problem = "not a profile link"
            return
        }
        busy = true
        defer { busy = false }
        do {
            try await profiles.add(remote: parsed.url, name: parsed.name)
            link = ""
            problem = nil
        } catch {
            problem = error.localizedDescription
        }
    }

    private func activate(_ p: Profile) async {
        do {
            try profiles.activate(p)
        } catch {
            problem = error.localizedDescription
        }
    }

    private func refresh(_ p: Profile) async {
        do {
            try await profiles.refresh(p)
        } catch {
            problem = error.localizedDescription
        }
    }

    private func importFile(_ result: Result<URL, Error>) async {
        do {
            let url = try result.get()
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let text = try String(contentsOf: url, encoding: .utf8)
            try profiles.add(text: text, name: url.deletingPathExtension().lastPathComponent)
            problem = nil
        } catch {
            problem = error.localizedDescription
        }
    }
}
