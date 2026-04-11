// SPDX-License-Identifier: MIT
//
// ContentView.swift
//
// Two-pane SwiftUI shell:
//   - LEFT:  wg-quick config text editor + Save / Connect / Disconnect
//   - RIGHT: live status from `sendProviderMessage("get=1\n\n")`,
//            polled every 2 s while the tunnel is connected
//
// At the top sits a status bar that follows NEVPNStatus and a row of
// "quick action" buttons that exercise UAPI SET (roam endpoint,
// add/remove peer, etc.) so you can demo every wg(8) feature without
// leaving the host app.

import SwiftUI
import NetworkExtension
#if canImport(AppKit)
import AppKit
#endif
#if canImport(UIKit)
import UIKit
#endif

struct ContentView: View {
    @StateObject private var manager = TunnelManager()
#if os(iOS)
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
#endif

    @State private var statusText: String = "(tunnel not running)"
    @State private var statusTimer: Timer?

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color.accentColor.opacity(0.08), Color.clear],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            if manager.isLoaded {
                VStack(spacing: 12) {
                    header
                    contentArea
                    actionsBar
                }
                .padding(16)
            } else {
                loadingView
                    .padding(16)
            }
        }
        .task {
            await manager.load()
            statusTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
                Task { @MainActor in await refreshStatus() }
            }
        }
        .onDisappear {
            statusTimer?.invalidate()
            statusTimer = nil
        }
    }

    // MARK: - Sections

    private var loadingView: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                .font(.system(size: 42))
                .foregroundStyle(Color.accentColor)
            Text("Loading profiles…")
                .font(.headline)
            ProgressView()
                .controlSize(.large)
        }
        .frame(maxWidth: 360)
        .padding(20)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    @ViewBuilder
    private var contentArea: some View {
#if os(macOS)
        HSplitView {
            configPanel
                .padding(.trailing, 6)
            statusPanel
                .padding(.leading, 6)
        }
#else
        ScrollView {
            VStack(spacing: 12) {
                configPanel
                statusPanel
            }
            .frame(maxWidth: .infinity)
        }
#endif
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                    .font(.title2)
                    .foregroundStyle(Color.accentColor)
                Text("WireGuard NE Sample")
                    .font(.title2.bold())
                Spacer()
                statusPill
            }

            Group {
                if isCompactLayout {
                    VStack(alignment: .leading, spacing: 8) {
                        Picker("Server", selection: Binding(
                            get: { manager.selectedProfileID ?? manager.profiles.first?.id ?? UUID() },
                            set: { manager.selectProfile($0) }
                        )) {
                            ForEach(manager.profiles) { profile in
                                Text(profile.name).tag(profile.id)
                            }
                        }
                        .pickerStyle(.menu)
                        .disabled(manager.profiles.isEmpty)

                        TextField("Server name", text: Binding(
                            get: { manager.selectedProfileName },
                            set: { manager.selectedProfileName = $0 }
                        ))
                        .textFieldStyle(.roundedBorder)

                        HStack(spacing: 8) {
                            Button("New Server") { manager.addProfile() }
                            Button("Delete") { manager.deleteSelectedProfile() }
                                .disabled(manager.profiles.count <= 1)
                        }
                    }
                } else {
                    HStack(spacing: 8) {
                        Picker("Server", selection: Binding(
                            get: { manager.selectedProfileID ?? manager.profiles.first?.id ?? UUID() },
                            set: { manager.selectProfile($0) }
                        )) {
                            ForEach(manager.profiles) { profile in
                                Text(profile.name).tag(profile.id)
                            }
                        }
                        .frame(minWidth: 180)
                        .disabled(manager.profiles.isEmpty)

                        TextField("Server name", text: Binding(
                            get: { manager.selectedProfileName },
                            set: { manager.selectedProfileName = $0 }
                        ))
                        .textFieldStyle(.roundedBorder)

                        Button("New Server") { manager.addProfile() }
                        Button("Delete") { manager.deleteSelectedProfile() }
                            .disabled(manager.profiles.count <= 1)
                    }
                }
            }
            .controlSize(.small)

            Group {
                if isCompactLayout {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Storage")
                            .font(.subheadline.weight(.semibold))
                        Picker("Storage", selection: Binding(
                            get: { manager.storageMode },
                            set: { manager.setStorageMode($0) }
                        )) {
                            ForEach(ProfileStorageMode.allCases) { mode in
                                Text(mode.title).tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)
                    }
                } else {
                    HStack(spacing: 8) {
                        Text("Storage")
                            .font(.subheadline.weight(.semibold))
                        Picker("Storage", selection: Binding(
                            get: { manager.storageMode },
                            set: { manager.setStorageMode($0) }
                        )) {
                            ForEach(ProfileStorageMode.allCases) { mode in
                                Text(mode.title).tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)
                        .frame(maxWidth: 320)
                        Spacer()
                    }
                }
            }
            .controlSize(.small)

            Group {
                if isCompactLayout {
                    VStack(alignment: .leading, spacing: 8) {
                        Picker("Routing", selection: $manager.routeMode) {
                            ForEach(RouteMode.allCases) { mode in
                                Text(mode.title).tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)

                        HStack(spacing: 8) {
                            Button("Save config") { Task { await manager.saveCurrentProfile() } }
                            Button("Connect") { manager.start() }
                                .disabled(manager.status == .connected || manager.status == .connecting)
                            Button("Disconnect") { manager.stop() }
                                .disabled(manager.status != .connected && manager.status != .connecting)
                        }
                    }
                } else {
                    HStack(spacing: 8) {
                        Picker("Routing", selection: $manager.routeMode) {
                            ForEach(RouteMode.allCases) { mode in
                                Text(mode.title).tag(mode)
                            }
                        }
                        .pickerStyle(.segmented)

                        Button("Save config") {
                            Task { await manager.saveCurrentProfile() }
                        }
                        Button("Connect") { manager.start() }
                            .disabled(manager.status == .connected || manager.status == .connecting)
                        Button("Disconnect") { manager.stop() }
                            .disabled(manager.status != .connected && manager.status != .connecting)
                    }
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)

            if manager.routeMode == .split {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Split Injected Routes (CIDR)", systemImage: "list.bullet.rectangle")
                        .font(.subheadline.weight(.semibold))
                    TextEditor(text: $manager.splitInjectedRoutes)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 64, maxHeight: 100)
                        .padding(8)
                        .background(platformTextBackgroundColor)
                        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                    Text("One per line or comma separated, e.g. 10.10.0.0/16, 172.16.203.0/24")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var statusPill: some View {
        let color: Color = {
            switch manager.status {
            case .connected:     return .green
            case .connecting,
                 .reasserting:   return .yellow
            case .disconnecting: return .orange
            case .disconnected,
                 .invalid:       return .gray
            @unknown default:    return .gray
            }
        }()
        return HStack(spacing: 6) {
            Circle().fill(color).frame(width: 10, height: 10)
            Text(manager.status.displayString)
                .font(.subheadline.monospaced())
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Color.secondary.opacity(0.12))
        .clipShape(Capsule())
    }

    private var actionsBar: some View {
        Group {
            if isCompactLayout {
                VStack(alignment: .leading, spacing: 8) {
                    if let err = manager.lastError {
                        Label(err, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .font(.caption)
                    }
                    HStack(spacing: 8) {
                        Button("Refresh") { Task { await refreshStatus() } }
                            .disabled(manager.status != .connected)
                        Button("Copy") { copyToClipboard(statusText) }
                            .disabled(statusText.isEmpty || statusText == "(tunnel not running)")
                        Menu("UAPI demos") {
                            Button("Roam endpoint to 192.0.2.5:51820") { Task { await sendDemoSet(setEndpointDemo) } }
                            Button("Set persistent_keepalive=15") { Task { await sendDemoSet(setKeepaliveDemo) } }
                            Divider()
                            Button("Add demo peer") { Task { await sendDemoSet(addPeerDemo) } }
                            Button("Remove demo peer") { Task { await sendDemoSet(removePeerDemo) } }
                        }
                        .disabled(manager.status != .connected)
                    }
                }
            } else {
                HStack(spacing: 8) {
                    if let err = manager.lastError {
                        Label(err, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .font(.caption)
                        Spacer()
                    } else {
                        Spacer()
                    }
                    Button("Refresh status now") {
                        Task { await refreshStatus() }
                    }
                    .disabled(manager.status != .connected)
                    Button("Copy status") {
                        copyToClipboard(statusText)
                    }
                    .disabled(statusText.isEmpty || statusText == "(tunnel not running)")

                    Menu("UAPI demos") {
                        Button("Roam endpoint to 192.0.2.5:51820") {
                            Task { await sendDemoSet(setEndpointDemo) }
                        }
                        Button("Set persistent_keepalive=15") {
                            Task { await sendDemoSet(setKeepaliveDemo) }
                        }
                        Divider()
                        Button("Add demo peer") {
                            Task { await sendDemoSet(addPeerDemo) }
                        }
                        Button("Remove demo peer") {
                            Task { await sendDemoSet(removePeerDemo) }
                        }
                    }
                    .disabled(manager.status != .connected)
                }
            }
        }
    }

    private var configPanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("wg-quick config", systemImage: "doc.text")
                .font(.headline)
            TextEditor(text: $manager.configText)
                .font(.system(.body, design: .monospaced))
                .padding(8)
                .background(platformTextBackgroundColor)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
        .panelCardStyle()
    }

    private var statusPanel: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Label("UAPI status (get=1)", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.headline)
                Spacer()
                Button {
                    copyToClipboard(statusText)
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(statusText.isEmpty || statusText == "(tunnel not running)")
            }
            ScrollView {
                Text(statusText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(8)
            }
            .frame(minHeight: 180)
            .background(platformTextBackgroundColor)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
        .panelCardStyle()
    }

    // MARK: - Helpers

    private var platformTextBackgroundColor: Color {
#if os(macOS)
        return Color(nsColor: .textBackgroundColor)
#else
        return Color(uiColor: .secondarySystemBackground)
#endif
    }

    private var isCompactLayout: Bool {
#if os(iOS)
        horizontalSizeClass == .compact
#else
        false
#endif
    }

    private func refreshStatus() async {
        guard manager.status == .connected else {
            statusText = "(tunnel not running)"
            return
        }
        if let resp = await manager.uapiGet() {
            statusText = resp
        } else {
            statusText = "(no response from extension)"
        }
    }

    private func sendDemoSet(_ body: String) async {
        let resp = await manager.uapiSet(body) ?? "(no response)"
        // Tack the response on top so the user can see what came back.
        statusText = "── last SET response ──\n" + resp + "\n\n" + statusText
    }

    private func copyToClipboard(_ text: String) {
#if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
#else
        UIPasteboard.general.string = text
#endif
    }
}

private extension View {
    func panelCardStyle() -> some View {
        self
            .padding(12)
            .background(Color.secondary.opacity(0.08))
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(Color.secondary.opacity(0.18), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

// MARK: - Default config + UAPI demo blobs

let defaultConfigText = """
[Interface]
PrivateKey = yPDHiay/NDkJE9OyUT0J8qhuJXpihZw1aD7Xl4JJEVw=
Address    = 10.88.0.2/24

[Peer]
PublicKey  = XXFzbjDln02y/aWfo2RFVZ/foiMC/NEo9QKXDdk9SXk=
Endpoint   = 172.16.203.128:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

// The peer pubkey from the default config, hex-encoded as
// wg(8) expects in the UAPI text protocol.
private let defaultPeerHex =
    "5d71736e30e59f4db2fda59fa36445559fdfa22302fcd128f502970dd93d4979"

private let demoNewPeerHex =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

private var setEndpointDemo: String {
    """
    set=1
    public_key=\(defaultPeerHex)
    endpoint=192.0.2.5:51820

    """
}

private var setKeepaliveDemo: String {
    """
    set=1
    public_key=\(defaultPeerHex)
    persistent_keepalive_interval=15

    """
}

private var addPeerDemo: String {
    """
    set=1
    public_key=\(demoNewPeerHex)
    endpoint=198.51.100.1:51820
    allowed_ip=10.99.0.0/24
    persistent_keepalive_interval=25

    """
}

private var removePeerDemo: String {
    """
    set=1
    public_key=\(demoNewPeerHex)
    remove=true

    """
}

#Preview {
    ContentView()
        .frame(width: 800, height: 540)
}
