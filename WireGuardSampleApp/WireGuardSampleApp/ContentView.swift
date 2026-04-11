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

struct ContentView: View {
    @StateObject private var manager = TunnelManager()

    @State private var configText: String = defaultConfigText
    @State private var statusText: String = "(tunnel not running)"
    @State private var statusTimer: Timer?

    var body: some View {
        VStack(spacing: 12) {
            header

            HSplitView {
                VStack(alignment: .leading, spacing: 8) {
                    Label("wg-quick config", systemImage: "doc.text")
                        .font(.headline)
                    TextEditor(text: $configText)
                        .font(.system(.body, design: .monospaced))
                        .border(Color.secondary.opacity(0.4))
                }
                .padding(.trailing, 6)

                VStack(alignment: .leading, spacing: 8) {
                    Label("UAPI status (get=1)", systemImage: "antenna.radiowaves.left.and.right")
                        .font(.headline)
                    ScrollView {
                        Text(statusText)
                            .font(.system(.caption, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                            .padding(8)
                    }
                    .background(Color(NSColor.textBackgroundColor))
                    .border(Color.secondary.opacity(0.4))
                }
                .padding(.leading, 6)
            }

            actionsBar
        }
        .padding(16)
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

    private var header: some View {
        HStack(spacing: 12) {
            Text("WireGuard NE Sample")
                .font(.title2.bold())
            Spacer()
            statusPill
            Button("Save config")    { Task { await manager.save(config: configText) } }
            Button("Connect")        { manager.start() }
                .disabled(manager.status == .connected || manager.status == .connecting)
            Button("Disconnect")     { manager.stop() }
                .disabled(manager.status != .connected && manager.status != .connecting)
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

    // MARK: - Helpers

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
