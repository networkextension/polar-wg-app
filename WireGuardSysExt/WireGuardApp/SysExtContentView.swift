// SysExtContentView.swift
//
// SwiftUI shell for the System Extension version. Three-phase flow:
//   1. Install System Extension (OSSystemExtensionRequest)
//   2. Configure + Connect VPN (NETunnelProviderManager)
//   3. Monitor status
//
// The config editor / node management is intentionally minimal here
// (just a text field + connect/disconnect). The full-featured UI
// lives in WireGuardSampleApp — this project focuses on proving the
// sysext activation + Developer ID distribution path.

import SwiftUI
import NetworkExtension

struct SysExtContentView: View {
    @StateObject private var sysExtManager = SystemExtensionManager()
    @StateObject private var tunnelManager = SysExtTunnelManager()

    @State private var configText: String = defaultSysExtConfig

    var body: some View {
        NavigationSplitView {
            List {
                Label("Extension", systemImage: "puzzlepiece.extension")
                Label("Tunnel", systemImage: "shield.checkered")
            }
            .navigationTitle("WireGuard")
        } detail: {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    sysExtSection
                    Divider()
                    tunnelSection
                }
                .padding(20)
            }
        }
    }

    // MARK: - System Extension Section

    private var sysExtSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("System Extension")
                .font(.title2.bold())

            HStack(spacing: 12) {
                statusBadge(for: sysExtManager.status)

                Button("Install Extension") {
                    sysExtManager.activate()
                }
                .buttonStyle(.borderedProminent)
                .disabled(sysExtManager.status == .activated ||
                          sysExtManager.status == .activating)

                Button("Uninstall") {
                    sysExtManager.deactivate()
                }
                .buttonStyle(.bordered)
            }

            switch sysExtManager.status {
            case .needsUserApproval:
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("Go to **System Settings → Privacy & Security → Network Extensions** and approve \"WireGuard Tunnel\".")
                        .font(.callout)
                }
                .padding(12)
                .background(.orange.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8))

            case .failed(let msg):
                HStack(spacing: 8) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.red)
                    Text(msg).font(.callout)
                }
                .padding(12)
                .background(.red.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8))

            default:
                EmptyView()
            }

            Text("The system extension runs as an independent process managed by macOS. It survives app exit and can be distributed via Developer ID (no App Store).")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Tunnel Section

    private var tunnelSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("VPN Tunnel")
                .font(.title2.bold())

            HStack(spacing: 12) {
                Circle()
                    .fill(tunnelStatusColor)
                    .frame(width: 10, height: 10)
                Text(tunnelManager.status.displayString)
                    .font(.subheadline.monospaced())

                Spacer()

                Button("Save & Connect") {
                    Task {
                        await tunnelManager.saveAndConnect(config: configText)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(tunnelManager.status == .connected ||
                          tunnelManager.status == .connecting ||
                          sysExtManager.status != .activated)

                Button("Disconnect") {
                    tunnelManager.disconnect()
                }
                .disabled(tunnelManager.status != .connected &&
                          tunnelManager.status != .connecting)
            }

            if sysExtManager.status != .activated {
                Text("Install the system extension first before connecting.")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            if let err = tunnelManager.lastError {
                Text(err)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            // Config editor
            Text("wg-quick config")
                .font(.headline)
            TextEditor(text: $configText)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 200)
                .padding(8)
                .background(Color(nsColor: .textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.secondary.opacity(0.2))
                )
        }
    }

    // MARK: - Helpers

    private func statusBadge(for status: SystemExtensionManager.Status) -> some View {
        let (color, text): (Color, String) = {
            switch status {
            case .unknown:           return (.gray, "Not installed")
            case .activating:        return (.yellow, "Installing...")
            case .needsUserApproval: return (.orange, "Needs approval")
            case .activated:         return (.green, "Installed")
            case .failed:            return (.red, "Failed")
            }
        }()
        return HStack(spacing: 6) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(text).font(.subheadline)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(color.opacity(0.1))
        .clipShape(Capsule())
    }

    private var tunnelStatusColor: Color {
        switch tunnelManager.status {
        case .connected:                return .green
        case .connecting, .reasserting: return .yellow
        case .disconnecting:            return .orange
        default:                        return .gray
        }
    }
}

let defaultSysExtConfig = """
[Interface]
PrivateKey = yPDHiay/NDkJE9OyUT0J8qhuJXpihZw1aD7Xl4JJEVw=
Address    = 10.88.0.2/24
DNS        = 1.1.1.1

[Peer]
PublicKey  = XXFzbjDln02y/aWfo2RFVZ/foiMC/NEo9QKXDdk9SXk=
Endpoint   = 172.16.203.128:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
