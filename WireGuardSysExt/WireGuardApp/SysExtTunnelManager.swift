// SysExtTunnelManager.swift
//
// Thin wrapper around NETunnelProviderManager for the sysext version.
// The only difference from the App Extension version is the
// providerBundleIdentifier — it points at the .systemextension
// bundle instead of the .appex.

import Foundation
import NetworkExtension

@MainActor
final class SysExtTunnelManager: ObservableObject {
    @Published var status: NEVPNStatus = .invalid
    @Published var lastError: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    func load() async {
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        manager = managers.first ?? NETunnelProviderManager()
        attachStatusObserver()
        refreshStatus()
    }

    func saveAndConnect(config: String) async {
        if manager == nil { await load() }
        guard let m = manager else { return }

        let proto = NETunnelProviderProtocol()
        // This bundle ID must match the system extension target
        proto.providerBundleIdentifier = "com.change.wg.mac.tunnel"
        proto.serverAddress = firstEndpoint(from: config) ?? "wireguard"
        proto.providerConfiguration = [
            "config": config,
            "routeMode": "full",
            "dnsMode": "plain",
            "splitInjectedRoutes": ""
        ]
        m.protocolConfiguration = proto
        m.localizedDescription = "WireGuard (SysExt)"
        m.isEnabled = true

        do {
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
            attachStatusObserver()
            refreshStatus()
            try m.connection.startVPNTunnel()
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    // MARK: - Private

    private func attachStatusObserver() {
        if let existing = statusObserver {
            NotificationCenter.default.removeObserver(existing)
        }
        guard let m = manager else { return }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: m.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
    }

    private func refreshStatus() {
        status = manager?.connection.status ?? .invalid
    }

    private func firstEndpoint(from config: String) -> String? {
        for line in config.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix("endpoint") {
                let parts = trimmed.split(separator: "=", maxSplits: 1)
                if parts.count == 2 {
                    return parts[1].trimmingCharacters(in: .whitespaces)
                }
            }
        }
        return nil
    }
}

extension NEVPNStatus {
    var displayString: String {
        switch self {
        case .invalid:       return "not configured"
        case .disconnected:  return "disconnected"
        case .connecting:    return "connecting…"
        case .connected:     return "connected"
        case .reasserting:   return "reasserting…"
        case .disconnecting: return "disconnecting…"
        @unknown default:    return "unknown"
        }
    }
}
