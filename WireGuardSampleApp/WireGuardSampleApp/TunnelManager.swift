// SPDX-License-Identifier: MIT
//
// TunnelManager.swift
//
// Thin wrapper around NETunnelProviderManager that exposes the four
// things the SwiftUI layer cares about:
//
//   1. load()         — fetch the existing manager (if any) from prefs
//   2. save(config:)  — install / update the protocolConfiguration so
//                       the host app and the extension share the wg-quick
//                       config text via providerConfiguration["config"]
//   3. start() / stop() — toggle the VPN tunnel
//   4. uapiGet()      — send "get=1\n\n" to the running extension via
//                       NETunnelProviderSession.sendProviderMessage and
//                       return the canonical wg UAPI text response
//
// The class also republishes the connection's NEVPNStatus as a
// @Published so the UI can react to it.

import Foundation
import NetworkExtension
import Combine

@MainActor
final class TunnelManager: ObservableObject {
    @Published var status: NEVPNStatus = .invalid
    @Published var lastError: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    /// Load the existing tunnel preference from the system, or create a
    /// fresh in-memory manager if none exists. Call this once at startup.
    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first ?? NETunnelProviderManager()
            attachStatusObserver()
            refreshStatus()
        } catch {
            lastError = "load: \(error.localizedDescription)"
        }
    }

    /// Persist a wg-quick-style config text to the tunnel preference.
    /// The first call also installs the provider in System Settings —
    /// macOS will pop a permission dialog.
    func save(config: String) async {
        guard let m = manager else { return }
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.change.wg.tunnel"
        // serverAddress is cosmetic for wg — it shows up in the system
        // VPN UI as the "server". Pull the first Endpoint line out of
        // the config text if we can find one.
        proto.serverAddress = firstEndpointFrom(config: config) ?? "wireguard"
        proto.providerConfiguration = ["config": config]
        m.protocolConfiguration = proto
        m.localizedDescription = "WireGuard Sample"
        m.isEnabled = true
        do {
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
            attachStatusObserver()
            refreshStatus()
            lastError = nil
        } catch {
            lastError = "save: \(error.localizedDescription)"
        }
    }

    func start() {
        guard let m = manager else { return }
        do {
            try m.connection.startVPNTunnel()
            lastError = nil
        } catch {
            lastError = "start: \(error.localizedDescription)"
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    /// Send a `get=1\n\n` request to the running extension and return
    /// the canonical wg UAPI text response. Returns nil if the tunnel
    /// is not running or the message round-trip failed.
    func uapiGet() async -> String? {
        guard let session = manager?.connection as? NETunnelProviderSession,
              status == .connected else {
            return nil
        }
        let req = "get=1\n\n".data(using: .utf8)!
        return await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            do {
                try session.sendProviderMessage(req) { resp in
                    if let data = resp, let text = String(data: data, encoding: .utf8) {
                        cont.resume(returning: text)
                    } else {
                        cont.resume(returning: nil)
                    }
                }
            } catch {
                cont.resume(returning: "send error: \(error.localizedDescription)")
            }
        }
    }

    /// Send a UAPI SET request (e.g. roam endpoint, change keepalive,
    /// add/remove peer). Returns the response text from the extension.
    func uapiSet(_ body: String) async -> String? {
        guard let session = manager?.connection as? NETunnelProviderSession,
              status == .connected else {
            return nil
        }
        let req = body.data(using: .utf8)!
        return await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            do {
                try session.sendProviderMessage(req) { resp in
                    if let data = resp, let text = String(data: data, encoding: .utf8) {
                        cont.resume(returning: text)
                    } else {
                        cont.resume(returning: nil)
                    }
                }
            } catch {
                cont.resume(returning: "send error: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Private

    private func attachStatusObserver() {
        if let existing = statusObserver {
            NotificationCenter.default.removeObserver(existing)
            statusObserver = nil
        }
        guard let m = manager else { return }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: m.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.refreshStatus()
            }
        }
    }

    private func refreshStatus() {
        status = manager?.connection.status ?? .invalid
    }

    private func firstEndpointFrom(config: String) -> String? {
        for line in config.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix("endpoint") {
                let parts = trimmed.split(separator: "=", maxSplits: 1).map { String($0) }
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
        case .invalid:       return "invalid"
        case .disconnected:  return "disconnected"
        case .connecting:    return "connecting…"
        case .connected:     return "connected"
        case .reasserting:   return "reasserting…"
        case .disconnecting: return "disconnecting…"
        @unknown default:    return "unknown"
        }
    }
}
