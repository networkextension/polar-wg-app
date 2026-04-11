// SPDX-License-Identifier: MIT
//
// TunnelManager.swift
//
// NETunnelProviderManager wrapper with multi-server profile support.
// Profiles are persisted in Keychain and can be switched in the UI.

import Foundation
import NetworkExtension
import Combine
import Security

enum RouteMode: String, CaseIterable, Identifiable, Codable {
    case full
    case split

    var id: String { rawValue }

    var title: String {
        switch self {
        case .full: return "Full Tunnel"
        case .split: return "Split Tunnel"
        }
    }
}

struct ServerProfile: Codable, Identifiable, Equatable {
    let id: UUID
    var name: String
    var config: String
    var routeMode: RouteMode
    var splitInjectedRoutes: String
}

enum ProfileStorageMode: String, CaseIterable, Identifiable {
    case local
    case iCloud

    var id: String { rawValue }

    var title: String {
        switch self {
        case .local: return "Local"
        case .iCloud: return "iCloud Sync"
        }
    }
}

@MainActor
final class TunnelManager: ObservableObject {
    @Published var status: NEVPNStatus = .invalid
    @Published var lastError: String?
    @Published var storageMode: ProfileStorageMode = .local

    @Published var profiles: [ServerProfile] = []
    @Published var selectedProfileID: UUID?

    @Published var configText: String = defaultConfigText
    @Published var routeMode: RouteMode = .full
    @Published var splitInjectedRoutes: String = ""

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private static let storageModeDefaultsKey = "serverProfileStorageMode"

    private struct StoredProfiles: Codable {
        var selectedProfileID: UUID?
        var profiles: [ServerProfile]
    }

    init() {
        storageMode = TunnelManager.loadStoredStorageMode()
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    var selectedProfileName: String {
        get { selectedProfile?.name ?? "" }
        set { renameSelectedProfile(newValue) }
    }

    private var selectedProfile: ServerProfile? {
        guard let id = selectedProfileID else { return nil }
        return profiles.first(where: { $0.id == id })
    }

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first ?? NETunnelProviderManager()

            let proto = manager?.protocolConfiguration as? NETunnelProviderProtocol
            let fallbackConfig = proto?.providerConfiguration?["config"] as? String ?? defaultConfigText
            let fallbackMode: RouteMode = {
                if let raw = proto?.providerConfiguration?["routeMode"] as? String,
                   let parsed = RouteMode(rawValue: raw) {
                    return parsed
                }
                return .full
            }()
            let fallbackSplit = proto?.providerConfiguration?["splitInjectedRoutes"] as? String ?? ""

            loadProfilesFromKeychain(
                fallbackConfig: fallbackConfig,
                fallbackMode: fallbackMode,
                fallbackSplit: fallbackSplit
            )
            attachStatusObserver()
            refreshStatus()
        } catch {
            lastError = "load: \(error.localizedDescription)"
        }
    }

    func setStorageMode(_ mode: ProfileStorageMode) {
        guard mode != storageMode else { return }
        syncCurrentProfileDraft()
        let currentProfiles = profiles
        let currentSelected = selectedProfileID

        storageMode = mode
        UserDefaults.standard.set(mode.rawValue, forKey: Self.storageModeDefaultsKey)

        if let data = KeychainStore.loadData(mode: mode),
           let stored = try? JSONDecoder().decode(StoredProfiles.self, from: data),
           !stored.profiles.isEmpty {
            profiles = stored.profiles
            if let selected = stored.selectedProfileID,
               profiles.contains(where: { $0.id == selected }) {
                selectedProfileID = selected
            } else {
                selectedProfileID = profiles.first?.id
            }
            applySelectedProfileToEditor()
            return
        }

        profiles = currentProfiles
        selectedProfileID = currentSelected ?? profiles.first?.id
        applySelectedProfileToEditor()
        persistProfilesToKeychain()
    }

    func selectProfile(_ id: UUID) {
        syncCurrentProfileDraft()
        selectedProfileID = id
        applySelectedProfileToEditor()
        persistProfilesToKeychain()
    }

    func addProfile(named proposedName: String? = nil) {
        syncCurrentProfileDraft()
        let base = selectedProfile
        let name = normalizedProfileName(proposedName) ?? "Server \(profiles.count + 1)"
        let profile = ServerProfile(
            id: UUID(),
            name: name,
            config: base?.config ?? defaultConfigText,
            routeMode: base?.routeMode ?? .full,
            splitInjectedRoutes: base?.splitInjectedRoutes ?? ""
        )
        profiles.append(profile)
        selectedProfileID = profile.id
        applySelectedProfileToEditor()
        persistProfilesToKeychain()
    }

    func deleteSelectedProfile() {
        guard let id = selectedProfileID else { return }
        guard profiles.count > 1 else {
            lastError = "At least one server profile is required."
            return
        }
        profiles.removeAll(where: { $0.id == id })
        selectedProfileID = profiles.first?.id
        applySelectedProfileToEditor()
        persistProfilesToKeychain()
    }

    func renameSelectedProfile(_ name: String) {
        guard let id = selectedProfileID,
              let idx = profiles.firstIndex(where: { $0.id == id }) else { return }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        profiles[idx].name = trimmed.isEmpty ? "Unnamed Server" : trimmed
        persistProfilesToKeychain()
    }

    /// Persist the currently edited profile to the NE provider prefs.
    func saveCurrentProfile() async {
        syncCurrentProfileDraft()
        guard let profile = selectedProfile else { return }
        await save(
            config: profile.config,
            routeMode: profile.routeMode,
            splitInjectedRoutes: profile.splitInjectedRoutes
        )
    }

    /// Keep this for compatibility with existing call sites.
    func save(config: String, routeMode: RouteMode, splitInjectedRoutes: String) async {
        configText = config
        self.routeMode = routeMode
        self.splitInjectedRoutes = splitInjectedRoutes
        syncCurrentProfileDraft()

        guard let m = manager else { return }
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.change.wg.tunnel"
        proto.serverAddress = firstEndpointFrom(config: config) ?? "wireguard"
        proto.providerConfiguration = [
            "config": config,
            "routeMode": routeMode.rawValue,
            "splitInjectedRoutes": splitInjectedRoutes
        ]
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

    private func applySelectedProfileToEditor() {
        guard let profile = selectedProfile else { return }
        configText = profile.config
        routeMode = profile.routeMode
        splitInjectedRoutes = profile.splitInjectedRoutes
    }

    private func syncCurrentProfileDraft() {
        guard let id = selectedProfileID,
              let idx = profiles.firstIndex(where: { $0.id == id }) else { return }
        profiles[idx].config = configText
        profiles[idx].routeMode = routeMode
        profiles[idx].splitInjectedRoutes = splitInjectedRoutes
        persistProfilesToKeychain()
    }

    private func normalizedProfileName(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private func loadProfilesFromKeychain(
        fallbackConfig: String,
        fallbackMode: RouteMode,
        fallbackSplit: String
    ) {
        if let data = KeychainStore.loadData(mode: storageMode),
           let stored = try? JSONDecoder().decode(StoredProfiles.self, from: data),
           !stored.profiles.isEmpty {
            profiles = stored.profiles
            if let selected = stored.selectedProfileID,
               profiles.contains(where: { $0.id == selected }) {
                selectedProfileID = selected
            } else {
                selectedProfileID = profiles.first?.id
            }
            applySelectedProfileToEditor()
            return
        }

        let initial = ServerProfile(
            id: UUID(),
            name: "Default Server",
            config: fallbackConfig,
            routeMode: fallbackMode,
            splitInjectedRoutes: fallbackSplit
        )
        profiles = [initial]
        selectedProfileID = initial.id
        applySelectedProfileToEditor()
        persistProfilesToKeychain()
    }

    private func persistProfilesToKeychain() {
        let payload = StoredProfiles(selectedProfileID: selectedProfileID, profiles: profiles)
        guard let data = try? JSONEncoder().encode(payload) else { return }
        do {
            try KeychainStore.saveData(data, mode: storageMode)
        } catch {
            lastError = "keychain save: \(error.localizedDescription)"
        }
    }

    private static func loadStoredStorageMode() -> ProfileStorageMode {
        guard let raw = UserDefaults.standard.string(forKey: storageModeDefaultsKey),
              let mode = ProfileStorageMode(rawValue: raw) else {
            return .local
        }
        return mode
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

private enum KeychainStore {
    private static let service = "com.change.wg.sampleapp"
    private static let accountBase = "server-profiles-v1"

    static func loadData(mode: ProfileStorageMode) -> Data? {
        let account = accountBase + "-" + mode.rawValue
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: mode == .iCloud ? kCFBooleanTrue as Any : kCFBooleanFalse as Any,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    static func saveData(_ data: Data, mode: ProfileStorageMode) throws {
        let account = accountBase + "-" + mode.rawValue
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: mode == .iCloud ? kCFBooleanTrue as Any : kCFBooleanFalse as Any
        ]

        let attrs: [CFString: Any] = [
            kSecValueData: data,
            kSecAttrAccessible: mode == .iCloud
                ? kSecAttrAccessibleAfterFirstUnlock
                : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(updateStatus))
        }

        var add = query
        add[kSecValueData] = data
        add[kSecAttrAccessible] = mode == .iCloud
            ? kSecAttrAccessibleAfterFirstUnlock
            : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(addStatus))
        }
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
