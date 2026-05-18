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

enum DNSMode: String, CaseIterable, Identifiable, Codable {
    case system     // no override — use whatever the OS has
    case plain      // plain DNS from config's "DNS = ..." line
    case doh        // DNS-over-HTTPS via Cloudflare 1.1.1.1

    var id: String { rawValue }

    var title: String {
        switch self {
        case .system: return "System DNS"
        case .plain:  return "Config DNS"
        case .doh:    return "DoH (1.1.1.1)"
        }
    }

    var subtitle: String {
        switch self {
        case .system: return "Use device default"
        case .plain:  return "Use DNS from wg-quick config"
        case .doh:    return "Encrypted DNS via Cloudflare"
        }
    }
}

enum NodeSource: String, Codable {
    case manual    // user-created, config visible + editable
    case platform  // API-delivered, config hidden, only name shown
}

struct VPNNode: Codable, Identifiable, Equatable {
    let id: UUID
    var name: String
    var config: String              // wg-quick text (always present for NE)
    var source: NodeSource
    var country: String             // emoji flag "🇯🇵" or "" if unknown
    var routeMode: RouteMode
    var dnsMode: DNSMode
    var splitInjectedRoutes: String

    // Platform metadata (nil for manual nodes)
    var platformProxyId: String?
    var platformProfileId: String?
    var proxyVersion: Int?
    var lastSynced: Date?
}

// Keep backward compat alias so existing code compiles during migration
typealias ServerProfile = VPNNode

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
    @Published var isLoaded: Bool = false
    @Published var isAuthenticated: Bool = false
    @Published var authError: String?
    @Published var authInfo: String?

    @Published var profiles: [ServerProfile] = []
    @Published var selectedProfileID: UUID?

    @Published var configText: String = defaultConfigText
    @Published var routeMode: RouteMode = .full
    @Published var dnsMode: DNSMode = .plain
    @Published var splitInjectedRoutes: String = ""

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private static let storageModeDefaultsKey = "serverProfileStorageMode"
    private static let authLoggedInDefaultsKey = "isLoggedIn"

    private struct StoredProfiles: Codable {
        var selectedProfileID: UUID?
        var profiles: [ServerProfile]
    }

    init() {
        storageMode = TunnelManager.loadStoredStorageMode()
        isAuthenticated = UserDefaults.standard.bool(forKey: Self.authLoggedInDefaultsKey)
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
        defer { isLoaded = true }
        do {
            let managers = try await loadManagersWithTimeout(seconds: 6)
            if let managers {
                manager = managers.first ?? NETunnelProviderManager()
            } else {
                // Avoid getting stuck on splash forever if NE prefs API stalls.
                manager = NETunnelProviderManager()
                lastError = "VPN service load timeout. You can still edit/save and retry connect."
            }

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

    func login(email: String, password: String, apiBaseURL: String) async {
        let user = email.trimmingCharacters(in: .whitespacesAndNewlines)
        let pass = password.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !user.isEmpty, !pass.isEmpty else {
            authError = "Email and password are required."
            return
        }

        APIClient.shared.setBaseURL(apiBaseURL)
        do {
            try await APIClient.shared.login(email: user, password: pass)
            authError = nil
            authInfo = nil
            isAuthenticated = true
            UserDefaults.standard.set(true, forKey: Self.authLoggedInDefaultsKey)
        } catch {
            isAuthenticated = false
            authInfo = nil
            authError = error.localizedDescription
        }
    }

    func register(username: String, email: String, password: String, apiBaseURL: String) async {
        let name = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let user = email.trimmingCharacters(in: .whitespacesAndNewlines)
        let pass = password.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !user.isEmpty, !pass.isEmpty else {
            authError = "Username, email, and password are required."
            return
        }

        APIClient.shared.setBaseURL(apiBaseURL)
        do {
            try await APIClient.shared.register(username: name, email: user, password: pass)
            authError = nil
            authInfo = "Register success. Please login."
            isAuthenticated = false
            UserDefaults.standard.set(false, forKey: Self.authLoggedInDefaultsKey)
        } catch {
            authInfo = nil
            authError = error.localizedDescription
        }
    }

    func skipLogin() {
        isAuthenticated = true
        authError = nil
        authInfo = "Skipped login (offline mode)"
        UserDefaults.standard.set(true, forKey: Self.authLoggedInDefaultsKey)
    }

    func logoutUser() {
        stop()
        isAuthenticated = false
        authError = nil
        authInfo = nil
        UserDefaults.standard.set(false, forKey: Self.authLoggedInDefaultsKey)
        Task {
            try? await APIClient.shared.logout()
        }
    }

    // MARK: - Platform sync

    @Published var isSyncing: Bool = false

    /// Fetch profiles from the Latch platform API, convert each proxy
    /// to a VPNNode, and merge into the local node list. Manual nodes
    /// are never touched. Platform nodes are matched by platformProxyId:
    ///   - new proxy → add node
    ///   - existing proxy with newer version → update config + name
    ///   - local platform node not in API response → remove
    func syncFromPlatform() async {
        guard !isSyncing else { return }
        isSyncing = true
        defer { isSyncing = false }

        do {
            let latchProfiles = try await APIClient.shared.getLatchProfiles()
            syncCurrentProfileDraft()

            // Collect all proxies across all profiles into VPNNodes.
            var incoming: [String: VPNNode] = [:]  // keyed by proxy.id
            for lp in latchProfiles {
                for proxy in lp.proxies {
                    guard let wgConfig = proxy.toWGQuickConfig() else {
                        // Config doesn't have required WG keys — skip.
                        continue
                    }
                    let node = VPNNode(
                        id: UUID(),
                        name: proxy.name,
                        config: wgConfig,
                        source: .platform,
                        country: proxy.country ?? "",
                        routeMode: .full,
                        dnsMode: .plain,
                        splitInjectedRoutes: "",
                        platformProxyId: proxy.id,
                        platformProfileId: lp.id,
                        proxyVersion: proxy.version,
                        lastSynced: Date()
                    )
                    incoming[proxy.id] = node
                }
            }

            // Merge.
            var merged: [VPNNode] = []

            // Keep all manual nodes as-is.
            for node in profiles where node.source == .manual {
                merged.append(node)
            }

            // For each existing platform node, update if still in API,
            // drop if removed from API.
            for node in profiles where node.source == .platform {
                if let proxyId = node.platformProxyId,
                   let fresh = incoming[proxyId] {
                    var updated = node
                    updated.name = fresh.name
                    updated.country = fresh.country
                    if fresh.proxyVersion != node.proxyVersion {
                        updated.config = fresh.config
                        updated.proxyVersion = fresh.proxyVersion
                    }
                    updated.lastSynced = Date()
                    merged.append(updated)
                    incoming.removeValue(forKey: proxyId)
                }
                // else: platform node no longer in API → dropped
            }

            // Add brand-new platform nodes.
            for (_, node) in incoming {
                merged.append(node)
            }

            profiles = merged

            // If the selected node was removed, pick the first available.
            if let sel = selectedProfileID,
               !profiles.contains(where: { $0.id == sel }) {
                selectedProfileID = profiles.first?.id
            }

            applySelectedProfileToEditor()
            persistProfilesToKeychain()
            lastError = nil
        } catch {
            lastError = "Sync failed: \(error.localizedDescription)"
        }
    }

    /// Convenience computed properties for UI sections.
    var platformNodes: [VPNNode] {
        profiles.filter { $0.source == .platform }
    }
    var manualNodes: [VPNNode] {
        profiles.filter { $0.source == .manual }
    }

    func selectProfile(_ id: UUID) {
        syncCurrentProfileDraft()
        selectedProfileID = id
        applySelectedProfileToEditor()
        persistProfilesToKeychain()
    }

    // MARK: - Polar mesh (post-login token-based join)

    /// Result of the last join attempt, surfaced as a banner in the UI.
    @Published var meshJoinError: String?
    @Published var meshJoinInfo: String?
    @Published var isJoiningMesh: Bool = false

    /// Per-profile mesh metadata (device_id + token + server) so a
    /// future heartbeat agent can keep the profile fresh. Stored next
    /// to the profile in keychain via persistProfilesToKeychain.
    /// For now the join flow only writes; the agent is TODO.
    private static let meshMetaDefaultsPrefix = "meshMeta."

    /// Join the Polar mesh: keypair → POST /v1/register → render conf
    /// → persist as a new ServerProfile and select it. UI calls this
    /// from the join sheet with token + serverURL (defaults to apiBase).
    ///
    /// Does not auto-connect; the user reviews the profile then taps
    /// Connect like any other server.
    func joinMesh(token rawToken: String, serverURL: String? = nil) async {
        meshJoinError = nil
        meshJoinInfo = nil
        isJoiningMesh = true
        defer { isJoiningMesh = false }

        let token = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else {
            meshJoinError = "token is empty"
            return
        }

        // Server URL: explicit > app's stored API base.
        let resolvedServer: String = {
            if let s = serverURL?.trimmingCharacters(in: .whitespacesAndNewlines),
               !s.isEmpty { return s }
            return UserDefaults.standard.string(forKey: "api_base_url") ?? ""
        }()

        do {
            let client = try MeshClient.from(serverString: resolvedServer)
            let (privB64, pubB64) = MeshClient.newKeypair()

            // Hostname: iOS doesn't expose scutil; use ProcessInfo's
            // hostname (often a generic "iPhone"), let server hash it.
            let hostname = ProcessInfo.processInfo.hostName
            let listen = 51820
            let agentVer = "wg-mac-app-ios-1"

            let resp = try await client.register(
                token: token,
                pubkey: pubB64,
                hostname: hostname,
                wgListen: listen,
                lanAddrs: LANAddrs.enumerate(),
                agentVer: agentVer
            )

            let conf = MeshConfRenderer.render(
                response: resp,
                privateKeyB64: privB64,
                listenPort: listen
            )

            // Save as new profile. Name = mesh-<role>-<short device_id>.
            let shortDev = String(resp.device_id.suffix(8))
            let role = resp.role ?? "device"
            let profileName = "mesh-\(role)-\(shortDev)"
            let profile = VPNNode(
                id: UUID(),
                name: profileName,
                config: conf,
                source: .manual,
                country: resp.hub_slug ?? "",
                routeMode: .split,
                dnsMode: .plain,
                splitInjectedRoutes: resp.mesh_cidr ?? "10.88.0.0/16"
            )
            profiles.append(profile)
            selectedProfileID = profile.id
            applySelectedProfileToEditor()
            persistProfilesToKeychain()

            // Persist mesh metadata for the future heartbeat agent.
            let meta: [String: String] = [
                "device_id":  resp.device_id,
                "device_ip":  resp.device_ip,
                "token":      resp.token ?? token,
                "server":     resolvedServer,
                "role":       role,
                "pubkey":     pubB64,
                "hub_slug":   resp.hub_slug ?? "",
                "site_id":    resp.site_id ?? "",
            ]
            if let encoded = try? JSONSerialization.data(withJSONObject: meta) {
                UserDefaults.standard.set(encoded,
                    forKey: Self.meshMetaDefaultsPrefix + profile.id.uuidString)
            }

            meshJoinInfo = "Joined: \(role) @ \(resp.device_ip)"
        } catch MeshClientError.http(let code, let body) {
            meshJoinError = "HTTP \(code) — \(body.prefix(180))"
        } catch MeshClientError.badServerURL {
            meshJoinError = "Bad server URL (need https://…)"
        } catch MeshClientError.decode(let why) {
            meshJoinError = "decode error: \(why)"
        } catch {
            meshJoinError = error.localizedDescription
        }
    }

    /// Look up mesh metadata stored at join time (used by /v1/leave + a
    /// future heartbeat agent). nil if this profile wasn't joined via
    /// mesh (e.g. user pasted a wg conf manually).
    func meshMetadata(for profileID: UUID) -> [String: String]? {
        guard let data = UserDefaults.standard.data(
                forKey: Self.meshMetaDefaultsPrefix + profileID.uuidString) else {
            return nil
        }
        return try? JSONSerialization.jsonObject(with: data) as? [String: String]
    }

    /// Best-effort /v1/leave for the selected profile, then delete it
    /// locally. Wraps deleteSelectedProfile.
    func leaveMeshAndDeleteSelected() async {
        guard let id = selectedProfileID, let meta = meshMetadata(for: id),
              let server = meta["server"], let dev = meta["device_id"],
              let tok = meta["token"] else {
            deleteSelectedProfile()
            return
        }
        if let client = try? MeshClient.from(serverString: server) {
            await client.leave(deviceID: dev, token: tok)
        }
        UserDefaults.standard.removeObject(
            forKey: Self.meshMetaDefaultsPrefix + id.uuidString)
        deleteSelectedProfile()
    }

    func addProfile(named proposedName: String? = nil) {
        syncCurrentProfileDraft()
        let base = selectedProfile
        let name = normalizedProfileName(proposedName) ?? "Server \(profiles.count + 1)"
        let profile = VPNNode(
            id: UUID(),
            name: name,
            config: base?.config ?? defaultConfigText,
            source: .manual,
            country: "",
            routeMode: base?.routeMode ?? .full,
            dnsMode: base?.dnsMode ?? .plain,
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
            "dnsMode": dnsMode.rawValue,
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

    private func loadManagersWithTimeout(seconds: TimeInterval) async throws -> [NETunnelProviderManager]? {
        try await withThrowingTaskGroup(of: [NETunnelProviderManager]?.self) { group in
            group.addTask {
                try await NETunnelProviderManager.loadAllFromPreferences()
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return nil
            }
            let first = try await group.next() ?? nil
            group.cancelAll()
            return first
        }
    }

    private func refreshStatus() {
        status = manager?.connection.status ?? .invalid
    }

    private func applySelectedProfileToEditor() {
        guard let profile = selectedProfile else { return }
        configText = profile.config
        routeMode = profile.routeMode
        dnsMode = profile.dnsMode
        splitInjectedRoutes = profile.splitInjectedRoutes
    }

    private func syncCurrentProfileDraft() {
        guard let id = selectedProfileID,
              let idx = profiles.firstIndex(where: { $0.id == id }) else { return }
        profiles[idx].config = configText
        profiles[idx].routeMode = routeMode
        profiles[idx].dnsMode = dnsMode
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

        let initial = VPNNode(
            id: UUID(),
            name: "Default Node",
            config: fallbackConfig,
            source: .manual,
            country: "",
            routeMode: fallbackMode,
            dnsMode: .plain,
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
        return loadData(account: account, mode: mode)
    }

    static func loadData(account: String, mode: ProfileStorageMode) -> Data? {
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
        try saveData(data, account: account, mode: mode)
    }

    static func saveData(_ data: Data, account: String, mode: ProfileStorageMode) throws {
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

    static func loadString(account: String, mode: ProfileStorageMode) -> String? {
        guard let data = loadData(account: account, mode: mode) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func saveString(_ value: String, account: String, mode: ProfileStorageMode) throws {
        guard let data = value.data(using: .utf8) else { return }
        try saveData(data, account: account, mode: mode)
    }
}

final class APIClient {
    static let shared = APIClient()

    private let session = URLSession.shared
    private let baseURLDefaultsKey = "api_base_url"

    var baseURL: URL? {
        let raw = UserDefaults.standard.string(forKey: baseURLDefaultsKey)?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let raw, !raw.isEmpty else { return nil }
        return URL(string: raw)
    }

    func setBaseURL(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            UserDefaults.standard.removeObject(forKey: baseURLDefaultsKey)
        } else {
            UserDefaults.standard.set(trimmed, forKey: baseURLDefaultsKey)
        }
    }

    func login(email: String, password: String) async throws {
        let body: [String: Any] = ["email": email, "password": password]
        _ = try await post(path: "/api/login", body: body, responseType: Empty.self)
    }

    func register(username: String, email: String, password: String) async throws {
        let body: [String: Any] = ["username": username, "email": email, "password": password]
        _ = try await post(path: "/api/register", body: body, responseType: Empty.self)
    }

    func logout() async throws {
        _ = try await post(path: "/api/logout", body: nil, responseType: Empty.self)
    }

    func getLatchProfiles() async throws -> [LatchProfile] {
        let resp = try await get(path: "/api/latch/profiles", responseType: LatchProfilesResponse.self)
        return resp.profiles
    }

    private func get<T: Decodable>(path: String, responseType: T.Type) async throws -> T {
        guard let baseURL else { throw APIError.invalidBaseURL }
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "GET"
        return try await perform(req, responseType: responseType)
    }

    private func post<T: Decodable>(path: String, body: Any?, responseType: T.Type) async throws -> T {
        guard let baseURL else { throw APIError.invalidBaseURL }
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let body {
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        return try await perform(req, responseType: responseType)
    }

    private func perform<T: Decodable>(_ request: URLRequest, responseType: T.Type) async throws -> T {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let message = (try? JSONDecoder().decode(ErrorResponse.self, from: data))?.error ?? "HTTP \(http.statusCode)"
            throw APIError.serverError(http.statusCode, message)
        }
        if T.self == Empty.self {
            return Empty() as! T
        }
        // Use the Latch API decoder (snake_case + ISO8601 dates) for
        // platform responses; plain JSONDecoder for everything else.
        let decoder: JSONDecoder = (T.self == LatchProfilesResponse.self)
            ? .latchAPI
            : JSONDecoder()
        return try decoder.decode(T.self, from: data)
    }

    private struct Empty: Decodable {}

    private struct ErrorResponse: Decodable {
        let error: String
    }

    private enum APIError: LocalizedError {
        case invalidBaseURL
        case invalidResponse
        case serverError(Int, String)

        var errorDescription: String? {
            switch self {
            case .invalidBaseURL:
                return "API Base URL is required."
            case .invalidResponse:
                return "Invalid server response."
            case .serverError(_, let message):
                return message
            }
        }
    }
}

// MARK: - Config Validator

struct WGConfigValidator {

    struct ValidationResult {
        let isValid: Bool
        let errors: [String]

        var errorSummary: String { errors.joined(separator: "\n") }

        static let ok = ValidationResult(isValid: true, errors: [])
    }

    /// Validate a wg-quick config text. Returns specific error messages
    /// for each problem found. An empty errors array means the config
    /// is structurally sound (it might still fail at runtime due to
    /// wrong keys or unreachable endpoints, but the format is correct).
    static func validate(_ config: String) -> ValidationResult {
        let trimmed = config.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .init(isValid: false, errors: ["Config is empty."])
        }

        var errors: [String] = []
        let lines = trimmed.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }

        // Section tracking
        var hasInterface = false
        var hasPeer = false
        var currentSection = ""

        // Required fields
        var hasPrivateKey = false
        var hasAddress = false
        var hasPublicKey = false
        var hasEndpoint = false
        var hasAllowedIPs = false

        for line in lines {
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }

            if line.hasPrefix("[") {
                let section = line.lowercased()
                    .replacingOccurrences(of: "[", with: "")
                    .replacingOccurrences(of: "]", with: "")
                    .trimmingCharacters(in: .whitespaces)
                currentSection = section
                if section == "interface" { hasInterface = true }
                if section == "peer"      { hasPeer = true }
                continue
            }

            let parts = line.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces)
            let value = parts[1].trimmingCharacters(in: .whitespaces)

            if currentSection == "interface" {
                switch key {
                case "PrivateKey":
                    hasPrivateKey = true
                    if !isValidBase64Key(value) {
                        errors.append("PrivateKey is not a valid 32-byte base64 key.")
                    }
                case "Address":
                    hasAddress = true
                    if value.isEmpty {
                        errors.append("Address is empty.")
                    }
                default: break
                }
            }

            if currentSection == "peer" {
                switch key {
                case "PublicKey":
                    hasPublicKey = true
                    if !isValidBase64Key(value) {
                        errors.append("PublicKey is not a valid 32-byte base64 key.")
                    }
                case "Endpoint":
                    hasEndpoint = true
                    if value.isEmpty {
                        errors.append("Endpoint is empty.")
                    } else if !value.contains(":") {
                        errors.append("Endpoint must be host:port format.")
                    }
                case "AllowedIPs":
                    hasAllowedIPs = true
                default: break
                }
            }
        }

        // Check required sections
        if !hasInterface {
            errors.append("Missing [Interface] section.")
        }
        if !hasPeer {
            errors.append("Missing [Peer] section.")
        }

        // Check required fields
        if hasInterface && !hasPrivateKey {
            errors.append("Missing PrivateKey in [Interface].")
        }
        if hasInterface && !hasAddress {
            errors.append("Missing Address in [Interface].")
        }
        if hasPeer && !hasPublicKey {
            errors.append("Missing PublicKey in [Peer].")
        }
        if hasPeer && !hasAllowedIPs {
            errors.append("Missing AllowedIPs in [Peer].")
        }

        return ValidationResult(isValid: errors.isEmpty, errors: errors)
    }

    /// Validate a VPNNode is ready to connect.
    static func validateForConnect(_ node: VPNNode?) -> ValidationResult {
        guard let node else {
            return .init(isValid: false, errors: ["No node selected."])
        }
        if node.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return .init(isValid: false, errors: ["Node name is empty."])
        }
        let configResult = validate(node.config)
        if !configResult.isValid {
            return configResult
        }
        return .ok
    }

    /// Check if a string looks like a valid 32-byte base64 WireGuard key.
    /// WG keys are always exactly 44 characters of base64 with trailing '='.
    private static func isValidBase64Key(_ s: String) -> Bool {
        let trimmed = s.trimmingCharacters(in: .whitespaces)
        guard trimmed.count == 44, trimmed.hasSuffix("=") else { return false }
        let charset = CharacterSet.alphanumerics
            .union(CharacterSet(charactersIn: "+/="))
        return trimmed.unicodeScalars.allSatisfy { charset.contains($0) }
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

// MARK: - Latch Platform Types

struct LatchProfilesResponse: Codable {
    let profiles: [LatchProfile]
}

struct LatchProfile: Codable, Identifiable {
    let id: String
    let name: String
    let description: String
    let proxyGroupIds: [String]
    let ruleGroupId: String?
    let enabled: Bool
    let shareable: Bool
    let createdAt: Date
    let updatedAt: Date
    let proxies: [LatchProxy]
    let rule: LatchRule?
}

struct LatchProxy: Codable, Identifiable {
    let id: String
    let groupId: String
    let name: String
    let type: String              // "wireguard" etc.
    let config: [String: JSONValue]
    let country: String?          // emoji flag "🇯🇵" or ISO "JP"
    let sha1: String
    let version: Int
    let createdAt: Date
}

struct LatchRule: Codable, Identifiable {
    let id: String
    let groupId: String
    let name: String
    let content: String
    let sha1: String
    let version: Int
    let createdAt: Date
}

// MARK: - JSONValue (dynamic JSON dict for proxy config)

enum JSONValue: Codable, Equatable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let v = try? c.decode(String.self)            { self = .string(v); return }
        if let v = try? c.decode(Int.self)               { self = .int(v); return }
        if let v = try? c.decode(Double.self)             { self = .double(v); return }
        if let v = try? c.decode(Bool.self)              { self = .bool(v); return }
        if let v = try? c.decode([String: JSONValue].self) { self = .object(v); return }
        if let v = try? c.decode([JSONValue].self)        { self = .array(v); return }
        if c.decodeNil()                                  { self = .null; return }
        throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unsupported JSON value")
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let v):  try c.encode(v)
        case .int(let v):     try c.encode(v)
        case .double(let v):  try c.encode(v)
        case .bool(let v):    try c.encode(v)
        case .object(let v):  try c.encode(v)
        case .array(let v):   try c.encode(v)
        case .null:           try c.encodeNil()
        }
    }

    /// Coerce any JSON value to a flat string for wg-quick config lines.
    var asString: String? {
        switch self {
        case .string(let v):  return v
        case .int(let v):     return String(v)
        case .double(let v):  return String(v)
        case .bool(let v):    return v ? "true" : "false"
        default:              return nil
        }
    }
}

// MARK: - LatchProxy → wg-quick config converter

extension LatchProxy {
    /// Convert the proxy's JSON config dict into a wg-quick INI text that
    /// the WireGuardCore C library can parse. Uses standard WireGuard
    /// config key names directly (no mapping). Keys are categorized into
    /// [Interface] vs [Peer] by a known-key set; unknowns default to
    /// [Interface]. Returns nil if essential keys (PrivateKey + PublicKey)
    /// are missing — the caller should discard this proxy.
    func toWGQuickConfig() -> String? {
        let peerKeys: Set<String> = [
            "PublicKey", "Endpoint", "AllowedIPs", "PresharedKey",
            "PersistentKeepalive"
        ]

        var ifaceLines: [String] = []
        var peerLines: [String] = []

        for (key, value) in config {
            guard let strVal = value.asString else { continue }
            if peerKeys.contains(key) {
                peerLines.append("\(key) = \(strVal)")
            } else {
                ifaceLines.append("\(key) = \(strVal)")
            }
        }

        // Must have at least PrivateKey and PublicKey to be usable.
        let hasPrivate = ifaceLines.contains { $0.hasPrefix("PrivateKey") }
        let hasPublic  = peerLines.contains  { $0.hasPrefix("PublicKey") }
        guard hasPrivate && hasPublic else { return nil }

        var text = "[Interface]\n"
        text += ifaceLines.joined(separator: "\n")
        text += "\n\n[Peer]\n"
        text += peerLines.joined(separator: "\n")
        text += "\n"
        return text
    }
}

// MARK: - ISO8601 + fractional seconds decoder for Latch API dates

extension JSONDecoder {
    static let latchAPI: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        d.dateDecodingStrategy = .custom { decoder in
            let s = try decoder.singleValueContainer().decode(String.self)
            let fmtFrac = ISO8601DateFormatter()
            fmtFrac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let d = fmtFrac.date(from: s) { return d }
            let fmtPlain = ISO8601DateFormatter()
            fmtPlain.formatOptions = [.withInternetDateTime]
            if let d = fmtPlain.date(from: s) { return d }
            throw DecodingError.dataCorruptedError(
                in: try decoder.singleValueContainer(),
                debugDescription: "Cannot parse date: \(s)"
            )
        }
        return d
    }()
}
