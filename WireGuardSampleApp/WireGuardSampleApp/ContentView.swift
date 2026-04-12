// SPDX-License-Identifier: MIT
//
// ContentView.swift
//
// VPN client UI matching the "WireGuard VPN Config Redesign" mockup:
//   - Tab 1 (Connection): hero server card with big Connect button,
//     server list, latency dots
//   - Tab 2 (Servers): full config editor, route mode, UAPI status
//
// Preserves all existing TunnelManager functionality (multi-profile,
// keychain persistence, auth, route modes, UAPI GET/SET demos).

import SwiftUI
import NetworkExtension
#if canImport(AppKit)
import AppKit
#endif
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Root

struct ContentView: View {
    @StateObject private var manager = TunnelManager()

    @State private var statusText: String = ""
    @State private var statusTimer: Timer?

    // Auth fields
    @State private var username = ""
    @State private var email = ""
    @State private var password = ""
    @State private var isRegisterMode = false
    @State private var isAuthLoading = false
    @State private var apiBaseURL: String = UserDefaults.standard.string(forKey: "api_base_url") ?? ""

    // Tab
    @State private var selectedTab: AppTab = .connection

    // Validation alerts
    @State private var showValidationAlert = false
    @State private var validationMessage = ""

    enum AppTab: Hashable {
        case connection, servers
    }

    var body: some View {
        ZStack {
            bgGradient.ignoresSafeArea()

            if !manager.isLoaded {
                loadingView
            } else if !manager.isAuthenticated {
                loginView
            } else {
                mainTabs
            }
        }
        .task {
            await manager.load()
            statusTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
                Task { @MainActor in await refreshStatus() }
            }
        }
        .onDisappear { statusTimer?.invalidate() }
        .alert("Config Validation", isPresented: $showValidationAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(validationMessage)
        }
    }

    // MARK: - Background

    private var bgGradient: some View {
        LinearGradient(
            colors: [Color.blue.opacity(0.06), bgColor],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    // MARK: - Loading

    private var loadingView: some View {
        VStack(spacing: 14) {
            Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                .font(.system(size: 44))
                .foregroundStyle(.blue)
            Text("Loading profiles...")
                .font(.headline)
            ProgressView().controlSize(.large)
        }
        .frame(maxWidth: 340)
        .padding(24)
        .cardStyle()
    }

    // MARK: - Tabs

    private var mainTabs: some View {
        #if os(macOS)
        // macOS: sidebar navigation (standard Mac pattern)
        NavigationSplitView {
            List(selection: $selectedTab) {
                Label("Connection", systemImage: "shield.checkered")
                    .tag(AppTab.connection)
                Label("Servers", systemImage: "server.rack")
                    .tag(AppTab.servers)
            }
            .listStyle(.sidebar)
            .navigationTitle("WireGuard")
        } detail: {
            Group {
                switch selectedTab {
                case .connection: connectionTab
                case .servers:    serversTab
                }
            }
        }
        .navigationSplitViewColumnWidth(min: 160, ideal: 200, max: 260)
        #else
        // iPhone / iPad: bottom tab bar (standard iOS pattern)
        TabView(selection: $selectedTab) {
            connectionTab
                .tabItem {
                    Label("Connection", systemImage: "shield.checkered")
                }
                .tag(AppTab.connection)

            serversTab
                .tabItem {
                    Label("Servers", systemImage: "server.rack")
                }
                .tag(AppTab.servers)
        }
        #endif
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // MARK: - Tab 1: Connection
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    private var connectionTab: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Title
                VStack(spacing: 4) {
                    Text("Connect to VPN")
                        .font(.title.bold())
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text("Secure and fast WireGuard VPN")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                // Hero card — selected server
                heroServerCard

                // Server list
                serverListSection

                // Footer
                if let err = manager.lastError {
                    Label(err, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                }

                Text("Last updated a few seconds ago")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            .padding(16)
        }
    }

    private var heroServerCard: some View {
        let profile = manager.profiles.first(where: { $0.id == manager.selectedProfileID })
        let name = profile?.name ?? "No Node"
        let flag = (profile?.country.isEmpty == false) ? profile!.country : flagEmoji(for: name)
        let isConnected = manager.status == .connected
        let isConnecting = manager.status == .connecting || manager.status == .reasserting

        return VStack(spacing: 16) {
            HStack(spacing: 14) {
                // Flag
                Text(flag)
                    .font(.system(size: 36))
                    .frame(width: 48, height: 48)
                    .background(Color.secondary.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))

                VStack(alignment: .leading, spacing: 3) {
                    Text(name)
                        .font(.title3.bold())
                    HStack(spacing: 6) {
                        Circle()
                            .fill(isConnected ? .green : .gray)
                            .frame(width: 8, height: 8)
                        Text(isConnected ? "Latency: -" : "")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Spacer()

                // Status badge
                HStack(spacing: 5) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 8, height: 8)
                    Text(manager.status.displayString.capitalized)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(statusColor)
                }
            }

            // Big connect / disconnect button
            Button {
                if isConnected || isConnecting {
                    manager.stop()
                } else {
                    // Validate before connecting
                    let node = manager.profiles.first { $0.id == manager.selectedProfileID }
                    let result = WGConfigValidator.validateForConnect(node)
                    if result.isValid {
                        Task { await manager.saveCurrentProfile() }
                        manager.start()
                    } else {
                        validationMessage = result.errorSummary
                        showValidationAlert = true
                    }
                }
            } label: {
                Text(isConnected ? "Disconnect" : isConnecting ? "Connecting..." : "Connect")
                    .font(.headline)
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 48)
                    .background(
                        isConnected ? Color.red :
                        isConnecting ? Color.orange : Color.blue
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            }
            .buttonStyle(.plain)
        }
        .padding(16)
        .cardStyle()
    }

    private var serverListSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Nodes")
                .font(.headline)

            // Platform nodes
            if !manager.platformNodes.isEmpty {
                HStack {
                    Text("Platform")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        Task { await manager.syncFromPlatform() }
                    } label: {
                        HStack(spacing: 4) {
                            if manager.isSyncing {
                                ProgressView().controlSize(.mini)
                            } else {
                                Image(systemName: "arrow.triangle.2.circlepath")
                            }
                            Text("Sync")
                        }
                        .font(.caption)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.mini)
                    .disabled(manager.isSyncing)
                }
                .padding(.leading, 4)

                ForEach(manager.platformNodes) { node in
                    nodeRow(node: node)
                }
            } else {
                // Show sync button even if no platform nodes yet
                Button {
                    Task { await manager.syncFromPlatform() }
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "arrow.triangle.2.circlepath")
                            .font(.title3)
                            .foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Sync from Platform")
                                .font(.body.weight(.medium))
                            Text("Pull nodes from your Latch account")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if manager.isSyncing {
                            ProgressView().controlSize(.small)
                        }
                    }
                    .padding(14)
                    .cardStyle()
                }
                .buttonStyle(.plain)
                .disabled(manager.isSyncing)
            }

            // Manual nodes
            if !manager.manualNodes.isEmpty {
                Text("Manual")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.leading, 4)

                ForEach(manager.manualNodes) { node in
                    nodeRow(node: node)
                }
            }

            // Add node (manual)
            Button {
                manager.addProfile()
                selectedTab = .servers
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: "plus.circle.fill")
                        .font(.title3)
                        .foregroundStyle(.blue)
                    Text("Add Node")
                        .font(.body.weight(.medium))
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
                .padding(14)
                .cardStyle()
            }
            .buttonStyle(.plain)
        }
    }

    private func nodeRow(node: VPNNode) -> some View {
        let isSelected = node.id == manager.selectedProfileID
        let isActive = isSelected && manager.status == .connected
        let flag = node.country.isEmpty ? flagEmoji(for: node.name) : node.country

        return Button {
            manager.selectProfile(node.id)
        } label: {
            HStack(spacing: 12) {
                Text(flag)
                    .font(.title3)
                    .frame(width: 36, height: 36)
                    .background(Color.secondary.opacity(0.06))
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 4) {
                        Text(node.name)
                            .font(.body.weight(.medium))
                            .foregroundStyle(.primary)
                        if node.source == .platform {
                            Image(systemName: "lock.fill")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Text(isActive ? "Connected" :
                         isSelected ? "Selected" :
                         node.source == .platform ? "Platform" : "Manual")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if isActive {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else if isSelected {
                    Image(systemName: "checkmark.circle")
                        .foregroundStyle(.blue)
                }

                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(14)
            .background(
                isSelected ? Color.blue.opacity(0.06) : Color.secondary.opacity(0.04)
            )
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(isSelected ? Color.blue.opacity(0.2) : Color.clear, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // MARK: - Tab 2: Servers (config editor + settings + UAPI)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    private var selectedNodeIsPlatform: Bool {
        guard let id = manager.selectedProfileID,
              let node = manager.profiles.first(where: { $0.id == id }) else {
            return false
        }
        return node.source == .platform
    }

    private var serversTab: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Node picker + rename
                serverEditorHeader

                // Platform node notice
                if selectedNodeIsPlatform {
                    HStack(spacing: 8) {
                        Image(systemName: "lock.shield.fill")
                            .foregroundStyle(.blue)
                        Text("Platform node — config is managed remotely and hidden for security.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(12)
                    .cardStyle()
                }

                // Route mode (both manual + platform)
                routeModeSection

                // Config editor — only for manual nodes
                if !selectedNodeIsPlatform {
                    configEditorSection
                }

                // Save / Connect / Disconnect
                HStack {
                    Button("Save") {
                        // Validate config before saving (manual nodes only)
                        if !selectedNodeIsPlatform {
                            let result = WGConfigValidator.validate(manager.configText)
                            if !result.isValid {
                                validationMessage = result.errorSummary
                                showValidationAlert = true
                                return
                            }
                        }
                        Task { await manager.saveCurrentProfile() }
                    }
                    .buttonStyle(.borderedProminent)

                    Button("Connect") {
                        let node = manager.profiles.first { $0.id == manager.selectedProfileID }
                        let result = WGConfigValidator.validateForConnect(node)
                        if result.isValid {
                            Task { await manager.saveCurrentProfile() }
                            manager.start()
                        } else {
                            validationMessage = result.errorSummary
                            showValidationAlert = true
                        }
                    }
                    .disabled(manager.status == .connected || manager.status == .connecting)

                    Button("Disconnect") { manager.stop() }
                        .disabled(manager.status != .connected && manager.status != .connecting)
                }
                .controlSize(.small)
                .cardStyle()

                // UAPI status
                uapiStatusSection

                // Actions
                actionsSection

                // Logout
                Button("Logout", role: .destructive) { manager.logoutUser() }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            }
            .padding(16)
        }
    }

    private var serverEditorHeader: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Node Settings")
                .font(.title2.bold())

            HStack(spacing: 8) {
                Picker("Node", selection: Binding(
                    get: { manager.selectedProfileID ?? manager.profiles.first?.id ?? UUID() },
                    set: { manager.selectProfile($0) }
                )) {
                    ForEach(manager.profiles) { p in
                        Text(p.name).tag(p.id)
                    }
                }
                .labelsHidden()

                TextField("Name", text: Binding(
                    get: { manager.selectedProfileName },
                    set: { manager.selectedProfileName = $0 }
                ))
                .textFieldStyle(.roundedBorder)
            }

            HStack(spacing: 8) {
                Button { manager.addProfile() } label: {
                    Label("New Node", systemImage: "plus")
                }
                Button { manager.deleteSelectedProfile() } label: {
                    Label("Delete", systemImage: "trash")
                }
                .disabled(manager.profiles.count <= 1 || selectedNodeIsPlatform)

                Spacer()

                // Storage mode
                Picker("Storage", selection: Binding(
                    get: { manager.storageMode },
                    set: { manager.setStorageMode($0) }
                )) {
                    ForEach(ProfileStorageMode.allCases) { m in
                        Text(m.title).tag(m)
                    }
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 200)
            }
            .controlSize(.small)
        }
        .cardStyle()
    }

    private var routeModeSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Routing", systemImage: "arrow.triangle.branch")
                .font(.subheadline.weight(.semibold))

            Picker("", selection: $manager.routeMode) {
                ForEach(RouteMode.allCases) { m in
                    Text(m.title).tag(m)
                }
            }
            .pickerStyle(.segmented)

            if manager.routeMode == .split {
                TextEditor(text: $manager.splitInjectedRoutes)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 60, maxHeight: 100)
                    .padding(6)
                    .background(textBg)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                Text("CIDRs: 10.10.0.0/16, 172.16.203.0/24")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .cardStyle()
    }

    private var configEditorSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("wg-quick config", systemImage: "doc.text")
                .font(.subheadline.weight(.semibold))
            TextEditor(text: $manager.configText)
                .font(.system(.caption, design: .monospaced))
                .frame(minHeight: 160)
                .padding(6)
                .background(textBg)
                .clipShape(RoundedRectangle(cornerRadius: 8))

            HStack {
                Button("Save config") { Task { await manager.saveCurrentProfile() } }
                    .buttonStyle(.borderedProminent)
                Button("Connect") { manager.start() }
                    .disabled(manager.status == .connected || manager.status == .connecting)
                Button("Disconnect") { manager.stop() }
                    .disabled(manager.status != .connected && manager.status != .connecting)
            }
            .controlSize(.small)
        }
        .cardStyle()
    }

    private var uapiStatusSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("UAPI Status", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Button("Refresh") { Task { await refreshStatus() } }
                    .controlSize(.mini)
                    .disabled(manager.status != .connected)
                Button { copyToClipboard(statusText) } label: {
                    Image(systemName: "doc.on.doc")
                }
                .controlSize(.mini)
            }
            ScrollView {
                Text(statusText.isEmpty ? "(not connected)" : statusText)
                    .font(.system(.caption2, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(6)
            }
            .frame(minHeight: 100, maxHeight: 180)
            .background(textBg)
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
        .cardStyle()
    }

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("UAPI Demos", systemImage: "wrench.and.screwdriver")
                .font(.subheadline.weight(.semibold))

            HStack(spacing: 6) {
                Button("Roam EP") { Task { await sendDemoSet(setEndpointDemo) } }
                Button("Keepalive=15") { Task { await sendDemoSet(setKeepaliveDemo) } }
                Button("Add Peer") { Task { await sendDemoSet(addPeerDemo) } }
                Button("Rm Peer") { Task { await sendDemoSet(removePeerDemo) } }
            }
            .controlSize(.mini)
            .buttonStyle(.bordered)
            .disabled(manager.status != .connected)
        }
        .cardStyle()
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // MARK: - Login
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    private var loginView: some View {
        ScrollView {
            VStack(spacing: 16) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 44))
                    .foregroundStyle(.blue)
                Text("Login Required")
                    .font(.title3.bold())
                Text("Register or login to use the VPN.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                Picker("Mode", selection: $isRegisterMode) {
                    Text("Login").tag(false)
                    Text("Register").tag(true)
                }
                .pickerStyle(.segmented)

                if isRegisterMode {
                    TextField("Username", text: $username)
                        .textFieldStyle(.roundedBorder)
                        #if !os(macOS)
                        .textInputAutocapitalization(.never)
                        #endif
                        .autocorrectionDisabled()
                }
                TextField("Email", text: $email)
                    .textFieldStyle(.roundedBorder)
                    #if !os(macOS)
                    .textInputAutocapitalization(.never)
                    #endif
                    .autocorrectionDisabled()
                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                TextField("API Base URL", text: $apiBaseURL)
                    .textFieldStyle(.roundedBorder)
                    #if !os(macOS)
                    .textInputAutocapitalization(.never)
                    #endif
                    .autocorrectionDisabled()

                if let info = manager.authInfo {
                    Text(info).font(.caption).foregroundStyle(.secondary)
                }
                if let err = manager.authError {
                    Text(err).font(.caption).foregroundStyle(.red)
                }

                Button {
                    Task {
                        isAuthLoading = true
                        if isRegisterMode {
                            await manager.register(username: username, email: email,
                                                   password: password, apiBaseURL: apiBaseURL)
                        } else {
                            await manager.login(email: email, password: password,
                                                apiBaseURL: apiBaseURL)
                        }
                        isAuthLoading = false
                    }
                } label: {
                    Group {
                        if isAuthLoading { ProgressView() }
                        else { Text(isRegisterMode ? "Register" : "Login") }
                    }
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                }
                .buttonStyle(.borderedProminent)
                .disabled(isAuthLoading || apiBaseURL.isEmpty || email.isEmpty || password.isEmpty
                          || (isRegisterMode && username.isEmpty))

                Divider()

                Button {
                    manager.skipLogin()
                } label: {
                    Text("Skip — use without account")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .tint(.secondary)
            }
            .frame(maxWidth: 400)
            .padding(20)
            .cardStyle()
            .padding(16)
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // MARK: - Helpers
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    private var bgColor: Color {
        #if os(macOS)
        Color(nsColor: .windowBackgroundColor)
        #else
        Color(uiColor: .systemBackground)
        #endif
    }

    private var statusColor: Color {
        switch manager.status {
        case .connected:                return .green
        case .connecting, .reasserting: return .yellow
        case .disconnecting:            return .orange
        default:                        return .red
        }
    }

    private var textBg: Color {
        #if os(macOS)
        Color(nsColor: .textBackgroundColor)
        #else
        Color(uiColor: .secondarySystemBackground)
        #endif
    }

    private func refreshStatus() async {
        guard manager.status == .connected else {
            statusText = ""
            return
        }
        statusText = await manager.uapiGet() ?? "(no response)"
    }

    private func sendDemoSet(_ body: String) async {
        let resp = await manager.uapiSet(body) ?? "(no response)"
        statusText = "── SET response ──\n" + resp + "\n\n" + statusText
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

// MARK: - Flag emoji guesser

private func flagEmoji(for serverName: String) -> String {
    let low = serverName.lowercased()
    let map: [(String, String)] = [
        ("tokyo", "🇯🇵"), ("japan", "🇯🇵"), ("jp", "🇯🇵"),
        ("us", "🇺🇸"), ("united states", "🇺🇸"), ("america", "🇺🇸"),
        ("london", "🇬🇧"), ("uk", "🇬🇧"), ("england", "🇬🇧"),
        ("frankfurt", "🇩🇪"), ("germany", "🇩🇪"), ("de", "🇩🇪"),
        ("singapore", "🇸🇬"), ("sg", "🇸🇬"),
        ("sydney", "🇦🇺"), ("australia", "🇦🇺"), ("au", "🇦🇺"),
        ("canada", "🇨🇦"), ("toronto", "🇨🇦"), ("ca", "🇨🇦"),
        ("korea", "🇰🇷"), ("seoul", "🇰🇷"), ("kr", "🇰🇷"),
        ("hong kong", "🇭🇰"), ("hk", "🇭🇰"),
        ("india", "🇮🇳"), ("mumbai", "🇮🇳"),
        ("brazil", "🇧🇷"), ("sao paulo", "🇧🇷"),
        ("france", "🇫🇷"), ("paris", "🇫🇷"),
        ("home", "🏠"), ("local", "🏠"), ("dev", "🛠"),
    ]
    for (keyword, emoji) in map {
        if low.contains(keyword) { return emoji }
    }
    return "🌐"
}

// MARK: - Card modifier

private extension View {
    func cardStyle() -> some View {
        self
            .padding(14)
            .background(.regularMaterial)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .shadow(color: .black.opacity(0.04), radius: 6, y: 2)
    }
}

// MARK: - UAPI demo blobs

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

private let defaultPeerHex =
    "5d71736e30e59f4db2fda59fa36445559fdfa22302fcd128f502970dd93d4979"
private let demoNewPeerHex =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

private var setEndpointDemo: String {
    "set=1\npublic_key=\(defaultPeerHex)\nendpoint=192.0.2.5:51820\n\n"
}
private var setKeepaliveDemo: String {
    "set=1\npublic_key=\(defaultPeerHex)\npersistent_keepalive_interval=15\n\n"
}
private var addPeerDemo: String {
    "set=1\npublic_key=\(demoNewPeerHex)\nendpoint=198.51.100.1:51820\nallowed_ip=10.99.0.0/24\npersistent_keepalive_interval=25\n\n"
}
private var removePeerDemo: String {
    "set=1\npublic_key=\(demoNewPeerHex)\nremove=true\n\n"
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
