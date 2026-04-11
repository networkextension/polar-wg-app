// SPDX-License-Identifier: MIT
//
// SwiftUI App entry point. Just opens the ContentView in a single
// window. The interesting code lives in TunnelManager.swift and
// the bundled WireGuardTunnelExtension target.

import SwiftUI

@main
struct WireGuardSampleApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 760, minHeight: 520)
        }
    }
}
