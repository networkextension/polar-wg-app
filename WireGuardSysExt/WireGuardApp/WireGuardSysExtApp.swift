import SwiftUI

@main
struct WireGuardSysExtApp: App {
    var body: some Scene {
        WindowGroup {
            SysExtContentView()
                .frame(minWidth: 700, minHeight: 500)
        }
    }
}
