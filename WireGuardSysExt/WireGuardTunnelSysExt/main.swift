// main.swift — System Extension entry point.
//
// Unlike an App Extension (.appex) which is loaded as a plugin by the
// host process, a System Extension (.systemextension) is a standalone
// executable managed by macOS. It needs an explicit main() that starts
// the NetworkExtension provider dispatch loop.
//
// NEProvider.startSystemExtensionMode() tells the NE framework to
// take over the run loop and dispatch incoming packets / provider
// messages to our PacketTunnelProvider subclass.

import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
