// swift-tools-version: 6.0
import PackageDescription

// wg-agent — Swift-only device-side reconciler. See doc/wg-agent-swift-design.md.
//
// Layering rule: WGAgentCore is pure logic with ZERO I/O and zero platform
// branches, so the same tests run on every target. Everything that touches the
// host lives behind the protocols in WGPlatform.
let package = Package(
    name: "WGAgent",
    platforms: [.macOS(.v13)],
    targets: [
        .target(name: "WGAgentCore"),
        .target(name: "WGPlatform", dependencies: ["WGAgentCore"]),
        .testTarget(name: "WGAgentCoreTests", dependencies: ["WGAgentCore"]),
        .testTarget(name: "WGPlatformTests", dependencies: ["WGPlatform"]),
    ]
)
