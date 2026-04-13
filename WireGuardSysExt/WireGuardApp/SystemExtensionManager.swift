// SystemExtensionManager.swift
//
// Handles the OSSystemExtensionRequest lifecycle:
//   1. Submit activation request for the tunnel sysext
//   2. Handle user-approval-needed callback
//   3. Handle replacement (upgrade) of existing extension
//   4. Report success / failure to the UI
//
// This is the key difference from the App Extension version: the
// host app must explicitly install the system extension before the
// NETunnelProviderManager can use it.

import Foundation
import SystemExtensions
import os.log

private let log = OSLog(subsystem: "com.change.wg.mac", category: "sysext")

@MainActor
final class SystemExtensionManager: NSObject, ObservableObject {

    static let extensionBundleID = "com.change.wg.mac.tunnel"

    enum Status: Equatable {
        case unknown
        case activating
        case needsUserApproval   // user must go to System Settings
        case activated
        case failed(String)
    }

    @Published var status: Status = .unknown

    func activate() {
        status = .activating
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        os_log("Submitted sysext activation request for %{public}@",
               log: log, Self.extensionBundleID)
    }

    func deactivate() {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }
}

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            switch result {
            case .completed:
                status = .activated
                os_log("System extension activated", log: log)
            case .willCompleteAfterReboot:
                status = .needsUserApproval
                os_log("System extension will complete after reboot", log: log)
            @unknown default:
                status = .failed("Unknown result: \(result)")
            }
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        Task { @MainActor in
            let msg = error.localizedDescription
            status = .failed(msg)
            os_log("System extension failed: %{public}@", log: log, type: .error, msg)
        }
    }

    nonisolated func requestNeedsUserApproval(
        _ request: OSSystemExtensionRequest
    ) {
        Task { @MainActor in
            status = .needsUserApproval
            os_log("System extension needs user approval in System Settings",
                   log: log, type: .info)
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        os_log("Replacing existing sysext (version %{public}@ → %{public}@)",
               log: log,
               existing.bundleShortVersion, ext.bundleShortVersion)
        return .replace
    }
}
