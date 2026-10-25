#if SBR_SYSTEM_EXTENSION
import Foundation
import SystemExtensions

/// macOS Developer ID builds ship the tunnel as a system extension, which
/// must be activated (and approved by the user in System Settings) before
/// the VPN profile can use it. Activating an already active extension is a
/// cheap no-op.
final class SystemExtensionActivator: NSObject, OSSystemExtensionRequestDelegate {
    private var continuation: CheckedContinuation<Void, Error>?

    static func activate(identifier: String) async throws {
        let activator = SystemExtensionActivator()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            activator.continuation = cont
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            request.delegate = activator
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // Stays pending until the user allows it in System Settings › Privacy & Security.
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        continuation?.resume()
        continuation = nil
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}
#endif
