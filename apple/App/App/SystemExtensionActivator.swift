#if SBR_SYSTEM_EXTENSION
import Foundation
import SbrKit
import SystemExtensions

/// macOS Developer ID builds ship the tunnel as a system extension, which
/// must be activated (and approved by the user in System Settings) before
/// the VPN profile can use it. Activating an already active extension is a
/// cheap no-op.
@MainActor
final class SystemExtensionActivator: NSObject, OSSystemExtensionRequestDelegate {
    /// A request waiting for the user's approval. It stays submitted, and
    /// finishes by itself once they allow it, so another is not submitted.
    private static var pending: SystemExtensionActivator?
    private static var inFlight: Task<Void, Error>?
    private var continuation: CheckedContinuation<Void, Error>?

    static let approvalNeeded = SbrError("allow sbr's network extension in System Settings, then connect again")

    /// Called whenever `awaitingApproval` changes, including when the user
    /// allows the extension long after the request that asked.
    static var approvalChanged: (() -> Void)?
    static var awaitingApproval: Bool { pending != nil }

    static func activate(identifier: String) async throws {
        if pending != nil { throw approvalNeeded }
        if let inFlight { return try await inFlight.value }
        let task = Task { try await submit(identifier: identifier) }
        inFlight = task
        defer { inFlight = nil }
        try await task.value
    }

    private static func submit(identifier: String) async throws {
        let activator = SystemExtensionActivator()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            activator.continuation = cont
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            request.delegate = activator
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    private func finish(_ result: Result<Void, Error>) {
        if Self.pending === self {
            Self.pending = nil
            Self.approvalChanged?()
        }
        continuation?.resume(with: result)
        continuation = nil
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        MainActor.assumeIsolated {
            Self.pending = self
            Self.approvalChanged?()
            continuation?.resume(throwing: Self.approvalNeeded)
            continuation = nil
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        MainActor.assumeIsolated { finish(.success(())) }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        MainActor.assumeIsolated { finish(.failure(error)) }
    }
}
#endif
