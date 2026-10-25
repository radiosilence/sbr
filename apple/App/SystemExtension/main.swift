// Entry point of the macOS system-extension flavour of the tunnel. The
// app-extension flavour has no main: NetworkExtension loads the principal
// class itself.
import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
