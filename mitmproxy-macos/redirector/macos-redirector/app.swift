import NetworkExtension
import OSLog
import SwiftProtobuf
import SwiftUI
import SystemExtensions

let log = Logger(subsystem: "org.mitmproxy.macos-redirector", category: "app")
let networkExtensionIdentifier = "org.mitmproxy.macos-redirector.network-extension"

/// Helper app to install the system extension and setup the transaprent proxy.
@main
struct App {
    static func main() async throws {
        log.debug("app starting with \(CommandLine.arguments, privacy: .public)")
        
        if #unavailable(macOS 12.0) {
            exitModal("This application only works on macOS 12 or above.")
        }

        let unixSocketPath = CommandLine.arguments.last!
        if !unixSocketPath.starts(with: "/tmp/") {
            exitModal(
                "This helper application is used to redirect local traffic to your mitmproxy instance. It cannot be run standalone."
            )
        }

        try await SystemExtensionInstaller.run()
        try await startProxy(unixSocketPath: unixSocketPath)
    }
    
    static func exitModal(_ message: String) {
        let notification = NSAlert()
        notification.messageText = "Mitmproxy Redirector"
        notification.informativeText = message
        notification.runModal()
        exit(1)
    }
}

class SystemExtensionInstaller: NSObject, OSSystemExtensionRequestDelegate {
    
    static func run() async throws {

        let inst = SystemExtensionInstaller()

        try await withCheckedThrowingContinuation { continuation in

            inst.continuation = continuation

            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: networkExtensionIdentifier,
                queue: DispatchQueue.main
            )
            request.delegate = inst
            OSSystemExtensionManager.shared.submitRequest(request)
            log.debug("system extension request submitted")
        }

    }
    
    var continuation: CheckedContinuation<Void, Error>?

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        log.debug("requesting to replace existing network extension")
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        log.debug("requestNeedsUserApproval")
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        log.debug("system extension install failed: \(error)")
        continuation?.resume(throwing: error)
    }
    
    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        log.debug("system extension install succeeded: {} \(result.rawValue)")
        continuation?.resume()
    }
}

func startProxy(unixSocketPath: String) async throws {
    let savedManagers = try await NETransparentProxyManager.loadAllFromPreferences()
    let manager =
        savedManagers.first(where: { m in
            (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == networkExtensionIdentifier
                && (!m.isEnabled || m.connection.status != NEVPNStatus.connected)
        }) ?? NETransparentProxyManager()

    let providerProtocol = NETunnelProviderProtocol()
    providerProtocol.providerBundleIdentifier = networkExtensionIdentifier
    providerProtocol.serverAddress = unixSocketPath
    
    /*
    // NETransparentProxyManager does not support these properties and setting them causes silent failures.
    providerProtocol.includeAllNetworks = true
    providerProtocol.enforceRoutes = true
    providerProtocol.excludeLocalNetworks = false
    providerProtocol.excludeAPNs = false
    providerProtocol.excludeCellularServices = false
     */

    manager.protocolConfiguration = providerProtocol
    manager.localizedDescription = "mitmproxy"
    manager.isEnabled = true

    try await manager.saveToPreferences()
    // https://stackoverflow.com/a/47569982/934719 - we need to call load again before starting the tunnel.
    try await manager.loadFromPreferences()
    try manager.connection.startVPNTunnel()

    log.debug("VPN initialized.")
}
