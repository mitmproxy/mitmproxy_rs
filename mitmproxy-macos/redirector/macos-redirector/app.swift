import OSLog
import NetworkExtension
import SystemExtensions
import SwiftUI
import SwiftProtobuf

let log = Logger(subsystem: "org.mitmproxy.macos-redirector", category: "app")
let networkExtensionIdentifier = "org.mitmproxy.macos-redirector.network-extension"
/* a designated requirement that matches all apps. */
let designatedRequirementWildcard = "identifier exists"

@main
struct App {
    
    static func main() async throws {
        log.debug("app starting with \(CommandLine.arguments, privacy: .public)")
        
        let pipeBase = CommandLine.arguments.last!;
        if !pipeBase.starts(with: "/tmp/") {
            let notification = NSAlert()
            notification.messageText = "Mitmproxy Redirector"
            notification.informativeText = "This helper application is used to redirect local traffic to your mitmproxy instance. It cannot be run standalone.";
            notification.runModal()
            return;
        }
        
        try await SystemExtensionInstaller.run()
        let manager = try await startVPN(pipeBase: pipeBase)
        
        log.debug("reading...")
        while let spec = try readIpcMessage(ofType: Mitmproxy_Ipc_InterceptSpec.self, fh: FileHandle.standardInput) {
            
            log.debug("received intercept spec: \(spec.spec, privacy: .public)")
            guard !spec.spec.starts(with: "!") else {
                log.error("inverse specs are not implemented yet.")
                continue
            }
            let bundleIds = spec.spec.split(separator: ",");
            manager.appRules = bundleIds.map({
                NEAppRule(signingIdentifier: String($0), designatedRequirement: designatedRequirementWildcard)
            });
            try await manager.saveToPreferences()
            
        }
        
        log.debug("exiting...")
        try await manager.removeFromPreferences()
    }
}

class SystemExtensionInstaller: NSObject, OSSystemExtensionRequestDelegate {
    var continuation: CheckedContinuation<Void, Error>?
    
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
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
    
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        log.debug("system extension install succeeded: {} \(result.rawValue)")
        continuation?.resume()
    }
    
    static func run() async throws {
        
        let inst = SystemExtensionInstaller();
        
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
}


func startVPN(pipeBase: String) async throws -> NETunnelProviderManager {
    let savedManagers = try await NETunnelProviderManager.loadAllFromPreferences()
    for m in savedManagers {
        if (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == networkExtensionIdentifier {
            if !m.isEnabled || m.connection.status != NEVPNStatus.connected {
                log.info("Cleaning up old VPN.")
                try await m.removeFromPreferences()
            }
        }
    }
    
    let manager = NETunnelProviderManager.forPerAppVPN()
    
    let providerProtocol = NETunnelProviderProtocol()
    providerProtocol.providerBundleIdentifier = networkExtensionIdentifier
    providerProtocol.serverAddress = pipeBase
    
    // XXX: it's unclear if these are actually necessary for per-app VPNs
    providerProtocol.enforceRoutes = true
    providerProtocol.includeAllNetworks = true
    providerProtocol.excludeLocalNetworks = false
    /*
     XXX: This somehow does not compile on GHA
    if #available(macOS 13.3, *) {
        providerProtocol.excludeAPNs = false
        providerProtocol.excludeCellularServices = false
    }
    */
    
    manager.protocolConfiguration = providerProtocol
    manager.localizedDescription = "mitmproxy"
    manager.isEnabled = true
    manager.appRules = []
    
    try await manager.saveToPreferences()
    // https://stackoverflow.com/a/47569982/934719 - we need to call load again before starting the tunnel.
    try await manager.loadFromPreferences()
    try manager.connection.startVPNTunnel()
    
    log.debug("VPN initialized.")
    return manager
}


