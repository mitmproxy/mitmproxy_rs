import OSLog
import NetworkExtension
import SystemExtensions
import SwiftUI
import SwiftProtobuf

let log = Logger(subsystem: "org.mitmproxy.macos-redirector", category: "app")
let networkExtensionIdentifier = "org.mitmproxy.macos-redirector.network-extension"


@main
struct App {
    
    static func main() async throws {
        log.debug("app starting with \(CommandLine.arguments)")
        
        /*
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: networkExtensionIdentifier,
            queue: DispatchQueue.main
        )
        OSSystemExtensionManager.shared.submitRequest(request)
        try await Task.sleep(nanoseconds: 5_000_000_000)
         */
        
        try await SystemExtensionInstaller.run()
        let manager = try await startVPN()
        
        log.debug("reading...")
        
        while let message = try readIpcMessage(ofType: Mitmproxy_Ipc_InterceptSpec.self, fh: FileHandle.standardInput) {
            print("readMessage: \(message)")
            return
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


func startVPN() async throws -> NETunnelProviderManager {
    let savedManagers = try await NETunnelProviderManager.loadAllFromPreferences()
    for m in savedManagers {
        if (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == networkExtensionIdentifier {
            if !m.isEnabled {
                log.info("Cleaning up old VPN.")
                try await m.removeFromPreferences()
            }
        }
    }
    
    let manager = NETunnelProviderManager.forPerAppVPN()
    
    let providerProtocol = NETunnelProviderProtocol()
    providerProtocol.providerBundleIdentifier = networkExtensionIdentifier
    providerProtocol.providerConfiguration = ["server": "127.0.0.1", "port": 1234]
    providerProtocol.serverAddress = "127.0.0.1"
    
    manager.protocolConfiguration = providerProtocol
    manager.localizedDescription = "mitmproxy"
    manager.isEnabled = true
    
    /*
     TODO: do those from the extension?
     FIXME: not possible
    manager.appRules = [
        NEAppRule(signingIdentifier: "com.apple.curl", designatedRequirement: "(identifier \"com.apple.curl\") and (anchor apple)")
    ]
     */
    manager.appRules = [
        NEAppRule(signingIdentifier: "com.apple.curl", designatedRequirement: "identifier exists")
    ]
    
    try await manager.saveToPreferences()
    // https://stackoverflow.com/a/47569982/934719 - we need to call load again before starting the tunnel.
    try await manager.loadFromPreferences()
    try manager.connection.startVPNTunnel()
    
    log.debug("VPN initialized.")
    return manager
}


