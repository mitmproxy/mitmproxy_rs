import OSLog
import NetworkExtension
import SystemExtensions
import SwiftUI

let log = Logger(subsystem: "org.mitmproxy.macos-redirector", category: "app")
let networkExtensionIdentifier = "org.mitmproxy.macos-redirector.network-extension"


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

func readMessage(fh: FileHandle) throws -> Data? {
    guard let len_buf = (try FileHandle.standardInput.read(upToCount: 8)) else { return nil }
    guard len_buf.count == 8 else { return nil }
    let len = len_buf[...].reduce(Int(0)) { $0 << 8 + Int($1) };
    
    return try FileHandle.standardInput.read(upToCount: len);
}

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
        try await App().initVPN()
        
        log.debug("reading...")
        
        //Mitmproxy_Ipc_FromProxy(contiguousBytes: readMessage(fh: FileHandle.standardInput))
        
        return
        
        /*
        readExact(fh: FileHandle.standardInput, count: 4)
        
        Mitmproxy_Ipc_FromProxy(contiguousBytes: data)*/
        
        //InputStream
        
        //FileHandle//.standardInput.
        
        /*for try await line in readLine() {
            Mitmproxy_Ipc_FromRedirector
            print("line")
        }*/
        
        log.debug("exiting")
        
    }
    
    func initVPN() async throws {
        
        let savedManagers = try await NETunnelProviderManager.loadAllFromPreferences()
        for m in savedManagers {
            if (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == networkExtensionIdentifier {
                // FIXME reenable
                //if !m.isEnabled {
                    log.info("Cleaning up old VPN.")
                    try await m.removeFromPreferences()
                //}
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
        try await manager.saveToPreferences()
        // https://stackoverflow.com/a/47569982/934719 - we need to call load again before starting the tunnel.
        try await manager.loadFromPreferences()
        try manager.connection.startVPNTunnel()
        
        log.debug("VPN initialized.")
    }
}

