import Foundation
import NetworkExtension
import Security
import AppKit
import OSLog

class Proxy {
    let bundleIdentifier = K.bundleIdentifier
    var fromRedirectorPipe: String? = nil
    var fromProxyPipe: String? = nil
    var process_match: String? = nil
    var appRules = [NEAppRule]()
    var processList = [String]()
    var logger = Logger()
    
    func startTunnel() async {
        do{
            let manager = await getManager()
            let session = manager.connection as? NETunnelProviderSession
            try session?.startTunnel(options: [:])
            try await Task.sleep(nanoseconds: UInt64(Double(NSEC_PER_SEC)))
            guard let fromRedirectorPipe = self.fromRedirectorPipe, let fromProxyPipe = self.fromProxyPipe else {
                logger.error("Pipes are not set")
                return
            }
            
            if let message = "\(fromRedirectorPipe) \(fromProxyPipe)".data(using: String.Encoding.utf8){
                try session?.sendProviderMessage(message)
            } else {
                logger.error("Problem encoding pipes")
            }
        } catch {
            logger.error("startTunnel error: \(error, privacy: .public)")
        }
    }

    func initVPNTunnelProviderManager() async {
        do {
            let savedManagers = try await NETunnelProviderManager.loadAllFromPreferences()
            let manager = savedManagers.first ?? NETunnelProviderManager.forPerAppVPN()
            try await manager.loadFromPreferences()
            let providerProtocol = NETunnelProviderProtocol()
            providerProtocol.providerBundleIdentifier = K.bundleIdentifier
            providerProtocol.providerConfiguration = ["server": K.serverAddress, "port": K.port]
            providerProtocol.serverAddress = K.serverAddress
            manager.protocolConfiguration = providerProtocol
            
            for identifier in processList{
                //at the moment this only blocks my terminal emulator (kitty).
                //This is because you can't create AppRule by PID but only by Identifier and we need to bypass the terminal to avoid loops.
                
                if identifier.contains("com.apple") || identifier.contains("net.kovidgoyal.kitty"){
                    continue
                }
                if let designatedRequirement = getDesignatedRequirement(for: identifier) {
                    self.appRules.append(NEAppRule(signingIdentifier: identifier, designatedRequirement: designatedRequirement))
                }
            }
            manager.localizedDescription = "Mitmproxy"
            manager.isEnabled = true
            manager.appRules = self.appRules
            try await manager.saveToPreferences()
        } catch {
            logger.error("initVPNTunnelProviderManager error: \(error, privacy: .public)")
        }
    }

    func getManager() async -> NETunnelProviderManager {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let tunnelManager = managers.first ?? NETunnelProviderManager.forPerAppVPN()
            return tunnelManager
        } catch {
            return NETunnelProviderManager.forPerAppVPN()
        }
    }
    
    func getRunningApplication(){
        let running = NSWorkspace.shared.runningApplications
        self.processList.removeAll()
        for process in running{
            if let identifier = process.bundleIdentifier{
                self.processList.append(identifier)
            }
        }
        if let process_match = self.process_match{
            self.processList = self.processList.filter { $0.contains(process_match) }
        }
    }

    func getDesignatedRequirement(for bundleIdentifier: String) -> String? {
        guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleIdentifier) else {
            return nil
        }
        var appSec: SecStaticCode?
        SecStaticCodeCreateWithPath(appURL as CFURL, [], &appSec)
        var requirement: SecRequirement?
        SecCodeCopyDesignatedRequirement(appSec!, [], &requirement)
        var requirementString: CFString?
        if SecRequirementCopyString(requirement!, [], &requirementString) == errSecSuccess {
            return requirementString! as String
        } else {
            return ""
        }
    }
    
    func clearPreferences() async{
        do {
            let manager = await getManager()
            try await manager.removeFromPreferences()
        } catch {
            logger.error("Problem while clearing preferences: \(error, privacy: .public)")
        }
    }
    
    func setPipePath(_ fromRedirectorPipe: String, _ fromProxyPipe: String){
        self.fromRedirectorPipe = fromRedirectorPipe
        self.fromProxyPipe = fromProxyPipe
    }
    
    func setProcessMatch(withString process: String) async{
        self.process_match = process
    }
    
    func interceptConf(){        
        while self.fromProxyPipe == nil {
            Thread.sleep(forTimeInterval: 0.1)
        }
        
        guard let pipe = self.fromProxyPipe else {
            return
        }
        
        guard let handler = FileHandle(forReadingAtPath: pipe) else {
            return
        }
        
        while true {
            guard let data = try? handler.read(upToCount: 8) else {
                continue
            }
            let length = UInt64(bigEndian: data.withUnsafeBytes { $0.load(as: UInt64.self) })
            
            guard let data = try? handler.read(upToCount: Int(length)),
                  let conf = try? Mitmproxy_Ipc_FromProxy(serializedData: data)
            else { continue }
                
            if !conf.interceptSpec.isEmpty{
                var interceptSpec = conf.interceptSpec
                var invert = false
                
                logger.debug("InterceptConf: \(interceptSpec, privacy: .public)")
                
                if interceptSpec.starts(with: "!"){
                    interceptSpec = String(interceptSpec.dropFirst())
                    invert = true
                }
                
                self.processList = processList.filter{ process in
                    invert ? !process.contains(interceptSpec) : process.contains(interceptSpec)
                }
            }
                
            Task{
                await clearPreferences()
                await self.initVPNTunnelProviderManager()
                await self.startTunnel()
            }
            break
        }
        
    }
    
}

