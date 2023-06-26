import Foundation
import NetworkExtension
import Security
import AppKit
import OSLog

class Proxy {
    let bundleIdentifier = K.bundleIdentifier
    var pipe_path: String? = nil
    var process_match: String? = nil
    var appRules = [NEAppRule]()
    var processList = [String]()
    
    func startTunnel() async {
        do{
            let manager = await getManager()
            let session = manager.connection as? NETunnelProviderSession
            try session?.startTunnel(options: [:])
            try await Task.sleep(nanoseconds: UInt64(Double(NSEC_PER_SEC)))
            if let message = self.pipe_path?.data(using: String.Encoding.utf8){
                try session?.sendProviderMessage(message)
                os_log("qqq - message with pipe path sent to provider: \(self.pipe_path!, privacy: .public)")
            } else {
                os_log("qqq - PROBLEM message with pipe path sent to provider")
            }
        } catch {
            print("error: \(error)")
        }
    }

    
    func initVPNTunnelProviderManager() async {
        do {
            let savedManagers = try await NETunnelProviderManager.loadAllFromPreferences()
            let manager = savedManagers.first ?? NETunnelProviderManager.forPerAppVPN()
            try await manager.loadFromPreferences()
            let providerProtocol = NETunnelProviderProtocol()
            providerProtocol.providerBundleIdentifier = K.bundleIdentifier
            providerProtocol.providerConfiguration = ["server": K.serverAddress]
            providerProtocol.serverAddress = K.serverAddress
            manager.protocolConfiguration = providerProtocol
            
            getRunningApplication()
            os_log("qqq - processlist: \(self.processList, privacy: .public)")
            for identifier in processList{
                if identifier.contains("com.apple"){
                    continue
                }
                if let designatedRequirement = getDesignatedRequirement(for: identifier) {
                    self.appRules.append(NEAppRule(signingIdentifier: identifier, designatedRequirement: designatedRequirement))
                }
            }
            os_log("qqq - app rules: \(self.appRules, privacy: .public)")
            manager.localizedDescription = "NEPacketTunnelVPNDemoConfig"
            manager.isEnabled = true
            manager.appRules = self.appRules
            
            try await manager.saveToPreferences()
        } catch {
            print(error)
        }
    }

    
    func getManager() async -> NETunnelProviderManager {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let tunnelManager = managers.first ?? NETunnelProviderManager.forPerAppVPN()
            return tunnelManager
        } catch let error1 {
            print("load error 1: %@", error1.localizedDescription)
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
            print("Could not find the application with bundle identifier: \(bundleIdentifier)")
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
            print("Failed to retrieve the designated requirement string.")
            return ""
        }
    }
    
    func clearPreferences() async{
        do {
            let manager = await getManager()
            try await manager.removeFromPreferences()
        } catch {
            print("error removing")
        }
    }
    
    func setPipePath(withPath path: String){
        os_log("qqq - path set: \(path, privacy: .public)")
        self.pipe_path = path
    }
    
    func setProcessMatch(withString process: String) async{
        os_log("qqq - process match set: \(process, privacy: .public)")
        self.process_match = process
    }
}

