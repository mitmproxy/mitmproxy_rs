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
    var filterProcesses = [String]()
    var logger = Logger()
    var terminalPid = String()
    
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
    
    func setPipePath(_ fromRedirectorPipe: String, _ fromProxyPipe: String, _ terminalPid: String){
        self.fromRedirectorPipe = fromRedirectorPipe
        self.fromProxyPipe = fromProxyPipe
        self.terminalPid = terminalPid
    }
    
    func setProcessMatch(withString process: String) async{
        self.process_match = process
    }
    
    func createProcessList() {
        let running = NSWorkspace.shared.runningApplications
        let invertedFilters = self.filterProcesses.filter { $0.starts(with: "!") }.map { String($0.dropFirst()) }
        let normalFilters = self.filterProcesses.filter { !$0.starts(with: "!") }
        for process in running {
            let processIdentifier = String(process.processIdentifier)
            if let bundleIdentifier = process.bundleIdentifier,
               !bundleIdentifier.contains("com.apple"),
               processIdentifier != self.terminalPid {
                var shouldAddToList = true
                // Check inverted filters
                if invertedFilters.contains(where: { $0 == processIdentifier || $0 == bundleIdentifier }) {
                    shouldAddToList = false
                }
                // Check normal filters
                if shouldAddToList && !normalFilters.isEmpty {
                    shouldAddToList = normalFilters.contains(processIdentifier) || normalFilters.contains(bundleIdentifier)
                }
                if shouldAddToList {
                    logger.log("qqq - process \(bundleIdentifier, privacy: .public) added")
                    self.processList.append(bundleIdentifier)
                }
            }
        }
    }
    
    func interceptSpec(){
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
            
            self.filterProcesses.removeAll()
            logger.log("qqq - process removed <<<<<<<<<<<<<<<<<<<<<<<<<")
            conf.interceptSpec.split(separator: " ").forEach{ filter in
                self.filterProcesses.append(String(filter))
            }

            self.createProcessList()
                
            Task{
                await clearPreferences()
                await self.initVPNTunnelProviderManager()
                await self.startTunnel()
            }
            break
        }
        
    }
    
}

