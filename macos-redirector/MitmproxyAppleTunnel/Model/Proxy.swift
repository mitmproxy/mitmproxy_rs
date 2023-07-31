import Foundation
import NetworkExtension
import Security
import AppKit
import OSLog

class Proxy {
    let bundleIdentifier = K.bundleIdentifier
    var ipPipe: String? = nil
    var netPipe: String? = nil
    var filterPipe: String? = nil
    var process_match: String? = nil
    var appRules = [NEAppRule]()
    var processList = [String]()
    
    func startTunnel() async {
        do{
            let manager = await getManager()
            let session = manager.connection as? NETunnelProviderSession
            try session?.startTunnel(options: [:])
            try await Task.sleep(nanoseconds: UInt64(Double(NSEC_PER_SEC)))
            if let ipPipe = self.ipPipe, let netPipe = self.netPipe {
                if let message = "\(ipPipe) \(netPipe)".data(using: String.Encoding.utf8){
                    try session?.sendProviderMessage(message)
                } else {
                    os_log("Problem encoding pipes")
                }
            } else {
                os_log("IpPipe or NetPipe are not set")
            }
        } catch {
            os_log("Error: \(error, privacy: .public)")
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
                //at the moment this sucks and only blocks my terminal emulator (kitty).
                //This is because you can't create AppRule by PID but only by Identifier and we need to bypass the terminal to avoid loops.
                //
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
            os_log("Error: \(error, privacy: .public)")
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
            os_log("Error: \(error, privacy: .public)")
        }
    }
    
    func setPipePath(ip: String, net: String, filter: String){
        self.ipPipe = ip
        self.netPipe = net
        self.filterPipe = filter
    }
    
    func setProcessMatch(withString process: String) async{
        self.process_match = process
    }
    
    func interceptConf(){
        if let pipe = self.filterPipe{
            let handler = FileHandle(forReadingAtPath: pipe)
            while true {
                if let data = handler?.availableData{
                    let _conf = self.deserializeConf(data: data)
                    if let conf = _conf {
                        if conf.processNames.count > 0{
                            self.processList = processList.filter{ process in
                                conf.invert ? !conf.processNames.contains { process.contains($0) } : conf.processNames.contains { process.contains($0) }
                            }
                        }
                        Task.init{
                            await clearPreferences()
                            await self.initVPNTunnelProviderManager()
                            await self.startTunnel()
                        }
                    }
                }
            }
        } else {
            interceptConf()
        }
    }
    
    func deserializeConf(data: Data) -> Mitmproxy_Ipc_InterceptConf? {
        do {
            return try Mitmproxy_Ipc_InterceptConf(serializedData: data)
        } catch {
            os_log("Error: \(error)")
            return nil
        }
    }
    
}

