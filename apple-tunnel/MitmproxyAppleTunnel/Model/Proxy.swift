import Foundation
import NetworkExtension
import Security
import AppKit
import OSLog

class Proxy {
    let bundleIdentifier = K.bundleIdentifier
    var ipPipe: String? = nil
    var netPipe: String? = nil
    var process_match: String? = nil
    var appRules = [NEAppRule]()
    var processList = [String]()
    var mitmproxyIdentifier: [String] = [""]
    
    func startTunnel() async {
        do{
            let manager = await getManager()
            let session = manager.connection as? NETunnelProviderSession
            try session?.startTunnel(options: [:])
            try await Task.sleep(nanoseconds: UInt64(Double(NSEC_PER_SEC)))
            if let ipPipe = self.ipPipe, let netPipe = self.netPipe {
                if let message = "\(ipPipe) \(netPipe)".data(using: String.Encoding.utf8){
                    try session?.sendProviderMessage(message)
                    os_log("qqq - message with pipe path sent to provider: \(self.ipPipe!, privacy: .public)")
                } else {
                    os_log("qqq - problem encoding pipes")
                }
            } else {
                os_log("qqq - PROBLEM, ipPipe is \(self.ipPipe ?? "N/A", privacy: .public) and netPipe is : \(self.netPipe ?? "N/A", privacy: .public)")
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
            providerProtocol.providerConfiguration = ["server": K.serverAddress, "port": K.port]
            providerProtocol.serverAddress = K.serverAddress
            manager.protocolConfiguration = providerProtocol
            
            getRunningApplication()
            os_log("qqq - processlist: \(self.processList, privacy: .public)")
            for identifier in processList{
                //os_log("qqq - mitmproxy identifier: \(self.mitmproxyIdentifier, privacy: .public)")
                if self.mitmproxyIdentifier.contains(identifier){
                    continue
                }
                
                if identifier.contains("com.apple"){
                    continue
                }
                
                if let designatedRequirement = getDesignatedRequirement(for: identifier) {
                    //os_log("qqq - designated Requirement: \(designatedRequirement, privacy: .public)")
                    
                    self.appRules.append(NEAppRule(signingIdentifier: identifier, designatedRequirement: designatedRequirement))
                }
            }
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
        } catch {
            return NETunnelProviderManager.forPerAppVPN()
        }
    }
    
    func getRunningApplication(){
        let running = NSWorkspace.shared.runningApplications
        //os_log("qqq - running \(running, privacy: .public)")
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
    
    func setPipePath(ip: String, net: String){
        os_log("qqq - pipes set: \(ip, privacy: .public) and \(net, privacy: .public)")
        self.ipPipe = ip
        self.netPipe = net
    }
    
    func setProcessMatch(withString process: String) async{
        //os_log("qqq - process match set: \(process, privacy: .public)")
        self.process_match = process
    }
    
    func processToSkip(pid: String) async{
        self.mitmproxyIdentifier.append("net.kovidgoyal.kitty")
        // check this pid
        /*if let identifier = getIdentifierFrom(pid: pid){
            self.mitmproxyIdentifier?.append(identifier)
        } else {
            // check children
            let command = "ps -o ppid=\(pid)"
            if let childPids = await run(command) {
                for childPid in childPids.components(separatedBy: "\n"){
                    if let identifier = getIdentifierFrom(pid: childPid){
                        self.mitmproxyIdentifier?.append(identifier)
                    }
                }
            }
        }
         */
    }
    
    /*func getIdentifierFrom(pid: String) -> String?{
        let pid = pid_t(Int(pid) ?? 0)
        if let app = NSRunningApplication(processIdentifier: pid){
            return app.bundleIdentifier
        }
        return nil
    }
    
    func run(_ cmd: String) async -> String? {
        let task = Process()
        let pipe = Pipe()
        
        task.standardOutput = pipe
        task.standardError = pipe
        task.arguments = ["-c", cmd]
        task.launchPath = "/bin/zsh"
        task.standardInput = nil
        task.launch()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)!
        os_log("qqq - command output is \(output, privacy: .public)")

        return output
    }
     */
}

