import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    
    var t: Task<Void, Error>?

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        log.debug("startTunnel options=\(String(describing:options), privacy: .public)")
                
        self.t = Task {
            
            log.debug("setting network settings")
            
            // TODO: All untested.
            let tunnelNetworkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.1.1.1")
            let ipv4Settings = NEIPv4Settings(addresses: ["192.168.1.2"], subnetMasks: ["255.255.255.0"])
            ipv4Settings.includedRoutes = [
                NEIPv4Route.default()
            ]
            let dnsSettings = NEDNSSettings(servers: ["10.0.0.53"])
            dnsSettings.matchDomains = [""]
            dnsSettings.matchDomainsNoSearch = true
            tunnelNetworkSettings.dnsSettings = dnsSettings
            tunnelNetworkSettings.ipv4Settings = ipv4Settings
            
            do {
                try await self.setTunnelNetworkSettings(tunnelNetworkSettings)
            } catch let error {
                completionHandler(error)
                throw error
            }
            
            completionHandler(nil)
            
            while !Task.isCancelled {
                log.debug("reading packet objects...")
                let packets = await self.packetFlow.readPacketObjects();
                for packet in packets {
                    log.debug("received packet: \(packet, privacy: .public)")
                }
            }
            log.debug("packet task cancelled")
        }
        log.debug("startTunnel done")
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.debug("stopTunnel \(String(describing:reason))")
        self.t?.cancel()
        completionHandler()
        log.debug("stopTunnel done")
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        log.debug("handleAppMessage \(messageData)")
        if let handler = completionHandler {
            handler(messageData)
        }
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        log.debug("sleep")
        completionHandler()
    }
    
    override func wake() {
        log.debug("wake")
    }
}
