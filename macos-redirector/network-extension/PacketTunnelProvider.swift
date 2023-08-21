import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        log.debug("startTunnel")
        
        let tunnelNetworkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.42")
        let ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.1"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [
            NEIPv4Route.default()
        ]
        tunnelNetworkSettings.ipv4Settings = ipv4Settings
        tunnelNetworkSettings.dnsSettings = NEDNSSettings(servers: ["10.0.0.53"])
        
        let addr = self.protocolConfiguration.serverAddress!
                
        let proxy_file: FileHandle, redir_file: FileHandle
        do {
            proxy_file = try FileHandle(forReadingFrom: URL(fileURLWithPath: "\(addr).proxy"));
            redir_file = try FileHandle(forWritingTo: URL(fileURLWithPath: "\(addr).redir"))
        } catch {
            return completionHandler(error)
        }
        
        self.setTunnelNetworkSettings(tunnelNetworkSettings) { err in
            completionHandler(err)
            log.debug("tunnel settings set (err=\(err))")
            if err == nil {
                DispatchQueue.global().async {
                    self.redirectPackets(redir_file)
                }
                DispatchQueue.global().async {
                    self.reinjectPackets(proxy_file)
                }
            }
        }
        
        log.debug("startTunnel done")
    }
    
    func redirectPackets(_ wfile: FileHandle) {
        log.debug("redirecting packets to \(wfile, privacy: .public)...")
        self.packetFlow.readPacketObjects { packets in
            for packet in packets {
                
                var message = Mitmproxy_Ipc_FromRedirector()
                message.packet.data = packet.data
                message.packet.pid = 0 // TODO
                message.packet.processName = packet.metadata!.sourceAppSigningIdentifier
                
                do {
                    try writeIpcMessage(message: message, fh: wfile)
                } catch {
                    log.error("redirectPackets errored: \(error)")
                    exit(1)
                }
                self.redirectPackets(wfile)
            }
        }
    }
    
    func reinjectPackets(_ rfile: FileHandle) {
        log.debug("reading \(rfile, privacy: .public)...")
        do {
            while let packet = try readIpcMessage(ofType: Mitmproxy_Ipc_Packet.self, fh: rfile) {
                
                log.debug("reinjecting packet...")
                self.packetFlow.writePackets([packet.data], withProtocols: [AF_INET as NSNumber])
                
            }
        } catch {
            log.error("redirectPackets errored: \(error)")
            exit(1)
        }
        
        log.debug("exiting...")
        exit(0)
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.debug("stopTunnel \(String(describing:reason))")
        completionHandler()
        exit(0) // XXX: is that a reasonable approach to tear things down?
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
