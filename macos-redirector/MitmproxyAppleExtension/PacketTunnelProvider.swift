import NetworkExtension
import OSLog

@available(macOSApplicationExtension 11.0, *)
class PacketTunnelProvider: NEPacketTunnelProvider {
    var session: NWUDPSession? = nil
    var conf = [String: AnyObject]()
    var ipPipe: String? = nil
    var netPipe: String? = nil

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        conf = (self.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration! as [String : AnyObject]
        let tunnelNetworkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4Settings = NEIPv4Settings(addresses: ["192.168.1.2"], subnetMasks: ["255.255.255.0"])
        var includedRoutes: [NEIPv4Route] = []
        includedRoutes.append(NEIPv4Route.default())
        let dnsSettings = NEDNSSettings(servers: ["10.0.0.53"])
        dnsSettings.matchDomains = [""]
        dnsSettings.matchDomainsNoSearch = true
        tunnelNetworkSettings.dnsSettings = dnsSettings
        tunnelNetworkSettings.ipv4Settings = ipv4Settings
        
        setTunnelNetworkSettings(tunnelNetworkSettings) { error in
            if let applyError = error {
                os_log("Failed to apply tunnel settings settings: %{public}@", applyError.localizedDescription)
            }
            completionHandler(error)
            let reinject = DispatchQueue(label: "org.mitmproxy.reinject", attributes: .concurrent)
            let write = DispatchQueue(label: "com.mitmproxy.write", attributes: .concurrent)
            reinject.async {
                self.setupUDPSession()
            }
            write.async {
                self.handleflow()
            }

            RunLoop.main.run()
        }
    }
    
    func handleflow(){
        self.packetFlow.readPacketObjects { packets in
            for (_, packet) in packets.enumerated(){
                self.writeToPipe(data: packet.data, processName: packet.metadata!.sourceAppSigningIdentifier)
            }
            self.handleflow()
        }
    }
    
    func reinjectFlow() {
        if let pipe = self.netPipe{
            let handler = FileHandle(forReadingAtPath: pipe)
            while true {
                if let data = handler?.availableData{
                    let _packet = self.deserializePacket(data: data)
                    if let packet = _packet {
                        // This is where decrypt() should reside, I just omit it like above
                        packetFlow.writePackets([packet.data], withProtocols: [AF_INET as NSNumber])
                    }
                }
            }
        } else {
            reinjectFlow()
        }
    }
    
    func setupUDPSession() {
        if self.session != nil {
            self.reasserting = true
            self.session = nil
        }
        let serverAddress = self.conf["server"] as! String
        let serverPort = self.conf["port"] as! String
        self.reasserting = false
        self.session = self.createUDPSession(to: NWHostEndpoint(hostname: serverAddress, port: serverPort), from: nil)
        self.reinjectFlow()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        session?.cancel()
        super.stopTunnel(with: reason, completionHandler: completionHandler)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        if let messageString = String(data: messageData, encoding: .utf8)?.components(separatedBy: " "){
            self.ipPipe = messageString[0]
            self.netPipe = messageString[1]
            if let handler = completionHandler {
                handler(messageData)
            }
        }
    }
    
    func writeToPipe(data: Data, processName: String) {
        if let pipe = self.ipPipe{
            do {
                let handler = FileHandle(forWritingAtPath: pipe)
                //os_log("qqq - processname: \(processName, privacy: .public)")
                var packet = Mitmproxy_Ipc_Packet()
                packet.data = data
                packet.processName = processName
                if let serializedPacket = self.serializePacket(packet: packet){
                    try handler?.write(contentsOf: serializedPacket)
                    handler?.closeFile()
                }
           } catch{
               os_log("Error: \(error, privacy: .public)")
           }
        }
    }
    
    // Serialize and deserialize UDP packets
    func serializePacket(packet: Mitmproxy_Ipc_Packet) -> Data? {
        do {
            return try packet.serializedData()
        } catch {
            os_log("Failed to serialize packet")
            return nil
        }
    }

    func deserializePacket(data: Data) -> Mitmproxy_Ipc_Packet? {
        do {
            return try Mitmproxy_Ipc_Packet(serializedData: data)
        } catch {
            os_log("Failed to deserialize packet")
            return nil
        }
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
    }
}
