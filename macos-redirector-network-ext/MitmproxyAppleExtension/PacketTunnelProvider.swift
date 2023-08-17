import NetworkExtension
import Foundation
import AppKit
import OSLog

@available(macOSApplicationExtension 11.0, *)
class PacketTunnelProvider: NEPacketTunnelProvider {
    var session: NWUDPSession? = nil
    var conf = [String: AnyObject]()
    var fromRedirectorPipe: String? = nil
    var fromProxyPipe: String? = nil
    var logger = Logger()

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
        
        setTunnelNetworkSettings(tunnelNetworkSettings) { [self] error in
            if let applyError = error {
                logger.error("Failed to apply tunnel settings: \(applyError, privacy: .public)")
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
        while self.fromProxyPipe == nil {
            logger.info("Waiting for self.fromProxyPipe to be set...")
            Thread.sleep(forTimeInterval: 0.3)
        }
        
        guard let pipe = self.fromProxyPipe else {
            logger.error("Not able to reinject the flow, self.fromProxyPipe does not exist")
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
                  let fromProxy = try? Mitmproxy_Ipc_FromProxy(serializedData: data)
            else {
                continue
            }
            
            if !packetFlow.writePackets([fromProxy.packet], withProtocols: [AF_INET as NSNumber]){
                logger.fault("Failed to write packets to packet flow")
            }
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
            self.fromRedirectorPipe = messageString[0]
            self.fromProxyPipe = messageString[1]
            if let handler = completionHandler {
                handler(messageData)
            }
        }
    }
    
    func writeToPipe(data: Data, processName: String) {
        if let pipe = self.fromRedirectorPipe{
            do {
                let handler = FileHandle(forWritingAtPath: pipe)
                var fromRedirector = Mitmproxy_Ipc_FromRedirector()
                fromRedirector.packet.data = data
                fromRedirector.packet.pid = 0
                fromRedirector.packet.processName = processName
                if let serializedPacket = try? fromRedirector.serializedData() {
                    handler?.write(serializedPacket)
                    try handler?.synchronize()
                } else {
                    logger.fault("Unable to serialize packet")
                }
           } catch{
               logger.error("WriteToPipe problem: \(error, privacy: .public)")
           }
        }
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
    }
}
