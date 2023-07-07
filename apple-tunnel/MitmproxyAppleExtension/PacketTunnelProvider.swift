//
//  PacketTunnelProvider.swift
//  NEPacketTunnelVPNDemoTunnel
//
//  Created by lxd on 12/8/16.
//  Copyright © 2016 lxd. All rights reserved.
//

import NetworkExtension
import OSLog

@available(macOSApplicationExtension 11.0, *)
class PacketTunnelProvider: NEPacketTunnelProvider {
    var session: NWUDPSession? = nil
    var conf = [String: AnyObject]()
    var ipPipe: String? = nil
    var netPipe: String? = nil

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("qqq - startTunnel")
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
                os_log("QQQ - Failed to apply tunnel settings settings: %{public}@", applyError.localizedDescription)
            }
            os_log("QQQ - settings ok")
            completionHandler(error)
            let reinject = DispatchQueue(label: "org.mitmproxy.reinject", attributes: .concurrent)
            let write = DispatchQueue(label: "com.mitmproxy.write", attributes: .concurrent)

            // Submit infinite loop blocks to the queues
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
        //os_log("qqq - handleFlow")
        self.packetFlow.readPacketObjects { packets in
            for (_, packet) in packets.enumerated(){
                //os_log("qqq - handleFlow \(packet.metadata!.sourceAppSigningIdentifier, privacy: .public)")
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
        os_log("qqq - Create UDP Session")
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
        os_log("qqq - stoptunnel")
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
               os_log("qqq - fail to write due to \(error, privacy: .public)")
           }
        }
    }
    
    // Serialize and deserialize UDP packets
    func serializePacket(packet: Mitmproxy_Ipc_Packet) -> Data? {
        do {
            return try packet.serializedData()
        } catch {
            print("Failed to serialize packet: \(error)")
            return nil
        }
    }

    func deserializePacket(data: Data) -> Mitmproxy_Ipc_Packet? {
        do {
            return try Mitmproxy_Ipc_Packet(serializedData: data)
        } catch {
            print("Failed to deserialize packet: \(error)")
            return nil
        }
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        os_log("qqq - sleep")
        completionHandler()
    }

    override func wake() {
        os_log("qqq - wake")
    }
}
