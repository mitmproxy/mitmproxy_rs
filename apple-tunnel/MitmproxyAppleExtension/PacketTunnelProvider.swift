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

    /*// These 2 are core methods for VPN tunnelling
    //   - read from tun device, encrypt, write to UDP fd
    //   - read from UDP fd, decrypt, write to tun device
    func tunToUDP() {
        os_log("qqq - tunToUDP")
        self.packetFlow.readPackets { (packets: [Data], protocols: [NSNumber]) in
            for packet in packets {
                // This is where encrypt() should reside
                // A comprehensive encryption is not easy and not the point for this demo
                // I just omit it
                self.session?.writeDatagram(packet, completionHandler: { (error: Error?) in
                    if let error = error {
                        print(error)
                        self.setupUDPSession()
                        return
                    }
                })
            }
            // Recursive to keep reading
            self.tunToUDP()
        }
    }
*/
    

 /*  func setupPacketTunnelNetworkSettings() {
        os_log("qqq - setupPacketTunnelNetworkSettings")
        let tunnelNetworkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: self.protocolConfiguration.serverAddress!)
        tunnelNetworkSettings.ipv4Settings = NEIPv4Settings(addresses: [conf["ip"] as! String], subnetMasks: [conf["subnet"] as! String])
        tunnelNetworkSettings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        tunnelNetworkSettings.mtu = Int(conf["mtu"] as! String) as NSNumber?
        let dnsSettings = NEDNSSettings(servers: (conf["dns"] as! String).components(separatedBy: ","))
        // This overrides system DNS settings
        dnsSettings.matchDomains = [""]
        tunnelNetworkSettings.dnsSettings = dnsSettings
        self.setTunnelNetworkSettings(tunnelNetworkSettings) { (error: Error?) -> Void in
            self.udpToTun()
        }
    }
     
     func setupUDPSession() {
        os_log("qqq - setupUDPSession")
        if self.session != nil {
            self.reasserting = true
            self.session = nil
        }
        let serverAddress = self.conf["server"] as! String
        let serverPort = self.conf["port"] as! String
        self.reasserting = false
        self.setTunnelNetworkSettings(nil) { (error: Error?) -> Void in
            if let error = error {
                print(error)
            }
            self.session = self.createUDPSession(to: NWHostEndpoint(hostname: serverAddress, port: serverPort), from: nil)
            self.setupPacketTunnelNetworkSettings()
        }
    }
     */

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
            self.setupUDPSession()
            //self.handleflow()
            
            //self.handleflow()
            
            self.handleflow()
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
    
    func reinjectFlow() async throws {
        //os_log("qqq - reinjectFlow")
        //DispatchQueue.global(qos: .userInitiated).async{ [weak self] in
        if let pipe = self.netPipe{
                let url = URL(fileURLWithPath: pipe)
            do {
                try FileManager.default.removeItem(at: url)
            } catch {
                os_log("qqq - error deleting: \(error, privacy: .public)")
            }
            mkfifo(url.path, 0o600)
            os_log("qqq - before timer")
            try await Task.sleep(nanoseconds: UInt64(Double(NSEC_PER_SEC)))
            os_log("qqq - after timer \(url.path, privacy: .public)")
            
            guard let handler = FileHandle(forReadingAtPath: url.path) else {
                os_log("qqq - handler problem")
                return
            }
            while true{
            os_log("qqq - the handler is")
                os_log("qqq - im inside netpipe inside the loop")
                let data = handler.availableData
                    let _packet = self.deserializePacket(data: data)
                    if let packet = _packet {
                        os_log("qqq - read packet from pipe -> process: \(packet.processName, privacy: .public)")
                        os_log("qqq - read packet from pipe: \(packet.data, privacy: .public)")
                        // This is where decrypt() should reside, I just omit it like above
                        self.session?.writeDatagram(packet.data, completionHandler: { (error: Error?) in
                            if let error = error {
                                print(error)
                                self.setupUDPSession()
                                return
                            }
                        })
                    }
            }
        } else {
            try await self.reinjectFlow()
        }
    }
    
    func setupUDPSession() {
        os_log("qqq - create UDP Session")
        if self.session != nil {
            self.reasserting = true
            self.session = nil
        }
        let serverAddress = self.conf["server"] as! String
        let serverPort = self.conf["port"] as! String
        self.reasserting = false
        self.session = self.createUDPSession(to: NWHostEndpoint(hostname: serverAddress, port: serverPort), from: nil)
        Task.init{
            try await self.reinjectFlow()
            os_log("qqq - reinjectFlow did finish")
        }
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
            os_log("qqq - the ip pipe is \(self.ipPipe ?? "no self.pipe installed", privacy: .public)")
            os_log("qqq - the net pipe is \(self.netPipe ?? "no self.pipe installed", privacy: .public)")
            if let handler = completionHandler {
                handler(messageData)
            }
        }
    }
    
    func writeToPipe(data: Data, processName: String) {
        os_log("qqq - I'm inside writeToPipe, I'm writing on %{public}@", self.ipPipe ?? "no self.pipe installed")
        if let pipe = self.ipPipe{
            do {
                let handler = FileHandle(forWritingAtPath: pipe)
                //os_log("qqq - processname: \(processName, privacy: .public)")
                var packet = Mitmproxy_RawPacket_Packet()
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
    func serializePacket(packet: Mitmproxy_RawPacket_Packet) -> Data? {
        do {
            return try packet.serializedData()
        } catch {
            print("Failed to serialize UDP packet: \(error)")
            return nil
        }
    }

    func deserializePacket(data: Data) -> Mitmproxy_RawPacket_Packet? {
        do {
            return try Mitmproxy_RawPacket_Packet(serializedData: data)
        } catch {
            print("Failed to deserialize UDP packet: \(error)")
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
