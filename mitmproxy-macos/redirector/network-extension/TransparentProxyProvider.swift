import Darwin
import NetworkExtension
import Foundation
import Network


enum TransparentProxyError: Error {
    case serverAddressMissing
    case connectionCancelled
}

extension NWConnection {
    /// Async wrapper to establish a connection and wait for NWConnection.State.ready
    func establish() async throws {
        let orig_handler = self.stateUpdateHandler;
        defer {
            self.stateUpdateHandler = orig_handler;
        }
        try await withCheckedThrowingContinuation { continuation in
            self.stateUpdateHandler = { state in
                log.info("stateUpdate: \(String(describing:state), privacy: .public)")
                switch state {
                    case .ready:
                        continuation.resume()
                    case .waiting(let err):
                        continuation.resume(with: .failure(err))
                    case .failed(let err):
                        continuation.resume(with: .failure(err))
                    case .cancelled:
                        continuation.resume(with: .failure(TransparentProxyError.connectionCancelled))
                    default:
                        break
                }
            };
            self.start(queue: DispatchQueue.global())
        }
    }
    
    func monitor(onUpdate: @escaping (_ spec: Mitmproxy_Ipc_InterceptSpec) -> Void) {
        Task {
            while let spec = try await self.receive(ipc: Mitmproxy_Ipc_InterceptSpec.self) {
                log.debug("Received spec: \(String(describing:spec), privacy: .public)")
                onUpdate(spec)
            }
        }
    }
}



class TransparentProxyProvider: NETransparentProxyProvider {
    var unix_socket: String?
    var control_channel: NWConnection?
    
    override func startProxy(options: [String : Any]? = nil) async throws {
        log.debug("startProxy")
        
        self.unix_socket = try self.protocolConfiguration.serverAddress ?? {
            throw TransparentProxyError.serverAddressMissing
        }()
        
        control_channel = NWConnection(
            to: .unix(path: self.unix_socket!),
            using: .tcp
        )
        try await control_channel?.establish()
        control_channel?.stateUpdateHandler = { state in
            switch state {
                case .failed(.posix(.ENETDOWN)):
                    log.debug("control channel closed, stopping proxy.")
                    self.cancelProxyWithError(.none)
                case .failed(let err):
                    log.error("control channel failed: \(err, privacy: .public)")
                    self.cancelProxyWithError(err)
                default:
                    break
            }
        }
        control_channel?.monitor(onUpdate: { spec in
            log.debug("TODO: Spec Update")
        })
        
        let proxySettings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        proxySettings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                protocol: .any,
                direction: .outbound // FIXME: Setting .any breaks right now?
            )
        ]
        
        try await setTunnelNetworkSettings(proxySettings)
        log.debug("startProxy completed.")
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        log.debug("stopProxy \(String(describing: reason), privacy: .public)")
        self.control_channel?.forceCancel()
    }
    
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        log.debug("handleNewFlow")
        let processInfo = ProcessInfoCache.getInfo(fromAuditToken: flow.metaData.sourceAppAuditToken)
        log.debug("processInfo: \(String(describing:processInfo), privacy: .public)")
        
        if processInfo?.path == "/usr/bin/curl" {
            
            Task {
                log.debug("remoteHostname: \(String(describing:flow.remoteHostname), privacy: .public) flow:\(String(describing: flow), privacy: .public)")
                try await flow.open(withLocalEndpoint: nil)
                                
                let tunnelInfo = Mitmproxy_Ipc_TunnelInfo.with {
                    if let pid = processInfo?.pid {
                        $0.pid = pid;
                    }
                    if let path = processInfo?.path {
                        $0.processName = path;
                    }
                };
                let message: Mitmproxy_Ipc_NewFlow;
                if let tcp_flow = flow as? NEAppProxyTCPFlow {
                    log.debug("remoteEndpoint: \(String(describing:tcp_flow.remoteEndpoint), privacy: .public)")
                    guard let endpoint = tcp_flow.remoteEndpoint as? NWHostEndpoint else {
                        log.debug("No remote endpoint for TCP flow: \(String(describing: tcp_flow), privacy: .public)")
                        return
                    }
                    message = Mitmproxy_Ipc_NewFlow.with {
                        $0.tcp = Mitmproxy_Ipc_TcpFlow.with {
                            $0.remoteAddress = Mitmproxy_Ipc_Address.init(endpoint: endpoint)
                            $0.tunnelInfo = tunnelInfo
                        };
                    };
                } else if let udp_flow = flow as? NEAppProxyUDPFlow {
                    guard let endpoint = udp_flow.localEndpoint as? NWHostEndpoint else {
                        log.debug("No local endpoint for UDP flow: \(String(describing: udp_flow), privacy: .public)")
                        return
                    }
                    message = Mitmproxy_Ipc_NewFlow.with {
                        $0.udp = Mitmproxy_Ipc_UdpFlow.with {
                            $0.localAddress = Mitmproxy_Ipc_Address.init(endpoint: endpoint)
                            $0.tunnelInfo = tunnelInfo
                        };
                    };
                } else {
                    log.debug("Unexpected flow: \(String(describing: flow), privacy: .public)")
                    return
                }
                                    
                let conn = NWConnection(
                    to: .unix(path: self.unix_socket!),
                    using: .tcp
                )
                do {
                    try await conn.establish()
                } catch {
                    flow.closeReadWithError(error)
                    flow.closeWriteWithError(error)
                    throw error
                }
                
                try await conn.send(ipc: message)
                log.debug("message sent.")
                
                if let tcp_flow = flow as? NEAppProxyTCPFlow {
                    tcp_flow.outboundCopier(conn)
                    tcp_flow.inboundCopier(conn)
                } else if let udp_flow = flow as? NEAppProxyUDPFlow {
                    udp_flow.outboundCopier(conn)
                    udp_flow.inboundCopier(conn)
                }
            }
            return true
        }
    
        return false
    }
}

extension NEAppProxyTCPFlow {
    func outboundCopier(_ conn: NWConnection) {
        readData { data, error in
            if error == nil, let readData = data, !readData.isEmpty {
                conn.send(content: readData, completion: .contentProcessed( { connectionError in
                    if connectionError == nil {
                        self.outboundCopier(conn)
                    } else {
                        log.debug("error copying: \(String(describing:connectionError), privacy: .public)")
                    }
                }))
            } else {
                log.debug("outbound copier end: \(String(describing:data), privacy: .public) \(String(describing:error), privacy: .public)")
                conn.send(content: nil, isComplete: true, completion: .idempotent)
            }
        }
    }
    
    func inboundCopier(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { (data, _, isComplete, error) in
            switch (data, isComplete, error) {
                case (let data?, _, _):
                    self.write(data) { writeError in
                        if writeError == nil {
                            self.inboundCopier(conn)
                        }
                    }
                case (_, true, _):
                    self.closeWriteWithError(error)
                default:
                    log.info("inboundCopier error=\(String(describing: error), privacy: .public) isComplete=\(String(describing: isComplete), privacy: .public)")
            }
        }
    }
}


extension NEAppProxyUDPFlow {
    
    func readDatagrams() async throws -> ([Data], [NetworkExtension.NWEndpoint]) {
        return try await withCheckedThrowingContinuation { continuation in
            readDatagrams { datagrams, endpoints, error in
                if let error = error {
                    continuation.resume(throwing: error)
                }
                guard let datagrams = datagrams, let endpoints = endpoints else {
                    fatalError("No error, but also no datagrams")
                }
                continuation.resume(returning: (datagrams, endpoints))
            }
        }
    }
    
    func outboundCopier(_ conn: NWConnection) {
        Task {
            while true {
                let (datagrams, endpoints) = try await readDatagrams();
                log.debug("localEndpoint in copier: \(String(describing:self.localEndpoint),privacy: .public)")
                if datagrams.isEmpty {
                    log.debug("outbound udp copier end")
                    conn.send(content: nil, isComplete: true, completion: .idempotent)
                    break
                }
                for (datagram, endpoint) in zip(datagrams, endpoints) {
                    let message = Mitmproxy_Ipc_UdpPacket.with {
                        $0.data = datagram;
                        $0.remoteAddress = Mitmproxy_Ipc_Address.init(endpoint: endpoint as! NWHostEndpoint);
                    };
                    try await conn.send(ipc: message);
                }
            }
        }
    }
    
    func inboundCopier(_ conn: NWConnection) {
        Task {
            while true {
                log.debug("UDP inbound: receiving...")
                guard let packet = try await conn.receive(ipc: Mitmproxy_Ipc_UdpPacket.self) else {
                    self.closeWriteWithError(nil)
                    break
                }
                log.debug("UDP inbound: received: \(String(describing: packet), privacy: .public)")
                let endpoint = NWHostEndpoint(address: packet.remoteAddress)
                log.debug("grams = \(String(describing: [packet.data]), privacy: .public)")
                log.debug("sentBy = \(String(describing: [endpoint]), privacy: .public)")
                try await self.writeDatagrams([packet.data], sentBy: [endpoint])
                log.debug("UDP inbound forward complete.")
            }
        }
    }
}
