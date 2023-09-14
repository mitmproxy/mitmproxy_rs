import Darwin
import Foundation
import Network
import NetworkExtension

enum TransparentProxyError: Error {
    case serverAddressMissing
    case connectionCancelled
}

extension NWConnection {
    /// Async wrapper to establish a connection and wait for NWConnection.State.ready
    func establish() async throws {
        let orig_handler = self.stateUpdateHandler
        defer {
            self.stateUpdateHandler = orig_handler
        }
        try await withCheckedThrowingContinuation { continuation in
            self.stateUpdateHandler = { state in
                log.info("stateUpdate: \(String(describing: state), privacy: .public)")
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
            }
            self.start(queue: DispatchQueue.global())
        }
    }
}

class TransparentProxyProvider: NETransparentProxyProvider {
    var unixSocket: String?
    var controlChannel: NWConnection?
    var spec: InterceptSpec?

    override func startProxy(options: [String: Any]? = nil) async throws {
        log.debug("startProxy")

        self.unixSocket =
            try self.protocolConfiguration.serverAddress
            ?? {
                throw TransparentProxyError.serverAddressMissing
            }()

        let control = NWConnection(
            to: .unix(path: self.unixSocket!),
            using: .tcp
        )
        controlChannel = control
        try await control.establish()
        control.stateUpdateHandler = { state in
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

        Task {
            log.debug("what happens here?")
            throw TransparentProxyError.connectionCancelled
        }

        Task {
            while let spec = try await control.receive(ipc: Mitmproxy_Ipc_InterceptSpec.self) {
                log.debug("Received spec: \(String(describing: spec), privacy: .public)")
                self.spec = InterceptSpec(from: spec)
            }
        }

        let proxySettings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        proxySettings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                protocol: .any,
                direction: .outbound  // FIXME: Setting .any breaks right now?
            )
        ]

        try await setTunnelNetworkSettings(proxySettings)
        log.debug("startProxy completed.")
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        log.debug("stopProxy \(String(describing: reason), privacy: .public)")
        self.controlChannel?.forceCancel()
    }
    
    func makeIpcHandshake(flow: NEAppProxyFlow, processInfo: ProcessInfo) -> Mitmproxy_Ipc_NewFlow? {
        let tunnelInfo = Mitmproxy_Ipc_TunnelInfo.with {
            $0.pid = processInfo.pid
            if let path = processInfo.path {
                $0.processName = path
            }
        }
        let message: Mitmproxy_Ipc_NewFlow
        if let tcp_flow = flow as? NEAppProxyTCPFlow {
            guard let endpoint = tcp_flow.remoteEndpoint as? NWHostEndpoint else {
                log.debug(
                    "No remote endpoint for TCP flow: \(String(describing: tcp_flow), privacy: .public)"
                )
                return nil
            }
            log.debug("remoteEndpoint: \(String(describing: endpoint), privacy: .public)")
            message = Mitmproxy_Ipc_NewFlow.with {
                $0.tcp = Mitmproxy_Ipc_TcpFlow.with {
                    $0.remoteAddress = Mitmproxy_Ipc_Address.init(endpoint: endpoint)
                    $0.tunnelInfo = tunnelInfo
                }
            }
        } else if let udp_flow = flow as? NEAppProxyUDPFlow {
            guard let endpoint = udp_flow.localEndpoint as? NWHostEndpoint else {
                log.debug(
                    "No local endpoint for UDP flow: \(String(describing: udp_flow), privacy: .public)"
                )
                return nil
            }
            message = Mitmproxy_Ipc_NewFlow.with {
                $0.udp = Mitmproxy_Ipc_UdpFlow.with {
                    $0.localAddress = Mitmproxy_Ipc_Address.init(endpoint: endpoint)
                    $0.tunnelInfo = tunnelInfo
                }
            }
        } else {
            log.debug("Unexpected flow: \(String(describing: flow), privacy: .public)")
            return nil
        }
        return message
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        log.debug("handleNewFlow")
        let processInfo = ProcessInfoCache.getInfo(fromAuditToken: flow.metaData.sourceAppAuditToken)
        
        
        log.debug("metadata: \(flow.metaData, privacy: .public)")
        log.debug("si: \(flow.metaData.sourceAppSigningIdentifier, privacy: .public)")
        log.debug("ui: \(flow.metaData.sourceAppUniqueIdentifier, privacy: .public)")
        log.debug("desc: \(flow.description, privacy: .public)")

        
        guard let processInfo = processInfo else {
            log.debug("Skipping flow without process info.")
            return false
        }
        log.debug("processInfo: \(String(describing: processInfo), privacy: .public)")

        guard let spec = self.spec else {
            log.debug("Skipping flow, no intercept spec provided.")
            return false
        }
        guard spec.shouldIntercept(processInfo) else {
            return false
        }

        // remoteHostname is a bit dangerous; for DNS UDP flows that's already pointing at the name that we want to look up.
        // log.debug("remoteHostname: \(String(describing: flow.remoteHostname), privacy: .public) flow:\(String(describing: flow), privacy: .public)")
        
        guard let message = self.makeIpcHandshake(flow: flow, processInfo: processInfo) else {
            return false
        }

        Task {
            try await flow.open(withLocalEndpoint: nil)

            let conn = NWConnection(
                to: .unix(path: self.unixSocket!),
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
            log.debug("Handshake sent.")

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
}

extension NEAppProxyTCPFlow {
    func outboundCopier(_ conn: NWConnection) {
        readData { data, error in
            if error == nil, let readData = data, !readData.isEmpty {
                conn.send(
                    content: readData,
                    completion: .contentProcessed({ error in
                        if error == nil {
                            self.outboundCopier(conn)
                        } else {
                            log.debug(
                                "error copying: \(String(describing: error), privacy: .public)")
                        }
                    }))
            } else {
                log.debug(
                    "outbound copier end: \(String(describing: data), privacy: .public) \(String(describing: error), privacy: .public)"
                )
                conn.send(content: nil, isComplete: true, completion: .idempotent)
            }
        }
    }

    func inboundCopier(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) {
            (data, _, isComplete, error) in
            switch (data, isComplete, error) {
            case (let data?, _, _):
                self.write(data) { error in
                    if error == nil {
                        self.inboundCopier(conn)
                    }
                }
            case (_, true, _):
                self.closeWriteWithError(error)
            default:
                log.info(
                    "inboundCopier error=\(String(describing: error), privacy: .public) isComplete=\(String(describing: isComplete), privacy: .public)"
                )
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
                let (datagrams, endpoints) = try await readDatagrams()
                log.debug(
                    "localEndpoint in copier: \(String(describing: self.localEndpoint), privacy: .public)"
                )
                if datagrams.isEmpty {
                    log.debug("outbound udp copier end")
                    conn.send(content: nil, isComplete: true, completion: .idempotent)
                    break
                }
                for (datagram, endpoint) in zip(datagrams, endpoints) {
                    guard let endpoint = endpoint as? NWHostEndpoint
                    else { continue }
                    let message = Mitmproxy_Ipc_UdpPacket.with {
                        $0.data = datagram
                        $0.remoteAddress = Mitmproxy_Ipc_Address.init(endpoint: endpoint)
                    }
                    try await conn.send(ipc: message)
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
