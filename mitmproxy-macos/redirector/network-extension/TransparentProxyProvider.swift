import Darwin
import Foundation
import Network
import NetworkExtension

enum TransparentProxyError: Error {
    case serverAddressMissing
    case noRemoteEndpoint
    case noLocalEndpoint
    case unexpectedFlow
}

class TransparentProxyProvider: NETransparentProxyProvider {
    var unixSocket: String?
    var controlChannel: NWConnection?
    var spec: InterceptConf?

    override func startProxy(options: [String: Any]? = nil) async throws {
        guard let unixSocket = self.protocolConfiguration.serverAddress
        else { throw TransparentProxyError.serverAddressMissing }
        self.unixSocket = unixSocket
        
        log.debug("Starting proxy. Establishing control channel via \(unixSocket, privacy: .public)...")
        let control = NWConnection(
            to: .unix(path: unixSocket),
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
            do {
                while let spec = try await control.receive(ipc: Mitmproxy_Ipc_InterceptConf.self) {
                    log.debug("Received spec: \(String(describing: spec), privacy: .public)")
                    self.spec = InterceptConf(from: spec)
                }
            } catch {
                log.error("Error on control channel: \(String(describing: error), privacy: .public)")
                self.cancelProxyWithError(error)
            }
        }
        log.debug("Established. Applying tunnel settings...")

        let proxySettings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        proxySettings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                protocol: .any,
                // https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings/3143656-includednetworkrules:
                // The matchDirection property must be NETrafficDirection.outbound.
                direction: .outbound
            )
        ]

        try await setTunnelNetworkSettings(proxySettings)
        log.debug("Applied. Proxy start complete.")
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        log.debug("stopProxy \(String(describing: reason), privacy: .public)")
        self.controlChannel?.forceCancel()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Called for every new flow that is started.
        // We first want to figure out if we want to intercept this one.
        // Our intercept specs are based on process name and pid, so we first need to convert from
        // audit token to that.
        
        let processInfo = ProcessInfoCache.getInfo(fromAuditToken: flow.metaData.sourceAppAuditToken)
        guard let processInfo = processInfo else {
            log.debug("Skipping flow without process info.")
            return false
        }
        log.debug("Handling new flow: \(String(describing: processInfo), privacy: .public)")

        guard let spec = self.spec else {
            log.debug("Skipping flow, no intercept spec provided.")
            return false
        }
        guard spec.shouldIntercept(processInfo) else {
            log.debug("Flow not in scope, leaving it to the system.")
            return false
        }
        
        let message: Mitmproxy_Ipc_NewFlow
        do {
            message = try self.makeIpcHandshake(flow: flow, processInfo: processInfo)
        } catch {
            log.error("Failed to create IPC handshake: \(error, privacy: .public), flow=\(flow, privacy: .public)")
            return false
        }
        Task {
            do {
                log.debug("Intercepting...")
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
            } catch {
                log.error("Error handling flow: \(String(describing: error), privacy: .public)")
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
            }
        }
        return true
    }
    
    func makeIpcHandshake(flow: NEAppProxyFlow, processInfo: ProcessInfo) throws -> Mitmproxy_Ipc_NewFlow {
        let tunnelInfo = Mitmproxy_Ipc_TunnelInfo.with {
            $0.pid = processInfo.pid
            if let path = processInfo.path {
                $0.processName = path
            }
        }
        
        // Do not use remoteHostname property; for DNS UDP flows that's already pointing at the name that we want to look up.
        // log.debug("remoteHostname: \(String(describing: flow.remoteHostname), privacy: .public) flow:\(String(describing: flow), privacy: .public)")
    
        let message: Mitmproxy_Ipc_NewFlow
        if let tcp_flow = flow as? NEAppProxyTCPFlow {
            guard let remoteEndpoint = tcp_flow.remoteEndpoint as? NWHostEndpoint else {
                throw TransparentProxyError.noRemoteEndpoint
            }
            log.debug("remoteEndpoint: \(String(describing: remoteEndpoint), privacy: .public)")
            // It would be nice if we could also include info on the local endpoint here, but that's not exposed.
            message = Mitmproxy_Ipc_NewFlow.with {
                $0.tcp = Mitmproxy_Ipc_TcpFlow.with {
                    $0.remoteAddress = Mitmproxy_Ipc_Address.init(endpoint: remoteEndpoint)
                    $0.tunnelInfo = tunnelInfo
                }
            }
        } else if let udp_flow = flow as? NEAppProxyUDPFlow {
            guard let localEndpoint = udp_flow.localEndpoint as? NWHostEndpoint else {
                throw TransparentProxyError.noLocalEndpoint
            }
            message = Mitmproxy_Ipc_NewFlow.with {
                $0.udp = Mitmproxy_Ipc_UdpFlow.with {
                    $0.localAddress = Mitmproxy_Ipc_Address.init(endpoint: localEndpoint)
                    $0.tunnelInfo = tunnelInfo
                }
            }
        } else {
            throw TransparentProxyError.unexpectedFlow
        }
        return message
    }
}

/// Inbound and outbound copying for TCP flows, based on https://developer.apple.com/documentation/networkextension/app_proxy_provider/handling_flow_copying
/// This could be a bit nicer with async syntax, but we stick to the callback-style from the example.
extension NEAppProxyTCPFlow {
    func outboundCopier(_ conn: NWConnection) {
        // log.debug("outbound copier: reading...")
        readData { data, error in
            if error == nil, let readData = data, !readData.isEmpty {
                // log.debug("outbound copier: forwarding \(readData.count) bytes.")
                conn.send(
                    content: readData,
                    completion: .contentProcessed({ error in
                        if error == nil {
                            // log.debug("outbound copier: forward complete.")
                            self.outboundCopier(conn)
                        } else {
                            // log.debug("outbound copier: error copying: \(String(describing: error), privacy: .public)")
                        }
                    }))
            } else {
                log.debug(
                    "outbound copier end: \(String(describing: data), privacy: .public) \(String(describing: error), privacy: .public)"
                )
                conn.send(content: nil, isComplete: true, completion: .contentProcessed({ error in
                    conn.cancel()
                    // log.debug("outbound copier: sent end.")
                }))
                self.closeWriteWithError(error)
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
                self.closeReadWithError(error)
            default:
                self.closeReadWithError(error)
                log.info(
                    "inbound copier error=\(String(describing: error), privacy: .public) isComplete=\(String(describing: isComplete), privacy: .public)"
                )
            }
        }
    }
}

/// Inbound and outbound copying for UDP flows.
/// Async is substantially nicer here because readDatagrams returns multiple datagrams at once.
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
            do {
                while true {
                    // log.debug("UDP outbound: receiving...")
                    let (datagrams, endpoints) = try await readDatagrams()
                    if datagrams.isEmpty {
                        // log.debug("outbound udp copier end")
                        conn.send(content: nil, isComplete: true, completion: .idempotent)
                        break
                    }
                    // log.debug("UDP outbound: received \(datagrams.count, privacy: .public) datagrams.")
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
            } catch {
                log.error("Error in outbound UDP copier: \(String(describing: error), privacy: .public)")
                self.closeWriteWithError(error)
                conn.cancel()
            }
        }
    }

    func inboundCopier(_ conn: NWConnection) {
        Task {
            do {
                while true {
                    // log.debug("UDP inbound: receiving...")
                    guard let packet = try await conn.receive(ipc: Mitmproxy_Ipc_UdpPacket.self) else {
                        self.closeReadWithError(nil)
                        break
                    }
                    // log.debug("UDP inbound: received packet.: \(String(describing: packet), privacy: .public)")
                    let endpoint = NWHostEndpoint(address: packet.remoteAddress)
                    try await self.writeDatagrams([packet.data], sentBy: [endpoint])
                }
            } catch {
                log.error("Error in inbound UDP copier: \(String(describing: error), privacy: .public)")
                self.closeReadWithError(error)
                conn.cancel()
            }
        }
    }
}
