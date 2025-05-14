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
        log.debug("Starting proxy...")

        guard let unixSocket = self.protocolConfiguration.serverAddress
        else { throw TransparentProxyError.serverAddressMissing }
        self.unixSocket = unixSocket
        log.debug("Establishing control channel via \(unixSocket, privacy: .public)...")
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
                control.forceCancel()
                self.cancelProxyWithError(.none)
            case .failed(let err):
                log.error("control channel failed: \(err, privacy: .public)")
                control.forceCancel()
                self.cancelProxyWithError(err)
            default:
                break
            }
        }
        Task {
            do {
                while let spec = try await control.receive(ipc: MitmproxyIpc_InterceptConf.self) {
                    log.debug("Received spec: \(String(describing: spec), privacy: .public)")
                    self.spec = try InterceptConf(from: spec)
                }
            } catch {
                log.error("Error on control channel: \(String(describing: error), privacy: .public)")
                control.forceCancel()
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
        
        let message: MitmproxyIpc_NewFlow
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
    
    func makeIpcHandshake(flow: NEAppProxyFlow, processInfo: ProcessInfo) throws -> MitmproxyIpc_NewFlow {
        let tunnelInfo = MitmproxyIpc_TunnelInfo.with {
            $0.pid = processInfo.pid
            if let path = processInfo.path {
                $0.processName = path
            }
        }
        
        // Do not use remoteHostname property; for DNS UDP flows that's already pointing at the name that we want to look up.
        // log.debug("remoteHostname: \(String(describing: flow.remoteHostname), privacy: .public) flow:\(String(describing: flow), privacy: .public)")
    
        let message: MitmproxyIpc_NewFlow
        if let tcp_flow = flow as? NEAppProxyTCPFlow {
            guard let remoteEndpoint = tcp_flow.remoteEndpoint as? NWHostEndpoint else {
                throw TransparentProxyError.noRemoteEndpoint
            }
            // log.debug("remoteEndpoint: \(String(describing: remoteEndpoint), privacy: .public)")
            // It would be nice if we could also include info on the local endpoint here, but that's not exposed.
            message = MitmproxyIpc_NewFlow.with {
                $0.tcp = MitmproxyIpc_TcpFlow.with {
                    $0.remoteAddress = MitmproxyIpc_Address.init(endpoint: remoteEndpoint)
                    $0.tunnelInfo = tunnelInfo
                }
            }
        } else if let udp_flow = flow as? NEAppProxyUDPFlow {
            guard let localEndpoint = udp_flow.localEndpoint as? NWHostEndpoint else {
                throw TransparentProxyError.noLocalEndpoint
            }
            message = MitmproxyIpc_NewFlow.with {
                $0.udp = MitmproxyIpc_UdpFlow.with {
                    $0.localAddress = MitmproxyIpc_Address.init(endpoint: localEndpoint)
                    $0.tunnelInfo = tunnelInfo
                }
            }
        } else {
            throw TransparentProxyError.unexpectedFlow
        }
        return message
    }
}
