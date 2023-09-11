import Darwin
import NetworkExtension
import Foundation
import Network


enum TransparentProxyError: Error {
    case serverAddressMissing
    case connectionCancelled
}

extension NWConnection {
    func monitor(
        onUpdate: @escaping (_ spec: Mitmproxy_Ipc_InterceptSpec) -> Void
    ) {
        receive(minimumIncompleteLength: 4, maximumLength: 4, completion: { len_buf,_,_,_  in
            guard
                let len_buf = len_buf,
                len_buf.count == 4
            else {
                if len_buf != nil {
                    log.error("Protocol error on control stream: \(String(describing:len_buf), privacy: .public)")
                }
                return
            }
            let len = len_buf[...].reduce(Int(0)) { $0 << 8 + Int($1) };
            
            self.receive(minimumIncompleteLength: len, maximumLength: len) { data,_,_,_  in
                guard
                    let data = data,
                    data.count == len,
                    let spec = try? Mitmproxy_Ipc_InterceptSpec(contiguousBytes: data)
                else {
                    log.error("Protocol error on control stream: \(String(describing:data), privacy: .public)")
                    return
                }
                log.debug("Received new intercept spec: \(String(describing: spec), privacy: .public)")
                onUpdate(spec)
                self.monitor(onUpdate: onUpdate)
            }
        })
    }
    
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
}

class TransparentProxyProvider: NETransparentProxyProvider {
    var control_channel: NWConnection?
    
    override func startProxy(options: [String : Any]? = nil) async throws {
        log.debug("startProxy")
        
        guard let path = self.protocolConfiguration.serverAddress else {
            throw TransparentProxyError.serverAddressMissing
        }
        log.debug("path: \(path, privacy: .public)")
        
        control_channel = NWConnection(
            to: .unix(path: path),
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
                remoteNetwork: NWHostEndpoint(hostname: "0.0.0.0", port: "80"),
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
    }
    
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        log.debug("handleNewFlow")
        let processInfo = ProcessInfoCache.getInfo(fromAuditToken: flow.metaData.sourceAppAuditToken)
        log.debug("processInfo: \(String(describing:processInfo), privacy: .public)")
        
        if processInfo?.path == "/usr/bin/curl" {
            return true
        }
    
        return false
    }
}
