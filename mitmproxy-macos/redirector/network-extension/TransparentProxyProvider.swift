import Darwin
import NetworkExtension
import Foundation


class TransparentProxyProvider: NETransparentProxyProvider {
    
    override func startProxy(options: [String : Any]? = nil) async throws {
        log.debug("startProxy")

        let proxySettings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        proxySettings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: NWHostEndpoint(hostname: "0.0.0.0", port: "80"),
               remotePrefix: 0,
               localNetwork: nil,
               localPrefix: 0,
               protocol: .TCP,
               direction: .outbound)
        ]
        
        try await setTunnelNetworkSettings(proxySettings)
        log.debug("start done")
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        log.debug("stopProxy \(String(describing: reason), privacy: .public)")
    }
    
    override func handleAppMessage(_ messageData: Data) async -> Data? {
        log.debug("handleAppMessage")
        return nil
    }
    
    override func sleep() async {
        //
    }
    
    override func wake() {
        //
    }
    
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        log.debug("handleNewFlow")
        let meta = flow.metaData;
        log.debug("meta \(String(describing: meta), privacy: .public)")
        log.debug("flow \(String(describing: flow), privacy: .public)")
        log.debug("sourceAppSigningIdentifier \(String(describing: meta.sourceAppSigningIdentifier), privacy: .public)")
        log.debug("sourceAppUniqueIdentifier \(String(describing: meta.sourceAppUniqueIdentifier), privacy: .public)")

        log.debug("sourceAppAuditToken \(String(describing: meta.sourceAppAuditToken!), privacy: .public)")

        guard let auditToken = flow.metaData.sourceAppAuditToken else {
              return false
        }

        guard auditToken.count == MemoryLayout<audit_token_t>.size else {
            return false
        }

        let tokenT: audit_token_t? = auditToken.withUnsafeBytes { buf in
          guard let baseAddress = buf.baseAddress else {
            return nil
          }
          return baseAddress.assumingMemoryBound(to: audit_token_t.self).pointee
        }

        guard let token = tokenT else {
          return false
        }

        let pid = audit_token_to_pid(token)
        
        log.debug("pid \(pid)")
        
        let PROC_PIDPATHINFO_MAXSIZE = MAXPATHLEN * 4
    
        let pathBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PROC_PIDPATHINFO_MAXSIZE))
        defer {
            pathBuffer.deallocate()
        }
        let pathLength = proc_pidpath(pid, pathBuffer, UInt32(PROC_PIDPATHINFO_MAXSIZE))
        if pathLength > 0 {
            let path = String(cString: pathBuffer)
            log.debug("  path=\(path, privacy: .public)")
        }
    
        return false
    }
}
