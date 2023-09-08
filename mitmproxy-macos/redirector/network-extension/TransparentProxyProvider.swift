import NetworkExtension

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
        return true
    }
}
