import NetworkExtension


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
                        let message = MitmproxyIpc_UdpPacket.with {
                            $0.data = datagram
                            $0.remoteAddress = MitmproxyIpc_Address.init(endpoint: endpoint)
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
                    guard let packet = try await conn.receive(ipc: MitmproxyIpc_UdpPacket.self) else {
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
