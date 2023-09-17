import Foundation

/// The intercept spec decides whether a TCP/UDP flow should be intercepted or not.
class InterceptConf {
    
    private var pids: Set<UInt32>
    private var processNames: [String]
    var invert: Bool = false
    
    init(pids: Set<UInt32>, processNames: [String], invert: Bool) {
        self.pids = pids
        self.processNames = processNames
        self.invert = invert
        if self.invert {
            assert(!(self.processNames.isEmpty && self.pids.isEmpty))
        }
    }
    
    convenience init(from ipc: Mitmproxy_Ipc_InterceptConf) {
        self.init(
            pids: Set(ipc.pids),
            processNames: ipc.processNames,
            invert: ipc.invert
        )
    }
    
    /// Mirrored after the Rust implementation
    func shouldIntercept(_ processInfo: ProcessInfo) -> Bool {
        let intercept: Bool
        if self.pids.contains(processInfo.pid) {
            intercept = true
        } else if let path = processInfo.path {
            intercept = self.processNames.contains(where: {path.contains($0)})
        } else {
            intercept = false
        }
        return self.invert != intercept
    }

}
