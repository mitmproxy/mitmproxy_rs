import Foundation

struct ProcessInfo {
    var pid: Int
    var path: String?
}


let PROC_PIDPATHINFO_MAXSIZE = UInt32(MAXPATHLEN * 4)


class ProcessInfoCache {
    private static var cache: [Data: ProcessInfo] = [:]
        
    static func getInfo(fromAuditToken tokenData: Data?) -> ProcessInfo? {
        guard let tokenData = tokenData
        else { return nil }
        
        if let cached = cache[tokenData] {
            return cached
        }
        
        // Data -> audit_token_t
        guard tokenData.count == MemoryLayout<audit_token_t>.size
        else { return nil }
        let token = tokenData.withUnsafeBytes { buf in
            buf.baseAddress!.assumingMemoryBound(to: audit_token_t.self).pointee
        }
        
        let pid = audit_token_to_pid(token)
        // log.debug("pid \(pid)")
        
        // pid -> path
        let pathBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(PROC_PIDPATHINFO_MAXSIZE))
        defer {
            pathBuffer.deallocate()
        }
        let path: String?;
        if proc_pidpath(pid, pathBuffer, PROC_PIDPATHINFO_MAXSIZE) > 0 {
            path = String(cString: pathBuffer)
        } else {
            path = nil;
        }
        
        let procInfo = ProcessInfo(pid: Int(pid), path: path)
        cache[tokenData] = procInfo
        return procInfo
    }
}
