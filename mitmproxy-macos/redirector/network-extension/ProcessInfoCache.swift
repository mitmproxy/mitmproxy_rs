import Foundation

struct ProcessInfo {
    var pid: UInt32
    var path: String?
}

let PROC_PIDPATHINFO_MAXSIZE = UInt32(MAXPATHLEN * 4)

/// An audit token -> (pid, process path) lookup cache.
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

        // pid -> path
        let pathBuffer = UnsafeMutablePointer<UInt8>.allocate(
            capacity: Int(PROC_PIDPATHINFO_MAXSIZE))
        defer {
            pathBuffer.deallocate()
        }
        let path: String?
        if proc_pidpath(pid, pathBuffer, PROC_PIDPATHINFO_MAXSIZE) > 0 {
            path = String(cString: pathBuffer)
        } else {
            path = nil
        }

        let procInfo = ProcessInfo(pid: UInt32(pid), path: path)
        cache[tokenData] = procInfo
        return procInfo
    }
}
