import Foundation
import SwiftProtobuf
import OSLog

enum IpcError: Error {
    case emptyRead
    case incompleteRead
    case tooLarge(Int)
}

func readIpcMessage<T: SwiftProtobuf.Message>(ofType: T.Type, fh: FileHandle) throws -> T? {
    // read u32
    guard let len_buf = try fh.read(upToCount: 4) else { throw IpcError.emptyRead }
    guard len_buf.count == 4 else { throw IpcError.incompleteRead }
    let len = len_buf[...].reduce(Int(0)) { $0 << 8 + Int($1) };
    // 4x \n (testing)
    if len == 168430090 {
        return nil
    }
    guard len < 1024 * 1024 else { throw IpcError.tooLarge(len) }
    // read protobuf data
    guard let data = try fh.read(upToCount: len) else { throw IpcError.incompleteRead }
    guard data.count == len else { throw IpcError.incompleteRead }
    // decode protobuf
    return try T(contiguousBytes: data)
}


func writeIpcMessage(message: SwiftProtobuf.Message, fh: FileHandle) throws {
    let data = try message.serializedData()
    let len = withUnsafeBytes(of: UInt32(data.count).bigEndian, Array.init)
    try fh.write(contentsOf: len)
    try fh.write(contentsOf: data)
}

class Log {
    var logFile: FileHandle? = nil
    var category = String()
    
    init(category: String){
        self.category = category
    }
    init(category: String, file: FileHandle){
        self.category = category
        self.logFile = file
    }

    func debug(_ message: String, consoleOnly: Bool = false) {
        log(level: .debug, message: message, consoleOnly)
    }
    
    func info(_ message: String, consoleOnly: Bool = false) {
        log(level: .info, message: message, consoleOnly)
    }
    
    func warning(_ message: String, consoleOnly: Bool = false) {
        log(level: .warning, message: message, consoleOnly)
    }
    
    func error(_ message: String, consoleOnly: Bool = false) {
        log(level: .error, message: message, consoleOnly)
    }
    
    private func log(level: Mitmproxy_Ipc_FromRedirector.LogMessage.LogLevel, message: String, _ consoleOnly: Bool) {
        let log = Logger(subsystem: "org.mitmproxy.macos-redirector", category: category)
        let osLogType: OSLogType
        switch level {
            case .debug:
                osLogType = .debug
            case .info:
                osLogType = .info
            case .error:
                osLogType = .error
            case .warning:
                osLogType = .fault
            default:
                osLogType = .default
        }
        log.log(level: osLogType ,"\(message, privacy: .public)")
        
        if let logFile = self.logFile,
        !consoleOnly{
            do {
                var fromRedirector = Mitmproxy_Ipc_FromRedirector()
                fromRedirector.log.level = level
                fromRedirector.log.message = message
                try writeIpcMessage(message: fromRedirector, fh: logFile)
            } catch {
                log.error("sendSignal errored: \(error)")
            }
        }
    }
}
