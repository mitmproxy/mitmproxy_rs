import Foundation
import SwiftProtobuf
import Network

enum IpcError: Error {
    case incompleteRead
    case tooLarge(Int)
}

func readIpcMessage<T: SwiftProtobuf.Message>(ofType: T.Type, fh: FileHandle) throws -> T? {
    // read u32
    guard let len_buf = try fh.read(upToCount: 4) else { return nil }
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

extension UInt32 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt32>.size)
    }
}

extension NWConnection {
    func send(ipc message: SwiftProtobuf.Message) async throws {
        
        let data = try message.serializedData()
        var to_send = Data(capacity: data.count + 4)
        to_send.append(UInt32(data.count).bigEndian.data)
        to_send.append(data)
        assert(to_send.count == data.count + 4)
        
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) -> Void in
            self.send(content: to_send, completion: .contentProcessed({ error in
                if let err = error {
                    continuation.resume(throwing: err)
                } else {
                    continuation.resume()
                }
            }))
        }
    }
}
