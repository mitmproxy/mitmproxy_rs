import Foundation
import SwiftProtobuf

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
