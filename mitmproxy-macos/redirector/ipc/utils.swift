import Foundation
import Network
import NetworkExtension
import SwiftProtobuf

extension UInt32 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt32>.size)
    }
}

enum IpcError: Error {
    case incompleteRead
}

extension NWConnection {
    func send(ipc message: SwiftProtobuf.Message) async throws {

        let data = try message.serializedData()
        var to_send = Data(capacity: data.count + 4)
        to_send.append(UInt32(data.count).bigEndian.data)
        to_send.append(data)
        assert(to_send.count == data.count + 4)

        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) -> Void in
            self.send(
                content: to_send,
                completion: .contentProcessed({ error in
                    if let err = error {
                        continuation.resume(throwing: err)
                    } else {
                        continuation.resume()
                    }
                }))
        }
    }

    func receive<T: SwiftProtobuf.Message>(ipc: T.Type) async throws -> T? {
        return try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<T?, _>) -> Void in
            receive(
                minimumIncompleteLength: 4, maximumLength: 4,
                completion: { len_buf, _, _, _ in
                    guard
                        let len_buf = len_buf,
                        len_buf.count == 4
                    else {
                        if len_buf == nil {
                            return continuation.resume(returning: nil)
                        } else {
                            return continuation.resume(throwing: IpcError.incompleteRead)
                        }
                    }
                    let len = len_buf[...].reduce(Int(0)) { $0 << 8 + Int($1) }

                    self.receive(minimumIncompleteLength: len, maximumLength: len) {
                        data, _, _, _ in
                        guard
                            let data = data,
                            data.count == len
                        else {
                            return continuation.resume(throwing: IpcError.incompleteRead)
                        }
                        do {
                            let message = try T(contiguousBytes: data)
                            continuation.resume(returning: message)
                        } catch {
                            continuation.resume(throwing: error)
                        }
                    }
                })
        }
    }
}

extension Mitmproxy_Ipc_Address {
    init(endpoint: NWHostEndpoint) {
        self.init()
        self.host = endpoint.hostname
        self.port = UInt32(endpoint.port)!
    }
}

extension NWHostEndpoint {
    convenience init(address: Mitmproxy_Ipc_Address) {
        self.init(hostname: address.host, port: String(address.port))
    }
}
