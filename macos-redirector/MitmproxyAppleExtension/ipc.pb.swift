// DO NOT EDIT.
// swift-format-ignore-file
//
// Generated by the Swift generator plugin for the protocol buffer compiler.
// Source: ipc.proto
//
// For information on using the generated types, please see the documentation:
//   https://github.com/apple/swift-protobuf/

import Foundation
import SwiftProtobuf

// If the compiler emits an error on this type, it is because this file
// was generated by a version of the `protoc` Swift plug-in that is
// incompatible with the version of SwiftProtobuf to which you are linking.
// Please ensure that you are building against the same version of the API
// that was used to generate this file.
fileprivate struct _GeneratedWithProtocGenSwiftVersion: SwiftProtobuf.ProtobufAPIVersionCheck {
  struct _2: SwiftProtobuf.ProtobufAPIVersion_2 {}
  typealias Version = _2
}

struct Mitmproxy_Ipc_Packet {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var data: Data = Data()

  var processName: String = String()

  var pid: Int32 = 0

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

struct Mitmproxy_Ipc_InterceptConf {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var pids: [Int32] = []

  var processNames: [String] = []

  var invert: Bool = false

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}
}

#if swift(>=5.5) && canImport(_Concurrency)
extension Mitmproxy_Ipc_Packet: @unchecked Sendable {}
extension Mitmproxy_Ipc_InterceptConf: @unchecked Sendable {}
#endif  // swift(>=5.5) && canImport(_Concurrency)

// MARK: - Code below here is support for the SwiftProtobuf runtime.

fileprivate let _protobuf_package = "mitmproxy.ipc"

extension Mitmproxy_Ipc_Packet: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".Packet"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "data"),
    2: .standard(proto: "process_name"),
    3: .same(proto: "pid"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBytesField(value: &self.data) }()
      case 2: try { try decoder.decodeSingularStringField(value: &self.processName) }()
      case 3: try { try decoder.decodeSingularInt32Field(value: &self.pid) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.data.isEmpty {
      try visitor.visitSingularBytesField(value: self.data, fieldNumber: 1)
    }
    if !self.processName.isEmpty {
      try visitor.visitSingularStringField(value: self.processName, fieldNumber: 2)
    }
    if self.pid != 0 {
      try visitor.visitSingularInt32Field(value: self.pid, fieldNumber: 3)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Mitmproxy_Ipc_Packet, rhs: Mitmproxy_Ipc_Packet) -> Bool {
    if lhs.data != rhs.data {return false}
    if lhs.processName != rhs.processName {return false}
    if lhs.pid != rhs.pid {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Mitmproxy_Ipc_InterceptConf: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".InterceptConf"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .same(proto: "pids"),
    2: .standard(proto: "process_names"),
    3: .same(proto: "invert"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeRepeatedInt32Field(value: &self.pids) }()
      case 2: try { try decoder.decodeRepeatedStringField(value: &self.processNames) }()
      case 3: try { try decoder.decodeSingularBoolField(value: &self.invert) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    if !self.pids.isEmpty {
      try visitor.visitPackedInt32Field(value: self.pids, fieldNumber: 1)
    }
    if !self.processNames.isEmpty {
      try visitor.visitRepeatedStringField(value: self.processNames, fieldNumber: 2)
    }
    if self.invert != false {
      try visitor.visitSingularBoolField(value: self.invert, fieldNumber: 3)
    }
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Mitmproxy_Ipc_InterceptConf, rhs: Mitmproxy_Ipc_InterceptConf) -> Bool {
    if lhs.pids != rhs.pids {return false}
    if lhs.processNames != rhs.processNames {return false}
    if lhs.invert != rhs.invert {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}
