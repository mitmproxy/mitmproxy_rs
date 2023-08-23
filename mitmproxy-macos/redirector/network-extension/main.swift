import Foundation
import NetworkExtension
import OSLog

let log = Logger(subsystem: "org.mitmproxy.macos-redirector", category: "extension")
let networkExtensionIdentifier = "org.mitmproxy.macos-redirector.network-extension"

autoreleasepool {
    log.error("starting system extension")
    log.debug("debug-level logging active")
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
