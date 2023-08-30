import Foundation
import NetworkExtension

let networkExtensionIdentifier = "org.mitmproxy.macos-redirector.network-extension"
let log = Log(category: "extension")

autoreleasepool {
    log.error("starting system extension")
    log.debug("debug-level logging active")
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
