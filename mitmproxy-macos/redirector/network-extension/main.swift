import Foundation
import NetworkExtension
import OSLog

let log = Logger(subsystem: "org.mitmproxy.macos-redirector", category: "extension")
let networkExtensionIdentifier = "org.mitmproxy.macos-redirector.network-extension"

autoreleasepool {
    let version = Bundle.main.infoDictionary!["CFBundleShortVersionString"] as! String
    log.error("starting mitmproxy redirector \(version, privacy: .public) system extension")
    log.debug("debug-level logging active")
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
