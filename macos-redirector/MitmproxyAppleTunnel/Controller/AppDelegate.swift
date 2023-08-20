import Cocoa
import OSLog

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    let logger = Logger()
    var proxy = Proxy()
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        let fromRedirectorPipe = CommandLine.arguments[1]
        let fromProxyPipe = CommandLine.arguments[2]
        let terminalPid = CommandLine.arguments[3]
        self.proxy.setPipePath(fromRedirectorPipe, fromProxyPipe, terminalPid)
        self.proxy.createProcessList()
        Task.init{
            let interceptConf = DispatchQueue(label: "org.mitmproxy.interceptConf", attributes: .concurrent)
            interceptConf.async {
                self.proxy.interceptSpec()
            }
            await self.proxy.initVPNTunnelProviderManager()
            await self.proxy.startTunnel()
        }
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        logger.info("Application will terminate")
        Task.init{
            await proxy.clearPreferences()
        }
    }
    
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        logger.info("Application should terminate")
        Task.init{
            await proxy.clearPreferences()
            NSApplication.shared.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        return true
    }
}

