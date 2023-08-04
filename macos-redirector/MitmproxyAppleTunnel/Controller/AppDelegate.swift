import Cocoa
import OSLog

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    var proxy = Proxy()
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        let fromRedirectorPipe = CommandLine.arguments[1]
        let fromProxyPipe = CommandLine.arguments[2]
        self.proxy.setPipePath(fromRedirectorPipe, fromProxyPipe)
        self.proxy.getRunningApplication()
        Task.init{
            let interceptConf = DispatchQueue(label: "org.mitmproxy.interceptConf", attributes: .concurrent)
            interceptConf.async {
                self.proxy.interceptConf()
            }
            await self.proxy.initVPNTunnelProviderManager()
            await self.proxy.startTunnel()
        }
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        os_log("qqq - application will terminate")
        Task.init{
            await proxy.clearPreferences()
        }
    }
    
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        os_log("qqq - application should terminate")
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

