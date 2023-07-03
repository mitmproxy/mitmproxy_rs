//
//  AppDelegate.swift
//  MitmproxyAppleTunnel
//
//  Created by Emanuele Micheletti on 13/06/23.
//

import Cocoa
import OSLog

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    var proxy = Proxy()
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        let pipePath = CommandLine.arguments[1]
        os_log("qqq - arguments are \(CommandLine.arguments, privacy: .public)")
        self.proxy.setPipePath(withPath: pipePath)
        Task.init{
            await self.proxy.processToSkip(pid: CommandLine.arguments[2])
            //os_log("qqq - mitmproxyidentifier: \(self.proxy.mitmproxyIdentifier ?? "no mitmproxy identifier", privacy: .public)")
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

