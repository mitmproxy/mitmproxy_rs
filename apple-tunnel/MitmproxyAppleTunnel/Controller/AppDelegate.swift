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
        os_log("qqq - pipe path is: \(pipePath, privacy: .public)")
        self.proxy.setPipePath(withPath: pipePath)
        Task.init{
            if CommandLine.arguments.count > 2 {
                await self.proxy.setProcessMatch(withString: CommandLine.arguments[2])
                os_log("qqq - process to match: \(CommandLine.arguments[2], privacy: .public)")
            } else {
                os_log("qqq - no process to match as arguments")
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

