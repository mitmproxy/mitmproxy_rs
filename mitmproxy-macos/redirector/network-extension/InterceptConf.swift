import Foundation

enum Action {
    case includeAll
    case include(Pattern)
    case exclude(Pattern)

    init(from string: String) throws {
        if string == "*" {
            self = .includeAll
        } else if string.hasPrefix("!") {
        self = .exclude(Pattern(from: String(string.dropFirst())))

        } else {
            self = .include(Pattern(from: string))
        }
    }
}

enum Pattern {
    case pid(UInt32)
    case process(String)

    init(from string: String) {
        if let pid = UInt32(string) {
            self = .pid(pid)
        } else {
            self = .process(string)
        }
    }

    func matches(_ processInfo: ProcessInfo) -> Bool {
        switch self {
        case .pid(let pid):
            return processInfo.pid == pid
        case .process(let name):
            if let processName = processInfo.path {
                return processName.contains(name)
            } else {
                return false 
            }
        }
    }
}


/// The intercept spec decides whether a TCP/UDP flow should be intercepted or not.
class InterceptConf {

    private var actions: [Action]
    
    init(actions: [Action]) {
        self.actions = actions
    }
    
    convenience init(from ipc: MitmproxyIpc_InterceptConf) throws {
        let actions = try ipc.actions.map { try Action(from: $0) }
        self.init(actions: actions)
    }
    
    /// Mirrored after the Rust implementation
    func shouldIntercept(_ processInfo: ProcessInfo) -> Bool {
        var intercept = false
        
        for action in actions {
            switch action {
            case .includeAll:
                intercept = true
            case .include(let pattern):
                intercept = intercept || pattern.matches(processInfo)
            case .exclude(let pattern):
                intercept = intercept && !pattern.matches(processInfo)
            }
        }
        
        return intercept
    }

}
