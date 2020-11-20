public struct SSHConnectionSettings {
    init() {}
    
    public var reconnect = SSHReconnectMode.once
}

public struct SSHReconnectMode: Equatable {
    internal enum Mode {
        case once, always, never
    }
    
    let mode: Mode
    
    public static let once = SSHReconnectMode(mode: .once)
    public static let always = SSHReconnectMode(mode: .always)
    public static let never = SSHReconnectMode(mode: .never)
}

// TODO: Reconnect delegate
