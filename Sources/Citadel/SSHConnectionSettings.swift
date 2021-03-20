internal struct SSHConnectionSettings {
    init() {}
    
    internal var reconnect = _SSHReconnectMode.never
}

internal struct _SSHReconnectMode {
    internal enum Mode {
        case once(String, Int)
        case always(String, Int)
        case never
    }
    
    let mode: Mode
    
    internal static func once(to host: String, port: Int) -> _SSHReconnectMode {
        _SSHReconnectMode(mode: .once(host, port))
    }
    
    internal static func always(to host: String, port: Int) -> _SSHReconnectMode {
        _SSHReconnectMode(mode: .always(host, port))
    }
    
    internal static let never = _SSHReconnectMode(mode: .never)
}

// TODO: Reconnect delegate
public struct SSHReconnectMode: Equatable {
    internal enum _Mode {
        case once, always, never
    }
    
    let mode: _Mode
    
    public static let once = SSHReconnectMode(mode: .once)
    public static let always = SSHReconnectMode(mode: .always)
    public static let never = SSHReconnectMode(mode: .never)
}
