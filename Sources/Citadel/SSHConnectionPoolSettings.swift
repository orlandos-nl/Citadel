internal struct SSHConnectionPoolSettings {
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

public struct SSHReconnectMode: Equatable, Sendable {
    internal enum _Mode {
        case once, always, never
    }
    
    let mode: _Mode
    
    /// Reconnect to the same host and port once.
    public static let once = SSHReconnectMode(mode: .once)

    /// Reconnect to the same host and port every time the connection is lost.
    public static let always = SSHReconnectMode(mode: .always)

    /// Never reconnect.
    public static let never = SSHReconnectMode(mode: .never)
}
