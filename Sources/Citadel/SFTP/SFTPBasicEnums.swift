/// A specific version of the SFTP protocol.
public enum SFTPProtocolVersion: RawRepresentable, Hashable, Comparable, Sendable {
    /// SFTP version 3 - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
    ///
    /// - Note: This is by far the most commonly implemented version of SFTP and the only one
    ///   currently supported by this implementation at the time of this writing.
    case v3
    
    /// A catchall for any other protocol version that may appear.
    ///
    /// Because this implementation, like most others, only supports protocol version 3, there
    /// seems little use to listing the various others, as most were never implemented by anyone
    /// at all and the rest never saw any significant adoption.
    case unsupported(UInt32)
    
    // See `RawRepresentable.rawValue`.
    public var rawValue: UInt32 {
        switch self {
        case .v3: return 3
        case .unsupported(let n): return n
        }
    }
    
    // See `RawRepresentable.init(rawValue:)`.
    public init?(rawValue: UInt32) {
        switch rawValue {
        case 3: self = .v3
        case let n: self = .unsupported(n)
        }
    }

    /// Non-failing overload.
    public init(_ rawValue: UInt32) {
        self.init(rawValue: rawValue)!
    }
}

public enum SFTPMessageType: UInt8 {
    case initialize = 1
    case version = 2
    case openFile = 3
    case closeFile = 4
    case read = 5
    case write = 6
    case lstat = 7
    case fstat = 8
    case setstat = 9
    case fsetstat = 10
    case opendir = 11
    case readdir = 12
    case remove = 13
    case mkdir = 14
    case rmdir = 15
    case realpath = 16
    case stat = 17
    case rename = 18
    case readlink = 19
    case symlink = 20
    
    case status = 101
    case handle = 102
    case data = 103
    case name = 104
    case attributes = 105
    
    case extended = 200
    case extendedReply = 201
    
    public var description: String {
        switch self {
        case .initialize: return "SSH_FXP_INIT"
        case .version: return "SSH_FXP_VERSION"
        case .openFile: return "SSH_FXP_OPEN"
        case .closeFile: return "SSH_FXP_CLOSE"
        case .read: return "SSH_FXP_READ"
        case .write: return "SSH_FXP_WRITE"
        case .lstat: return "SSH_FXP_LSTAT"
        case .fstat: return "SSH_FXP_FSTAT"
        case .setstat: return "SSH_FXP_SETSTAT"
        case .fsetstat: return "SSH_FXP_FSETSTAT"
        case .opendir: return "SSH_FXP_OPENDIR"
        case .readdir: return "SSH_FXP_READDIR"
        case .remove: return "SSH_FXP_REMOVE"
        case .mkdir: return "SSH_FXP_MKDIR"
        case .rmdir: return "SSH_FXP_RMDIR"
        case .realpath: return "SSH_FXP_REALPATH"
        case .stat: return "SSH_FXP_STAT"
        case .rename: return "SSH_FXP_RENAME"
        case .readlink: return "SSH_FXP_READLINK"
        case .symlink: return "SSH_FXP_SYMLINK"

        case .status: return "SSH_FXP_STATUS"
        case .handle: return "SSH_FXP_HANDLE"
        case .data: return "SSH_FXP_DATA"
        case .name: return "SSH_FXP_NAME"
        case .attributes: return "SSH_FXP_ATTRS"
        
        case .extended: return "SSH_FXP_EXTENDED"
        case .extendedReply: return "SSH_FXP_EXTENDED_REPLY"
        }
    }
}

public enum SFTPStatusCode: RawRepresentable, Hashable, CustomDebugStringConvertible, Sendable {
    case ok
    case eof
    case noSuchFile
    case permissionDenied
    case failure
    case badMessage
    case noConnection
    case connectionLost
    case unsupportedOperation
    case unknown(UInt32)
    
    public var rawValue: UInt32 {
        switch self {
        case .ok: return 0
        case .eof: return 1
        case .noSuchFile: return 2
        case .permissionDenied: return 3
        case .failure: return 4
        case .badMessage: return 5
        case .noConnection: return 6
        case .connectionLost: return 7
        case .unsupportedOperation: return 8
        case .unknown(let value): return value
        }
    }
    
    public init?(rawValue: UInt32) {
        switch rawValue {
        case 0: self = .ok
        case 1: self = .eof
        case 2: self = .noSuchFile
        case 3: self = .permissionDenied
        case 4: self = .failure
        case 5: self = .badMessage
        case 6: self = .noConnection
        case 7: self = .connectionLost
        case 8: self = .unsupportedOperation
        case let value: self = .unknown(value)
        }
    }
    
    public init(_ rawValue: UInt32) {
        self.init(rawValue: rawValue)!
    }

    public var debugDescription: String {
        switch self {
        case .ok: return "SSH_FX_OK"
        case .eof: return "SSH_FX_EOF"
        case .noSuchFile: return "SSH_FX_NO_SUCH_FILE"
        case .permissionDenied: return "SSH_FX_PERMISSION_DENIED"
        case .failure: return "SSH_FX_FAILURE"
        case .badMessage: return "SSH_FX_BAD_MESSAGE"
        case .noConnection: return "SSH_FX_NO_CONNECTION"
        case .connectionLost: return "SSH_FX_CONNECTION_LOST"
        case .unsupportedOperation: return "SSH_FX_OP_UNSUPPORTED"
        case .unknown(let value): return "SSH_FX_\(value)"
        }
    }
}
