import NIO
import Foundation

// pflags
public struct SFTPOpenFileFlags: OptionSet {
    public var rawValue: UInt32
    
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    /// SSH_FXF_READ
    ///
    /// Open the file for reading.
    public static let read = SFTPOpenFileFlags(rawValue: 0x00000001)
    
    /// SSH_FXF_WRITE
    ///
    /// Open the file for writing.  If both this and SSH_FXF_READ are
    /// specified, the file is opened for both reading and writing.
    public static let write = SFTPOpenFileFlags(rawValue: 0x00000002)
    
    /// SSH_FXF_APPEND
    ///
    /// Force all writes to append data at the end of the file.
    public static let append = SFTPOpenFileFlags(rawValue: 0x00000004)
    
    /// SSH_FXF_CREAT
    ///
    /// If this flag is specified, then a new file will be created if one
    /// does not already exist (if O_TRUNC is specified, the new file will
    /// be truncated to zero length if it previously exists).
    public static let create = SFTPOpenFileFlags(rawValue: 0x00000008)
    
    /// SSH_FXF_TRUNC
    ///
    /// Forces an existing file with the same name to be truncated to zero
    /// length when creating a file by specifying SSH_FXF_CREAT.
    /// SSH_FXF_CREAT MUST also be specified if this flag is used.
    public static let truncate = SFTPOpenFileFlags(rawValue: 0x00000010)
    
    /// SSH_FXF_EXCL
    ///
    /// Causes the request to fail if the named file already exists.
    /// SSH_FXF_CREAT MUST also be specified if this flag is used.
    public static let forceCreate = SFTPOpenFileFlags(rawValue: 0x00000020)
}

public struct SFTPFileAttributes {
    public struct Flags: OptionSet {
        public var rawValue: UInt32
        
        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }
        
        public static let size = Flags(rawValue: 0x00000001)
        public static let uidgid = Flags(rawValue: 0x00000002)
        public static let permissions = Flags(rawValue: 0x00000004)
        public static let acmodtime = Flags(rawValue: 0x00000008)
        public static let extended = Flags(rawValue: 0x80000000)
    }
    
    public struct UserGroupId {
        public let userId: UInt32
        public let groupId: UInt32
        
        public init(
            userId: UInt32,
            groupId: UInt32
        ) {
            self.userId = userId
            self.groupId = groupId
        }
    }
    
    public struct AccessModificationTime {
        // Both written as UInt32 seconds since jan 1 1970 as UTC
        public let accessTime: Date
        public let modificationTime: Date
        
        public init(
            accessTime: Date,
            modificationTime: Date
        ) {
            self.accessTime = accessTime
            self.modificationTime = modificationTime
        }
    }
    
    public var flags: Flags {
        var flags: Flags = []
        
        if size != nil {
            flags.insert(.size)
        }
        
        if permissions != nil {
            flags.insert(.permissions)
        }
        
        if accessModificationTime != nil {
            flags.insert(.acmodtime)
        }
        
        if !extended.isEmpty {
            flags.insert(.extended)
        }
        
        return flags
    }
    
    public var size: UInt64?
    public var uidgid: UserGroupId?
    
    // TODO: Permissions as OptionSet
    public var permissions: UInt32?
    public var accessModificationTime: AccessModificationTime?
    public var extended = [(String, String)]()
    
    public init() {}
    // TODO: Extended
//    let extended_count: UInt32?
    
    public static let none = SFTPFileAttributes()
}

enum SFTPMessageType: UInt8 {
    case initialize = 1
    case version = 2
    case openFile = 3
    case closeFile = 4
    case read = 5
    case write = 6
    
    case status = 101
    case handle = 102
    case data = 103
    case name = 104
    case attributes = 105
}

enum SFTPRequest {
    case openFile(SFTPMessage.OpenFile)
    case closeFile(SFTPMessage.CloseFile)
    case read(SFTPMessage.ReadFile)
    case write(SFTPMessage.WriteFile)
    
    var requestId: UInt32 {
        get {
            switch self {
            case .openFile(let message):
                return message.requestId
            case .closeFile(let message):
                return message.requestId
            case .read(let message):
                return message.requestId
            case .write(let message):
                return message.requestId
            }
        }
    }
    
    func makeMessage() -> SFTPMessage {
        switch self {
        case .openFile(let message):
            return .openFile(message)
        case .closeFile(let message):
            return .closeFile(message)
        case .read(let message):
            return .read(message)
        case .write(let message):
            return .write(message)
        }
    }
}

enum SFTPResponse {
    case handle(SFTPMessage.Handle)
    case status(SFTPMessage.Status)
    case data(SFTPMessage.FileData)
    
    var requestId: UInt32 {
        get {
            switch self {
            case .handle(let message):
                return message.requestId
            case .status(let message):
                return message.requestId
            case .data(let message):
                return message.requestId
            }
        }
    }
    
    func makeMessage() -> SFTPMessage {
        switch self {
        case .handle(let message):
            return .handle(message)
        case .status(let message):
            return .status(message)
        case .data(let message):
            return .data(message)
        }
    }
    
    init?(message: SFTPMessage) {
        switch message {
        case .handle(let message):
            self = .handle(message)
        case .status(let message):
            self = .status(message)
        case .data(let message):
            self = .data(message)
        case .openFile, .closeFile, .read, .write, .initialize, .version:
            return nil
        }
    }
}

enum SFTPMessage {
    struct Initialize {
        static let id = SFTPMessageType.initialize
        
        let version: UInt32
    }
    
    struct Version {
        static let id = SFTPMessageType.version
        
        let version: UInt32
        let extensionData: [(String, String)]
    }
    
    struct OpenFile {
        static let id = SFTPMessageType.openFile
        
        var requestId: UInt32
        
        // Called `filename` in spec
        let filePath: String
        
        let pFlags: SFTPOpenFileFlags
        let attributes: SFTPFileAttributes
    }
    
    struct CloseFile {
        static let id = SFTPMessageType.closeFile
        
        var requestId: UInt32
        var handle: ByteBuffer
    }
    
    struct ReadFile {
        static let id = SFTPMessageType.read
        
        var requestId: UInt32
        var handle: ByteBuffer
        var offset: UInt64
        var length: UInt32
    }
    
    struct WriteFile {
        static let id = SFTPMessageType.write
        
        var requestId: UInt32
        var handle: ByteBuffer
        var offset: UInt64
        var data: ByteBuffer
    }
    
    struct Status: Error {
        static let id = SFTPMessageType.status
        
        let requestId: UInt32
        let errorCode: UInt32
        let message: String
        let languageTag: String
    }
    
    struct Handle {
        static let id = SFTPMessageType.handle
        
        let requestId: UInt32
        var handle: ByteBuffer
    }
    
    struct FileData {
        static let id = SFTPMessageType.data
        
        let requestId: UInt32
        var data: ByteBuffer
    }
    
    case initialize(Initialize)
    case version(Version)
    
    /// Client.
    ///
    /// Receives `handle` on success and `status` on failure
    case openFile(OpenFile)
    
    /// Client.
    ///
    /// Close file immediately invaldiates the handle
    /// The only valid response is `status`
    case closeFile(CloseFile)
    
    case read(ReadFile)
    
    case write(WriteFile)
    
    /// Server.
    ///
    /// Successfully opened a file
    case handle(Handle)
    
    /// Server.
    ///
    /// Successfully closed a file, or failed to open a file
    case status(Status)
    
    case data(FileData)
}
