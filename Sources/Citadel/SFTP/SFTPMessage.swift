import NIO
import Foundation

public struct SFTPPathComponent {
    public let filename: String
    public let longname: String
    public let attributes: SFTPFileAttributes
    
    public init(filename: String, longname: String, attributes: SFTPFileAttributes) {
        self.filename = filename
        self.longname = longname
        self.attributes = attributes
    }
}

public struct SFTPFileListing {
    public let path: [SFTPPathComponent]
    
    public init(path: [SFTPPathComponent]) {
        self.path = path
    }
}

enum SFTPRequest: CustomDebugStringConvertible {
    case openFile(SFTPMessage.OpenFile)
    case closeFile(SFTPMessage.CloseFile)
    case read(SFTPMessage.ReadFile)
    case write(SFTPMessage.WriteFile)
    case mkdir(SFTPMessage.MkDir)
    case stat(SFTPMessage.Stat)
    case fstat(SFTPMessage.FileStat)
    case readdir(SFTPMessage.ReadDir)
    case opendir(SFTPMessage.OpenDir)
    case realpath(SFTPMessage.RealPath)
    
    var requestId: UInt32 {
        get {
            switch self {
            case .openFile(let message):
                return message.requestId
            case .opendir(let message):
                return message.requestId
            case .closeFile(let message):
                return message.requestId
            case .read(let message):
                return message.requestId
            case .write(let message):
                return message.requestId
            case .mkdir(let message):
                return message.requestId
            case .stat(let message):
                return message.requestId
            case .fstat(let message):
                return message.requestId
            case .readdir(let message):
                return message.requestId
            case .realpath(let message):
                return message.requestId
            }
        }
    }
    
    func makeMessage() -> SFTPMessage {
        switch self {
        case .openFile(let message):
            return .openFile(message)
        case .opendir(let message):
            return .opendir(message)
        case .closeFile(let message):
            return .closeFile(message)
        case .read(let message):
            return .read(message)
        case .write(let message):
            return .write(message)
        case .mkdir(let message):
            return .mkdir(message)
        case .stat(let message):
            return .stat(message)
        case .fstat(let message):
            return .fstat(message)
        case .readdir(let message):
            return .readdir(message)
        case .realpath(let message):
            return .realpath(message)
        }
    }
    
    var debugDescription: String {
        switch self {
        case .openFile(let message): return message.debugDescription
        case .closeFile(let message): return message.debugDescription
        case .read(let message): return message.debugDescription
        case .write(let message): return message.debugDescription
        case .mkdir(let message): return message.debugDescription
        case .stat(let message): return message.debugDescription
        case .fstat(let message): return message.debugDescription
        case .readdir(let message): return message.debugDescription
        case .opendir(let message): return message.debugDescription
        case .realpath(let message): return message.debugDescription
        }
    }
}

enum SFTPResponse {
    case handle(SFTPMessage.Handle)
    case status(SFTPMessage.Status)
    case data(SFTPMessage.FileData)
    case mkdir(SFTPMessage.MkDir)
    case name(SFTPMessage.Name)
    case attributes(SFTPMessage.Attributes)
    
    var requestId: UInt32 {
        get {
            switch self {
            case .handle(let message):
                return message.requestId
            case .status(let message):
                return message.requestId
            case .data(let message):
                return message.requestId
            case .mkdir(let message):
                return message.requestId
            case .name(let message):
                return message.requestId
            case .attributes(let message):
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
        case .mkdir(let message):
            return .mkdir(message)
        case .name(let message):
            return .name(message)
        case .attributes(let message):
            return .attributes(message)
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
        case .mkdir(let message):
            self = .mkdir(message)
        case .name(let message):
            self = .name(message)
        case .attributes(let message):
            self = .attributes(message)
        case .realpath, .openFile, .fstat, .closeFile, .read, .write, .initialize, .version, .stat, .lstat, .rmdir, .opendir, .readdir, .remove, .fsetstat, .setstat, .symlink, .readlink:
            return nil
        }
    }
    
    var debugDescription: String {
        switch self {
        case .handle(let message): return message.debugDescription
        case .status(let message): return message.debugDescription
        case .data(let message): return message.debugDescription
        case .mkdir(let message): return message.debugDescription
        case .name(let message): return message.debugDescription
        case .attributes(let message): return message.debugDescription
        }
    }
}

public protocol SFTPMessageContent: CustomDebugStringConvertible {
    static var id: SFTPMessageType { get }
}

extension SFTPMessageContent {
    fileprivate var id: SFTPMessageType { Self.id }
    fileprivate var debugVariantWithoutLargeData: Self { self }
}

public enum SFTPMessage {
    public struct Initialize: SFTPMessageContent {
        public static let id = SFTPMessageType.initialize
        
        public let version: SFTPProtocolVersion
        
        public var debugDescription: String { "(version: \(version))" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct Version: SFTPMessageContent {
        public static let id = SFTPMessageType.version
        
        public let version: SFTPProtocolVersion
        public let extensionData: [(String, String)]
        
        public var debugDescription: String { "(\(self.version), extensions: [\(extensionData.map(\.0).joined(separator: ", "))])" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct OpenFile: SFTPMessageContent {
        public static let id = SFTPMessageType.openFile
        
        public var requestId: UInt32
        
        // Called `filename` in spec
        public let filePath: String
        
        public let pFlags: SFTPOpenFileFlags
        public let attributes: SFTPFileAttributes
        
        public var debugDescription: String { "{\(self.requestId)}('\(self.filePath)', flags: \(self.pFlags.debugDescription), attrs: \(self.attributes.debugDescription))" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct CloseFile: SFTPMessageContent {
        public static let id = SFTPMessageType.closeFile
        
        public var requestId: UInt32
        public var handle: ByteBuffer
        
        public var debugDescription: String { "{\(self.requestId)}(\(self.handle.sftpHandleDebugDescription))" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct ReadFile: SFTPMessageContent {
        public static let id = SFTPMessageType.read
        
        public var requestId: UInt32
        public var handle: ByteBuffer
        public var offset: UInt64
        public var length: UInt32
        
        public var debugDescription: String { "{\(self.requestId)}(\(self.handle.sftpHandleDebugDescription), \(self.length) bytes from \(self.offset))" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct WriteFile: SFTPMessageContent {
        public static let id = SFTPMessageType.write
        
        public var requestId: UInt32
        public var handle: ByteBuffer
        public var offset: UInt64
        public var data: ByteBuffer
        
        public var debugDescription: String { "{\(self.requestId)}(\(self.handle.sftpHandleDebugDescription), <\(data.readableBytes) bytes> to \(self.offset))" }
        fileprivate var debugVariantWithoutLargeData: Self { .init(requestId: self.requestId, handle: self.handle, offset: self.offset, data: .init()) }
    }
    
    public struct Status: Error, SFTPMessageContent {
        public static let id = SFTPMessageType.status
        
        public let requestId: UInt32
        public let errorCode: SFTPStatusCode
        public let message: String
        public let languageTag: String
        
        public var localizedDescription: String { "\(message)" }
        public var debugDescription: String { "{\(self.requestId)}(code: \(self.errorCode.debugDescription), \(self.languageTag)#'\(self.message)')" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct Handle: SFTPMessageContent {
        public static let id = SFTPMessageType.handle
        
        public let requestId: UInt32
        public var handle: ByteBuffer
        
        public var debugDescription: String { "{\(self.requestId)}(\(self.handle.sftpHandleDebugDescription))" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct FileStat: SFTPMessageContent {
        public static let id = SFTPMessageType.fstat
        
        public let requestId: UInt32
        public var handle: ByteBuffer
        
        public var debugDescription: String { "{\(self.requestId)}(\(self.handle.sftpHandleDebugDescription))" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct Remove: SFTPMessageContent {
        public static let id = SFTPMessageType.remove
        
        public let requestId: UInt32
        public var filename: String
        
        public var debugDescription: String { "{\(self.requestId)}(\(self.filename))" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct FileSetStat: SFTPMessageContent {
        public static let id = SFTPMessageType.fsetstat
        
        public let requestId: UInt32
        public var handle: ByteBuffer
        public var attributes: SFTPFileAttributes
        
        public var debugDescription: String { "{\(self.requestId)}(\(self.handle),\(self.attributes)" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct SetStat: SFTPMessageContent {
        public static let id = SFTPMessageType.setstat
        
        public let requestId: UInt32
        public var path: String
        public var attributes: SFTPFileAttributes
        
        public var debugDescription: String { "{\(self.requestId)}(\(self.path),\(self.attributes)" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct Symlink: SFTPMessageContent {
        public static let id = SFTPMessageType.symlink
        
        public let requestId: UInt32
        public var linkPath: String
        public var targetPath: String
        
        public var debugDescription: String { "{\(self.requestId)}(\(self.linkPath),\(self.targetPath)" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct Readlink: SFTPMessageContent {
        public static let id = SFTPMessageType.symlink
        
        public let requestId: UInt32
        public var path: String
        
        public var debugDescription: String { "{\(self.requestId)}(\(self.path)" }
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct FileData: SFTPMessageContent {
        public static let id = SFTPMessageType.data
        
        public let requestId: UInt32
        public var data: ByteBuffer
        
        public var debugDescription: String { "{\(self.requestId)}(<\(data.readableBytes) bytes>)" }
        fileprivate var debugVariantWithoutLargeData: Self { .init(requestId: self.requestId, data: .init()) }
    }
    
    public struct MkDir: SFTPMessageContent {
        public static let id = SFTPMessageType.mkdir
        
        public let requestId: UInt32

        public let filePath: String
        public let attributes: SFTPFileAttributes
        
        public var debugDescription: String { "{\(self.requestId)}('\(self.filePath)', attrs: \(self.attributes.debugDescription))" }

        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct RmDir: SFTPMessageContent {
        public static let id = SFTPMessageType.rmdir
        
        public let requestId: UInt32
        
        public let filePath: String
        
        public var debugDescription: String { "{\(self.requestId)}('\(self.filePath)')" }
        
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct OpenDir: SFTPMessageContent {
        public static let id = SFTPMessageType.opendir
        
        public let requestId: UInt32
        
        public let handle: String
        
        public var debugDescription: String { "{\(self.requestId)}('\(self.handle)')" }
        
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct Stat: SFTPMessageContent {
        public static let id = SFTPMessageType.stat
        
        public let requestId: UInt32
        public let path: String
        
        public var debugDescription: String { "{\(self.requestId)}('\(self.path)')" }
        
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct LStat: SFTPMessageContent {
        public static let id = SFTPMessageType.lstat
        
        public let requestId: UInt32
        public let path: String
        
        public var debugDescription: String { "{\(self.requestId)}('\(self.path)')" }
        
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct RealPath: SFTPMessageContent {
        public static let id = SFTPMessageType.realpath
        
        public let requestId: UInt32
        public let path: String
        
        public var debugDescription: String { "{\(self.requestId)}('\(self.path)')" }
        
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct Name: SFTPMessageContent {
        public static let id = SFTPMessageType.name
        
        public let requestId: UInt32
        public var count: UInt32 { UInt32(components.count) }
        public let components: [SFTPPathComponent]
        
        var path: String {
            return components.map(\.filename).joined(separator: "/")
        }
        
        public var debugDescription: String { "{\(self.requestId)}('\(self.count)', components)" }
        
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct Attributes: SFTPMessageContent {
        public static let id = SFTPMessageType.attributes
        
        public let requestId: UInt32
        public let attributes: SFTPFileAttributes
        
        public var debugDescription: String { "{\(self.requestId)}('\(self.attributes)'" }
        
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    public struct ReadDir: SFTPMessageContent {
        public static let id = SFTPMessageType.readdir
        
        public let requestId: UInt32
        public internal(set) var handle: ByteBuffer
        
        public var debugDescription: String { "{\(self.requestId)}('\(self.handle)'" }
        
        fileprivate var debugVariantWithoutLargeData: Self { self }
    }
    
    /// Client.
    ///
    /// Starts SFTP session and indicates client version.
    /// Response is `version`.
    case initialize(Initialize)
    
    /// Server.
    ///
    /// Indicates server version and supported extensions.
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
    
    /// Client.
    ///
    /// Response is `data` on success or `status` on failure.
    case read(ReadFile)
    
    /// Client.
    ///
    /// Response is `status`.
    case write(WriteFile)
    
    /// Server.
    ///
    /// Successfully opened a file
    case handle(Handle)
    
    /// Server.
    ///
    /// Successfully closed a file, or failed to open a file
    case status(Status)
    
    /// Server.
    ///
    /// Data read from file.
    case data(FileData)
    
    /// Server.
    ///
    /// No response, directory gets created or an error is thrown.
    case mkdir(MkDir)
    
    case rmdir(RmDir)
    case opendir(OpenDir)
    case stat(Stat)
    case fstat(FileStat)
    case remove(Remove)
    case fsetstat(FileSetStat)
    case setstat(SetStat)
    case symlink(Symlink)
    case readlink(Readlink)
    case lstat(LStat)
    case realpath(RealPath)
    case name(Name)
    case attributes(Attributes)
    case readdir(ReadDir)
    
    public var messageType: SFTPMessageType {
        switch self {
        case
                .initialize(let message as SFTPMessageContent),
                .version(let message as SFTPMessageContent),
                .openFile(let message as SFTPMessageContent),
                .closeFile(let message as SFTPMessageContent),
                .read(let message as SFTPMessageContent),
                .write(let message as SFTPMessageContent),
                .handle(let message as SFTPMessageContent),
                .status(let message as SFTPMessageContent),
                .data(let message as SFTPMessageContent),
                .mkdir(let message as SFTPMessageContent),
                .stat(let message as SFTPMessageContent),
                .fstat(let message as SFTPMessageContent),
                .lstat(let message as SFTPMessageContent),
                .attributes(let message as SFTPMessageContent),
                .rmdir(let message as SFTPMessageContent),
                .realpath(let message as SFTPMessageContent),
                .name(let message as SFTPMessageContent),
                .opendir(let message as SFTPMessageContent),
                .readdir(let message as SFTPMessageContent),
                .remove(let message as SFTPMessageContent),
                .fsetstat(let message as SFTPMessageContent),
                .setstat(let message as SFTPMessageContent),
                .symlink(let message as SFTPMessageContent),
                .readlink(let message as SFTPMessageContent):
            return message.id
        }
    }
    
    public var debugDescription: String {
        switch self {
        case
                .initialize(let message as SFTPMessageContent),
                .version(let message as SFTPMessageContent),
                .openFile(let message as SFTPMessageContent),
                .closeFile(let message as SFTPMessageContent),
                .read(let message as SFTPMessageContent),
                .write(let message as SFTPMessageContent),
                .handle(let message as SFTPMessageContent),
                .status(let message as SFTPMessageContent),
                .data(let message as SFTPMessageContent),
                .mkdir(let message as SFTPMessageContent),
                .stat(let message as SFTPMessageContent),
                .fstat(let message as SFTPMessageContent),
                .lstat(let message as SFTPMessageContent),
                .attributes(let message as SFTPMessageContent),
                .rmdir(let message as SFTPMessageContent),
                .realpath(let message as SFTPMessageContent),
                .name(let message as SFTPMessageContent),
                .opendir(let message as SFTPMessageContent),
                .readdir(let message as SFTPMessageContent),
                .remove(let message as SFTPMessageContent),
                .fsetstat(let message as SFTPMessageContent),
                .setstat(let message as SFTPMessageContent),
                .symlink(let message as SFTPMessageContent),
                .readlink(let message as SFTPMessageContent):
            return "\(message.id)\(message.debugDescription)"
        }
    }
    
    private var debugVariantWithoutLargeData: SFTPMessage {
        switch self {
        case .initialize(let message): return Self.initialize(message.debugVariantWithoutLargeData)
        case .version(let message): return Self.version(message.debugVariantWithoutLargeData)
        case .openFile(let message): return Self.openFile(message.debugVariantWithoutLargeData)
        case .closeFile(let message): return Self.closeFile(message.debugVariantWithoutLargeData)
        case .read(let message): return Self.read(message.debugVariantWithoutLargeData)
        case .write(let message): return Self.write(message.debugVariantWithoutLargeData)
        case .handle(let message): return Self.handle(message.debugVariantWithoutLargeData)
        case .status(let message): return Self.status(message.debugVariantWithoutLargeData)
        case .data(let message): return Self.data(message.debugVariantWithoutLargeData)
        case .mkdir(let message): return Self.mkdir(message.debugVariantWithoutLargeData)
        case .stat(let message): return Self.stat(message.debugVariantWithoutLargeData)
        case .fstat(let message): return Self.fstat(message.debugVariantWithoutLargeData)
        case .lstat(let message): return Self.lstat(message.debugVariantWithoutLargeData)
        case .attributes(let message): return Self.attributes(message.debugVariantWithoutLargeData)
        case .rmdir(let message): return Self.rmdir(message.debugVariantWithoutLargeData)
        case .realpath(let message): return Self.realpath(message.debugVariantWithoutLargeData)
        case .name(let message): return Self.name(message.debugVariantWithoutLargeData)
        case .opendir(let message): return Self.opendir(message.debugVariantWithoutLargeData)
        case .readdir(let message): return Self.readdir(message.debugVariantWithoutLargeData)
        case .remove(let message): return Self.remove(message.debugVariantWithoutLargeData)
        case .fsetstat(let message): return Self.fsetstat(message.debugVariantWithoutLargeData)
        case .setstat(let message): return Self.setstat(message.debugVariantWithoutLargeData)
        case .symlink(let message): return Self.symlink(message.debugVariantWithoutLargeData)
        case .readlink(let message): return Self.readlink(message.debugVariantWithoutLargeData)
        }
    }
    
    /// Returns a stringified representation of the packet's serialized data bytes, omitting large data buffers
    /// such as outgoing file data.
    internal var debugRawBytesRepresentation: String {
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        try! SFTPMessageSerializer().encode(data: self.debugVariantWithoutLargeData, out: &buffer)
        return buffer.readableBytesView.map { "0\(String($0, radix: 16))".suffix(2) }.joined(separator: " ")
    }
}
