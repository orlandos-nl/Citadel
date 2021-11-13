import NIO
import Foundation

enum SFTPRequest: CustomDebugStringConvertible {
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
    
    var debugDescription: String {
        switch self {
        case .openFile(let message): return message.debugDescription
        case .closeFile(let message): return message.debugDescription
        case .read(let message): return message.debugDescription
        case .write(let message): return message.debugDescription
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
    
    var debugDescription: String {
        switch self {
        case .handle(let message): return message.debugDescription
        case .status(let message): return message.debugDescription
        case .data(let message): return message.debugDescription
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
        
        public var debugDescription: String { "(\(self.version), extensions: [\(extensionData.map(\.0).joined(separator: ", "))]" }
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
    
    public struct FileData: SFTPMessageContent {
        public static let id = SFTPMessageType.data
        
        public let requestId: UInt32
        public var data: ByteBuffer
        
        public var debugDescription: String { "{\(self.requestId)}(<\(data.readableBytes) bytes>)" }
        fileprivate var debugVariantWithoutLargeData: Self { .init(requestId: self.requestId, data: .init()) }
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
    
    public var messageType: SFTPMessageType {
        switch self {
        case .initialize(let message as SFTPMessageContent), .version(let message as SFTPMessageContent),
             .openFile(let message as SFTPMessageContent), .closeFile(let message as SFTPMessageContent),
             .read(let message as SFTPMessageContent), .write(let message as SFTPMessageContent),
             .handle(let message as SFTPMessageContent), .status(let message as SFTPMessageContent),
             .data(let message as SFTPMessageContent):
            return message.id
        }
    }
    
    public var debugDescription: String {
        switch self {
        case .initialize(let message as SFTPMessageContent), .version(let message as SFTPMessageContent),
             .openFile(let message as SFTPMessageContent), .closeFile(let message as SFTPMessageContent),
             .read(let message as SFTPMessageContent), .write(let message as SFTPMessageContent),
             .handle(let message as SFTPMessageContent), .status(let message as SFTPMessageContent),
             .data(let message as SFTPMessageContent):
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
