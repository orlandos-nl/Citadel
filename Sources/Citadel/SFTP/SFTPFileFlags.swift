import Foundation

// pflags
public struct SFTPOpenFileFlags: OptionSet, CustomDebugStringConvertible, Sendable {
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
    
    public var debugDescription: String {
        String(format: "0x%08x", self.rawValue)
    }
}

public struct SFTPFileAttributes: CustomDebugStringConvertible, Sendable {
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
    
    public struct UserGroupId: Sendable {
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
    
    public struct AccessModificationTime: Sendable {
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
        
        if uidgid != nil {
            flags.insert(.uidgid)
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
    
    public init(size: UInt64? = nil, accessModificationTime: AccessModificationTime? = nil) {
        self.size = size
        self.accessModificationTime = accessModificationTime
    }
    
    public static let none = SFTPFileAttributes()
    public static let all: SFTPFileAttributes = {
        var attr = SFTPFileAttributes()
//        attr.permissions = 777
        return attr
    }()
    
    public var debugDescription: String { "{perm: \(String(describing: permissions)), size: \(String(describing: size)), uidgid: \(String(describing: uidgid))}" }
}

