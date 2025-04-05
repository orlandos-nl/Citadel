import Foundation
import NIO
import NIOSSH
import Logging

/// Represents a file in the SFTP subsystem.
public protocol SFTPFileHandle {
    /// Reads data from the file. The length of the data read is determined by the length parameter. The data is read from the given offset in the file.
    func read(at offset: UInt64, length: UInt32) async throws -> ByteBuffer

    /// Writes data to the file. The data is written to the given offset in the file.
    func write(_ data: ByteBuffer, atOffset offset: UInt64) async throws -> SFTPStatusCode

    /// Closes the file. This is equivalent to the `close()` system call.
    func close() async throws -> SFTPStatusCode

    /// Reads the attributes of the file. This is equivalent to the `stat()` system call.
    func readFileAttributes() async throws -> SFTPFileAttributes

    /// Sets the attributes of the file. This is equivalent to the `fsetstat()` system call.
    func setFileAttributes(to attributes: SFTPFileAttributes) async throws
}

/// Represents a file listing in a directory.
public protocol SFTPDirectoryHandle {
    func listFiles(context: SSHContext) async throws -> [SFTPFileListing]
}

/// The context for the current SSH connection. This is passed to the delegate for each operation.
public struct SSHContext {
    /// The username of the user that is connected to the SSH server.
    public let username: String?
}

public struct SSHShellContext {
    public struct WindowSize {
        public let columns: Int
        public let rows: Int
    }

    public let session: SSHContext
    internal let channel: Channel
    public let windowSize: AsyncStream<WindowSize>

    public var isClosed: Bool {
        !channel.isActive
    }

    public func close(mode: CloseMode = .all) async throws {
        try await channel.close(mode: mode)
    }
}

/// The delegate for the SFTP subsystem. This is the interface that the SFTP subsystem uses to interact with the rest of the application. The delegate is responsible for implementing the various SFTP operations.
public protocol SFTPDelegate: Sendable {
    /// Returns the attributes for the file at the given path. This is equivalent to the `stat()` system call.
    func fileAttributes(atPath path: String, context: SSHContext) async throws -> SFTPFileAttributes

    /// Opens a file at the given path with the given attributes and flags. This is equivalent to the `open()` system call.
    func openFile(_ filePath: String, withAttributes: SFTPFileAttributes, flags: SFTPOpenFileFlags, context: SSHContext) async throws -> SFTPFileHandle
    
    /// Removes the file at the given path. This is equivalent to the `unlink()` system call.
    func removeFile(_ filePath: String, context: SSHContext) async throws -> SFTPStatusCode

    /// Creates a directory at the given path with the given attributes. This is equivalent to the `mkdir()` system call.
    func createDirectory(_ filePath: String, withAttributes: SFTPFileAttributes, context: SSHContext) async throws -> SFTPStatusCode

    /// Removes the directory at the given path. This is equivalent to the `rmdir()` system call.
    func removeDirectory(_ filePath: String, context: SSHContext) async throws -> SFTPStatusCode

    /// Resolves the given path to a canonical path. This is equivalent to the `realpath()` system call.
    func realPath(for canonicalUrl: String, context: SSHContext) async throws -> [SFTPPathComponent]

    /// Opens a directory at the given path. This is equivalent to the `opendir()` system call.
    /// Returns a handle to the directory that can be used to list the files in the directory.
    func openDirectory(atPath path: String, context: SSHContext) async throws -> SFTPDirectoryHandle

    /// Sets the file attributes for the file at the given path. This is equivalent to the `chmod()` system call.
    func setFileAttributes(to attributes: SFTPFileAttributes, atPath path: String, context: SSHContext) async throws -> SFTPStatusCode

    /// Creates a symbolic link at the given path with the given target. This is equivalent to the `symlink()` system call.
    func addSymlink(linkPath: String, targetPath: String, context: SSHContext) async throws -> SFTPStatusCode

    /// Reads the target of the symbolic link at the given path. This is equivalent to the `readlink()` system call.
    func readSymlink(atPath path: String, context: SSHContext) async throws -> [SFTPPathComponent]

    /// Renames a file
    func rename(oldPath: String, newPath: String, flags: UInt32, context: SSHContext) async throws -> SFTPStatusCode
}

enum SFTPServerSubsystem {
    static func setupChannelHanders(
        channel: Channel,
        sftp: SFTPDelegate,
        logger: Logger,
        username: String?
    ) -> EventLoopFuture<Void> {
        let deserializeHandler = ByteToMessageHandler(SFTPMessageParser())
        let serializeHandler = MessageToByteHandler(SFTPMessageSerializer())
        let sftpInboundHandler = SFTPServerInboundHandler(
            logger: logger,
            delegate: sftp,
            eventLoop: channel.eventLoop,
            username: username
        )
        
        return channel.pipeline.addHandlers(
            SSHChannelDataUnwrapper(),
            SSHOutboundChannelDataWrapper(),
            deserializeHandler,
            serializeHandler,
            sftpInboundHandler,
            CloseErrorHandler(logger: logger)
        )
    }
}
