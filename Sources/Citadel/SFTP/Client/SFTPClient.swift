import Foundation
import NIO
import NIOConcurrencyHelpers
import NIOSSH
import Logging

/// The SFTP client does not concern itself with the created SSH subsystem channel.
///
/// Per specification, SFTP could be used over other transport layers, too.
public final class SFTPClient: Sendable {
    /// The SSH child channel created for this connection.
    fileprivate let channel: Channel
    
    /// A monotonically increasing counter for gneerating request IDs.
    private let _nextRequestId = NIOLockedValueBox<UInt32>(0)

    private func incrementAndGetNextRequestId() -> UInt32 {
        _nextRequestId.withLockedValue { value in
            value &+= 1
            return value
        }
    }
    
    /// In-flight request ID tracker.
    fileprivate let responses: SFTPResponses
    
    /// What it says on the tin.
    public let logger: Logger
    
    fileprivate init(channel: Channel, responses: SFTPResponses, logger: Logger) {
        self.channel = channel
        self.responses = responses
        self.logger = logger
    }

    public func close() async throws {
        try await self.channel.close()
    }
    
    fileprivate static func setupChannelHanders(channel: Channel, logger: Logger) -> EventLoopFuture<SFTPClient> {
        let responses = SFTPResponses(sftpVersion: channel.eventLoop.makePromise())
        
        let deserializeHandler = ByteToMessageHandler(SFTPMessageParser())
        let serializeHandler = MessageToByteHandler(SFTPMessageSerializer())
        let sftpInboundHandler = SFTPClientInboundHandler(responses: responses, logger: logger)
        
        return channel.pipeline.addHandlers(
            SSHChannelDataUnwrapper(),
            SSHOutboundChannelDataWrapper(),
            deserializeHandler,
            serializeHandler,
            sftpInboundHandler,
            CloseErrorHandler(logger: logger)
        ).map {
            let client = SFTPClient(channel: channel, responses: responses, logger: logger)

            client.channel.closeFuture.whenComplete { _ in
                logger.info("SFTP channel closed")
                logger.trace("SFTP shutdown, failing any remaining incomplete requests")
                responses.close()
            }
            return client
        }
    }
    
    /// True if the SFTP connection is still open, false otherwise.
    public var isActive: Bool {
        self.channel.isActive
    }
    
    /// The SFTP client's event loop.
    public var eventLoop: EventLoop {
        self.channel.eventLoop
    }
    
    /// Returns a unique request ID for use in an SFTP message. Does _not_ register the ID for
    /// a response; that is handled by `sendRequest(_:)`.
    internal func allocateRequestId() -> UInt32 {
        return incrementAndGetNextRequestId()
    }
    
    /// Sends an SFTP request. The request's ID is used to track the response.
    ///
    /// - Warning: It is the caller's responsibility to ensure that only one request with any given
    ///   ID is in flight at any given time; multiple reponses to the same ID are likely to cause
    ///   unpredictable behavior.
    internal func sendRequest(_ request: SFTPRequest) async throws -> SFTPResponse {
        try await self.eventLoop.flatSubmit {
            let requestId = request.requestId
            let promise = self.channel.eventLoop.makePromise(of: SFTPResponse.self)
            
            // In release builds, silently accept overlapping request IDs, since it can accidentally work correctly.
            assert(self.responses.responses[requestId] == nil, "Attempt to send request with request ID \(requestId) already in flight.")

            let message = request.makeMessage()
            
            self.logger.trace("SFTP OUT: \(message.debugDescription)")
            //logger.trace("SFTP OUT: \(message.debugRawBytesRepresentation)")

            self.responses.responses[requestId] = promise
            return self.channel.writeAndFlush(request.makeMessage()).flatMap {
                promise.futureResult
            }
        }.get()
    }
    
    /// List the contents of a directory on the SFTP server.
    ///
    /// - Parameter path: The path to list
    /// - Returns: Array of directory entries
    /// - Throws: SFTPError if the request fails
    ///
    /// ## Example
    /// ```swift
    /// let contents = try await sftp.listDirectory(atPath: "/home/user")
    /// for item in contents {
    ///     print(item.filename)
    ///     print(item.longname) // ls -l style output
    ///     print(item.attributes) // File attributes
    /// }
    /// ```
    public func listDirectory(
        atPath path: String
    ) async throws -> [SFTPMessage.Name] {
        var path = path
        var oldPath: String

        repeat {
            oldPath = path
            guard case .name(let realpath) = try await sendRequest(.realpath(.init(requestId: self.allocateRequestId(), path: path))) else {
                self.logger.warning("SFTP server returned bad response to open file request, this is a protocol error")
                throw SFTPError.invalidResponse
            }

            path = realpath.path
        } while path != oldPath
        
        guard case .handle(let handle) = try await sendRequest(.opendir(.init(requestId: self.allocateRequestId(), handle: path))) else {
            self.logger.warning("SFTP server returned bad response to open file request, this is a protocol error")
            throw SFTPError.invalidResponse
        }
        
        var names = [SFTPMessage.Name]()
        var response = try await sendRequest(
            .readdir(
                .init(
                    requestId: self.allocateRequestId(),
                    handle: handle.handle
                )
            )
        )
        
        while case .name(let name) = response {
            names.append(name)
            response = try await sendRequest(
                .readdir(
                    .init(
                        requestId: self.allocateRequestId(),
                        handle: handle.handle
                    )
                )
            )
        }
        
        return names
    }
    
    /// Get the attributes of a file on the SFTP server.
    ///
    /// - Parameter filePath: Path to the file
    /// - Returns: File attributes including size, permissions, etc
    /// - Throws: SFTPError if the file doesn't exist or request fails
    ///
    /// ## Example
    /// ```swift
    /// let attrs = try await sftp.getAttributes(at: "test.txt")
    /// print("Size:", attrs.size)
    /// print("Permissions:", attrs.permissions)
    /// print("Modified:", attrs.modificationTime)
    /// ```
    public func getAttributes(
        at filePath: String
    ) async throws -> SFTPFileAttributes {
        self.logger.info("SFTP requesting file attributes at '\(filePath)'")
        
        let response = try await sendRequest(.stat(.init(
            requestId: allocateRequestId(),
            path: filePath
        )))
        
        guard case .attributes(let attributes) = response else {
            self.logger.warning("SFTP server returned bad response to open file request, this is a protocol error")
            throw SFTPError.invalidResponse
        }
        
        return attributes.attributes
    }
    
    /// Open a file at the specified path on the SFTP server.
    ///
    /// - Parameters:
    ///   - filePath: Path to the file
    ///   - flags: File open flags (.read, .write, .create, etc)
    ///   - attributes: File attributes to set if creating file
    /// - Returns: An SFTPFile object for performing operations
    /// - Throws: SFTPError if open fails
    ///
    /// ## Example
    /// ```swift
    /// // Open file for reading
    /// let file = try await sftp.openFile(
    ///     filePath: "test.txt",
    ///     flags: .read
    /// )
    /// 
    /// // Read entire contents
    /// let data = try await file.readToEnd()
    /// 
    /// // Don't forget to close
    /// try await file.close()
    /// ```
    public func openFile(
        filePath: String,
        flags: SFTPOpenFileFlags,
        attributes: SFTPFileAttributes = .none
    ) async throws -> SFTPFile {
        self.logger.info("SFTP requesting to open file at '\(filePath)' with flags \(flags)")
        
        let response = try await sendRequest(.openFile(.init(
            requestId: self.allocateRequestId(),
            filePath: filePath,
            pFlags: flags,
            attributes: attributes
        )))

        guard case .handle(let handle) = response else {
            self.logger.warning("SFTP server returned bad response to open file request, this is a protocol error")
            throw SFTPError.invalidResponse
        }
            
        self.logger.debug("SFTP opened file \(filePath), file handle \(handle.handle.sftpHandleDebugDescription)")
        return SFTPFile(client: self, path: filePath, handle: handle.handle)
    }
    
    /// Open and automatically close a file with the given closure.
    ///
    /// - Parameters:
    ///   - filePath: Path to the file
    ///   - flags: File open flags (.read, .write, .create, etc)
    ///   - attributes: File attributes to set if creating file
    ///   - closure: Operation to perform with the open file
    /// - Returns: The value returned by the closure
    /// - Throws: SFTPError if open fails or closure throws
    ///
    /// ## Example
    /// ```swift
    /// // Read file contents
    /// let contents = try await sftp.withFile(
    ///     filePath: "test.txt",
    ///     flags: .read
    /// ) { file in
    ///     try await file.readToEnd()
    /// }
    /// 
    /// // Write file contents
    /// try await sftp.withFile(
    ///     filePath: "new.txt",
    ///     flags: [.write, .create]
    /// ) { file in
    ///     try await file.write(ByteBuffer(string: "Hello World"))
    /// }
    /// ```
    public func withFile<R>(
        filePath: String,
        flags: SFTPOpenFileFlags,
        attributes: SFTPFileAttributes = .none,
        _ closure: @escaping @Sendable (SFTPFile) async throws -> R
    ) async throws -> R {
        let file = try await self.openFile(filePath: filePath, flags: flags, attributes: attributes)
        
        do {
            let result = try await closure(file)
            try await file.close() // should we ignore errors from this? always been a question for the close(2) syscall too
            return result
        } catch {
            try await file.close() // if this errors, should we throw it as an underlying error? or just ignore?
            throw error
        }
    }
    
    /// Create a directory at the specified path.
    ///
    /// - Parameters:
    ///   - path: Path where directory should be created
    ///   - attributes: Attributes to set on the new directory
    /// - Throws: SFTPError if creation fails
    ///
    /// ## Example
    /// ```swift
    /// // Create simple directory
    /// try await sftp.createDirectory(atPath: "new_folder")
    /// 
    /// // Create with specific permissions
    /// try await sftp.createDirectory(
    ///     atPath: "private_folder",
    ///     attributes: .init(permissions: 0o700)
    /// )
    /// ```
    public func createDirectory(
        atPath path: String,
        attributes: SFTPFileAttributes = .none
    ) async throws {
        self.logger.info("SFTP requesting mkdir at '\(path)'")
        
        let _ = try await sendRequest(.mkdir(.init(
            requestId: self.allocateRequestId(),
            filePath: path,
            attributes: attributes
        )))
        
        self.logger.debug("SFTP created directory \(path)")
    }

    /// Remove a file at the specified path.
    ///
    /// - Parameter filePath: Path to the file to remove
    /// - Throws: SFTPError if removal fails
    ///
    /// ## Example
    /// ```swift
    /// try await sftp.remove(at: "file_to_delete.txt")
    /// ```
    public func remove(
        at filePath: String
    ) async throws {
        self.logger.info("SFTP requesting remove file at '\(filePath)'")

        let _ = try await sendRequest(.remove(.init(
            requestId: allocateRequestId(),
            filename: filePath
        )))

        self.logger.debug("SFTP removed file at \(filePath)")
    }

    /// Remove a directory at the specified path.
    ///
    /// - Parameter filePath: Path to the directory to remove
    /// - Throws: SFTPError if removal fails
    ///
    /// ## Example
    /// ```swift
    /// try await sftp.rmdir(at: "empty_directory")
    /// ```
    public func rmdir(
        at filePath: String
    ) async throws {
        self.logger.info("SFTP requesting remove directory at '\(filePath)'")

        let _ = try await sendRequest(.rmdir(.init(
            requestId: allocateRequestId(),
            filePath: filePath
        )))

        self.logger.debug("SFTP removed directory at \(filePath)")
    }

    /// Rename a file or directory.
    ///
    /// - Parameters:
    ///   - oldPath: Current path of the file
    ///   - newPath: Desired new path
    ///   - flags: Optional flags affecting the rename operation
    /// - Throws: SFTPError if rename fails
    ///
    /// ## Example
    /// ```swift
    /// try await sftp.rename(
    ///     at: "old_name.txt",
    ///     to: "new_name.txt"
    /// )
    /// ```
    public func rename(
        at oldPath: String,
        to newPath: String,
        flags: UInt32 = 0
    ) async throws {
        self.logger.info("SFTP requesting rename file at '\(oldPath)' to '\(newPath)'")

        let _ = try await sendRequest(.rename(.init(
            requestId: allocateRequestId(),
            oldPath: oldPath,
            newPath: newPath,
            flags: flags
        )))

        self.logger.debug("SFTP renamed file at \(oldPath) to \(newPath)")
    }

    /// Get the canonical absolute path.
    ///
    /// - Parameter path: Path to resolve
    /// - Returns: Absolute canonical path
    /// - Throws: SFTPError if path resolution fails
    ///
    /// ## Example
    /// ```swift
    /// // Resolve current directory
    /// let pwd = try await sftp.getRealPath(atPath: ".")
    /// 
    /// // Resolve relative path
    /// let absolute = try await sftp.getRealPath(atPath: "../some/path")
    /// ```
    public func getRealPath(atPath path: String) async throws -> String {
        guard case let .name(realpath) = try await sendRequest(.realpath(.init(requestId: self.allocateRequestId(), path: path))) else {
            self.logger.warning("SFTP server returned bad response to open file request, this is a protocol error")
            throw SFTPError.invalidResponse
        }
        return realpath.path
    }

}

extension SSHClient {
    /// Open a SFTP subchannel over the SSH connection using the `sftp` subsystem.
    ///
    /// - Parameters:
    ///   - logger: A logger to use for logging SFTP operations. Creates a new logger by default.
    ///   - closure: A closure to execute with the opened SFTP client. The client is automatically closed when the closure returns.
    ///
    /// ## Logging levels
    /// Several events in the lifetime of an SFTP connection are logged to the provided logger at various levels:
    /// - `.critical`, `.error`: Unused.
    /// - `.warning`: Logs non-`ok` SFTP status responses and SSH-level errors.
    /// - `.info`: Logs major interesting events in the SFTP connection lifecycle (opened, closed, etc.)
    /// - `.debug`: Logs detailed connection events (opened file, read from file, wrote to file, etc.)
    /// - `.trace`: Logs a protocol-level packet trace.
    ///
    /// ## Example
    /// ```swift
    /// let client = try await SSHClient(/* ... */)
    /// 
    /// try await client.withSFTP { sftp in
    ///     // List directory contents
    ///     let contents = try await sftp.listDirectory(atPath: "/home/user")
    ///     
    ///     // Read a file
    ///     try await sftp.withFile(filePath: "test.txt", flags: .read) { file in
    ///         let data = try await file.readToEnd()
    ///         print(String(buffer: data))
    ///     }
    /// }
    /// ```
    public func withSFTP<ReturnType>(
        logger: Logger = .init(label: "nl.orlandos.citadel.sftp"),
        _ closure: @escaping @Sendable (SFTPClient) async throws -> ReturnType
    ) async throws -> ReturnType {
        let client = try await self.openSFTP(logger: logger)
        do {
            let result = try await closure(client)
            try await client.close()
            return result
        } catch {
            try await client.close()
            throw error
        }
    }
    
    /// Open a SFTP subchannel over the SSH connection using the `sftp` subsystem.
    ///
    /// - Parameters:
    ///   - logger: A logger to use for logging SFTP operations. Creates a new logger by default.
    /// - Returns: An initialized SFTP client
    /// - Throws: SFTPError if connection fails or version is unsupported
    ///
    /// ## Example
    /// ```swift
    /// let client = try await SSHClient(/* ... */)
    /// let sftp = try await client.openSFTP()
    /// 
    /// // Use SFTP client
    /// let contents = try await sftp.listDirectory(atPath: "/home/user")
    /// 
    /// // Remember to close when done
    /// try await sftp.close()
    /// ```
    public func openSFTP(
        logger: Logger = .init(label: "nl.orlandos.citadel.sftp")
    ) async throws -> SFTPClient {
        try await eventLoop.flatSubmit {
            let createChannel = self.eventLoop.makePromise(of: Channel.self)
            let createClient = self.eventLoop.makePromise(of: SFTPClient.self)
            let timeoutCheck = self.eventLoop.makePromise(of: Void.self)
            
            self.session.sshHandler.createChannel(createChannel) { channel, _ in
                SFTPClient.setupChannelHanders(channel: channel, logger: logger)
                    .map { client in
                        createClient.succeed(client)
                    }
            }
            
            timeoutCheck.futureResult.whenFailure { _ in
                logger.warning("SFTP subsystem request or initialize message received no reply after 15 seconds. Likely the result of opening too many SFTPClient handles.")
            }
            
            self.eventLoop.scheduleTask(in: .seconds(15)) {
                timeoutCheck.fail(SFTPError.missingResponse)
                createChannel.fail(SFTPError.missingResponse)
                createClient.fail(SFTPError.missingResponse)
            }
            
            return createChannel.futureResult.flatMap { channel in
                let openSubsystem = self.eventLoop.makePromise(of: Void.self)

                logger.debug("SFTP requesting subsystem")

                channel.triggerUserOutboundEvent(
                    SSHChannelRequestEvent.SubsystemRequest(
                        subsystem: "sftp",
                        wantReply: true
                    ),
                    promise: openSubsystem
                )
                return openSubsystem.futureResult
            }.flatMap {
                logger.debug("SFTP subsystem request completed")
                return createClient.futureResult
            }.flatMap { (client: SFTPClient) in
                timeoutCheck.succeed(())
                
                let initializeMessage = SFTPMessage.initialize(.init(version: .v3))
                
                logger.debug("SFTP start with version \(SFTPProtocolVersion.v3)")
                logger.trace("SFTP OUT: \(initializeMessage.debugDescription)")
                //logger.trace("SFTP OUT: \(initializeMessage.debugRawBytesRepresentation)")

                return client.channel.writeAndFlush(initializeMessage).flatMap {
                    return client.responses.sftpVersion.futureResult
                }.flatMapThrowing { serverVersion in
                    guard serverVersion.version >= .v3 else {
                        logger.warning("SFTP ERROR: Server version is unrecognized: \(serverVersion.version.rawValue)")
                        throw SFTPError.unsupportedVersion(serverVersion.version)
                    }
                    
                    logger.info("SFTP connection opened and ready")
                    return client
                }
            }
        }.get()
    }
}

/// A tracker for in-flight SFTP requests. Request IDs are allocated by `SFTPClient`.
final class SFTPResponses: @unchecked Sendable {
    let _initialized: NIOLockedValueBox<Bool> = NIOLockedValueBox<Bool>(false)
    var isInitialized: Bool {
        get { _initialized.withLockedValue { $0 } }
        set { _initialized.withLockedValue { $0 = newValue } }
    }
    let sftpVersion: EventLoopPromise<SFTPMessage.Version>
    var responses = [UInt32: EventLoopPromise<SFTPResponse>]()
    
    init(sftpVersion: EventLoopPromise<SFTPMessage.Version>) {
        self.sftpVersion = sftpVersion
        
        sftpVersion.futureResult.whenSuccess { [weak self] _ in
            self?.isInitialized = true
        }
    }
    
    func close() {
        self.isInitialized = false
        self.sftpVersion.fail(SFTPError.connectionClosed)
        
        for promise in self.responses.values {
            promise.fail(SFTPError.connectionClosed)
        }
    }

    deinit {
        close()
    }
}
