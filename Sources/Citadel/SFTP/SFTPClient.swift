import Foundation
import NIO
import NIOSSH
import Logging

/// The SFTP client does not concern itself with the created SSH subsystem
///
/// Per specification, SFTP could be used over other transport layers, too.
public final class SFTPClient {
    /// The SSH child channel created for this connection.
    fileprivate let channel: Channel
    
    /// A monotonically increasing counter for gneerating request IDs.
    private var nextRequestId: UInt32 = 0
    
    /// In-flight request ID tracker.
    fileprivate let responses: SFTPResponses
    
    /// What it says on the tin.
    public let logger: Logger
    
    fileprivate init(channel: Channel, responses: SFTPResponses, logger: Logger) {
        self.channel = channel
        self.responses = responses
        self.logger = logger
    }
    
    fileprivate static func setupChannelHanders(channel: Channel, logger: Logger) -> EventLoopFuture<SFTPClient> {
        let responses = SFTPResponses(initialized: channel.eventLoop.makePromise())
        
        let deserializeHandler = ByteToMessageHandler(SFTPMessageParser())
        let serializeHandler = MessageToByteHandler(SFTPMessageSerializer())
        let sftpInboundHandler = SFTPInboundHandler(responses: responses, logger: logger)
        
        return channel.pipeline.addHandlers(
            SSHChannelDataUnwrapper(),
            SSHChannelDataWrapper(),
            deserializeHandler,
            serializeHandler,
            sftpInboundHandler,
            CloseErrorHandler()
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
        defer {
            self.nextRequestId &+= 1
        }
        return self.nextRequestId
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
    
    /// Open a file at the specified path on the SFTP server, using the given flags and attributes.  If the `.create`
    /// flag is specified, the given attributes are applied to the created file. If successful, an `SFTPFile` is
    /// returned which can be used to perform various operations on the open file. The file object must be explicitly
    /// closed by the caller; the client does not keep track of open files.
    ///
    /// - Warning: The `attributes` parameter is currently unimplemented; any values provided are ignored.
    ///
    /// - Important: This API is annoying to use safely. Strongly consider using
    ///   `withFile(filePath:flags:attributes:_:)` instead.
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
        return SFTPFile(client: self, handle: handle.handle)
    }
    
    /// Open a file at the specified path on the SFTP server, using the given flags. If the `.create` flag is specified,
    /// the given attributes are applied to the created file. If the open succeeds, the provided closure is invoked with
    /// an `SFTPFile` object which can be used to perform operations on the file. When the closure returns, the file is
    /// automatically closed. The `SFTPFile` object must not be persisted beyond the lifetime of the closure.
    ///
    /// - Warning: The `attributes` parameter is currently unimplemented; any values provided are ignored.
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
}

extension SSHClient {
    /// Open a SFTP subchannel over the SSH connection using the `sftp` subsystem.
    ///
    /// - Parameters:
    ///   - subsystem: The subsystem name sent to the SSH server. You probably want to just use the default of `sftp`.
    ///   - logger: A logger to use for logging SFTP operations. Creates a new logger by default. See below for details.
    ///
    /// ## Logging levels
    ///
    /// Several events in the lifetime of an SFTP connection are logged to the provided logger at various levels:
    ///
    /// - `.critical`, `.error`: Unused.
    /// - `.warning`: Logs non-`ok` SFTP status responses and SSH-level errors.
    /// - `.notice`: Unused.
    /// - `.info`: Logs major interesting events in the SFTP connection lifecycle (opened, closed, etc.)
    /// - `.debug`: Logs detailed connection events (opened file, read from file, wrote to file, etc.)
    /// - `.trace`: Logs a protocol-level packet trace, including raw packet bytes (excluding large items such
    ///   as incoming data read from a file). Care is taken to ensure sensitive information is not included in
    ///   packet traces.
    public func openSFTP(
        subsystem: String = "sftp",
        logger: Logger = .init(label: "nl.orlandos.citadel.sftp")
    ) async throws -> SFTPClient {
        try await eventLoop.flatSubmit {
            let createChannel = self.eventLoop.makePromise(of: Channel.self)
            let createClient = self.eventLoop.makePromise(of: SFTPClient.self)
            let timeoutCheck = self.eventLoop.makePromise(of: Void.self)
            
            self.session.sshHandler.createChannel(createChannel) { channel, _ in
                SFTPClient.setupChannelHanders(channel: channel, logger: logger).map(createClient.succeed)
            }
            
            timeoutCheck.futureResult.whenFailure { _ in
                logger.warning("SFTP ERROR: subsystem request or initialize message received no reply after 15 seconds")
            }
            
            self.eventLoop.scheduleTask(in: .seconds(15)) {
                timeoutCheck.fail(SFTPError.missingResponse)
                createChannel.fail(SFTPError.missingResponse)
                createClient.fail(SFTPError.missingResponse)
            }
            
            return createChannel.futureResult.flatMap { channel in
                let openSubsystem = self.eventLoop.makePromise(of: Void.self)

                logger.debug("SFTP requesting subsystem with name '\(subsystem)'")

                channel.triggerUserOutboundEvent(
                    SSHChannelRequestEvent.SubsystemRequest(
                        subsystem: subsystem,
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
                    return client.responses.initialized.futureResult
                }.flatMapThrowing { serverVersion in
                    guard serverVersion.version == .v3 else {
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
final class SFTPResponses {
    var isInitialized: Bool = false
    let initialized: EventLoopPromise<SFTPMessage.Version>
    var responses = [UInt32: EventLoopPromise<SFTPResponse>]()
    
    init(initialized: EventLoopPromise<SFTPMessage.Version>) {
        self.initialized = initialized
        
        initialized.futureResult.whenSuccess { [unowned self] _ in
            self.isInitialized = true
        }
    }
    
    deinit {
        self.close()
    }
    
    func close() {
        self.isInitialized = false
        self.initialized.fail(SFTPError.connectionClosed)
        
        for promise in self.responses.values {
            promise.fail(SFTPError.connectionClosed)
        }
    }
}

final class SFTPInboundHandler: ChannelInboundHandler {
    typealias InboundIn = SFTPMessage
    
    let responses: SFTPResponses
    let logger: Logger
    
    init(responses: SFTPResponses, logger: Logger) {
        self.responses = responses
        self.logger = logger
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        
        self.logger.trace("SFTP IN:  \(message.debugDescription)")
        //self.logger.trace("SFTP IN:  \(message.debugRawBytesRepresentation)")

        if !self.responses.isInitialized, case .version(let version) = message {
            if version.version != .v3 {
                logger.warning("SFTP ERROR: Server version is unrecognized or incompatible: \(version.version.rawValue)")
                context.fireErrorCaught(SFTPError.unsupportedVersion(version.version))
            } else {
                responses.initialized.succeed(version)
            }
        } else if let response = SFTPResponse(message: message) {
            if let promise = responses.responses.removeValue(forKey: response.requestId) {
                if case .status(let status) = response, status.errorCode != .ok {
                    // logged as debug rather than warning because there are many cases in which a protocol error is
                    // not only nonfatal, but even expected (such as SSH_FX_EOF).
                    self.logger.debug("SFTP error received: \(status)")
                    promise.fail(status)
                } else {
                    promise.succeed(response)
                }
            } else {
                self.logger.warning("SFTP response received for nonexistent request, this is a protocol error")
                context.fireErrorCaught(SFTPError.noResponseTarget)
            }
        } else {
            self.logger.warning("SFTP received unrecognized response message, this is a protocol error")
            context.fireErrorCaught(SFTPError.invalidResponse)
        }
    }
}
