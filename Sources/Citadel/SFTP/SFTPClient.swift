import Foundation
import NIO
import NIOSSH

/// The SFTP client does not concern itself with the created SSH subsystem
///
/// Per specification, SFTP could be used over other transport layers, too.
public final class SFTPClient {
    let sshClient: SSHClient
    let channel: Channel
    var requestId: UInt32 = 0
    let responses: SFTPResponses
    
    private init(sshClient: SSHClient, channel: Channel, responses: SFTPResponses) {
        self.sshClient = sshClient
        self.channel = channel
        self.responses = responses
    }
    
    static func setupChannelHanders(channel: Channel, sshClient: SSHClient) -> EventLoopFuture<SFTPClient> {
        let responses = SFTPResponses(initialized: channel.eventLoop.makePromise())
        
        let deserializeHandler = ByteToMessageHandler(SFTPMessageParser())
        let serializeHandler = MessageToByteHandler(SFTPMessageSerializer())
        let sftpInboundHandler = SFTPInboundHandler(responses: responses)
        
        return channel.pipeline.addHandlers(
            SSHChannelDataUnwrapper(),
            SSHChannelDataWrapper(),
            deserializeHandler,
            serializeHandler,
            sftpInboundHandler,
            CloseErrorHandler()
        ).map {
            let client = SFTPClient(sshClient: sshClient, channel: channel, responses: responses)
            // TODO: Check version
            client.channel.closeFuture.whenComplete { _ in
                responses.close()
            }
            return client
        }
    }
    
    private func nextRequestId() -> UInt32 {
        let id = self.requestId
        self.requestId = self.requestId &+ 1
        return id
    }
    
    func sendRequest(_ request: SFTPRequest) -> EventLoopFuture<SFTPResponse> {
        let requestId = request.requestId
        let promise = channel.eventLoop.makePromise(of: SFTPResponse.self)
        
        responses.responses[requestId] = promise
        return channel.writeAndFlush(request.makeMessage()).flatMap {
            promise.futureResult
        }
    }
    
    func readFile(
        handle: ByteBuffer,
        offset: UInt64,
        length: UInt32
    ) -> EventLoopFuture<ByteBuffer> {
        return sendRequest(
            .read(
                .init(
                    requestId: nextRequestId(),
                    handle: handle,
                    offset: offset,
                    length: length
                )
            )
        ).flatMapThrowing { response in
            guard case .data(let data) = response else {
                throw SFTPError.invalidResponse
            }
            
            return data.data
        }
    }
    
    func writeFile(
        handle: ByteBuffer,
        data: ByteBuffer,
        offset: UInt64,
        length: UInt32
    ) -> EventLoopFuture<Void> {
        return sendRequest(
            .write(
                .init(
                    requestId: nextRequestId(),
                    handle: handle,
                    offset: offset,
                    data: data
                )
            )
        ).map { _ in }
    }
    
    public func openFile(
        filePath: String,
        flags: SFTPOpenFileFlags,
        attributes: SFTPFileAttributes = .none
    ) -> EventLoopFuture<SFTPFile> {
        return sendRequest(
            .openFile(
                .init(
                    requestId: nextRequestId(),
                    filePath: filePath,
                    pFlags: flags,
                    attributes: attributes
                )
            )
        ).flatMapThrowing { response in
            guard case .handle(let handle) = response else {
                throw SFTPError.invalidResponse
            }
            
            return SFTPFile(handle: handle.handle, client: self)
        }
    }
}

extension SSHClient {
    public func openSFTP() -> EventLoopFuture<SFTPClient> {
        eventLoop.flatSubmit {
            let createChannel = self.eventLoop.makePromise(of: Channel.self)
            let createClient = self.eventLoop.makePromise(of: SFTPClient.self)
            self.session.sshHandler.createChannel(createChannel) { channel, _ in
                SFTPClient.setupChannelHanders(channel: channel, sshClient: self).map(createClient.succeed)
            }
            
            self.eventLoop.scheduleTask(in: .seconds(15)) {
                createChannel.fail(SFTPError.missingResponse)
                createClient.fail(SFTPError.missingResponse)
            }
            
            return createChannel.futureResult.flatMap { channel in
                let openSubsystem = self.eventLoop.makePromise(of: Void.self)
                
                channel.triggerUserOutboundEvent(
                    SSHChannelRequestEvent.SubsystemRequest(
                        subsystem: "sftp",
                        wantReply: true
                    ),
                    promise: openSubsystem
                )
                
                return openSubsystem.futureResult
            }.flatMap {
                createClient.futureResult
            }.flatMap { client in
                client.channel.writeAndFlush(SFTPMessage.initialize(.init(version: 3))).flatMap {
                    return client.responses.initialized.futureResult
                }.map { _ in
                    client
                }
            }
        }
    }
}

final class SFTPResponses {
    let initialized: EventLoopPromise<SFTPMessage.Version>
    var responses = [UInt32: EventLoopPromise<SFTPResponse>]()
    
    init(initialized: EventLoopPromise<SFTPMessage.Version>) {
        self.initialized = initialized
    }
    
    deinit {
        close()
    }
    
    func close() {
        initialized.fail(SFTPError.connectionClosed)
        
        for promise in responses.values {
            promise.fail(SFTPError.connectionClosed)
        }
    }
}

final class SFTPInboundHandler: ChannelInboundHandler {
    typealias InboundIn = SFTPMessage
    
    let responses: SFTPResponses
    
    init(responses: SFTPResponses) {
        self.responses = responses
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        
        if case .version(let version) = message {
            responses.initialized.succeed(version)
        } else if case .status(let status) = message {
            if let promise = responses.responses[status.requestId] {
                if status.errorCode == 0 {
                    promise.succeed(.status(status))
                } else {
                    promise.fail(status)
                }
            } else {
                context.fireErrorCaught(SFTPError.noResponseTarget)
            }
        } else if let response = SFTPResponse(message: message) {
            if let promise = responses.responses[response.requestId] {
                promise.succeed(response)
            } else {
                context.fireErrorCaught(SFTPError.noResponseTarget)
            }
        } else {
            context.fireErrorCaught(SFTPError.invalidResponse)
        }
    }
}
