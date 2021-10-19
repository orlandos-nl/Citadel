import Foundation
import NIO
import NIOSSH

final class TTYResponses {
    var writabilityFuture: EventLoopFuture<Void>
    var responses = [EventLoopPromise<ByteBuffer>]()
    
    init(writabilityFuture: EventLoopFuture<Void>) {
        self.writabilityFuture = writabilityFuture
    }
    
    deinit {
        close()
    }
    
    func close() {
        for response in responses {
            response.fail(SFTPError.connectionClosed)
        }
    }
}

public struct TTYSTDError: Error {
    public let message: ByteBuffer
}

final class TTYHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    let responses: TTYResponses
    
    init(responses: TTYResponses) {
        self.responses = responses
    }
    
    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is SSHChannelRequestEvent.ExitStatus:
            ()
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        responses.close()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .byteBuffer(let bytes) = data.data else {
            fatalError("Unexpected read type")
        }
        
        guard !responses.responses.isEmpty else {
            // No responses to fulfill
            return
        }
        
        let response = responses.responses.removeFirst()

        switch data.type {
        case .channel:
            // Channel data is forwarded on, the pipe channel will handle it.
            response.succeed(bytes)
            return
        case .stdErr:
            response.fail(TTYSTDError(message: bytes))
        default:
            ()
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(data))), promise: promise)
    }
}

/// The SFTP client does not concern itself with the created SSH subsystem
///
/// Per specification, SFTP could be used over other transport layers, too.
public final class TTY {
    let sshClient: SSHClient
    let channel: Channel
    let responses: TTYResponses
    
    private init(sshClient: SSHClient, channel: Channel, responses: TTYResponses) {
        self.sshClient = sshClient
        self.channel = channel
        self.responses = responses
    }
    
    public func executeCommand(_ command: String) -> EventLoopFuture<ByteBuffer> {
        // We need to exec a thing.
        let execRequest = SSHChannelRequestEvent.ExecRequest(
            command: command,
            wantReply: true
        )
        
        let promise = channel.eventLoop.makePromise(of: ByteBuffer.self)
        responses.responses.append(promise)
        
        responses.writabilityFuture = responses.writabilityFuture.flatMap { [channel] in
            channel.triggerUserOutboundEvent(execRequest).whenFailure { [channel] error in
                channel.close(promise: nil)
                promise.fail(error)
            }
            
            return promise.futureResult.map { _ in }
        }
        
        return promise.futureResult
    }
    
    internal static func setupChannelHanders(
        channel: Channel,
        sshClient: SSHClient
    ) -> EventLoopFuture<TTY> {
        let responses = TTYResponses(writabilityFuture: channel.eventLoop.makeSucceededVoidFuture())
        
        return channel.pipeline.addHandlers(
            TTYHandler(responses: responses),
            CloseErrorHandler()
        ).map {
            let client = TTY(sshClient: sshClient, channel: channel, responses: responses)
            
            client.channel.closeFuture.whenComplete { _ in
                responses.close()
            }
            return client
        }
    }
}

extension SSHClient {
    public func openTTY() -> EventLoopFuture<TTY> {
        eventLoop.flatSubmit {
            let createChannel = self.eventLoop.makePromise(of: Channel.self)
            let createClient = self.eventLoop.makePromise(of: TTY.self)
            self.session.sshHandler.createChannel(createChannel) { channel, _ in
                TTY.setupChannelHanders(channel: channel, sshClient: self).map(createClient.succeed)
            }
            
            self.eventLoop.scheduleTask(in: .seconds(15)) {
                createChannel.fail(SFTPError.missingResponse)
                createClient.fail(SFTPError.missingResponse)
            }
            
            return createClient.futureResult
        }
    }
}
