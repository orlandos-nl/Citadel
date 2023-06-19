import NIO
import NIOSSH
import Logging

public enum ShellClientEvent {
    case stdin(ByteBuffer)
}

public enum ShellServerEvent {
    case stdout(ByteBuffer)
}

public protocol ShellDelegate {
    func startShell(
        reading stream: AsyncStream<ShellClientEvent>,
        context: SSHShellContext
    ) async throws -> AsyncThrowingStream<ShellServerEvent, Error>
}

fileprivate struct ShellContinuation {
    var continuation: AsyncStream<ShellClientEvent>.Continuation!
}

final class ShellServerInboundHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    
    let logger: Logger
    let delegate: ShellDelegate
    let username: String?
    let eventLoop: EventLoop
    fileprivate var streamWriter: ShellContinuation
    let stream: AsyncStream<ShellClientEvent>
    
    init(logger: Logger, delegate: ShellDelegate, eventLoop: EventLoop, username: String?) {
        self.logger = logger
        self.delegate = delegate
        self.username = username
        self.eventLoop = eventLoop
        
        var streamWriter = ShellContinuation()
        self.stream = AsyncStream { continuation in
            streamWriter.continuation = continuation
        }
        self.streamWriter = streamWriter
    }
    
    func handlerAdded(context: ChannelHandlerContext) {
        let channel = context.channel

        let shellContext = SSHShellContext(
            session: SSHContext(username: self.username),
            channel: channel
        )

        let done = context.eventLoop.makePromise(of: Void.self)
        done.completeWithTask {
            let output = try await self.delegate.startShell(
                reading: self.stream,
                context: shellContext
            )
            
            for try await chunk in output {
                switch chunk {
                case .stdout(let data):
                    try await channel.writeAndFlush(data)
                }
            }

            try await shellContext.close(mode: .output)
        }

        done.futureResult.whenFailure(context.fireErrorCaught)
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        streamWriter.continuation.yield(.stdin(unwrapInboundIn(data)))
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }
}

enum ShellServerSubsystem {
    static func setupChannelHanders(
        channel: Channel,
        shell: ShellDelegate,
        logger: Logger,
        username: String?
    ) -> EventLoopFuture<Void> {
        let shellInboundHandler = ShellServerInboundHandler(
            logger: logger,
            delegate: shell,
            eventLoop: channel.eventLoop,
            username: username
        )
        
        return channel.pipeline.addHandlers(
            SSHChannelDataUnwrapper(),
            SSHOutboundChannelDataWrapper(),
            shellInboundHandler,
            CloseErrorHandler(logger: logger)
        )
    }
}
