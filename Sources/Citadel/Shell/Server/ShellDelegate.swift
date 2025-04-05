import NIO
import NIOSSH
import Logging

public enum ShellClientEvent {
    case stdin(ByteBuffer)
}

public struct ShellServerEvent: Sendable {
    internal enum Event {
        case stdout(ByteBuffer)
    }
    
    let event: Event

    public static func stdout(_ data: ByteBuffer) -> ShellServerEvent {
        ShellServerEvent(event: .stdout(data))
    }
}

public protocol ShellDelegate: Sendable {
    func startShell(
        inbound: AsyncStream<ShellClientEvent>,
        outbound: ShellOutboundWriter,
        context: SSHShellContext
    ) async throws
}

public struct ShellOutboundWriter: Sendable {
    let continuation: AsyncThrowingStream<ShellServerEvent, Error>.Continuation

    public func write(_ string: String) {
        write(ByteBuffer(string: string))
    }
    
    public func write(_ data: [UInt8]) {
        write(ByteBuffer(bytes: data))
    }
    
    public func write(_ data: ByteBuffer) {
        continuation.yield(.stdout(data))
    }
}

final class ShellServerInboundHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    
    let logger: Logger
    let delegate: ShellDelegate
    let username: String?
    let eventLoop: EventLoop
    let inbound = AsyncStream<ShellClientEvent>.makeStream()
    let outbound = AsyncThrowingStream<ShellServerEvent, Error>.makeStream()
    let windowSize = AsyncStream<SSHShellContext.WindowSize>.makeStream()
    
    init(logger: Logger, delegate: ShellDelegate, eventLoop: EventLoop, username: String?) {
        self.logger = logger
        self.delegate = delegate
        self.username = username
        self.eventLoop = eventLoop
    }
    
    func handlerAdded(context: ChannelHandlerContext) {
        let channel = context.channel

        let shellContext = SSHShellContext(
            session: SSHContext(username: self.username),
            channel: channel,
            windowSize: windowSize.stream
        )

        let done = context.eventLoop.makePromise(of: Void.self)
        done.completeWithTask {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    try await self.delegate.startShell(
                        inbound: self.inbound.stream,
                        outbound: ShellOutboundWriter(continuation: self.outbound.continuation),
                        context: shellContext
                    )
                }

                group.addTask {
                    for try await message in self.outbound.stream {
                        switch message.event {
                        case .stdout(let data):
                            try await channel.writeAndFlush(data)
                        }
                    }
                }

                do {
                    try await group.next()
                    try await shellContext.close()
                } catch {
                    try await shellContext.close()
                    throw error
                }
            }
        }

        done.futureResult.whenFailure(context.fireErrorCaught)
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        inbound.continuation.yield(.stdin(unwrapInboundIn(data)))
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as SSHChannelRequestEvent.WindowChangeRequest:
            windowSize.continuation.yield(.init(columns: event.terminalCharacterWidth, rows: event.terminalRowHeight))
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
