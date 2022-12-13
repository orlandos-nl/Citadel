import NIO
import Logging
import NIOSSH

final class CloseErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any
    let logger: Logger
    
    init(logger: Logger) {
        self.logger = logger
    }
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("SSH Server Error: \(error)")
        context.close(promise: nil)
    }
}

final class SubsystemHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = SSHChannelData
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData
    
    let sftp: SFTPDelegate?
    
    init(sftp: SFTPDelegate?) {
        self.sftp = sftp
    }
    
    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }
    
    func channelInactive(context: ChannelHandlerContext) {
        context.fireChannelInactive()
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as SSHChannelRequestEvent.SubsystemRequest:
            switch event.subsystem {
            case "sftp":
                guard let sftp = sftp else {
                    context.channel.close(promise: nil)
                    return
                }
                
                SFTPServerSubsystem.setupChannelHanders(
                    channel: context.channel,
                    delegate: sftp,
                    logger: .init(label: "nl.orlandos.citadel.sftp-server")
                ).flatMap { () -> EventLoopFuture<Void> in
                    let promise = context.eventLoop.makePromise(of: Void.self)
                    context.channel.triggerUserOutboundEvent(ChannelSuccessEvent(), promise: promise)
                    return promise.futureResult
                }.whenFailure { _ in
                    context.channel.triggerUserOutboundEvent(ChannelFailureEvent(), promise: nil)
                }
            default:
                context.fireUserInboundEventTriggered(event)
            }
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        context.write(data, promise: promise)
    }
}

final class CitadelServerDelegate {
    var sftp: SFTPDelegate?
    var exec: ExecDelegate?
    
    fileprivate init() {}
    
    public func initializeSshChildChannel(_ channel: Channel, _ channelType: SSHChannelType, username: String?) -> NIOCore.EventLoopFuture<Void> {
        switch channelType {
        case .session:
            var handlers = [ChannelHandler]()
            
            handlers.append(SubsystemHandler(sftp: self.sftp))
            
            if let exec = self.exec {
                handlers.append(ExecHandler(delegate: exec, username: username))
            }
            
            return channel.pipeline.addHandlers(handlers)
        case .directTCPIP, .forwardedTCPIP:
            return channel.eventLoop.makeFailedFuture(CitadelError.unsupported)
        }
    }
}

/// An SSH Server implementation.
/// This class is used to start an SSH server on a specified host and port.
/// The server can be closed using the `close()` method.
/// - Note: This class is not thread safe.
public final class SSHServer {
    let channel: Channel
    let delegate: CitadelServerDelegate
    let logger: Logger
    public var closeFuture: EventLoopFuture<Void> {
        channel.closeFuture
    }
    
    init(channel: Channel, logger: Logger, delegate: CitadelServerDelegate) {
        self.channel = channel
        self.logger = logger
        self.delegate = delegate
    }

    
    /// Enables SFTP for SSH session targetting this SSH Server. 
    /// Once SFTP is enabled, the SSH session can be used to send and receive files.
    /// - Parameter delegate: The delegate object that will handle SFTP events.
    /// - Note: SFTP is disabled by default.
    public func enableSFTP(withDelegate delegate: SFTPDelegate) {
        self.delegate.sftp = delegate
    }
    
    /// Enables Exec for SSH session targetting this SSH Server.
    /// Once Exec is enabled, the SSH session can be used to execute commands.
    /// - Note: Exec is disabled by default.
    public func enableExec(withDelegate delegate: ExecDelegate) {
        self.delegate.exec = delegate
    }
    
    /// Closes the SSH Server, stopping new connections from coming in.
    public func close() async throws {
        try await channel.close()
    }
    
    /// Starts a new SSH Server on the specified host and port.
    public static func host(
        host: String,
        port: Int,
        hostKeys: [NIOSSHPrivateKey],
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = [],
        logger: Logger = Logger(label: "nl.orlandos.citadel.server"),
        authenticationDelegate: NIOSSHServerUserAuthenticationDelegate,
        group: MultiThreadedEventLoopGroup = .init(numberOfThreads: 1)
    ) async throws -> SSHServer {
        let delegate = CitadelServerDelegate()
        
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                var server = SSHServerConfiguration(
                    hostKeys: hostKeys,
                    userAuthDelegate: authenticationDelegate,
                    globalRequestDelegate: nil
                )
                
                algorithms.apply(to: &server)
                
                logger.debug("New session being instantiated over TCP")
                
                for option in protocolOptions {
                    option.apply(to: &server)
                }
                
                return channel.pipeline.addHandlers([
                    NIOSSHHandler(
                        role: .server(server),
                        allocator: channel.allocator,
                        inboundChildChannelInitializer: { childChannel, channelType in
                            channel.pipeline.handler(type: NIOSSHHandler.self).flatMap { handler in
                                delegate.initializeSshChildChannel(childChannel, channelType, username: handler.username)
                            }
                        }
                    ),
                    CloseErrorHandler(logger: logger)
                ])
            }
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)

        return try await bootstrap.bind(host: host, port: port).map { channel in
            SSHServer(channel: channel, logger: logger, delegate: delegate)
        }.get()
    }
}

/// A set of options that can be applied to the SSH protocol.
public struct SSHProtocolOption: Hashable {
    internal enum Value: Hashable {
        case maximumPacketSize(Int)
    }
    
    internal let value: Value
    
    /// The maximum packet size that can be sent over the SSH connection.
    public static func maximumPacketSize(_ size: Int) -> Self {
        return .init(value: .maximumPacketSize(size))
    }
    
    func apply(to client: inout SSHClientConfiguration) {
        switch value {
        case .maximumPacketSize(let size):
            client.maximumPacketSize = size
        }
    }
    
    func apply(to server: inout SSHServerConfiguration) {
        switch value {
        case .maximumPacketSize(let size):
            server.maximumPacketSize = size
        }
    }
}
