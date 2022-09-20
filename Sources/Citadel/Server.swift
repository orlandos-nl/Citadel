import NIO
import Logging
import NIOSSH

final class CloseErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
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
                
                _ = SFTPServerSubsystem.setupChannelHanders(
                    channel: context.channel,
                    delegate: sftp,
                    logger: .init(label: "nl.orlandos.citadel.sftp-server")
                )
            default:
                context.fireUserInboundEventTriggered(event)
            }
        case ChannelEvent.inputClosed:
            context.channel.close(promise: nil)
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
    
    fileprivate init() {}
    
    public func initializeSshChildChannel(_ channel: Channel, _ channelType: SSHChannelType) -> NIOCore.EventLoopFuture<Void> {
        switch channelType {
        case .session:
            return channel.pipeline.addHandler(SubsystemHandler(sftp: sftp))
        case .directTCPIP, .forwardedTCPIP:
            return channel.eventLoop.makeFailedFuture(CitadelError.unsupported)
        }
    }
}

public final class SSHServer {
    let channel: Channel
    let delegate: CitadelServerDelegate
    public var closeFuture: EventLoopFuture<Void> {
        channel.closeFuture
    }
    
    init(channel: Channel, delegate: CitadelServerDelegate) {
        self.channel = channel
        self.delegate = delegate
    }
    
    public func enableSFTP(withDelegate delegate: SFTPDelegate) {
        self.delegate.sftp = delegate
    }
    
    public func close() async throws {
        try await channel.close()
    }
    
    public static func host(
        host: String,
        port: Int,
        hostKeys: [NIOSSHPrivateKey],
        authenticationDelegate: NIOSSHServerUserAuthenticationDelegate,
        group: MultiThreadedEventLoopGroup = .init(numberOfThreads: 1)
    ) async throws -> SSHServer {
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let delegate = CitadelServerDelegate()
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.pipeline.addHandlers([
                    NIOSSHHandler(
                        role: .server(
                            .init(
                                hostKeys: [hostKey],
                                userAuthDelegate: authenticationDelegate,
                                globalRequestDelegate: nil
                            )
                        ),
                        allocator: channel.allocator,
                        inboundChildChannelInitializer: delegate.initializeSshChildChannel
                    ),
                    CloseErrorHandler()
                ])
            }
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)

        return try await bootstrap.bind(host: host, port: port).map { channel in
            SSHServer(channel: channel, delegate: delegate)
        }.get()
    }
}
