import NIO
import NIOSSH

final class ClientHandshakeHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    private let promise: EventLoopPromise<Void>
    public var authenticated: EventLoopFuture<Void> {
        promise.futureResult
    }

    init(eventLoop: EventLoop) {
        let promise = eventLoop.makePromise(of: Void.self)
        self.promise = promise
        
        struct AuthenticationFailed: Error {}
        eventLoop.scheduleTask(in: .seconds(10)) {
            promise.fail(AuthenticationFailed())
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is UserAuthSuccessEvent {
            self.promise.succeed(())
        }
    }
    
    deinit {
        struct Disconnected: Error {}
        self.promise.fail(Disconnected())
    }
}

//final class

final class SSHClientSession {
    let channel: Channel
    let sshHandler: NIOSSHHandler
    
    init(channel: Channel, sshHandler: NIOSSHHandler) {
        self.channel = channel
        self.sshHandler = sshHandler
    }
    
    public static func connect(
        on channel: Channel,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator
    ) -> EventLoopFuture<SSHClientSession> {
        let handshakeHandler = ClientHandshakeHandler(eventLoop: channel.eventLoop)
        return channel.pipeline.addHandlers(
            NIOSSHHandler(
                role: .client(
                    .init(
                        userAuthDelegate: authenticationMethod,
                        serverAuthDelegate: hostKeyValidator
                    )
                ),
                allocator: channel.allocator,
                inboundChildChannelInitializer: nil
            ),
            handshakeHandler
        ).flatMap {
            handshakeHandler.authenticated
        }.flatMap {
            channel.pipeline.handler(type: NIOSSHHandler.self).map { sshHandler in
                SSHClientSession(channel: channel, sshHandler: sshHandler)
            }
        }
    }
    
    public static func connect(
        host: String,
        port: Int = 22,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        group: EventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    ) -> EventLoopFuture<SSHClientSession> {
        let handshakeHandler = ClientHandshakeHandler(eventLoop: group.next())
        let bootstrap = ClientBootstrap(group: group).channelInitializer { channel in
            channel.pipeline.addHandlers([
                NIOSSHHandler(
                    role: .client(
                        .init(
                            userAuthDelegate: authenticationMethod,
                            serverAuthDelegate: hostKeyValidator
                        )
                    ),
                    allocator: channel.allocator,
                    inboundChildChannelInitializer: nil
                ),
                handshakeHandler
            ])
        }
        .connectTimeout(.seconds(30))
        .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
        
        return bootstrap.connect(host: host, port: port).flatMap { channel in
            return handshakeHandler.authenticated.flatMap {
                channel.pipeline.handler(type: NIOSSHHandler.self)
            }.map { sshHandler in
                SSHClientSession(channel: channel, sshHandler: sshHandler)
            }
        }
    }
}

public struct InvalidHostKey: Error {}

public struct SSHHostKeyValidator: NIOSSHClientServerAuthenticationDelegate {
    private enum Method {
        case trustedKeys(Set<NIOSSHPublicKey>)
        case acceptAnything
        case custom(NIOSSHClientServerAuthenticationDelegate)
    }
    
    private let method: Method
    
    public func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        switch method {
        case .trustedKeys(let keys):
            if keys.contains(hostKey) {
                validationCompletePromise.succeed(())
            } else {
                validationCompletePromise.fail(InvalidHostKey())
            }
        case .acceptAnything:
            validationCompletePromise.succeed(())
        case .custom(let validator):
            validator.validateHostKey(hostKey: hostKey, validationCompletePromise: validationCompletePromise)
        }
    }
    
    public static func trustedKeys(_ keys: Set<NIOSSHPublicKey>) -> SSHHostKeyValidator {
        SSHHostKeyValidator(method: .trustedKeys(keys))
    }
    
    public static func acceptAnything() -> SSHHostKeyValidator {
        SSHHostKeyValidator(method: .acceptAnything)
    }
    
    public static func custom(_ validator: NIOSSHClientServerAuthenticationDelegate) -> SSHHostKeyValidator {
        SSHHostKeyValidator(method: .custom(validator))
    }
}
