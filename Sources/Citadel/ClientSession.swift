import NIO
import NIOSSH
import Logging

final class ClientHandshakeHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    private let promise: EventLoopPromise<Void>
    let logger = Logger(label: "nl.orlandos.citadel.handshake")

    /// A future that will be fulfilled when the handshake is complete.
    public var authenticated: EventLoopFuture<Void> {
        promise.futureResult
    }

    init(eventLoop: EventLoop, loginTimeout: TimeAmount) {
        let promise = eventLoop.makePromise(of: Void.self)
        self.promise = promise
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is UserAuthSuccessEvent {
            self.promise.succeed(())
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        self.promise.fail(error)
    }
    
    deinit {
        struct Disconnected: Error {}
        self.promise.fail(Disconnected())
    }
}

final class SSHClientSession {
    let channel: Channel
    let sshHandler: NIOSSHHandler
    
    init(channel: Channel, sshHandler: NIOSSHHandler) {
        self.channel = channel
        self.sshHandler = sshHandler
    }
    
    /// Creates a new SSH session on the given channel. This allows you to use an existing channel for the SSH session.
    /// - authenticationMethod: The authentication method to use, see `SSHAuthenticationMethod`.
    /// - hostKeyValidator: The host key validator to use, see `SSHHostKeyValidator`.
    /// - algorithms: The algorithms to use, will use the default algorithms if not specified.
    /// - protocolOptions: The protocol options to use, will use the default options if not specified.
    /// - group: The event loop group to use, will use a new group with one thread if not specified.
    public static func connect(
        on channel: Channel,
        authenticationMethod: @escaping @autoclosure () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = []
    ) async throws -> SSHClientSession {
        let handshakeHandler = ClientHandshakeHandler(
            eventLoop: channel.eventLoop,
            loginTimeout: .seconds(10)
        )
        var clientConfiguration = SSHClientConfiguration(
            userAuthDelegate: authenticationMethod(),
            serverAuthDelegate: hostKeyValidator
        )
        
        algorithms.apply(to: &clientConfiguration)
        
        for option in protocolOptions {
            option.apply(to: &clientConfiguration)
        }
        
        return try await channel.pipeline.addHandlers(
            NIOSSHHandler(
                role: .client(clientConfiguration),
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
        }.get()
    }
    
    /// Creates a new SSH session on a new channel. This will connect to the given host and port.
    /// - Parameters:
    ///  - host: The host to connect to.
    /// - port: The port to connect to.
    /// - authenticationMethod: The authentication method to use, see `SSHAuthenticationMethod`.
    /// - hostKeyValidator: The host key validator to use, see `SSHHostKeyValidator`.
    /// - algorithms: The algorithms to use, will use the default algorithms if not specified.
    /// - protocolOptions: The protocol options to use, will use the default options if not specified.
    /// - group: The event loop group to use, will use a new group with one thread if not specified.
    /// - channelHandlers: Pass in an array of channel prehandlers that execute first. Default empty array
    /// - connectTimeout: Pass in the time before the connection times out. Default 30 seconds.
    public static func connect(
        host: String,
        port: Int = 22,
        authenticationMethod: @escaping @autoclosure () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = [],
        group: EventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1),
        channelHandlers: [ChannelHandler] = [],
        connectTimeout: TimeAmount = .seconds(30)
    ) async throws -> SSHClientSession {
        let handshakeHandler = ClientHandshakeHandler(
            eventLoop: group.next(),
            loginTimeout: .seconds(10)
        )
        var clientConfiguration = SSHClientConfiguration(
            userAuthDelegate: authenticationMethod(),
            serverAuthDelegate: hostKeyValidator
        )
        
        algorithms.apply(to: &clientConfiguration)
        
        for option in protocolOptions {
            option.apply(to: &clientConfiguration)
        }
        
        let bootstrap = ClientBootstrap(group: group).channelInitializer { channel in
            channel.pipeline.addHandlers(channelHandlers + [
                NIOSSHHandler(
                    role: .client(clientConfiguration),
                    allocator: channel.allocator,
                    inboundChildChannelInitializer: nil
                ),
                handshakeHandler
            ])
        }
        .connectTimeout(connectTimeout)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
        
        return try await bootstrap.connect(host: host, port: port).flatMap { channel in
            return handshakeHandler.authenticated.flatMap {
                channel.pipeline.handler(type: NIOSSHHandler.self)
            }.map { sshHandler in
                SSHClientSession(channel: channel, sshHandler: sshHandler)
            }
        }.get()
    }
}

public struct InvalidHostKey: Error, Equatable {}

/// A host key validator that can be used to validate an SSH host key. This can be used to validate the host key against a set of trusted keys, or to accept any key.
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
    
    /// Creates a new host key validator that will validate the host key against the given set of trusted keys. If the host key is not in the set, the validation will fail.
    /// - Parameter keys: The set of trusted keys.
    public static func trustedKeys(_ keys: Set<NIOSSHPublicKey>) -> SSHHostKeyValidator {
        SSHHostKeyValidator(method: .trustedKeys(keys))
    }
    
    /// Creates a new host key validator that will accept any host key. This is not recommended for production use.
    public static func acceptAnything() -> SSHHostKeyValidator {
        SSHHostKeyValidator(method: .acceptAnything)
    }
    
    /// Creates a new host key validator that will use the given custom validator. This can be used to implement custom host key validation logic.
    public static func custom(_ validator: NIOSSHClientServerAuthenticationDelegate) -> SSHHostKeyValidator {
        SSHHostKeyValidator(method: .custom(validator))
    }
}
