import NIO
@preconcurrency import NIOSSH
import Logging
import NIOConcurrencyHelpers

final class ClientHandshakeHandler: ChannelInboundHandler, Sendable {
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

public struct SSHConnectionSettings: Sendable {
    public var host: String
    public var port: Int
    public var authenticationMethod: @Sendable () -> SSHAuthenticationMethod
    public var hostKeyValidator: SSHHostKeyValidator
    public var algorithms: SSHAlgorithms = SSHAlgorithms()
    public var protocolOptions: Set<SSHProtocolOption> = []
    public var group: EventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    internal var channelHandlers: [ChannelHandler & Sendable] = []
    public var connectTimeout: TimeAmount = .seconds(30)

    init(
        host: String,
        port: Int = 22,
        authenticationMethod: @Sendable @escaping () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator
    ) {
        self.host = host
        self.port = port
        self.authenticationMethod = authenticationMethod
        self.hostKeyValidator = hostKeyValidator
    }
}

final class SSHClientSession {
    let channel: Channel
    let sshHandler: NIOLoopBoundBox<NIOSSHHandler>
    
    init(channel: Channel, sshHandler: NIOSSHHandler) {
        self.channel = channel
        self.sshHandler = NIOLoopBoundBox(sshHandler, eventLoop: channel.eventLoop)
    }
    
    /// Creates a new SSH session on the given channel. This allows you to use an existing channel for the SSH session.
    /// - authenticationMethod: The authentication method to use, see `SSHAuthenticationMethod`.
    /// - hostKeyValidator: The host key validator to use, see `SSHHostKeyValidator`.
    /// - algorithms: The algorithms to use, will use the default algorithms if not specified.
    /// - protocolOptions: The protocol options to use, will use the default options if not specified.
    /// - group: The event loop group to use, will use a new group with one thread if not specified.
    public static func connect(
        on channel: Channel,
        authenticationMethod: @escaping @Sendable @autoclosure () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = []
    ) async throws -> SSHClientSession {
        try await connect(
            on: channel,
            settings: SSHConnectionSettings(
                host: "127.0.0.1",
                port: 22,
                authenticationMethod: authenticationMethod,
                hostKeyValidator: hostKeyValidator
            )
        )
    }

    /// Creates a new SSH session on the given channel. This allows you to use an existing channel for the SSH session.
    /// - channel: The channel to use for the SSH session, could be an existing TCP socket or proxy connection.
    /// - settings: The settings to use for the SSH session.
    public static func connect(
        on channel: Channel,
        settings: SSHConnectionSettings
    ) async throws -> SSHClientSession {
        let handshakeHandler = ClientHandshakeHandler(
            eventLoop: settings.group.next(),
            loginTimeout: .seconds(10)
        )
        var clientConfiguration = SSHClientConfiguration(
            userAuthDelegate: settings.authenticationMethod(),
            serverAuthDelegate: settings.hostKeyValidator
        )
        
        settings.algorithms.apply(to: &clientConfiguration)
        
        for option in settings.protocolOptions {
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
    /// - settings: The settings to use for the SSH session.
    public static func connect(
        settings: SSHConnectionSettings
    ) async throws -> SSHClientSession {
        let handshakeHandler = ClientHandshakeHandler(
            eventLoop: settings.group.next(),
            loginTimeout: .seconds(10)
        )
        var clientConfiguration = SSHClientConfiguration(
            userAuthDelegate: settings.authenticationMethod(),
            serverAuthDelegate: settings.hostKeyValidator
        )
        
        settings.algorithms.apply(to: &clientConfiguration)
        
        for option in settings.protocolOptions {
            option.apply(to: &clientConfiguration)
        }
        
        let bootstrap = ClientBootstrap(group: settings.group).channelInitializer { channel in
            channel.pipeline.addHandlers(settings.channelHandlers + [
                NIOSSHHandler(
                    role: .client(clientConfiguration),
                    allocator: channel.allocator,
                    inboundChildChannelInitializer: nil
                ),
                handshakeHandler
            ])
        }
        .connectTimeout(settings.connectTimeout)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
        
        return try await bootstrap.connect(host: settings.host, port: settings.port).flatMap { channel in
            return handshakeHandler.authenticated.flatMap {
                channel.pipeline.handler(type: NIOSSHHandler.self)
            }.map { sshHandler in
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
        authenticationMethod: @Sendable @escaping @autoclosure () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = [],
        group: EventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1),
        channelHandlers: [ChannelHandler] = [],
        connectTimeout: TimeAmount = .seconds(30)
    ) async throws -> SSHClientSession {
        var settings = SSHConnectionSettings(
            host: host,
            port: port,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator
        )

        settings.algorithms = algorithms
        settings.protocolOptions = protocolOptions
        settings.group = group
        settings.channelHandlers = channelHandlers
        settings.connectTimeout = connectTimeout
        
        return try await connect(
            settings: settings
        )
    }
}

public struct InvalidHostKey: Error, Equatable {}

/// A host key validator that can be used to validate an SSH host key. This can be used to validate the host key against a set of trusted keys, or to accept any key.
public struct SSHHostKeyValidator: NIOSSHClientServerAuthenticationDelegate, Sendable {
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
