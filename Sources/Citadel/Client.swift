import Foundation
import NIO
import Crypto
import Logging
import NIOSSH

extension SSHAlgorithms.Modification<NIOSSHTransportProtection.Type> {
    func apply(to configuration: inout [any NIOSSHTransportProtection.Type]) {
        switch self {
        case .add(let algorithms):
            configuration.append(contentsOf: algorithms)
            
            for algorithm: any NIOSSHTransportProtection.Type in algorithms {
                NIOSSHAlgorithms.register(transportProtectionScheme: algorithm)
            }
        case .replace(with: let algorithms):
            configuration = algorithms
            
            for algorithm in algorithms {
                NIOSSHAlgorithms.register(transportProtectionScheme: algorithm)
            }
        }
    }
}

extension SSHAlgorithms.Modification<NIOSSHKeyExchangeAlgorithmProtocol.Type> {
    func apply(to configuration: inout [any NIOSSHKeyExchangeAlgorithmProtocol.Type]) {
        switch self {
        case .add(let algorithms):
            configuration.append(contentsOf: algorithms)
            
            for algorithm in algorithms {
                NIOSSHAlgorithms.register(keyExchangeAlgorithm: algorithm)
            }
        case .replace(with: let algorithms):
            configuration = algorithms
            
            for algorithm in algorithms {
                NIOSSHAlgorithms.register(keyExchangeAlgorithm: algorithm)
            }
        }
    }
}

extension SSHAlgorithms.Modification<(NIOSSHPublicKeyProtocol.Type, NIOSSHSignatureProtocol.Type)>{
    func register() {
        switch self {
        case .add(let algorithms):
            for (publicKey, signature) in algorithms {
                NIOSSHAlgorithms.register(publicKey: publicKey, signature: signature)
            }
        case .replace(with: let algorithms):
            for (publicKey, signature) in algorithms {
                NIOSSHAlgorithms.register(publicKey: publicKey, signature: signature)
            }
        }
    }
}

public struct SSHAlgorithms: Sendable {
    /// Represents a modification to a list of items.
    ///
    /// - replace: Replaces the existing list of items with the given list of items.
    /// - add: Adds the given list of items to the list of items.
    public enum Modification<T: Sendable>: Sendable {
        case replace(with: [T])
        case add([T])
    }
    
    /// The enabled TransportProtectionSchemes.
    public var transportProtectionSchemes: Modification<NIOSSHTransportProtection.Type>?
    
    /// The enabled KeyExchangeAlgorithms
    public var keyExchangeAlgorithms: Modification<NIOSSHKeyExchangeAlgorithmProtocol.Type>?

    public var publicKeyAlgorihtms: Modification<(NIOSSHPublicKeyProtocol.Type, NIOSSHSignatureProtocol.Type)>?

    func apply(to clientConfiguration: inout SSHClientConfiguration) {
        transportProtectionSchemes?.apply(to: &clientConfiguration.transportProtectionSchemes)
        keyExchangeAlgorithms?.apply(to: &clientConfiguration.keyExchangeAlgorithms)
        publicKeyAlgorihtms?.register()
    }
    
    func apply(to serverConfiguration: inout SSHServerConfiguration) {
        transportProtectionSchemes?.apply(to: &serverConfiguration.transportProtectionSchemes)
        keyExchangeAlgorithms?.apply(to: &serverConfiguration.keyExchangeAlgorithms)
        publicKeyAlgorihtms?.register()
    }
    
    public init() {}

    public static let all: SSHAlgorithms = {
        var algorithms = SSHAlgorithms()

        algorithms.transportProtectionSchemes = .add([
            AES128CTR.self
        ])

        algorithms.keyExchangeAlgorithms = .add([
            DiffieHellmanGroup14Sha1.self,
            DiffieHellmanGroup14Sha256.self
        ])

        algorithms.publicKeyAlgorihtms = .add([
            (Insecure.RSA.PublicKey.self, Insecure.RSA.Signature.self),
        ])

        return algorithms
    }()
}

/// Represents an SSH connection.
public final class SSHClient {
    private(set) var session: SSHClientSession!
    private var userInitiatedClose = false
    let authenticationMethod: () -> SSHAuthenticationMethod
    let hostKeyValidator: SSHHostKeyValidator
    internal var connectionSettings = SSHConnectionPoolSettings()
    private let algorithms: SSHAlgorithms
    private let protocolOptions: Set<SSHProtocolOption>
    private var onDisconnect: (@Sendable () -> ())?
    public let logger = Logger(label: "nl.orlandos.citadel.client")
    internal var forwardedTCPIPHandler: (@Sendable (Channel, SSHChannelType.ForwardedTCPIP) -> EventLoopFuture<Void>)?
    public var isConnected: Bool {
        session?.channel.isActive ?? false
    }

    /// The event loop that this SSH connection is running on.
    public var eventLoop: EventLoop {
        session.channel.eventLoop
    }

    init(
        session: SSHClientSession?,
        authenticationMethod: @escaping @autoclosure () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption>
    ) {
        self.session = session
        self.authenticationMethod = authenticationMethod
        self.hostKeyValidator = hostKeyValidator
        self.algorithms = algorithms
        self.protocolOptions = protocolOptions

        if let session = session {
            onNewSession(session)
        }
    }
    
    public func onDisconnect(perform onDisconnect: @escaping @Sendable () -> ()) {
        self.onDisconnect = onDisconnect
    }

    /// Helper to create the inbound channel initializer for handling forwarded-tcpip channels
    private static func makeInboundChannelInitializer(
        for client: SSHClient
    ) -> (@Sendable (Channel, SSHChannelType) -> EventLoopFuture<Void>) {
        return { [weak client] channel, channelType in
            guard let client = client else {
                return channel.eventLoop.makeFailedFuture(SSHClientError.channelCreationFailed)
            }

            client.logger.trace("Inbound channel initializer called", metadata: ["channel_type": "\(channelType)"])

            switch channelType {
            case .forwardedTCPIP(let forwardedInfo):
                client.logger.debug("Received forwardedTCPIP channel request", metadata: [
                    "originator": "\(forwardedInfo.originatorAddress)",
                    "listening_host": "\(forwardedInfo.listeningHost)",
                    "listening_port": "\(forwardedInfo.listeningPort)"
                ])

                guard let handler = client.forwardedTCPIPHandler else {
                    client.logger.error("No forwardedTCPIPHandler set - rejecting connection")
                    return channel.eventLoop.makeFailedFuture(SSHClientError.channelCreationFailed)
                }

                // Add DataToBufferCodec to unwrap SSHChannelData, just like DirectTCPIP does
                client.logger.trace("Adding DataToBufferCodec to channel pipeline")
                do {
                    try channel.pipeline.syncOperations.addHandler(DataToBufferCodec())
                    client.logger.trace("DataToBufferCodec added successfully")
                } catch {
                    client.logger.error("Failed to add DataToBufferCodec", metadata: ["error": "\(error)"])
                    return channel.eventLoop.makeFailedFuture(error)
                }

                return handler(channel, forwardedInfo)

            default:
                client.logger.warning("Unsupported inbound channel type", metadata: ["channel_type": "\(channelType)"])
                return channel.eventLoop.makeFailedFuture(SSHClientError.channelCreationFailed)
            }
        }
    }

    /// Connects to an SSH server.
    /// - settings: The settings to use for the connection.
    /// - Returns: An SSH client.
    public static func connect(
        to settings: SSHClientSettings
    ) async throws -> SSHClient {
        var modifiedSettings = settings
        let client = SSHClient(
            session: nil,
            authenticationMethod: settings.authenticationMethod(),
            hostKeyValidator: settings.hostKeyValidator,
            algorithms: settings.algorithms,
            protocolOptions: settings.protocolOptions
        )

        // Setup the inbound channel initializer to handle forwarded-tcpip channels
        modifiedSettings.inboundChildChannelInitializer = makeInboundChannelInitializer(for: client)

        let session = try await SSHClientSession.connect(settings: modifiedSettings)
        client.session = session
        client.onNewSession(session)

        return client
    }

    /// Connects to an SSH server.
    /// - settings: The settings to use for the connection.
    /// - Returns: An SSH client.
    public static func connect(
        on channel: Channel,
        settings: SSHClientSettings
    ) async throws -> SSHClient {
        var modifiedSettings = settings
        let client = SSHClient(
            session: nil,
            authenticationMethod: settings.authenticationMethod(),
            hostKeyValidator: settings.hostKeyValidator,
            algorithms: settings.algorithms,
            protocolOptions: settings.protocolOptions
        )

        // Setup the inbound channel initializer to handle forwarded-tcpip channels
        modifiedSettings.inboundChildChannelInitializer = makeInboundChannelInitializer(for: client)

        try await SSHClientSession.addHandlers(
            on: channel,
            settings: modifiedSettings
        ).get()

        let sshHandler = try await channel.pipeline.handler(type: NIOSSHHandler.self).get()
        let handshakeHandler = try await channel.pipeline.handler(type: ClientHandshakeHandler.self).get()
        let session = try await handshakeHandler.authenticated.map {
            SSHClientSession(channel: channel, sshHandler: sshHandler)
        }.get()

        client.session = session
        client.onNewSession(session)

        return client
    }

    public func jump(to settings: SSHClientSettings) async throws -> SSHClient {
        var modifiedSettings = settings
        let client = SSHClient(
            session: nil,
            authenticationMethod: settings.authenticationMethod(),
            hostKeyValidator: settings.hostKeyValidator,
            algorithms: settings.algorithms,
            protocolOptions: settings.protocolOptions
        )

        // Setup the inbound channel initializer to handle forwarded-tcpip channels
        modifiedSettings.inboundChildChannelInitializer = SSHClient.makeInboundChannelInitializer(for: client)

        let originatorAddress = try SocketAddress(ipAddress: "fe80::1", port: 22)
        let channel = try await self.createDirectTCPIPChannel(
            using: SSHChannelType.DirectTCPIP(
                targetHost: settings.host,
                targetPort: settings.port,
                originatorAddress: originatorAddress
            )
        ) { channel in
            SSHClientSession.addHandlers(
                on: channel,
                settings: modifiedSettings
            )
        }

        let sshHandler = try await channel.pipeline.handler(type: NIOSSHHandler.self).get()
        let handshakeHandler = try await channel.pipeline.handler(type: ClientHandshakeHandler.self).get()
        let session = try await handshakeHandler.authenticated.map {
            SSHClientSession(channel: channel, sshHandler: sshHandler)
        }.get()

        client.session = session
        client.onNewSession(session)

        return client
    }
    
    /// Connects to an SSH server.
    /// - Parameters:
    ///  - channel: The channel to use for the connection.
    /// - authenticationMethod: The authentication method to use. See `SSHAuthenticationMethod` for more information.
    /// - hostKeyValidator: The host key validator to use. See `SSHHostKeyValidator` for more information.
    /// - algorithms: The algorithms to use. See `SSHAlgorithms` for more information.
    /// - protocolOptions: The protocol options to use. See `SSHProtocolOption` for more information.
    /// - Returns: An SSH client.
    public static func connect(
        on channel: Channel,
        authenticationMethod: @escaping @autoclosure () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = []
    ) async throws -> SSHClient {
        let client = SSHClient(
            session: nil,
            authenticationMethod: authenticationMethod(),
            hostKeyValidator: hostKeyValidator,
            algorithms: algorithms,
            protocolOptions: protocolOptions
        )

        var settings = SSHClientSettings(
            host: "unknown",
            port: 0,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator
        )
        settings.algorithms = algorithms
        settings.protocolOptions = protocolOptions

        // Setup the inbound channel initializer to handle forwarded-tcpip channels
        settings.inboundChildChannelInitializer = SSHClient.makeInboundChannelInitializer(for: client)

        try await SSHClientSession.addHandlers(
            on: channel,
            settings: settings
        ).get()

        let sshHandler = try await channel.pipeline.handler(type: NIOSSHHandler.self).get()
        let session = SSHClientSession(channel: channel, sshHandler: sshHandler)

        client.session = session
        client.onNewSession(session)

        return client
    }
    
    /// Connects to an SSH server.
    /// - Parameters:
    /// - host: The host to connect to.
    /// - port: The port to connect to. Defaults to 22.
    /// - authenticationMethod: The authentication method to use. See `SSHAuthenticationMethod` for more information.
    /// - hostKeyValidator: The host key validator to use. See `SSHHostKeyValidator` for more information.
    /// - reconnect: The reconnect mode to use. See `SSHReconnectMode` for more information.
    /// - algorithms: The algorithms to use. See `SSHAlgorithms` for more information.
    /// - protocolOptions: The protocol options to use. See `SSHProtocolOption` for more information.
    /// - group: The event loop group to use. Defaults to a single-threaded event loop group.
    /// - channelHandlers: Pass in an array of channel prehandlers that execute first. Default empty array
    /// - connectTimeout: Pass in the time before the connection times out. Default 30 seconds.
    /// - Returns: An SSH client.
    public static func connect(
        host: String,
        port: Int = 22,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        reconnect: SSHReconnectMode,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = [],
        group: MultiThreadedEventLoopGroup = .singleton,
        channelHandlers: [ChannelHandler] = [],
        connectTimeout:TimeAmount = .seconds(30)
    ) async throws -> SSHClient {
        // Create settings and use the main connect method to ensure proper setup
        var settings = SSHClientSettings(
            host: host,
            port: port,
            authenticationMethod: { authenticationMethod },
            hostKeyValidator: hostKeyValidator
        )
        settings.algorithms = algorithms
        settings.protocolOptions = protocolOptions
        settings.group = group
        settings.channelHandlers = channelHandlers
        settings.connectTimeout = connectTimeout

        let client = try await connect(to: settings)
        
        switch reconnect.mode {
        case .always:
            client.connectionSettings.reconnect = .always(to: host, port: port)
        case .once:
            client.connectionSettings.reconnect = .once(to: host, port: port)
        case .never:
            client.connectionSettings.reconnect = .never
        }
        
        return client
    }
    
    private func onNewSession(_ session: SSHClientSession) {
        session.channel.closeFuture.whenComplete { [weak self] _ in
            self?.onClose()
        }
    }
    
    private func onClose() {
        Task {
            self.onDisconnect?()
            
            switch connectionSettings.reconnect.mode {
            case .never:
                return
            case .once(let host, let port):
                _ = try? await self.recreateSession(host: host, port: port)
            case .always(let host, let port):
                func tryAgain() async throws {
                    do {
                        try await self.recreateSession(host: host, port: port)
                    } catch {
                        return try await tryAgain()
                    }
                }
                
                _ = try? await tryAgain()
            }
        }
    }
    
    private func recreateSession(host: String, port: Int) async throws {
        if userInitiatedClose {
            return
        }
        
        self.session = try await SSHClientSession.connect(
            host: host,
            port: port,
            authenticationMethod: self.authenticationMethod(),
            hostKeyValidator: self.hostKeyValidator,
            protocolOptions: protocolOptions,
            group: session.channel.eventLoop
        )
        
        onNewSession(session)
    }
    
    public func close() async throws {
        self.userInitiatedClose = true
        try await self.session.channel.close()
    }
}
