import NIO
import NIOSSH

public struct SSHAlgorithms {
    public enum Modification<T> {
        case replace(with: [T])
        case add([T])
    }
    
    /// The enabled TransportProtectionSchemes
    public var transportProtectionSchemes: Modification<NIOSSHTransportProtection.Type>?
    
    /// The enabled KeyExchangeAlgorithms
    public var keyExchangeAlgorithms: Modification<NIOSSHKeyExchangeAlgorithmProtocol.Type>?

    func apply(to clientConfiguration: inout SSHClientConfiguration) {
        switch transportProtectionSchemes {
        case .add(let algorithms):
            clientConfiguration.transportProtectionSchemes.append(contentsOf: algorithms)
        case .replace(with: let algorithms):
            clientConfiguration.transportProtectionSchemes = algorithms
        case .none:
            ()
        }
        
        switch keyExchangeAlgorithms {
        case .add(let algorithms):
            clientConfiguration.keyExchangeAlgorithms.append(contentsOf: algorithms)
        case .replace(with: let algorithms):
            clientConfiguration.keyExchangeAlgorithms = algorithms
        case .none:
            ()
        }
    }
    
    func apply(to serverConfiguration: inout SSHServerConfiguration) {
        switch transportProtectionSchemes {
        case .add(let algorithms):
            serverConfiguration.transportProtectionSchemes.append(contentsOf: algorithms)
        case .replace(with: let algorithms):
            serverConfiguration.transportProtectionSchemes = algorithms
        case .none:
            ()
        }
        
        switch keyExchangeAlgorithms {
        case .add(let algorithms):
            serverConfiguration.keyExchangeAlgorithms.append(contentsOf: algorithms)
        case .replace(with: let algorithms):
            serverConfiguration.keyExchangeAlgorithms = algorithms
        case .none:
            ()
        }
    }
    
    public init() {}
}

public final class SSHClient {
    private(set) var session: SSHClientSession
    private var userInitiatedClose = false
    let authenticationMethod: SSHAuthenticationMethod
    let hostKeyValidator: SSHHostKeyValidator
    internal var connectionSettings = SSHConnectionSettings()
    private let algorithms: SSHAlgorithms
    private let protocolOptions: Set<SSHProtocolOption>
    public var eventLoop: EventLoop {
        session.channel.eventLoop
    }
    
    init(
        session: SSHClientSession,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption>
    ) {
        self.session = session
        self.authenticationMethod = authenticationMethod
        self.hostKeyValidator = hostKeyValidator
        self.algorithms = algorithms
        self.protocolOptions = protocolOptions
    }
    
    public static func connect(
        on channel: Channel,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = []
    ) async throws -> SSHClient {
        let session = try await SSHClientSession.connect(
            on: channel,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator,
            protocolOptions: protocolOptions
        )
        
        return SSHClient(
            session: session,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator,
            algorithms: algorithms,
            protocolOptions: protocolOptions
        )
    }
    
    public static func connect(
        host: String,
        port: Int = 22,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        reconnect: SSHReconnectMode,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = [],
        group: MultiThreadedEventLoopGroup = .init(numberOfThreads: 1)
    ) async throws -> SSHClient {
        let session = try await SSHClientSession.connect(
            host: host,
            port: port,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator,
            algorithms: algorithms,
            protocolOptions: protocolOptions,
            group: group
        )
        
        let client = SSHClient(
            session: session,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator,
            algorithms: algorithms,
            protocolOptions: protocolOptions
        )
        
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
            authenticationMethod: authenticationMethod,
            hostKeyValidator: self.hostKeyValidator,
            protocolOptions: protocolOptions,
            group: session.channel.eventLoop
        )
    }
    
    public func close() async throws {
        self.userInitiatedClose = true
        try await self.session.channel.close()
    }
}
