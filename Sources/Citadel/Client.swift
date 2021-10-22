import NIO
import NIOSSH

public final class SSHClient {
    private(set) var session: SSHClientSession
    private var userInitiatedClose = false
    let authenticationMethod: SSHAuthenticationMethod
    let hostKeyValidator: SSHHostKeyValidator
    internal var connectionSettings = SSHConnectionSettings()
    public var eventLoop: EventLoop {
        session.channel.eventLoop
    }
    
    init(
        session: SSHClientSession,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator
    ) {
        self.session = session
        self.authenticationMethod = authenticationMethod
        self.hostKeyValidator = hostKeyValidator
    }
    
    public static func connect(
        on channel: Channel,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator
    ) async throws -> SSHClient {
        let session = try await SSHClientSession.connect(
            on: channel,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator
        )
        
        return SSHClient(
            session: session,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator
        )
    }
    
    public static func connect(
        host: String,
        port: Int = 22,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        reconnect: SSHReconnectMode,
        group: MultiThreadedEventLoopGroup = .init(numberOfThreads: 1)
    ) async throws -> SSHClient {
        let session = try await SSHClientSession.connect(
            host: host,
            port: port,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator,
            group: group
        )
        
        let client = SSHClient(
            session: session,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator
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
            group: session.channel.eventLoop
        )
    }
    
    public func close() async throws {
        self.userInitiatedClose = true
        try await self.session.channel.close()
    }
}
