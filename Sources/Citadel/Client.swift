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
    ) -> EventLoopFuture<SSHClient> {
        SSHClientSession.connect(
            on: channel,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator
        ).map { session in
            return SSHClient(
                session: session,
                authenticationMethod: authenticationMethod,
                hostKeyValidator: hostKeyValidator
            )
        }
    }
    
    public static func connect(
        host: String,
        port: Int = 22,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        reconnect: SSHReconnectMode,
        group: MultiThreadedEventLoopGroup = .init(numberOfThreads: 1)
    ) -> EventLoopFuture<SSHClient> {
        return SSHClientSession.connect(
            host: host,
            port: port,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator,
            group: group
        ).map { session in
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
    }
    
    private func onNewSession(_ session: SSHClientSession) {
        session.channel.closeFuture.whenComplete { [weak self] _ in
            self?.onClose()
        }
    }
    
    private func onClose() {
        switch connectionSettings.reconnect.mode {
        case .never:
            return
        case .once(let host, let port):
            _ = self.recreateSession(host: host, port: port)
        case .always(let host, let port):
            func tryAgain() -> EventLoopFuture<Void> {
                recreateSession(host: host, port: port).flatMapError { _ in
                    return tryAgain()
                }
            }
            
            _ = tryAgain()
        }
    }
    
    private func recreateSession(host: String, port: Int) -> EventLoopFuture<Void> {
        if userInitiatedClose {
            return self.eventLoop.makeSucceededVoidFuture()
        }
        
        return SSHClientSession.connect(
            host: host,
            port: port,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: self.hostKeyValidator,
            group: session.channel.eventLoop
        ).map { session in
            self.session = session
        }
    }
    
    public func close() -> EventLoopFuture<Void> {
        return session.channel.eventLoop.flatSubmit {
            self.userInitiatedClose = true
            return self.session.channel.close()
        }
    }
}
