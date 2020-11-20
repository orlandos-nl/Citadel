import NIO
import NIOSSH

public final class SSHClient {
    private(set) var session: SSHClientSession
    private var userInitiatedClose = false
    let host: String
    let port: Int
    let authenticationMethod: AuthenticationMethod
    let hostKeyValidator: HostKeyValidator
    public var connectionSettings = SSHConnectionSettings()
    public var eventLoop: EventLoop {
        session.channel.eventLoop
    }
    
    init(
        session: SSHClientSession,
        host: String,
        port: Int,
        authenticationMethod: AuthenticationMethod,
        hostKeyValidator: HostKeyValidator
    ) {
        self.session = session
        self.host = host
        self.port = port
        self.authenticationMethod = authenticationMethod
        self.hostKeyValidator = hostKeyValidator
    }
    
    public static func connect(
        host: String,
        port: Int = 22,
        authenticationMethod: AuthenticationMethod,
        hostKeyValidator: HostKeyValidator,
        group: MultiThreadedEventLoopGroup = .init(numberOfThreads: 1)
    ) -> EventLoopFuture<SSHClient> {
        return SSHClientSession.connect(
            host: host,
            port: port,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator,
            group: group
        ).map { session in
            return SSHClient(
                session: session,
                host: host,
                port: port,
                authenticationMethod: authenticationMethod,
                hostKeyValidator: hostKeyValidator
            )
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
        case .once:
            _ = self.recreateSession()
        case .always:
            func tryAgain() -> EventLoopFuture<Void> {
                recreateSession().flatMapError { _ in
                    return tryAgain()
                }
            }
            
            _ = tryAgain()
        }
    }
    
    private func recreateSession() -> EventLoopFuture<Void> {
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
    
    public func reconnect() -> EventLoopFuture<Void> {
        let promise = eventLoop.makePromise(of: Void.self)
        
        close().whenComplete { _ in
            self.recreateSession().cascade(to: promise)
        }
        
        return promise.futureResult
    }
    
    public func close() -> EventLoopFuture<Void> {
        return session.channel.eventLoop.flatSubmit {
            self.userInitiatedClose = true
            return self.session.channel.close()
        }
    }
}
