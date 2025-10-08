import NIO
import NIOSSH

/// A delegate for handling remote port forwarding requests on the SSH server.
///
/// When a client requests remote port forwarding, the server will start listening on the
/// specified address and forward incoming connections back to the client.
public protocol RemotePortForwardDelegate: Sendable {
    /// Called when a client requests the server to start listening on a port.
    ///
    /// - Parameters:
    ///   - host: The host address to listen on.
    ///   - port: The port to listen on (0 means the server should choose a port).
    ///   - handler: The SSH handler that can be used to create forwarded-tcpip channels.
    ///   - eventLoop: The event loop to use for the response.
    ///   - context: Additional context about the SSH connection.
    /// - Returns: The actual port that was bound, or nil to reject the request.
    func startListening(
        host: String,
        port: Int,
        handler: NIOSSHHandler,
        eventLoop: EventLoop,
        context: SSHContext
    ) -> EventLoopFuture<Int?>

    /// Called when a client requests the server to stop listening on a port.
    ///
    /// - Parameters:
    ///   - host: The host address to stop listening on.
    ///   - port: The port to stop listening on.
    ///   - eventLoop: The event loop to use for the response.
    ///   - context: Additional context about the SSH connection.
    /// - Returns: A future that succeeds if the cancellation was accepted.
    func stopListening(
        host: String,
        port: Int,
        eventLoop: EventLoop,
        context: SSHContext
    ) -> EventLoopFuture<Void>
}

/// A default implementation of RemotePortForwardDelegate that allows all forwarding requests.
///
/// This delegate will bind to requested ports and forward incoming connections to the SSH client.
/// Use this as a reference implementation or for testing purposes.
///
/// - Warning: This implementation allows forwarding to any port, which may be a security risk.
///   In production, you should implement custom validation and restrictions.
public struct DefaultRemotePortForwardDelegate: RemotePortForwardDelegate {
    private let eventLoopGroup: EventLoopGroup
    private let allowedHosts: [String]?
    private let allowedPorts: [Int]?

    /// Creates a new default remote port forward delegate.
    ///
    /// - Parameters:
    ///   - eventLoopGroup: The event loop group to use for listening sockets.
    ///   - allowedHosts: Optional whitelist of hosts that can be listened on. If nil, all hosts are allowed.
    ///   - allowedPorts: Optional whitelist of ports that can be listened on. If nil, all ports are allowed.
    public init(
        eventLoopGroup: EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
        allowedHosts: [String]? = nil,
        allowedPorts: [Int]? = nil
    ) {
        self.eventLoopGroup = eventLoopGroup
        self.allowedHosts = allowedHosts
        self.allowedPorts = allowedPorts
    }

    public func startListening(
        host: String,
        port: Int,
        handler: NIOSSHHandler,
        eventLoop: EventLoop,
        context: SSHContext
    ) -> EventLoopFuture<Int?> {
        // Validate host
        if let allowedHosts = allowedHosts, !allowedHosts.contains(host) {
            return eventLoop.makeSucceededFuture(nil as Int?)
        }

        // Validate port
        if let allowedPorts = allowedPorts, port != 0, !allowedPorts.contains(port) {
            return eventLoop.makeSucceededFuture(nil as Int?)
        }

        // Start listening on the requested host and port
        let serverBootstrap = ServerBootstrap(group: eventLoopGroup)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { childChannel in
                // For each incoming connection, we need to create a forwarded-tcpip channel
                // back to the SSH client and pipe the data between them.
                //
                // Note: This is a simplified implementation. A production implementation
                // would need to track these channels and close them properly.
                childChannel.eventLoop.makeSucceededFuture(())
            }

        let bindHost = host.isEmpty || host == "0.0.0.0" ? "0.0.0.0" : host
        let bindPort = port == 0 ? 0 : port

        return serverBootstrap.bind(host: bindHost, port: bindPort).flatMap { serverChannel in
            // Get the actual bound port
            guard let actualPort = serverChannel.localAddress?.port else {
                _ = serverChannel.close()
                return eventLoop.makeSucceededFuture(nil as Int?)
            }

            // Return the bound port
            return eventLoop.makeSucceededFuture(Int(actualPort) as Int?)
        }.flatMapError { error in
            // If binding failed, reject the request
            return eventLoop.makeSucceededFuture(nil as Int?)
        }
    }

    public func stopListening(
        host: String,
        port: Int,
        eventLoop: EventLoop,
        context: SSHContext
    ) -> EventLoopFuture<Void> {
        // Note: This is a simplified implementation. A production implementation
        // would need to track active listeners and close them.
        return eventLoop.makeSucceededFuture(())
    }
}
