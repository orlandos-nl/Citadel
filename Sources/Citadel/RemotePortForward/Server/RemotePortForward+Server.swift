import NIO
import NIOSSH
import Logging

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

/// A high-level implementation of RemotePortForwardDelegate using NIOAsyncChannel.
///
/// This delegate uses modern async/await patterns to handle remote port forwarding requests.
/// For each incoming connection, it creates a forwarded-tcpip channel back to the SSH client
/// and invokes the provided handler closure.
///
/// Example:
/// ```swift
/// let delegate = AsyncRemotePortForwardDelegate { channel, clientAddress in
///     // Handle each forwarded connection with async/await
///     try await channel.executeThenClose { inbound, outbound in
///         for try await data in inbound {
///             // Process and forward data back to client
///             try await outbound.write(data)
///         }
///     }
/// }
///
/// server.enableRemotePortForward(withDelegate: delegate)
/// ```
/// Actor for managing active server channels in a thread-safe manner
private actor ServerChannelStorage {
    var servers: [String: Channel] = [:]

    func store(_ channel: Channel, forKey key: String) {
        servers[key] = channel
    }

    func remove(forKey key: String) -> Channel? {
        servers.removeValue(forKey: key)
    }
}

public final class AsyncRemotePortForwardDelegate: RemotePortForwardDelegate, Sendable {
    private let eventLoopGroup: EventLoopGroup
    private let allowedHosts: [String]?
    private let allowedPorts: [Int]?
    private let logger: Logger
    private let onAccept: @Sendable (NIOAsyncChannel<ByteBuffer, ByteBuffer>, SocketAddress) async throws -> Void

    /// Active server channels, keyed by "host:port"
    private let activeServers: ServerChannelStorage

    /// Creates a new async remote port forward delegate.
    ///
    /// - Parameters:
    ///   - eventLoopGroup: The event loop group to use for listening sockets.
    ///   - allowedHosts: Optional whitelist of hosts that can be listened on. If nil, all hosts are allowed.
    ///   - allowedPorts: Optional whitelist of ports that can be listened on. If nil, all ports are allowed.
    ///   - logger: Logger instance for structured logging.
    ///   - onAccept: Closure called for each incoming connection with a NIOAsyncChannel.
    public init(
        eventLoopGroup: EventLoopGroup = MultiThreadedEventLoopGroup.singleton,
        allowedHosts: [String]? = nil,
        allowedPorts: [Int]? = nil,
        logger: Logger = Logger(label: "nl.orlandos.citadel.server.remote-forward"),
        onAccept: @escaping @Sendable (NIOAsyncChannel<ByteBuffer, ByteBuffer>, SocketAddress) async throws -> Void
    ) {
        self.eventLoopGroup = eventLoopGroup
        self.allowedHosts = allowedHosts
        self.allowedPorts = allowedPorts
        self.logger = logger
        self.onAccept = onAccept
        self.activeServers = ServerChannelStorage()
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
            logger.warning("Remote port forward request rejected - host not allowed", metadata: [
                "host": "\(host)",
                "port": "\(port)"
            ])
            return eventLoop.makeSucceededFuture(nil)
        }

        // Validate port
        if let allowedPorts = allowedPorts, port != 0, !allowedPorts.contains(port) {
            logger.warning("Remote port forward request rejected - port not allowed", metadata: [
                "host": "\(host)",
                "port": "\(port)"
            ])
            return eventLoop.makeSucceededFuture(nil)
        }

        logger.debug("Starting remote port forward listener", metadata: [
            "host": "\(host)",
            "port": "\(port)"
        ])

        let bindHost = host.isEmpty || host == "0.0.0.0" ? "0.0.0.0" : host
        let bindPort = port == 0 ? 0 : port

        let logger = self.logger
        let onAccept = self.onAccept

        // Create server using traditional ServerBootstrap pattern
        let serverBootstrap = ServerBootstrap(group: eventLoopGroup)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                // Setup pipeline for each incoming connection
                channel.eventLoop.makeCompletedFuture {
                    // Create async channel for the incoming connection
                    let asyncChannel = try NIOAsyncChannel<ByteBuffer, ByteBuffer>(
                        wrappingChannelSynchronously: channel
                    )

                    // Get the remote address
                    guard let remoteAddress = channel.remoteAddress else {
                        logger.warning("Incoming connection has no remote address")
                        return
                    }

                    logger.debug("Accepting forwarded connection", metadata: [
                        "remote_address": "\(remoteAddress)"
                    ])

                    // Handle the connection asynchronously
                    Task {
                        do {
                            try await onAccept(asyncChannel, remoteAddress)
                        } catch {
                            logger.error("Error handling forwarded connection", metadata: [
                                "error": "\(error)",
                                "remote_address": "\(remoteAddress)"
                            ])
                        }
                    }
                }
            }

        return serverBootstrap.bind(host: bindHost, port: bindPort)
            .flatMap { serverChannel in
                // Get the actual bound port
                guard let actualPort = serverChannel.localAddress?.port else {
                    logger.error("Server channel has no local address")
                    _ = serverChannel.close()
                    return eventLoop.makeSucceededFuture(nil as Int?)
                }

                // Store the server channel for later cleanup
                let key = "\(host):\(actualPort)"
                Task {
                    await self.activeServers.store(serverChannel, forKey: key)
                }

                logger.info("Remote port forward listener started", metadata: [
                    "host": "\(host)",
                    "bound_port": "\(actualPort)"
                ])

                return eventLoop.makeSucceededFuture(Int(actualPort))
            }
            .flatMapError { error in
                logger.error("Failed to bind remote port forward listener", metadata: [
                    "error": "\(error)",
                    "host": "\(bindHost)",
                    "port": "\(bindPort)"
                ])
                return eventLoop.makeSucceededFuture(nil as Int?)
            }
    }

    public func stopListening(
        host: String,
        port: Int,
        eventLoop: EventLoop,
        context: SSHContext
    ) -> EventLoopFuture<Void> {
        let key = "\(host):\(port)"

        logger.debug("Stopping remote port forward listener", metadata: [
            "host": "\(host)",
            "port": "\(port)"
        ])

        let promise = eventLoop.makePromise(of: Void.self)

        Task {
            let serverChannel = await self.activeServers.remove(forKey: key)

            if let serverChannel = serverChannel {
                serverChannel.close().whenComplete { result in
                    switch result {
                    case .success:
                        self.logger.info("Remote port forward listener stopped", metadata: [
                            "host": "\(host)",
                            "port": "\(port)"
                        ])
                        promise.succeed(())
                    case .failure(let error):
                        promise.fail(error)
                    }
                }
            } else {
                self.logger.warning("No active listener found to stop", metadata: [
                    "host": "\(host)",
                    "port": "\(port)"
                ])
                promise.succeed(())
            }
        }

        return promise.futureResult
    }
}
