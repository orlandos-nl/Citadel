import Foundation
import NIO
import NIOSSH
import Logging

/// A remote port forward represents an active port forward on the remote SSH server.
///
/// When the remote server receives connections on the forwarded port, they will be
/// forwarded to this client through "forwarded-tcpip" channels.
public struct SSHRemotePortForward: Sendable, Hashable {
    /// The host address being listened on by the remote server.
    public let host: String

    /// The actual port that was bound on the remote server.
    public let boundPort: Int
}

extension SSHClient {
    /// Requests remote port forwarding from the SSH server.
    ///
    /// When you call this method, the SSH server will start listening on the specified host and port.
    /// When a connection is received, the server will open a "forwarded-tcpip" channel back to this client.
    /// The `handler` closure will be called to initialize each incoming connection channel.
    ///
    /// This is useful for exposing local services through the remote server (reverse tunneling).
    ///
    /// Example:
    /// ```swift
    /// // Forward remote port 8080 to a local service
    /// let forward = try await client.createRemotePortForward(
    ///     host: "0.0.0.0",
    ///     port: 8080
    /// ) { channel, forwardedInfo in
    ///     // Connect to local service
    ///     ClientBootstrap(group: channel.eventLoop)
    ///         .connect(host: "localhost", port: 3000)
    ///         .flatMap { localChannel in
    ///             // Pipe data between forwarded channel and local service
    ///             channel.pipeline.addHandler(DataToBufferCodec())
    ///                 .flatMap {
    ///                     // Setup bidirectional forwarding
    ///                     localChannel.pipeline.addHandler(...)
    ///                 }
    ///         }
    /// }
    /// ```
    ///
    /// - Important: This method will store the handler to process incoming forwarded connections.
    ///   Only one remote port forward handler can be active at a time. Calling this method multiple
    ///   times will replace the previous handler. To handle multiple ports, use the handler closure
    ///   to dispatch based on the `ForwardedTCPIP` information.
    ///
    /// - Parameters:
    ///   - host: The host address to listen on. Use "0.0.0.0" or "" to listen on all interfaces, "localhost" or "127.0.0.1" for loopback only.
    ///   - port: The port to listen on. Use 0 to let the server choose a port.
    ///   - handler: A closure that will be called for each incoming forwarded connection. The closure receives the channel and forwarding details.
    /// - Returns: Information about the established port forward, including the actual bound port.
    /// - Throws: If the server rejects the port forwarding request or if the request fails.
    public func withRemotePortForward(
        host: String,
        port: Int,
        onOpen: @escaping @Sendable (SSHRemotePortForward) async throws -> Void,
        handleChannel: @escaping @Sendable (Channel, SSHChannelType.ForwardedTCPIP) -> EventLoopFuture<Void>
    ) async throws {
        let result = session.inboundChannelHandler.registerForwardedTCPIP(
            host: host,
            port: port,
            handler: handleChannel
        )

        switch result {
        case .success:
            ()
        case .alreadyRegistered:
            throw SSHClientError.channelCreationFailed
        }

        defer { session.inboundChannelHandler.unregisterForwardedTCPIP(host: host, port: port) }

        let response = try await eventLoop.flatSubmit {
            let responsePromise = self.eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)
            self.logger.debug("Sending TCP forwarding request", metadata: ["host": "\(host)", "port": "\(port)"])
            self.session.sshHandler.value.sendTCPForwardingRequest(
                .listen(host: host, port: port),
                promise: responsePromise
            )
            return responsePromise.futureResult
        }.get()

        guard let response = response else {
            logger.error("No response from server for TCP forwarding request")
            throw SSHClientError.channelCreationFailed
        }

        logger.info("Server accepted port forward", metadata: ["bound_port": "\(response.boundPort ?? port)"])

        // Sleep until cancelled
        do {
            try await onOpen(SSHRemotePortForward(host: host, boundPort: response.boundPort ?? port))
            while !Task.isCancelled {
                try await Task.sleep(for: .seconds(100_000))
            }

            try await sendTCPIPForwardingCancellationRequest(host: host, port: port)
        } catch {
            try await sendTCPIPForwardingCancellationRequest(host: host, port: port)
            throw error
        }
    }

    /// Cancels a previously established remote port forward.
    ///
    /// This tells the SSH server to stop listening on the specified host and port.
    /// Any existing forwarded connections will continue to work, but no new connections will be accepted.
    ///
    /// - Parameters:
    ///   - host: The host address that was being listened on.
    ///   - port: The port that was being listened on.
    /// - Throws: If the server rejects the cancellation request or if the request fails.
    private func sendTCPIPForwardingCancellationRequest(
        host: String,
        port: Int
    ) async throws {
        return try await eventLoop.flatSubmit { [eventLoop, sshHandler = self.session.sshHandler] in
            let responsePromise = eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)

            sshHandler.value.sendTCPForwardingRequest(
                .cancel(host: host, port: port),
                promise: responsePromise
            )

            return responsePromise.futureResult.map { _ in () }
        }.get()
    }

    /// Establishes a remote port forward with a high-level NIOAsyncChannel-based API.
    ///
    /// This is a convenience method that wraps the low-level `createRemotePortForward` API
    /// with modern async/await patterns using NIOAsyncChannel. The `onAccept` closure is called
    /// for each incoming connection with a fully configured async channel.
    ///
    /// Example:
    /// ```swift
    /// try await client.withRemotePortForward(
    ///     host: "0.0.0.0",
    ///     port: 8080
    /// ) { (channel: NIOAsyncChannel<ByteBuffer, ByteBuffer>) in
    ///     // Handle each connection using structured concurrency
    ///     try await channel.executeThenClose { inbound, outbound in
    ///         for try await data in inbound {
    ///             // Process and echo data
    ///             try await outbound.write(data)
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// - Important: This method will not return until the port forward is cancelled.
    ///   The remote port forward remains active for the lifetime of the closure.
    ///
    /// - Parameters:
    ///   - host: The host address to listen on. Use "0.0.0.0" or "" to listen on all interfaces.
    ///   - port: The port to listen on. Use 0 to let the server choose a port.
    ///   - configure: Optional closure to configure the channel pipeline before creating the NIOAsyncChannel.
    ///   - onAccept: A closure called for each incoming connection with a NIOAsyncChannel.
    /// - Returns: Information about the established port forward, including the actual bound port.
    /// - Throws: If the server rejects the port forwarding request or if the request fails.
    public func withRemotePortForward<Inbound: Sendable, Outbound: Sendable>(
        host: String,
        port: Int,
        inboundType: Inbound.Type = ByteBuffer.self,
        outboundType: Outbound.Type = ByteBuffer.self,
        configure: @escaping @Sendable (Channel) -> EventLoopFuture<Void> = { $0.eventLoop.makeSucceededVoidFuture() },
        onOpen: @escaping @Sendable (SSHRemotePortForward) async throws -> Void = { _ in },
        onAccept: @escaping @Sendable (NIOAsyncChannel<Inbound, Outbound>) async throws -> Void
    ) async throws {
        logger.debug("Setting up high-level remote port forward with NIOAsyncChannel", metadata: [
            "host": "\(host)",
            "port": "\(port)"
        ])

        let (newClients, continuation) = AsyncStream<NIOAsyncChannel<Inbound, Outbound>>.makeStream()

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                return try await self.withRemotePortForward(
                    host: host,
                    port: port,
                    onOpen: onOpen
                 ) { channel, _ in
                    return configure(channel).flatMapThrowing {
                        let channel = try NIOAsyncChannel<Inbound, Outbound>(
                            wrappingChannelSynchronously: channel
                        )
                        continuation.yield(channel)
                    }
                }
            }

            group.addTask {
                await withDiscardingTaskGroup { group in
                    for await client in newClients {
                        group.addTask {
                            do {
                                try await onAccept(client)
                            } catch {
                                self.logger.error("Error in remote port forwarded connection", metadata: [
                                    "error": "\(error)"
                                ])
                            }
                        }
                    }
                }
            }

            defer { 
                continuation.finish()
                group.cancelAll()
            }

            try await group.next()
        }
    }

    /// Establishes a remote port forward and forwards connections to a local service.
    ///
    /// This is a high-level convenience method that automatically connects to a local service
    /// and forwards data bidirectionally. This is the most common use case for remote port forwarding.
    ///
    /// Example:
    /// ```swift
    /// // Forward remote port 8080 to local HTTP server on port 3000
    /// try await client.withRemotePortForward(
    ///     host: "0.0.0.0",
    ///     port: 8080,
    ///     forwardingTo: "127.0.0.1",
    ///     port: 3000
    /// )
    /// ```
    ///
    /// - Important: This method will not return - it keeps the port forward active indefinitely.
    ///   Cancel the task or close the client to stop forwarding.
    ///
    /// - Parameters:
    ///   - host: The host address to listen on. Use "0.0.0.0" to listen on all interfaces.
    ///   - port: The remote port to listen on. Use 0 to let the server choose a port.
    ///   - localHost: The local host to forward connections to.
    ///   - localPort: The local port to forward connections to.
    /// - Returns: Information about the established port forward, including the actual bound port.
    /// - Throws: If the server rejects the port forwarding request or if connection fails.
    @discardableResult
    public func runRemotePortForward(
        host: String,
        port: Int,
        forwardingTo localHost: String,
        port localPort: Int,
        onOpen: @escaping @Sendable (SSHRemotePortForward) async throws -> Void = { _ in },
    ) async throws {
        try await withRemotePortForward(
            host: host,
            port: port,
            onOpen: onOpen
         ) { inboundClient in
            let outboundClient = try await ClientBootstrap(group: inboundClient.channel.eventLoop)
                .connect(host: localHost, port: localPort)
                .flatMapThrowing { channel in
                    let channel = try NIOAsyncChannel<ByteBuffer, ByteBuffer>(
                        wrappingChannelSynchronously: channel
                    )
                    return channel
                }
                .get()
            
            try await inboundClient.executeThenClose { inboundA, outboundA in
                try await outboundClient.executeThenClose { inboundB, outboundB in
                    try await withThrowingTaskGroup(of: Void.self) { group in
                        group.addTask {
                            for try await data in inboundA {
                                try await outboundB.write(data)
                            }
                        }
                        group.addTask {
                            for try await data in inboundB {
                                try await outboundA.write(data)
                            }
                        }

                        defer { group.cancelAll() }
                        try await group.next()
                    }
                }
            }
        }
    }
}
