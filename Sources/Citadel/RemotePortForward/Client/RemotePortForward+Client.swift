import Foundation
import NIO
import NIOSSH
import Logging

/// A remote port forward represents an active port forward on the remote SSH server.
///
/// When the remote server receives connections on the forwarded port, they will be
/// forwarded to this client through "forwarded-tcpip" channels.
public struct SSHRemotePortForward: Sendable {
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
    @discardableResult
    public func createRemotePortForward(
        host: String,
        port: Int,
        handler: @escaping @Sendable (Channel, SSHChannelType.ForwardedTCPIP) -> EventLoopFuture<Void>
    ) async throws -> SSHRemotePortForward {
        // Store the handler for incoming forwarded connections
        logger.debug("Setting forwardedTCPIPHandler on client")
        self.forwardedTCPIPHandler = handler
        logger.debug("Handler set successfully", metadata: ["has_handler": "\(self.forwardedTCPIPHandler != nil)"])

        return try await eventLoop.flatSubmit { [eventLoop, sshHandler = self.session.sshHandler, logger = self.logger] in
            let responsePromise = eventLoop.makePromise(of: GlobalRequest.TCPForwardingResponse?.self)

            logger.debug("Sending TCP forwarding request", metadata: ["host": "\(host)", "port": "\(port)"])
            sshHandler.value.sendTCPForwardingRequest(
                .listen(host: host, port: port),
                promise: responsePromise
            )

            return responsePromise.futureResult.flatMapThrowing { response in
                logger.trace("Received TCP forwarding response", metadata: ["response": "\(String(describing: response))"])

                guard let response = response else {
                    logger.error("No response from server for TCP forwarding request")
                    throw SSHClientError.channelCreationFailed
                }

                logger.info("Server accepted port forward", metadata: ["bound_port": "\(response.boundPort ?? port)"])

                return SSHRemotePortForward(
                    host: host,
                    boundPort: response.boundPort ?? port
                )
            }
        }.get()
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
    public func cancelRemotePortForward(
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

    /// Cancels a previously established remote port forward using the SSHRemotePortForward object.
    ///
    /// This tells the SSH server to stop listening on the specified host and port.
    /// Any existing forwarded connections will continue to work, but no new connections will be accepted.
    ///
    /// - Parameter forward: The remote port forward to cancel.
    /// - Throws: If the server rejects the cancellation request or if the request fails.
    public func cancelRemotePortForward(_ forward: SSHRemotePortForward) async throws {
        try await cancelRemotePortForward(host: forward.host, port: forward.boundPort)
    }
}
