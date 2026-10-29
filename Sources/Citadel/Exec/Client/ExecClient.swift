import Foundation
import NIO
@preconcurrency import NIOSSH

/// A channel handler that manages TTY (terminal) input/output for SSH command execution.
/// This handler processes both incoming and outgoing data through the SSH channel.
final class TTYHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    /// Maximum allowed size for command response data
    let maxResponseSize: Int
    /// Flag to indicate if input should be ignored (e.g., when response size exceeds limit)
    var isIgnoringInput = false
    /// Buffer to store the command's response data
    var response = ByteBuffer()
    /// Promise that will be fulfilled with the final response
    let done: EventLoopPromise<ByteBuffer>
    /// Buffer to store error messages from stderr
    private var errorBuffer = ByteBuffer()
    
    init(
        maxResponseSize: Int,
        done: EventLoopPromise<ByteBuffer>
    ) {
        self.maxResponseSize = maxResponseSize
        self.done = done
    }
    
    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let status as SSHChannelRequestEvent.ExitStatus:
            if status.exitStatus != 0 {
                done.fail(SSHClient.CommandFailed(exitCode: status.exitStatus))
            }
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        if errorBuffer.readableBytes > 0 {
            done.fail(TTYSTDError(message: errorBuffer))
        } else {
            done.succeed(response)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .byteBuffer(var bytes) = data.data, !isIgnoringInput else {
            return
        }

        guard bytes.readableBytes <= maxResponseSize - response.readableBytes - errorBuffer.readableBytes else {
            isIgnoringInput = true
            done.fail(CitadelError.commandOutputTooLarge)
            context.close(promise: nil)
            return
        }
        
        switch data.type {
        case .channel:
            // Channel data is forwarded on, the pipe channel will handle it.
            response.writeBuffer(&bytes)
            return
        case .stdErr:
            errorBuffer.writeBuffer(&bytes)
        default:
            ()
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(data))), promise: promise)
    }
}

extension SSHClient {
    /// Executes a command on the remote SSH server and returns its output.
    ///
    /// This method establishes a new channel, executes the specified command, and collects
    /// its output. The command execution is handled asynchronously and includes timeout protection
    /// for channel creation.
    ///
    /// - Parameters:
    ///   - command: The shell command to execute on the remote server
    ///   - maxResponseSize: Maximum combined stdout and stderr size in bytes.
    ///                     If exceeded, throws `CitadelError.commandOutputTooLarge`
    ///
    /// - Returns: A ByteBuffer containing the command's output
    ///
    /// - Throws:
    ///   - `CitadelError.channelCreationFailed` if the channel cannot be created within 15 seconds
    ///   - `CitadelError.commandOutputTooLarge` if the response exceeds maxResponseSize
    ///   - `SSHClient.CommandFailed` if the command returns a non-zero exit status
    ///   - `TTYSTDError` if there was output to stderr
    public func executeCommand(_ command: String, maxResponseSize: Int = .max) async throws -> ByteBuffer {
        try await executeBoundedCommand(command, maxResponseSize: maxResponseSize, onChannelCreated: { _ in })
    }

    /// Executes a command with a combined stdout/stderr byte limit.
    ///
    /// `onChannelCreated` runs on the child's event loop before its handlers and exec
    /// request are installed, even if the caller cancelled while channel creation was
    /// pending. Retain and close this child to implement cancellation or a deadline
    /// without closing the SSH connection. The callback may close it immediately.
    /// Task cancellation alone does not close the child. Callers must track their own
    /// cancellation state and translate the result when they intentionally close it.
    /// Errors and exit status otherwise match `executeCommand(_:maxResponseSize:)`.
    public func executeBoundedCommand(
        _ command: String,
        maxResponseSize: Int,
        onChannelCreated: @escaping @Sendable (Channel) -> Void
    ) async throws -> ByteBuffer {
        let promise = eventLoop.makePromise(of: ByteBuffer.self)
        
        let channel: Channel
        
        do {
            channel = try await eventLoop.flatSubmit { [eventLoop, sshHandler = session.sshHandler] in
                let createChannel = eventLoop.makePromise(of: Channel.self)
                sshHandler.value.createChannel(createChannel) { channel, _ in
                    onChannelCreated(channel)
                    return channel.pipeline.addHandlers(
                        TTYHandler(
                            maxResponseSize: maxResponseSize,
                            done: promise
                        )
                    )
                }
                
                eventLoop.scheduleTask(in: .seconds(15)) {
                    createChannel.fail(CitadelError.channelCreationFailed)
                }
                
                return createChannel.futureResult
            }.get()
        } catch {
            promise.fail(error)
            throw error
        }
        
        // We need to exec a thing.
        let execRequest = SSHChannelRequestEvent.ExecRequest(
            command: command,
            wantReply: true
        )
        
        return try await eventLoop.flatSubmit {
            channel.triggerUserOutboundEvent(execRequest).whenFailure { [channel] error in
                channel.close(promise: nil)
                promise.fail(error)
            }
            
            return promise.futureResult
        }.get()
    }
}
