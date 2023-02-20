import Foundation
import NIO
import NIOSSH

public struct TTYSTDError: Error {
    public let message: ByteBuffer
}

final class CollectingExecCommandHelper {
    let maxResponseSize: Int?
    var isIgnoringInput = false
    let stdoutPromise: EventLoopPromise<ByteBuffer>?
    let stderrPromise: EventLoopPromise<ByteBuffer>?
    var stdout: ByteBuffer
    var stderr: ByteBuffer
    
    init(
        maxResponseSize: Int?,
        stdoutPromise: EventLoopPromise<ByteBuffer>?,
        stderrPromise: EventLoopPromise<ByteBuffer>?,
        allocator: ByteBufferAllocator
    ) {
        self.maxResponseSize = maxResponseSize
        self.stdoutPromise = stdoutPromise
        self.stderrPromise = stderrPromise
        self.stdout = allocator.buffer(capacity: 4096)
        self.stderr = allocator.buffer(capacity: 4096)
    }
    
    public func onOutput(_ output: ExecCommandHandler.Output) {
        switch output {
        case .stdout(let byteBuffer):
            if
                let maxResponseSize = maxResponseSize,
                stdout.readableBytes + byteBuffer.readableBytes > maxResponseSize
            {
                isIgnoringInput = true
                stdoutPromise?.fail(CitadelError.commandOutputTooLarge)
                stderrPromise?.fail(CitadelError.commandOutputTooLarge)
                return
            }
            
            stdout.writeImmutableBuffer(byteBuffer)
        case .stderr(let byteBuffer):
            if
                let maxResponseSize = maxResponseSize,
                stderr.readableBytes + byteBuffer.readableBytes > maxResponseSize
            {
                isIgnoringInput = true
                stdoutPromise?.fail(CitadelError.commandOutputTooLarge)
                stderrPromise?.fail(CitadelError.commandOutputTooLarge)
                return
            }
            
            stderr.writeImmutableBuffer(byteBuffer)
        case .eof(.some(let error)):
            stdoutPromise?.fail(error)
            stderrPromise?.fail(error)
        case .eof(.none):
            stdoutPromise?.succeed(stdout)
            stderrPromise?.succeed(stderr)
        }
    }
}

public struct ExecCommandStream {
    public let stdout: AsyncThrowingStream<ByteBuffer, Error>
    public let stderr: AsyncThrowingStream<ByteBuffer, Error>
    
    struct Continuation {
        let stdout: AsyncThrowingStream<ByteBuffer, Error>.Continuation
        let stderr: AsyncThrowingStream<ByteBuffer, Error>.Continuation
        
        func onOutput(_ output: ExecCommandHandler.Output) {
            switch output {
            case .stdout(let buffer):
                stdout.yield(buffer)
            case .stderr(let buffer):
                stderr.yield(buffer)
            case .eof(let error):
                stdout.finish(throwing: error)
                stderr.finish(throwing: error)
            }
        }
    }
}

final class ExecCommandHandler: ChannelDuplexHandler {
    enum Output {
        case stdout(ByteBuffer)
        case stderr(ByteBuffer)
        case eof(Error?)
    }
    
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    let onOutput: (Output) -> ()
    
    init(onOutput: @escaping (Output) -> ()) {
        self.onOutput = onOutput
    }
    
    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is SSHChannelRequestEvent.ExitStatus:
            ()
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        onOutput(.eof(nil))
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .byteBuffer(let buffer) = data.data else {
            return
        }
        
        switch data.type {
        case .channel:
            onOutput(.stdout(buffer))
        case .stdErr:
            onOutput(.stderr(buffer))
        default:
            // We don't know this std channel
            ()
        }
    }
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        onOutput(.eof(error))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(data))), promise: promise)
    }
}

extension SSHClient {
    /// Executes a command on the remote server. This will return the output of the command. If the command fails, the error will be thrown. If the output is too large, the command will fail.
    /// - Parameters:
    ///  - command: The command to execute.
    /// - maxResponseSize: The maximum size of the response. If the response is larger, the command will fail.
    public func executeCommand(_ command: String, maxResponseSize: Int = .max) async throws -> ByteBuffer {
        let promise = eventLoop.makePromise(of: ByteBuffer.self)
        
        let channel: Channel
        
        do {
            channel = try await eventLoop.flatSubmit {
                let createChannel = self.eventLoop.makePromise(of: Channel.self)
                self.session.sshHandler.createChannel(createChannel) { channel, _ in
                    let collecting = CollectingExecCommandHelper(
                        maxResponseSize: maxResponseSize,
                        stdoutPromise: promise,
                        stderrPromise: nil,
                        allocator: channel.allocator
                    )
                    
                    return channel.pipeline.addHandlers(
                        ExecCommandHandler(onOutput: collecting.onOutput)
                    )
                }
                
                self.eventLoop.scheduleTask(in: .seconds(15)) {
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
    
    /// Executes a command on the remote server. This will return the output of the command. If the command fails, the error will be thrown. If the output is too large, the command will fail.
    /// - Parameters:
    ///  - command: The command to execute.
    /// - maxResponseSize: The maximum size of the response. If the response is larger, the command will fail.
    public func executeCommandStream(_ command: String) async throws -> ExecCommandStream {
        var stdoutContinuation: AsyncThrowingStream<ByteBuffer, Error>.Continuation!
        var stderrContinuation: AsyncThrowingStream<ByteBuffer, Error>.Continuation!
        let stdout = AsyncThrowingStream<ByteBuffer, Error> { continuation in
            stdoutContinuation = continuation
        }
        
        let stderr = AsyncThrowingStream<ByteBuffer, Error> { continuation in
            stderrContinuation = continuation
        }
        
        let continuation = ExecCommandStream.Continuation(stdout: stdoutContinuation, stderr: stderrContinuation)
        let handler = ExecCommandHandler(onOutput: continuation.onOutput)
        
        let stream = ExecCommandStream(stdout: stdout, stderr: stderr)
        let promise = eventLoop.makePromise(of: ByteBuffer.self)
        
        let channel: Channel
        
        do {
            channel = try await eventLoop.flatSubmit {
                let createChannel = self.eventLoop.makePromise(of: Channel.self)
                self.session.sshHandler.createChannel(createChannel) { channel, _ in
                    channel.pipeline.addHandlers(handler)
                }
                
                self.eventLoop.scheduleTask(in: .seconds(15)) {
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
        
        try await channel.triggerUserOutboundEvent(execRequest)
        
        return stream
    }
}
