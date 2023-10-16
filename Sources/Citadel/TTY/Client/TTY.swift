import Foundation
import Logging
import NIO
import NIOSSH

public struct TTYSTDError: Error {
    public let message: ByteBuffer
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
            case .channelSuccess:
                ()
            }
        }
    }
}

public enum ExecCommandOutput {
    case stdout(ByteBuffer)
    case stderr(ByteBuffer)
}


final class ExecCommandHandler: ChannelDuplexHandler {
    enum Output {
        case channelSuccess
        case stdout(ByteBuffer)
        case stderr(ByteBuffer)
        case eof(Error?)
    }
    
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    let logger: Logger
    let onOutput: (Channel, Output) -> ()
    
    init(logger: Logger, onOutput: @escaping (Channel, Output) -> ()) {
        self.logger = logger
        self.onOutput = onOutput
    }
    
    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is NIOSSH.ChannelSuccessEvent:
            onOutput(context.channel, .channelSuccess)
        case is NIOSSH.ChannelFailureEvent:
            onOutput(context.channel, .eof(CitadelError.channelFailure))
        case is SSHChannelRequestEvent.ExitStatus:
            onOutput(context.channel, .eof(nil))
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        onOutput(context.channel, .eof(nil))
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .byteBuffer(let buffer) = data.data else {
            logger.error("Unable to process channelData for executed command. Data was not a ByteBuffer")
            return onOutput(context.channel, .eof(SSHExecError.invalidData))
        }
        
        switch data.type {
        case .channel:
            onOutput(context.channel, .stdout(buffer))
        case .stdErr:
            onOutput(context.channel, .stderr(buffer))
        default:
            // We don't know this std channel
            ()
        }
    }
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        onOutput(context.channel, .eof(error))
    }
}

extension SSHClient {
    /// Executes a command on the remote server. This will return the output of the command (stdout). If the command fails, the error will be thrown. If the output is too large, the command will fail.
    /// - Parameters:
    /// - command: The command to execute.
    /// - maxResponseSize: The maximum size of the response. If the response is larger, the command will fail.
    /// - mergeStreams: If the answer should also include stderr.
    /// - inShell:  Whether to request the remote server to start a shell before executing the command. 
    public func executeCommand(_ command: String, maxResponseSize: Int = .max, mergeStreams: Bool = false, inShell: Bool = false) async throws -> ByteBuffer {
        var result = ByteBuffer()
        let stream = try await executeCommandStream(command, inShell: inShell)

        for try await chunk in stream {
            switch chunk {
            case .stderr(let chunk):
                guard mergeStreams else {
                    continue
                }

                fallthrough
            case .stdout(let chunk):
                let newResponseSize = chunk.readableBytes + result.readableBytes

                if newResponseSize > maxResponseSize {
                    throw CitadelError.commandOutputTooLarge
                }

                result.writeImmutableBuffer(chunk)
            }
        }

        return result
    }

    /// Executes a command on the remote server. This will return the output stream of the command. If the command fails, the error will be thrown.
    /// - Parameters:
    /// - command: The command to execute.
    /// - inShell:  Whether to request the remote server to start a shell before executing the command.
    public func executeCommandStream(_ command: String, inShell: Bool = false) async throws -> AsyncThrowingStream<ExecCommandOutput, Error> {
        var streamContinuation: AsyncThrowingStream<ExecCommandOutput, Error>.Continuation!
        let stream = AsyncThrowingStream<ExecCommandOutput, Error> { continuation in
            streamContinuation = continuation
        }
        
        var hasReceivedChannelSuccess = false

        let handler = ExecCommandHandler(logger: logger) { channel, output in
            switch output {
            case .stdout(let stdout):
                streamContinuation.yield(.stdout(stdout))
            case .stderr(let stderr):
                streamContinuation.yield(.stderr(stderr))
            case .eof(let error):
                streamContinuation.finish(throwing: error)
            case .channelSuccess:
                if inShell, !hasReceivedChannelSuccess {
                    let commandData = SSHChannelData(type: .channel,
                                                     data: .byteBuffer(ByteBuffer(string: command + ";exit\n")))
                    channel.writeAndFlush(commandData, promise: nil)
                    hasReceivedChannelSuccess = true
                }
            }
        }

        let channel = try await eventLoop.flatSubmit {
            let createChannel = self.eventLoop.makePromise(of: Channel.self)
            self.session.sshHandler.createChannel(createChannel) { channel, _ in
                channel.pipeline.addHandlers(handler)
            }

            self.eventLoop.scheduleTask(in: .seconds(15)) {
                createChannel.fail(CitadelError.channelCreationFailed)
            }

            return createChannel.futureResult
        }.get()

        if inShell {
            try await channel.triggerUserOutboundEvent(SSHChannelRequestEvent.ShellRequest(
                wantReply: true
            ))
        } else {
            try await channel.triggerUserOutboundEvent(SSHChannelRequestEvent.ExecRequest(
                command: command,
                wantReply: true
            ))
        }
        
        return stream
    }

    /// Executes a command on the remote server. This will return the pair of streams stdout and stderr of the command. If the command fails, the error will be thrown.
    /// - Parameters:
    /// - command: The command to execute.
    public func executeCommandPair(_ command: String, inShell: Bool = false) async throws -> ExecCommandStream {
        var stdoutContinuation: AsyncThrowingStream<ByteBuffer, Error>.Continuation!
        var stderrContinuation: AsyncThrowingStream<ByteBuffer, Error>.Continuation!
        let stdout = AsyncThrowingStream<ByteBuffer, Error> { continuation in
            stdoutContinuation = continuation
        }
        
        let stderr = AsyncThrowingStream<ByteBuffer, Error> { continuation in
            stderrContinuation = continuation
        }
        
        let handler = ExecCommandStream.Continuation(
            stdout: stdoutContinuation,
            stderr: stderrContinuation
        )
        
        Task {
            do {
                let stream = try await executeCommandStream(command, inShell: inShell)
                for try await chunk in stream {
                    switch chunk {
                    case .stdout(let buffer):
                        handler.stdout.yield(buffer)
                    case .stderr(let buffer):
                        handler.stderr.yield(buffer)
                    }
                }
                
                handler.stdout.finish()
                handler.stderr.finish()
            } catch {
                handler.stdout.finish(throwing: error)
                handler.stderr.finish(throwing: error)
            }
        }
        
        return ExecCommandStream(stdout: stdout, stderr: stderr)
    }
}
