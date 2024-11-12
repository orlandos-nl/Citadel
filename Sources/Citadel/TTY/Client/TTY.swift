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
            case .exit(0):
                stdout.finish()
                stderr.finish()
            case .exit(let status):
                stdout.finish(throwing: SSHClient.CommandFailed(exitCode: status))
                stderr.finish(throwing: SSHClient.CommandFailed(exitCode: status))
            }
        }
    }
}

public enum ExecCommandOutput {
    case stdout(ByteBuffer)
    case stderr(ByteBuffer)
}

struct EmptySequence<Element>: Sendable, AsyncSequence {
    struct AsyncIterator: AsyncIteratorProtocol {
        func next() async throws -> Element? {
            nil
        }
    }

    func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator()
    }
}

@available(macOS 15.0, *)
public struct TTYOutput: AsyncSequence {
    internal let sequence: AsyncThrowingStream<ExecCommandOutput, Error>
    public typealias Element = ExecCommandOutput

    public struct AsyncIterator: AsyncIteratorProtocol {
        public typealias Element = ExecCommandOutput
        var iterator: AsyncThrowingStream<ExecCommandOutput, Error>.AsyncIterator

        public mutating func next() async throws -> ExecCommandOutput? {
            try await iterator.next()
        }
    }

    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(iterator: sequence.makeAsyncIterator())
    }
}

public struct TTYStdinWriter {
    internal let channel: Channel

    public func write(_ buffer: ByteBuffer) async throws {
        try await channel.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(buffer)))
    }

    public func changeSize(cols: Int, rows: Int, pixelWidth:Int, pixelHeight:Int) async throws {
        try await channel.triggerUserOutboundEvent(
            SSHChannelRequestEvent.WindowChangeRequest(
                terminalCharacterWidth: cols,
                terminalRowHeight: rows,
                terminalPixelWidth: pixelWidth,
                terminalPixelHeight: pixelHeight
            )
        )
    }
}

final class ExecCommandHandler: ChannelDuplexHandler {
    enum Output {
        case channelSuccess
        case stdout(ByteBuffer)
        case stderr(ByteBuffer)
        case eof(Error?)
        case exit(Int)
    }
    
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    let logger: Logger
    let onOutput: (Channel, Output) -> Void

    init(
        logger: Logger,
        onOutput: @escaping (Channel, Output) -> Void
    ) {
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
        case let status as SSHChannelRequestEvent.ExitStatus:
            onOutput(context.channel, .exit(status.exitStatus))
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
    public struct CommandFailed: Error {
        public let exitCode: Int
    }

    /// Executes a command on the remote server. This will return the output of the command (stdout). If the command fails, the error will be thrown. If the output is too large, the command will fail.
    /// - Parameters:
    /// - command: The command to execute.
    /// - maxResponseSize: The maximum size of the response. If the response is larger, the command will fail.
    /// - mergeStreams: If the answer should also include stderr.
    /// - inShell:  Whether to request the remote server to start a shell before executing the command. 
    public func executeCommand(
        _ command: String,
        maxResponseSize: Int = .max,
        mergeStreams: Bool = false,
        inShell: Bool = false
    ) async throws -> ByteBuffer {
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
    public func executeCommandStream(
        _ command: String,
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        inShell: Bool = false
    ) async throws -> AsyncThrowingStream<ExecCommandOutput, Error> {
        try await _executeCommandStream(
            environment: environment,
            mode: inShell ? .tty(command: command) : .command(command)
        ).output
    }

    enum CommandMode {
        case pty(SSHChannelRequestEvent.PseudoTerminalRequest), tty(command: String?), command(String)
    }

    internal func _executeCommandStream(
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        mode: CommandMode
    ) async throws -> (channel: Channel, output: AsyncThrowingStream<ExecCommandOutput, Error>) {
        let (stream, streamContinuation) = AsyncThrowingStream<ExecCommandOutput, Error>.makeStream()

        var hasReceivedChannelSuccess = false
        var exitCode: Int?

        let handler = ExecCommandHandler(logger: logger) { channel, output in
            switch output {
            case .stdout(let stdout):
                streamContinuation.yield(.stdout(stdout))
            case .stderr(let stderr):
                streamContinuation.yield(.stderr(stderr))
            case .eof(let error):
                if let error {
                    streamContinuation.finish(throwing: error)
                } else if let exitCode, exitCode != 0 {
                    streamContinuation.finish(throwing: CommandFailed(exitCode: exitCode))
                } else {
                    streamContinuation.finish()
                }
            case .channelSuccess:
                if case .tty(.some(let command)) = mode, !hasReceivedChannelSuccess {
                    let commandData = SSHChannelData(
                        type: .channel,
                        data: .byteBuffer(ByteBuffer(string: command + ";exit\n"))
                    )
                    channel.writeAndFlush(commandData, promise: nil)
                    hasReceivedChannelSuccess = true
                }
            case .exit(let status):
                exitCode = status
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

        for env in environment {
            try await channel.triggerUserOutboundEvent(env)
        }

        switch mode {
        case .pty(let request):
            try await channel.triggerUserOutboundEvent(request)
            fallthrough
        case .tty:
            try await channel.triggerUserOutboundEvent(SSHChannelRequestEvent.ShellRequest(
                wantReply: true
            ))
        case .command(let command):
            try await channel.triggerUserOutboundEvent(SSHChannelRequestEvent.ExecRequest(
                command: command,
                wantReply: true
            ))
        }
        
        return (channel, stream)
    }

    @available(macOS 15.0, *)
    public func withPTY(
        _ request: SSHChannelRequestEvent.PseudoTerminalRequest,
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        perform: (_ inbound: TTYOutput, _ outbound: TTYStdinWriter) async throws -> Void
    ) async throws {
        let (channel, output) = try await _executeCommandStream(
            environment: environment,
            mode: .pty(request)
        )

        func close() async throws {
            try await channel.close()
        }

        do {
            let inbound = TTYOutput(sequence: output)
            try await perform(inbound, TTYStdinWriter(channel: channel))
            try await close()
        } catch {
            try await close()
            throw error
        }
    }

    @available(macOS 15.0, *)
    public func withTTY(
        environment: [SSHChannelRequestEvent.EnvironmentRequest] = [],
        perform: (_ inbound: TTYOutput, _ outbound: TTYStdinWriter) async throws -> Void
    ) async throws {
        let (channel, output) = try await _executeCommandStream(
            environment: environment,
            mode: .tty(command: nil)
        )

        func close() async throws {
            try await channel.close()
        }

        do {
            let inbound = TTYOutput(sequence: output)
            try await perform(inbound, TTYStdinWriter(channel: channel))
            try await close()
        } catch {
            try await close()
            throw error
        }
    }

    /// Executes a command on the remote server. This will return the pair of streams stdout and stderr of the command. If the command fails, the error will be thrown.
    /// - Parameters:
    /// - command: The command to execute.
    public func executeCommandPair(_ command: String, inShell: Bool = false) async throws -> ExecCommandStream {
        var stdoutContinuation: AsyncThrowingStream<ByteBuffer, Error>.Continuation!
        var stderrContinuation: AsyncThrowingStream<ByteBuffer, Error>.Continuation!
        let stdout = AsyncThrowingStream<ByteBuffer, Error>(bufferingPolicy: .unbounded) { continuation in
            stdoutContinuation = continuation
        }
        
        let stderr = AsyncThrowingStream<ByteBuffer, Error>(bufferingPolicy: .unbounded) { continuation in
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
