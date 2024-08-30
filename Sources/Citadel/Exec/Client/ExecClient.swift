import Foundation
import NIO
import NIOSSH

final class TTYHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    let maxResponseSize: Int
    var isIgnoringInput = false
    var response = ByteBuffer()
    let done: EventLoopPromise<ByteBuffer>
    
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
        done.succeed(response)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .byteBuffer(var bytes) = data.data, !isIgnoringInput else {
            return
        }
        
        switch data.type {
        case .channel:
            if
                response.readableBytes + bytes.readableBytes > maxResponseSize
            {
                isIgnoringInput = true
                done.fail(CitadelError.commandOutputTooLarge)
                return
            }
            
            // Channel data is forwarded on, the pipe channel will handle it.
            response.writeBuffer(&bytes)
            return
        case .stdErr:
            done.fail(TTYSTDError(message: bytes))
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
                    channel.pipeline.addHandlers(
                        TTYHandler(
                            maxResponseSize: maxResponseSize,
                            done: promise
                        )
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
}
