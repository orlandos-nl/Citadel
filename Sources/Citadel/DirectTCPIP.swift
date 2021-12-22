import NIO
import NIOSSH

final class DataToBufferCodec: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .byteBuffer(let bytes) = data.data else {
            fatalError("Unexpected read type")
        }

        guard case .channel = data.type else {
            context.fireErrorCaught(SSHChannelError.invalidDataType)
            return
        }

        context.fireChannelRead(self.wrapInboundOut(bytes))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(data))), promise: promise)
    }
}

extension SSHClient {
    public func createDirectTCPIPChannel(
        using settings: SSHChannelType.DirectTCPIP,
        initialize: @escaping (Channel) async throws -> Void
    ) async throws -> Channel {
        try await eventLoop.flatSubmit {
            let createdChannel = self.eventLoop.makePromise(of: Channel.self)
            self.session.sshHandler.createChannel(
                createdChannel,
                channelType: .directTCPIP(settings)
            ) { channel, type in
                guard case .directTCPIP = type else {
                    return channel.eventLoop.makeFailedFuture(SSHClientError.channelCreationFailed)
                }
                
                return channel.pipeline.addHandler(DataToBufferCodec()).flatMap {
                    let promise = channel.eventLoop.makePromise(of: Void.self)
                    promise.completeWithTask {
                        try await initialize(channel)
                    }
                    return promise.futureResult
                }
            }
            
            return createdChannel.futureResult
        }.get()
    }
}
