import NIO
import NIOSSH

final class SSHChannelDataUnwrapper: ChannelInboundHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer

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
}

final class SSHOutboundChannelDataWrapper: ChannelOutboundHandler {
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(data))), promise: promise)
    }
}

final class SSHInboundChannelDataWrapper: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = SSHChannelData

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = self.unwrapInboundIn(data)
        let data = SSHChannelData(type: .channel, data: .byteBuffer(buffer))
        context.fireChannelRead(wrapInboundOut(data))
    }
}
