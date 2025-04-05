import NIO
import NIOSSH

fileprivate final class ProxyChannelHandler: ChannelOutboundHandler {
    typealias OutboundIn = ByteBuffer

    private let write: (ByteBuffer, EventLoopPromise<Void>?) -> Void

    init(write: @escaping (ByteBuffer, EventLoopPromise<Void>?) -> Void) {
        self.write = write
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        write(data, promise)
    }
}

public protocol DirectTCPIPDelegate: Sendable {
    func initializeDirectTCPIPChannel(_ channel: Channel, request: SSHChannelType.DirectTCPIP, context: SSHContext) -> EventLoopFuture<Void>
}

public struct DirectTCPIPForwardingDelegate: DirectTCPIPDelegate {
    internal enum Error: Swift.Error {
        case forbidden
    }

    public var whitelistedHosts: [String]?
    public var whitelistedPorts: [Int]?

    public init() {}

    public func initializeDirectTCPIPChannel(_ channel: Channel, request: SSHChannelType.DirectTCPIP, context: SSHContext) -> EventLoopFuture<Void> {
        if let whitelistedHosts, !whitelistedHosts.contains(request.targetHost) {
            return channel.eventLoop.makeFailedFuture(Error.forbidden)
        }

        if let whitelistedPorts, !whitelistedPorts.contains(request.targetPort) {
            return channel.eventLoop.makeFailedFuture(Error.forbidden)
        }

        return ClientBootstrap(group: channel.eventLoop)
            .connect(host: request.targetHost, port: request.targetPort)
            .flatMap { remote in
                channel.pipeline.addHandlers([
                    DataToBufferCodec()
                ]).flatMap {
                    channel.pipeline.addHandler(ProxyChannelHandler { data, promise in
                        remote.writeAndFlush(data, promise: promise)
                    })
                }.flatMap {
                    remote.pipeline.addHandler(ProxyChannelHandler { [weak channel] data, promise in
                        guard let channel else {
                            promise?.fail(ChannelError.ioOnClosedChannel)
                            return
                        }
                        channel.writeAndFlush(data, promise: promise)
                    })
                }
            }
    }
}