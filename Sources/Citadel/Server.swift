import NIO
import NIOSSH

public protocol SSHServerDelegate: NIOSSHServerUserAuthenticationDelegate, GlobalRequestDelegate {
    func initializeSshChildChannel(_ channel: Channel, _ channelType: SSHChannelType) -> EventLoopFuture<Void>
}

final class CloseErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

//public final class SSHServer {
//    let channel: Channel
//    
//    init(channel: Channel) {
//        self.channel = channel
//    }
//    
//    public static func host(
//        host: String,
//        port: Int,
//        serverDelegate: SSHServerDelegate,
//        group: MultiThreadedEventLoopGroup = .init(numberOfThreads: 1)
//    ) -> EventLoopFuture<SSHServer> {
//        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
//        let bootstrap = ServerBootstrap(group: group)
//            .childChannelInitializer { channel in
//                channel.pipeline.addHandlers([
//                    NIOSSHHandler(
//                        role: .server(
//                            .init(
//                                hostKeys: [hostKey],
//                                userAuthDelegate: serverDelegate,
//                                globalRequestDelegate: serverDelegate
//                            )
//                        ),
//                        allocator: channel.allocator,
//                        inboundChildChannelInitializer: serverDelegate.initializeSshChildChannel
//                    ),
//                    CloseErrorHandler()
//                ])
//            }
//            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
//            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
//
//        return bootstrap.bind(host: "0.0.0.0", port: 2222).map { channel in
//            SSHServer(channel: channel)
//        }
//    }
//}
