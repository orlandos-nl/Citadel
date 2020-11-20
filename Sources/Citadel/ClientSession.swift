import NIO
import NIOSSH

internal final class CloseErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

final class SSHClientSession {
    let channel: Channel
    let sshHandler: NIOSSHHandler
    
    init(channel: Channel, sshHandler: NIOSSHHandler) {
        self.channel = channel
        self.sshHandler = sshHandler
    }
    
    public static func connect(
        host: String,
        port: Int = 22,
        authenticationMethod: AuthenticationMethod,
        hostKeyValidator: HostKeyValidator,
        group: EventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    ) -> EventLoopFuture<SSHClientSession> {
        let bootstrap = ClientBootstrap(group: group).channelInitializer { channel in
            channel.pipeline.addHandlers([
                NIOSSHHandler(
                    role: .client(
                        .init(
                            userAuthDelegate: authenticationMethod,
                            serverAuthDelegate: hostKeyValidator
                        )
                    ),
                    allocator: channel.allocator,
                    inboundChildChannelInitializer: nil
                ),
                CloseErrorHandler()
            ])
        }
        .connectTimeout(.seconds(30))
        .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
        
        return bootstrap.connect(host: host, port: port).flatMap { channel in
            return channel.pipeline.handler(type: NIOSSHHandler.self).map { sshHandler in
                SSHClientSession(channel: channel, sshHandler: sshHandler)
            }
        }
    }
}

public struct InvalidHostKey: Error {}

public struct HostKeyValidator: NIOSSHClientServerAuthenticationDelegate {
    private enum Method {
        case trustedKeys(Set<NIOSSHPublicKey>)
        case acceptAnything
        case custom(NIOSSHClientServerAuthenticationDelegate)
    }
    
    private let method: Method
    
    public func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        switch method {
        case .trustedKeys(let keys):
            if keys.contains(hostKey) {
                validationCompletePromise.succeed(())
            } else {
                validationCompletePromise.fail(InvalidHostKey())
            }
        case .acceptAnything:
            validationCompletePromise.succeed(())
        case .custom(let validator):
            validator.validateHostKey(hostKey: hostKey, validationCompletePromise: validationCompletePromise)
        }
    }
    
    public static func trustedKeys(_ keys: Set<NIOSSHPublicKey>) -> HostKeyValidator {
        HostKeyValidator(method: .trustedKeys(keys))
    }
    
    public static func acceptAnything() -> HostKeyValidator {
        HostKeyValidator(method: .acceptAnything)
    }
    
    public static func custom(_ validator: NIOSSHClientServerAuthenticationDelegate) -> HostKeyValidator {
        HostKeyValidator(method: .custom(validator))
    }
}
