import NIO
import NIOSSH

extension SSHClient {
    public func createDirectTCPIPChannel(
        using settings: SSHChannelType.DirectTCPIP,
        initialize: @escaping (Channel) -> EventLoopFuture<Void>
    ) -> EventLoopFuture<Channel> {
        let createdChannel = eventLoop.makePromise(of: Channel.self)
        session.sshHandler.createChannel(
            createdChannel,
            channelType: .directTCPIP(settings)
        ) { channel, type in
            guard case .directTCPIP = type else {
                return channel.eventLoop.makeFailedFuture(SSHClientError.channelCreationFailed)
            }
            
            return initialize(channel)
        }
        
        return createdChannel.futureResult
    }
}
