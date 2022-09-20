import Foundation
import NIO
import NIOSSH
import Logging

public protocol SFTPFileHandle {
    func write(_ data: ByteBuffer, atOffset offset: UInt64, promise: EventLoopPromise<SFTPStatusCode>)
    func close(promise: EventLoopPromise<SFTPStatusCode>)
}

public protocol SFTPDelegate {
    func fileAttributes(atPath path: String) async throws -> SFTPFileAttributes
    func openFile(_ filePath: String, withAttributes: SFTPFileAttributes, flags: SFTPOpenFileFlags) async throws -> SFTPFileHandle
}

struct SFTPServerSubsystem {
    static func setupChannelHanders(
        channel: Channel,
        delegate: SFTPDelegate,
        logger: Logger
    ) -> EventLoopFuture<Void> {
        let deserializeHandler = ByteToMessageHandler(SFTPMessageParser())
        let serializeHandler = MessageToByteHandler(SFTPMessageSerializer())
        let sftpInboundHandler = SFTPServerInboundHandler(
            logger: logger,
            delegate: delegate,
            eventLoop: channel.eventLoop
        )
        
        return channel.pipeline.addHandlers(
            SSHChannelDataUnwrapper(),
            SSHChannelDataWrapper(),
            deserializeHandler,
            serializeHandler,
            sftpInboundHandler,
            CloseErrorHandler()
        ).map {
            sftpInboundHandler
        }
    }
}
