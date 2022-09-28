import Foundation
import NIO
import NIOSSH
import Logging

public protocol SFTPFileHandle {
    func read(at offset: UInt64, length: UInt32) async throws -> ByteBuffer
    func write(_ data: ByteBuffer, atOffset offset: UInt64) async throws -> SFTPStatusCode
    func close() async throws -> SFTPStatusCode
}

public struct SSHContext {}

public protocol SFTPDelegate {
    func fileAttributes(atPath path: String, context: SSHContext) async throws -> SFTPFileAttributes
    func openFile(_ filePath: String, withAttributes: SFTPFileAttributes, flags: SFTPOpenFileFlags, context: SSHContext) async throws -> SFTPFileHandle
    func createDirectory(_ filePath: String, withAttributes: SFTPFileAttributes, context: SSHContext) async throws -> SFTPStatusCode
    func removeDirectory(_ filePath: String, context: SSHContext) async throws -> SFTPStatusCode
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
            SSHOutboundChannelDataWrapper(),
            deserializeHandler,
            serializeHandler,
            sftpInboundHandler,
            CloseErrorHandler()
        )
    }
}
