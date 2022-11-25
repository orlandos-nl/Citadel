import Foundation
import NIO
import NIOSSH
import Logging

public protocol SFTPFileHandle {
    func read(at offset: UInt64, length: UInt32) async throws -> ByteBuffer
    func write(_ data: ByteBuffer, atOffset offset: UInt64) async throws -> SFTPStatusCode
    func close() async throws -> SFTPStatusCode
    func readFileAttributes() async throws -> SFTPFileAttributes
    func setFileAttributes(to attributes: SFTPFileAttributes) async throws
}

public protocol SFTPDirectoryHandle {
    func listFiles(context: SSHContext) async throws -> [SFTPFileListing]
}

public struct SSHContext {
    public let username: String?
}

public protocol SFTPDelegate {
    func fileAttributes(atPath path: String, context: SSHContext) async throws -> SFTPFileAttributes
    func openFile(_ filePath: String, withAttributes: SFTPFileAttributes, flags: SFTPOpenFileFlags, context: SSHContext) async throws -> SFTPFileHandle
    func removeFile(_ filePath: String, context: SSHContext) async throws -> SFTPStatusCode
    func createDirectory(_ filePath: String, withAttributes: SFTPFileAttributes, context: SSHContext) async throws -> SFTPStatusCode
    func removeDirectory(_ filePath: String, context: SSHContext) async throws -> SFTPStatusCode
    func realPath(for canonicalUrl: String, context: SSHContext) async throws -> [SFTPPathComponent]
    func openDirectory(atPath path: String, context: SSHContext) async throws -> SFTPDirectoryHandle
    func setFileAttributes(to attributes: SFTPFileAttributes, atPath path: String, context: SSHContext) async throws -> SFTPStatusCode
    func addSymlink(linkPath: String, targetPath: String, context: SSHContext) async throws -> SFTPStatusCode
    func readSymlink(atPath path: String, context: SSHContext) async throws -> [SFTPPathComponent]
}

struct SFTPServerSubsystem {
    static func setupChannelHanders(
        channel: Channel,
        delegate: SFTPDelegate,
        logger: Logger
    ) -> EventLoopFuture<Void> {
        channel.pipeline.handler(type: NIOSSHHandler.self).flatMap { handler in
            let deserializeHandler = ByteToMessageHandler(SFTPMessageParser())
            let serializeHandler = MessageToByteHandler(SFTPMessageSerializer())
            let sftpInboundHandler = SFTPServerInboundHandler(
                logger: logger,
                delegate: delegate,
                eventLoop: channel.eventLoop,
                username: handler.username
            )
            
            return channel.pipeline.addHandlers(
                SSHChannelDataUnwrapper(),
                SSHOutboundChannelDataWrapper(),
                deserializeHandler,
                serializeHandler,
                sftpInboundHandler,
                CloseErrorHandler(logger: logger)
            )
        }
    }
}
