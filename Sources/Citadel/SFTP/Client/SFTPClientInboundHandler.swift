import Foundation
import NIO
import NIOSSH
import Logging

final class SFTPClientInboundHandler: ChannelInboundHandler {
    typealias InboundIn = SFTPMessage
    
    let responses: SFTPResponses
    let logger: Logger
    
    init(responses: SFTPResponses, logger: Logger) {
        self.responses = responses
        self.logger = logger
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        
        if !self.responses.isInitialized, case .version(let version) = message {
            if version.version != .v3 {
                logger.warning("SFTP ERROR: Server version is unrecognized or incompatible: \(version.version.rawValue)")
                context.fireErrorCaught(SFTPError.unsupportedVersion(version.version))
            } else {
                responses.sftpVersion.succeed(version)
            }
        } else if let response = SFTPResponse(message: message) {
            if let promise = responses.responses.removeValue(forKey: response.requestId) {
                if case .status(let status) = response {
                    switch status.errorCode {
                    case .eof, .ok:
                        promise.succeed(response)
                    default:
                        // logged as debug rather than warning because there are many cases in which a protocol error is
                        // not only nonfatal, but even expected (such as SSH_FX_EOF).
                        self.logger.debug("SFTP error received: \(status)")
                        promise.fail(status)
                    }
                } else {
                    promise.succeed(response)
                }
            } else {
                self.logger.warning("SFTP response received for nonexistent request, this is a protocol error")
                context.fireErrorCaught(SFTPError.noResponseTarget)
            }
        } else {
            self.logger.warning("SFTP received unrecognized response message, this is a protocol error")
            context.fireErrorCaught(SFTPError.invalidResponse)
        }
    }
}
