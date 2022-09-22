import Foundation
import NIO
import NIOSSH
import Logging

final class SFTPServerInboundHandler: ChannelInboundHandler {
    typealias InboundIn = SFTPMessage
    
    let logger: Logger
    let delegate: SFTPDelegate
    let initialized: EventLoopPromise<Void>
    var currentHandleID: UInt32 = 0
    var files = [UInt32: SFTPFileHandle]()
    
    init(logger: Logger, delegate: SFTPDelegate, eventLoop: EventLoop) {
        self.logger = logger
        self.delegate = delegate
        self.initialized = eventLoop.makePromise()
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .initialize(let message):
            guard message.version == .v3 else {
                return context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    context.channel.close(promise: nil)
                }
            }
            
            context.writeAndFlush(
                NIOAny(SFTPMessage.version(
                    .init(
                        version: .v3,
                        extensionData: []
                    )
                )),
                promise: nil
            )
        case .openFile(let command):
            let promise = context.eventLoop.makePromise(of: SFTPFileHandle.self)
            promise.completeWithTask {
                try await self.delegate.openFile(
                    command.filePath,
                    withAttributes: command.attributes,
                    flags: command.pFlags,
                    context: SSHContext()
                )
            }
            
            promise.futureResult.map { file in
                let handle = self.currentHandleID
                self.files[handle] = file
                self.currentHandleID &+= 1
                
                return SFTPMessage.handle(
                    SFTPMessage.Handle(
                        requestId: command.requestId,
                        handle: ByteBuffer(integer: handle, endianness: .big)
                    )
                )
            }.whenSuccess { handle in
                context.writeAndFlush(NIOAny(handle), promise: nil)
            }
        case .closeFile(let command):
            var handle = command.handle
            
            guard
                let id: UInt32 = handle.readInteger(),
                handle.readableBytes == 0,
                let file = files[id]
            else {
                logger.error("bad SFTP file handle")
                return
            }
            
            let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
            promise.completeWithTask {
                try await file.close()
            }
            files[id] = nil
            promise.futureResult.flatMap { status in
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: command.requestId,
                            errorCode: status,
                            message: "uploaded",
                            languageTag: "EN"
                        )
                    )
                )
            }.whenFailure { _ in
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    context.channel.close(promise: nil)
                }
            }
        case .read(let command):
            var handle = command.handle
            
            guard
                let id: UInt32 = handle.readInteger(),
                handle.readableBytes == 0,
                let file = files[id]
            else {
                logger.error("bad SFTP file andle")
                return
            }
            
            let promise = context.eventLoop.makePromise(of: ByteBuffer.self)
            promise.completeWithTask {
                try await file.read(at: command.offset, length: command.length)
            }
            promise.futureResult.flatMap { data in
                context.channel.writeAndFlush(
                    SFTPMessage.data(
                        SFTPMessage.FileData(
                            requestId: command.requestId,
                            data: data
                        )
                    )
                )
            }.whenFailure { _ in
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    context.channel.close(promise: nil)
                }
            }
        case .write(let command):
            var handle = command.handle
            
            guard
                let id: UInt32 = handle.readInteger(),
                handle.readableBytes == 0,
                let file = files[id]
            else {
                logger.error("bad SFTP file andle")
                return
            }
            
            let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
            promise.completeWithTask {
                try await file.write(command.data, atOffset: command.offset)
            }
            promise.futureResult.flatMap { status in
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: command.requestId,
                            errorCode: status,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }.whenFailure { _ in
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    context.channel.close(promise: nil)
                }
            }
        case .version, .handle, .status, .data, .attributes:
            // Client cannot send these messages
            context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                context.channel.close(promise: nil)
            }
        case .mkdir(let command):
            let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
            promise.completeWithTask {
                try await self.delegate.createDirectory(
                    command.filePath,
                    withAttributes: command.attributes,
                    context: SSHContext()
                )
            }
            
            promise.futureResult.flatMap { status in
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: command.requestId,
                            errorCode: status,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }.whenFailure { _ in
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    context.channel.close(promise: nil)
                }
            }
        case .rmdir(let command):
            let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
            promise.completeWithTask {
                try await self.delegate.removeDirectory(
                    command.filePath,
                    context: SSHContext()
                )
            }
            
            promise.futureResult.flatMap { status in
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: command.requestId,
                            errorCode: status,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }.whenFailure { _ in
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    context.channel.close(promise: nil)
                }
            }
        case .stat(let command):
            let promise = context.eventLoop.makePromise(of: SFTPFileAttributes.self)
            promise.completeWithTask {
                try await self.delegate.fileAttributes(atPath: command.path, context: SSHContext())
            }
            
            promise.futureResult.whenSuccess { attributes in
                context.writeAndFlush(
                    NIOAny(SFTPMessage.attributes(
                        .init(
                            requestId: command.requestId,
                            attributes: attributes
                        )
                    )),
                    promise: nil
                )
            }
        case .lstat(let command):
            let promise = context.eventLoop.makePromise(of: SFTPFileAttributes.self)
            promise.completeWithTask {
                try await self.delegate.fileAttributes(atPath: command.path, context: SSHContext())
            }
                
            promise.futureResult.whenSuccess { attributes in
                context.writeAndFlush(
                    NIOAny(SFTPMessage.attributes(
                        .init(
                            requestId: command.requestId,
                            attributes: attributes
                        )
                    )),
                    promise: nil
                )
            }
        }
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case ChannelEvent.inputClosed:
            context.channel.close(promise: nil)
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }
    
    deinit {
        initialized.fail(SFTPError.connectionClosed)
    }
}
