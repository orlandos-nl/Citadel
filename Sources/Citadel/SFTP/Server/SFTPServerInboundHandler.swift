import Foundation
import NIO
import NIOSSH
import Logging

public struct SFTPDirectoryHandleIterator {
    var listing = [SFTPFileListing]()
}

final class SFTPServerInboundHandler: ChannelInboundHandler {
    typealias InboundIn = SFTPMessage
    
    let logger: Logger
    let delegate: SFTPDelegate
    let initialized: EventLoopPromise<Void>
    var currentHandleID: UInt32 = 0
    var files = [UInt32: SFTPFileHandle]()
    var directories = [UInt32: SFTPDirectoryHandle]()
    var directoryListing = [UInt32: SFTPDirectoryHandleIterator]()
    
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
            
            promise.futureResult.map { file -> SFTPMessage in
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
                handle.readableBytes == 0
            else {
                logger.error("bad SFTP file handle")
                return
            }
            
            if let file = files[id] {
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
            } else if directories[id] != nil {
                directories[id] = nil
                directoryListing[id] = nil
                
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: command.requestId,
                            errorCode: .ok,
                            message: "closed",
                            languageTag: "EN"
                        )
                    )
                )
            } else {
                logger.error("unknown SFTP handle")
            }
        case .read(let command):
            var handle = command.handle
            
            guard
                let id: UInt32 = handle.readInteger(),
                handle.readableBytes == 0,
                let file = files[id]
            else {
                logger.error("bad SFTP file handle")
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
            
            promise.futureResult.flatMap { attributes in
                context.writeAndFlush(
                    NIOAny(SFTPMessage.attributes(
                        .init(
                            requestId: command.requestId,
                            attributes: attributes
                        )
                    ))
                )
            }
        case .lstat(let command):
            let promise = context.eventLoop.makePromise(of: SFTPFileAttributes.self)
            promise.completeWithTask {
                try await self.delegate.fileAttributes(atPath: command.path, context: SSHContext())
            }
                
            promise.futureResult.flatMap { attributes in
                context.writeAndFlush(
                    NIOAny(SFTPMessage.attributes(
                        .init(
                            requestId: command.requestId,
                            attributes: attributes
                        )
                    ))
                )
            }
        case .realpath(let realPath):
            let promise = context.eventLoop.makePromise(of: [SFTPPathComponent].self)
            promise.completeWithTask {
                try await self.delegate.realPath(for: realPath.path, context: SSHContext())
            }
            
            promise.futureResult.whenSuccess { components in
                context.writeAndFlush(
                    NIOAny(SFTPMessage.name(
                        .init(
                            requestId: realPath.requestId,
                            components: components
                        )
                    ))
                )
            }
        case .opendir(let opendir):
            let promise = context.eventLoop.makePromise(of: (SFTPDirectoryHandle, SFTPDirectoryHandleIterator).self)
            promise.completeWithTask {
                let handle = try await self.delegate.openDirectory(atPath: opendir.handle, context: SSHContext())
                let files = try await handle.listFiles(context: SSHContext())
                let iterator = SFTPDirectoryHandleIterator(listing: files)
                return (handle, iterator)
            }
            
            promise.futureResult.map { (directory, listing) -> SFTPMessage in
                let handle = self.currentHandleID
                self.directories[handle] = directory
                self.directoryListing[handle] = listing
                self.currentHandleID &+= 1
                
                return SFTPMessage.handle(
                    SFTPMessage.Handle(
                        requestId: opendir.requestId,
                        handle: ByteBuffer(integer: handle, endianness: .big)
                    )
                )
            }.whenSuccess { handle in
                context.writeAndFlush(NIOAny(handle), promise: nil)
            }
        case .readdir(let readdir):
            var handle = readdir.handle
            
            guard
                let id: UInt32 = handle.readInteger(),
                handle.readableBytes == 0,
                var listing = directoryListing[id]
            else {
                logger.error("bad SFTP directory andle")
                return
            }
            
            func emitFile(listing: inout SFTPDirectoryHandleIterator) -> EventLoopFuture<Void> {
                if listing.listing.isEmpty {
                    self.directoryListing[id] = nil
                    return context.channel.writeAndFlush(SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: readdir.requestId,
                            errorCode: .eof,
                            message: "",
                            languageTag: "EN"
                        )
                    ))
                } else {
                    let file = listing.listing.removeFirst()
                    return context.channel.writeAndFlush(SFTPMessage.name(
                        .init(
                            requestId: readdir.requestId,
                            components: file.path
                        )
                    ))
                }
            }
            
            let result = emitFile(listing: &listing)
            self.directoryListing[id] = listing
            result.whenFailure { error in
                self.logger.error("\(error)")
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: readdir.requestId,
                            errorCode: .failure,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }
        case .version, .handle, .status, .data, .attributes, .name:
            // Client cannot send these messages
            context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                context.channel.close(promise: nil)
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
