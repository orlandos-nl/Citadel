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
        case .read(var command):
            withFileHandle(&command.handle, context: context) { file in
                try await file.read(at: command.offset, length: command.length)
            }.flatMap { data in
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
        case .write(var command):
            withFileHandle(&command.handle, context: context) { file in
                try await file.write(command.data, atOffset: command.offset)
            }.flatMap { status in
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
        case .fstat(var fstat):
            withFileHandle(&fstat.handle, context: context) { file in
                try await file.readFileAttributes()
            }.flatMap { attributes in
                context.channel.writeAndFlush(
                    SFTPMessage.attributes(
                        .init(
                            requestId: fstat.requestId,
                            attributes: attributes
                        )
                    )
                )
            }.flatMapError { _ in
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: fstat.requestId,
                            errorCode: .failure,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }
        case .remove(let remove):
            let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
            promise.completeWithTask {
                try await self.delegate.removeFile(remove.filename, context: SSHContext())
            }   
            promise.futureResult.flatMap { status in
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: remove.requestId,
                            errorCode: status,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }
        case .fsetstat(var fsetstat):
            withFileHandle(&fsetstat.handle, context: context) { handle in
                try await handle.setFileAttributes(to: fsetstat.attributes)
            }.flatMap {
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: fsetstat.requestId,
                            errorCode: .ok,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }.flatMapError { _ in
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: fsetstat.requestId,
                            errorCode: .failure,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }
        case .setstat(let setstat):
            let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
            promise.completeWithTask {
                try await self.delegate.setFileAttributes(
                    to: setstat.attributes,
                    atPath: setstat.path,
                    context: SSHContext()
                )
            }
            promise.futureResult.flatMap { status in
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: setstat.requestId,
                            errorCode: status,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }
        case .symlink(let symlink):
            let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
            promise.completeWithTask {
                try await self.delegate.addSymlink(
                    linkPath: symlink.linkPath,
                    targetPath: symlink.targetPath,
                    context: SSHContext()
                )
            }
            promise.futureResult.flatMap { status in
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: symlink.requestId,
                            errorCode: status,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }
        case .readlink(let readlink):
            let promise = context.eventLoop.makePromise(of: [SFTPPathComponent].self)
            promise.completeWithTask {
                try await self.delegate.readSymlink(
                    atPath: readlink.path,
                    context: SSHContext()
                )
            }
            promise.futureResult.flatMap { components in
                context.channel.writeAndFlush(
                    SFTPMessage.name(
                        SFTPMessage.Name(
                            requestId: readlink.requestId,
                            components: components
                        )
                    )
                )
            }.flatMapError { _ in
                context.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: readlink.requestId,
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
    
    func withFileHandle<T>(_ handle: inout ByteBuffer, context: ChannelHandlerContext, perform: @escaping (SFTPFileHandle) async throws -> T) -> EventLoopFuture<T> {
        guard
            let id: UInt32 = handle.readInteger(),
            handle.readableBytes == 0,
            let file = files[id]
        else {
            logger.error("bad SFTP file andle")
            return context.eventLoop.makeFailedFuture(SFTPError.fileHandleInvalid)
        }
        
        let promise = context.eventLoop.makePromise(of: T.self)
        promise.completeWithTask {
            try await perform(file)
        }
        return promise.futureResult
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
