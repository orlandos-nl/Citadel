import Foundation
import NIO
import NIOSSH
import Logging

struct SFTPDirectoryHandleIterator {
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
    var previousTask: EventLoopFuture<Void>
    let username: String?
    
    init(logger: Logger, delegate: SFTPDelegate, eventLoop: EventLoop, username: String?) {
        self.logger = logger
        self.delegate = delegate
        self.initialized = eventLoop.makePromise()
        self.previousTask = eventLoop.makeSucceededVoidFuture()
        self.username = username
    }
    
    func initialize(command: SFTPMessage.Initialize, context: ChannelHandlerContext) {
        guard command.version >= .v3 else {
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
    }
    
    func makeContext() -> SSHContext {
        SSHContext(username: self.username)
    }
    
    func openFile(command: SFTPMessage.OpenFile, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPFileHandle.self)
        promise.completeWithTask {
            try await self.delegate.openFile(
                command.filePath,
                withAttributes: command.attributes,
                flags: command.pFlags,
                context: self.makeContext()
            )
        }
        
        _ = promise.futureResult.map { file -> SFTPMessage in
            let handle = self.currentHandleID
            self.files[handle] = file
            self.currentHandleID &+= 1
            
            return SFTPMessage.handle(
                SFTPMessage.Handle(
                    requestId: command.requestId,
                    handle: ByteBuffer(integer: handle, endianness: .big)
                )
            )
        }.flatMap { handle in
            context.writeAndFlush(NIOAny(handle))
        }
    }
    
    func closeFile(command: SFTPMessage.CloseFile, context: ChannelHandlerContext) {
        guard let id: UInt32 = command.handle.getInteger(at: 0) else {
            logger.error("bad SFTP file handle")
            return
        }
        
        if let file = files[id] {
            previousTask = previousTask.flatMap {
                let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
                promise.completeWithTask {
                    try await file.close()
                }
                self.files[id] = nil
                return promise.futureResult.flatMap { status in
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
                }.flatMapError { _ in
                    context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).flatMap {
                        context.channel.close()
                    }
                }
            }
        } else if directories[id] != nil {
            directories[id] = nil
            directoryListing[id] = nil
            
            previousTask = previousTask.flatMap {
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
            }
        } else {
            logger.error("unknown SFTP handle")
        }
    }
    
    func readFile(command: SFTPMessage.ReadFile, context: ChannelHandlerContext) {
        previousTask = previousTask.flatMap {
            self.withFileHandle(command.handle, context: context) { file -> ByteBuffer in
                try await file.read(at: command.offset, length: command.length)
            }.flatMap { data -> EventLoopFuture<Void> in
                if data.readableBytes == 0 {
                    return context.channel.writeAndFlush(
                        SFTPMessage.status(
                            .init(
                                requestId: command.requestId,
                                errorCode: .eof,
                                message: "EOF",
                                languageTag: "EN"
                            )
                        )
                    )
                } else {
                    return context.channel.writeAndFlush(
                        SFTPMessage.data(
                            SFTPMessage.FileData(
                                requestId: command.requestId,
                                data: data
                            )
                        )
                    )
                }
            }.flatMapError { _ in
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).flatMap {
                    context.channel.close()
                }
            }
        }
    }
    
    func writeFile(command: SFTPMessage.WriteFile, context: ChannelHandlerContext) {
        previousTask = previousTask.flatMap {
            self.withFileHandle(command.handle, context: context) { file -> SFTPStatusCode in
                try await file.write(command.data, atOffset: command.offset)
            }.flatMap { status -> EventLoopFuture<Void> in
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
            }.flatMapError { _ in
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).flatMap {
                    context.channel.close()
                }
            }
        }
    }
    
    func createDir(command: SFTPMessage.MkDir, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.createDirectory(
                command.filePath,
                withAttributes: command.attributes,
                context: self.makeContext()
            )
        }
        
        _ = promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
        }.flatMapError { _ in
            context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).flatMap {
                context.channel.close()
            }
        }
    }
    
    func removeDir(command: SFTPMessage.RmDir, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.removeDirectory(
                command.filePath,
                context: self.makeContext()
            )
        }
        
        _ =  promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
        }.flatMapError { _ in
            context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).flatMap {
                context.channel.close()
            }
        }
    }
    
    func stat(command: SFTPMessage.Stat, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPFileAttributes.self)
        promise.completeWithTask {
            try await self.delegate.fileAttributes(atPath: command.path, context: self.makeContext())
        }
        
        _ = promise.futureResult.flatMap { attributes -> EventLoopFuture<Void> in
            context.writeAndFlush(
                NIOAny(SFTPMessage.attributes(
                    .init(
                        requestId: command.requestId,
                        attributes: attributes
                    )
                ))
            )
        }.flatMapErrorThrowing { _ in }
    }
    
    func lstat(command: SFTPMessage.LStat, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPFileAttributes.self)
        promise.completeWithTask {
            try await self.delegate.fileAttributes(atPath: command.path, context: self.makeContext())
        }
        
        _ = promise.futureResult.flatMap { attributes -> EventLoopFuture<Void> in
            context.writeAndFlush(
                NIOAny(SFTPMessage.attributes(
                    .init(
                        requestId: command.requestId,
                        attributes: attributes
                    )
                ))
            )
        }.flatMapErrorThrowing { _ in }
    }
    
    func realPath(command: SFTPMessage.RealPath, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: [SFTPPathComponent].self)
        promise.completeWithTask {
            try await self.delegate.realPath(for: command.path, context: self.makeContext())
        }
        
        _ = promise.futureResult.flatMap { components -> EventLoopFuture<Void> in
            context.writeAndFlush(
                NIOAny(SFTPMessage.name(
                    .init(
                        requestId: command.requestId,
                        components: components
                    )
                ))
            )
        }.flatMapErrorThrowing { _ in }
    }
    
    func openDir(command: SFTPMessage.OpenDir, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: (SFTPDirectoryHandle, SFTPDirectoryHandleIterator).self)
        promise.completeWithTask {
            let handle = try await self.delegate.openDirectory(atPath: command.handle, context: self.makeContext())
            let files = try await handle.listFiles(context: self.makeContext())
            let iterator = SFTPDirectoryHandleIterator(listing: files)
            return (handle, iterator)
        }
        
    _ = promise.futureResult.map { (directory, listing) -> SFTPMessage in
            let handle = self.currentHandleID
            self.directories[handle] = directory
            self.directoryListing[handle] = listing
            self.currentHandleID &+= 1
            
            return SFTPMessage.handle(
                SFTPMessage.Handle(
                    requestId: command.requestId,
                    handle: ByteBuffer(integer: handle, endianness: .big)
                )
            )
        }.flatMap { handle in
            context.writeAndFlush(NIOAny(handle))
        }.flatMapErrorThrowing { _ in }
    }
    
    func readDir(command: SFTPMessage.ReadDir, context: ChannelHandlerContext) {
        guard
            let id: UInt32 = command.handle.getInteger(at: 0),
            var listing = directoryListing[id]
        else {
            logger.error("bad SFTP directory handle")
            return
        }
        
        let result: EventLoopFuture<Void>
        if listing.listing.isEmpty {
            self.directoryListing[id] = nil
            result = context.channel.writeAndFlush(SFTPMessage.status(
                SFTPMessage.Status(
                    requestId: command.requestId,
                    errorCode: .eof,
                    message: "",
                    languageTag: "EN"
                )
            ))
        } else {
            let file = listing.listing.removeFirst()
            result = context.channel.writeAndFlush(SFTPMessage.name(
                .init(
                    requestId: command.requestId,
                    components: file.path
                )
            ))
        }
        
        self.directoryListing[id] = listing
        _ = result.flatMapError { error -> EventLoopFuture<Void> in
            self.logger.error("\(error)")
            return context.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: .failure,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }
    }
    
    func fileStat(command: SFTPMessage.FileStat, context: ChannelHandlerContext) {
        _ = self.withFileHandle(command.handle, context: context) { file in
            try await file.readFileAttributes()
        }.flatMap { attributes -> EventLoopFuture<Void> in
            context.channel.writeAndFlush(
                SFTPMessage.attributes(
                    .init(
                        requestId: command.requestId,
                        attributes: attributes
                    )
                )
            )
        }.flatMapError { _ -> EventLoopFuture<Void> in
            context.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: .failure,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }
    }
    
    func removeFile(command: SFTPMessage.Remove, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.removeFile(command.filename, context: self.makeContext())
        }
        _ = promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
        }.flatMapErrorThrowing { _ in }
    }
    
    func fileSetStat(command: SFTPMessage.FileSetStat, context: ChannelHandlerContext) {
        _ = self.withFileHandle(command.handle, context: context) { handle in
            try await handle.setFileAttributes(to: command.attributes)
        }.flatMap { () -> EventLoopFuture<Void> in
            context.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: .ok,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }.flatMapError { _ -> EventLoopFuture<Void> in
            context.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: .failure,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }
    }
    
    func setStat(command: SFTPMessage.SetStat, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.setFileAttributes(
                to: command.attributes,
                atPath: command.path,
                context: self.makeContext()
            )
        }
        _ = promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
        }.flatMapErrorThrowing { _ in }
    }
    
    func symlink(command: SFTPMessage.Symlink, context:ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.addSymlink(
                linkPath: command.linkPath,
                targetPath: command.targetPath,
                context: self.makeContext()
            )
        }
        _ = promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
        }.flatMapErrorThrowing { _ in }
    }

    func rename(command: SFTPMessage.Rename, context:ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.rename(
                oldPath: command.oldPath,
                newPath: command.newPath,
                flags: command.flags,
                context: self.makeContext()
            )
        }
        _ = promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
        }.flatMapErrorThrowing { _ in }
    }

    func readlink(command: SFTPMessage.Readlink, context:ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: [SFTPPathComponent].self)
        promise.completeWithTask {
            try await self.delegate.readSymlink(
                atPath: command.path,
                context: self.makeContext()
            )
        }
        _ = promise.futureResult.flatMap { components -> EventLoopFuture<Void> in
            context.channel.writeAndFlush(
                SFTPMessage.name(
                    SFTPMessage.Name(
                        requestId: command.requestId,
                        components: components
                    )
                )
            )
        }.flatMapError { _ -> EventLoopFuture<Void> in
            context.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: .failure,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .initialize(let command):
            initialize(command: command, context: context)
        case .openFile(let command):
            openFile(command: command, context: context)
        case .closeFile(let command):
            closeFile(command: command, context: context)
        case .read(let command):
            readFile(command: command, context: context)
        case .write(let command):
            writeFile(command: command, context: context)
        case .mkdir(let command):
            createDir(command: command, context: context)
        case .opendir(let command):
            openDir(command: command, context: context)
        case .rmdir(let command):
            removeDir(command: command, context: context)
        case .stat(let command):
            stat(command: command, context: context)
        case .lstat(let command):
            lstat(command: command, context: context)
        case .realpath(let command):
            realPath(command: command, context: context)
        case .readdir(let command):
            readDir(command: command, context: context)
        case .fstat(let command):
            fileStat(command: command, context: context)
        case .remove(let command):
            removeFile(command: command, context: context)
        case .fsetstat(let command):
            fileSetStat(command: command, context: context)
        case .setstat(let command):
            setStat(command: command, context: context)
        case .symlink(let command):
            symlink(command: command, context: context)
        case .readlink(let command):
            readlink(command: command, context: context)
        case .rename(let command):
            rename(command: command, context: context)
        case .version, .handle, .status, .data, .attributes, .name:
            // Client cannot send these messages
            context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                context.channel.close(promise: nil)
            }
        }
    }
    
    func withFileHandle<T>(_ handle: ByteBuffer, context: ChannelHandlerContext, perform: @Sendable @escaping (SFTPFileHandle) async throws -> T) -> EventLoopFuture<T> {
        guard
            let id: UInt32 = handle.getInteger(at: 0),
            let file = files[id]
        else {
            logger.error("bad SFTP file handle")
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
