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
    
    @inline(never)
    func initialize(command: SFTPMessage.Initialize, context: ChannelHandlerContext) {
        guard command.version == .v3 else {
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
    
    @inline(never)
    func openFile(command: SFTPMessage.OpenFile, context: ChannelHandlerContext) {
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
    }
    
    @inline(never)
    func closeFile(command: SFTPMessage.CloseFile, context: ChannelHandlerContext) {
        guard let id: UInt32 = command.handle.getInteger(at: 0) else {
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
    }
    
    @inline(never)
    func readFile(command: SFTPMessage.ReadFile, context: ChannelHandlerContext) {
        withFileHandle(command.handle, context: context) { file -> ByteBuffer in
            try await file.read(at: command.offset, length: command.length)
        }.flatMap { data -> EventLoopFuture<Void> in
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
    }
    
    @inline(never)
    func writeFile(command: SFTPMessage.WriteFile, context: ChannelHandlerContext) {
        withFileHandle(command.handle, context: context) { file -> SFTPStatusCode in
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
        }.whenFailure { _ in
            context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                context.channel.close(promise: nil)
            }
        }
    }
    
    @inline(never)
    func createDir(command: SFTPMessage.MkDir, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.createDirectory(
                command.filePath,
                withAttributes: command.attributes,
                context: SSHContext()
            )
        }
        
        promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
    }
    
    @inline(never)
    func removeDir(command: SFTPMessage.RmDir, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.removeDirectory(
                command.filePath,
                context: SSHContext()
            )
        }
        
        promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
    }
    
    @inline(never)
    func stat(command: SFTPMessage.Stat, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPFileAttributes.self)
        promise.completeWithTask {
            try await self.delegate.fileAttributes(atPath: command.path, context: SSHContext())
        }
        
        promise.futureResult.flatMap { attributes -> EventLoopFuture<Void> in
            context.writeAndFlush(
                NIOAny(SFTPMessage.attributes(
                    .init(
                        requestId: command.requestId,
                        attributes: attributes
                    )
                ))
            )
        }
    }
    
    @inline(never)
    func lstat(command: SFTPMessage.LStat, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPFileAttributes.self)
        promise.completeWithTask {
            try await self.delegate.fileAttributes(atPath: command.path, context: SSHContext())
        }
        
        promise.futureResult.flatMap { attributes -> EventLoopFuture<Void> in
            context.writeAndFlush(
                NIOAny(SFTPMessage.attributes(
                    .init(
                        requestId: command.requestId,
                        attributes: attributes
                    )
                ))
            )
        }
    }
    
    @inline(never)
    func realPath(command: SFTPMessage.RealPath, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: [SFTPPathComponent].self)
        promise.completeWithTask {
            try await self.delegate.realPath(for: command.path, context: SSHContext())
        }
        
        promise.futureResult.flatMap { components -> EventLoopFuture<Void> in
            context.writeAndFlush(
                NIOAny(SFTPMessage.name(
                    .init(
                        requestId: command.requestId,
                        components: components
                    )
                ))
            )
        }
    }
    
    @inline(never)
    func openDir(command: SFTPMessage.OpenDir, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: (SFTPDirectoryHandle, SFTPDirectoryHandleIterator).self)
        promise.completeWithTask {
            let handle = try await self.delegate.openDirectory(atPath: command.handle, context: SSHContext())
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
                    requestId: command.requestId,
                    handle: ByteBuffer(integer: handle, endianness: .big)
                )
            )
        }.whenSuccess { handle in
            context.writeAndFlush(NIOAny(handle), promise: nil)
        }
    }
    
    @inline(never)
    func readDir(command: SFTPMessage.ReadDir, context: ChannelHandlerContext) {
        guard
            let id: UInt32 = command.handle.getInteger(at: 0),
            var listing = directoryListing[id]
        else {
            logger.error("bad SFTP directory andle")
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
        result.flatMapError { error -> EventLoopFuture<Void> in
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
    
    @inline(never)
    func fileStat(command: SFTPMessage.FileStat, context: ChannelHandlerContext) {
        withFileHandle(command.handle, context: context) { file in
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
    
    @inline(never)
    func removeFile(command: SFTPMessage.Remove, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.removeFile(command.filename, context: SSHContext())
        }
        promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
        }
    }
    
    @inline(never)
    func fileSetStat(command: SFTPMessage.FileSetStat, context: ChannelHandlerContext) {
        withFileHandle(command.handle, context: context) { handle in
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
    
    @inline(never)
    func setStat(command: SFTPMessage.SetStat, context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.setFileAttributes(
                to: command.attributes,
                atPath: command.path,
                context: SSHContext()
            )
        }
        promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
        }
    }
    
    @inline(never)
    func symlink(command: SFTPMessage.Symlink, context:ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask {
            try await self.delegate.addSymlink(
                linkPath: command.linkPath,
                targetPath: command.targetPath,
                context: SSHContext()
            )
        }
        promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
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
        }
    }
    
    @inline(never)
    func readlink(command: SFTPMessage.Readlink, context:ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: [SFTPPathComponent].self)
        promise.completeWithTask {
            try await self.delegate.readSymlink(
                atPath: command.path,
                context: SSHContext()
            )
        }
        promise.futureResult.flatMap { components -> EventLoopFuture<Void> in
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
    
    @inline(never)
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .initialize(let command as SFTPMessage.Initialize):
            self.initialize(command: command, context: context)
        case .openFile(let command as SFTPMessage.OpenFile):
            self.openFile(command: command, context: context)
        case .closeFile(let command as SFTPMessage.CloseFile):
            self.closeFile(command: command, context: context)
        case .read(let command as SFTPMessage.ReadFile):
            self.readFile(command: command, context: context)
        case .write(let command as SFTPMessage.WriteFile):
            self.writeFile(command: command, context: context)
        case .mkdir(let command as SFTPMessage.MkDir):
            self.createDir(command: command, context: context)
        case .opendir(let command as SFTPMessage.OpenDir):
            self.openDir(command: command, context: context)
        case .rmdir(let command as SFTPMessage.RmDir):
            self.removeDir(command: command, context: context)
        case .stat(let command as SFTPMessage.Stat):
            self.stat(command: command, context: context)
        case .lstat(let command as SFTPMessage.LStat):
            self.lstat(command: command, context: context)
        case .realpath(let command as SFTPMessage.RealPath):
            self.realPath(command: command, context: context)
        case .readdir(let command as SFTPMessage.ReadDir):
            self.readDir(command: command, context: context)
        case .fstat(let command as SFTPMessage.FileStat):
            self.fileStat(command: command, context: context)
        case .remove(let command as SFTPMessage.Remove):
            self.removeFile(command: command, context: context)
        case .fsetstat(let command as SFTPMessage.FileSetStat):
            self.fileSetStat(command: command, context: context)
        case .setstat(let command as SFTPMessage.SetStat):
            self.setStat(command: command, context: context)
        case .symlink(let command as SFTPMessage.Symlink):
            self.symlink(command: command, context: context)
        case .readlink(let command as SFTPMessage.Readlink):
            self.readlink(command: command, context: context)
        case .version, .handle, .status, .data, .attributes, .name:
            // Client cannot send these messages
            context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                context.channel.close(promise: nil)
            }
        }
    }
    
    @inline(never)
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
