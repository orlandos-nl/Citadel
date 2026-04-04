//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Dispatch
import Foundation
import NIOCore
import NIOFoundationCompat
import NIOPosix
import NIOSSH

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Bionic)
import Bionic
#endif

enum SSHServerError: Error {
    case invalidCommand
    case invalidDataType
    case invalidChannelType
    case alreadyListening
    case notListening
}

final class ExecHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = SSHChannelData
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData
    
    let delegate: ExecDelegate?
    
    init(delegate: ExecDelegate?, username: String?) {
        self.delegate = delegate
        self.username = username
    }
    
    var context: ExecCommandContext?
    var pipeChannel: Channel?
    var environment: [String: String] = [:]
    let username: String?
    
    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }
    
    func channelInactive(context: ChannelHandlerContext) {
        Task {
            try await self.context?.terminate()
            self.context = nil
            self.pipeChannel = nil
        }
        context.fireChannelInactive()
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as SSHChannelRequestEvent.ExecRequest:
            if let delegate = delegate {
                self.exec(event, delegate: delegate, channel: context.channel)
            } else if event.wantReply {
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    context.channel.close(promise: nil)
                }
            }
        case let event as SSHChannelRequestEvent.EnvironmentRequest:
            if let delegate = delegate {
                Task {
                    try await delegate.setEnvironmentValue(event.value, forKey: event.name)
                }
            }
        case ChannelEvent.inputClosed:
            Task {
                try await self.context?.inputClosed()
            }
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        context.write(data, promise: promise)
    }
    
    private func exec(_ event: SSHChannelRequestEvent.ExecRequest, delegate: ExecDelegate, channel: Channel) {
        let successPromise = channel.eventLoop.makePromise(of: Int.self)
        let handler = ExecOutputHandler(username: username) { code in
            successPromise.succeed(code)
        } onFailure: { _ in
            if event.wantReply {
                channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    channel.close(promise: nil)
                }
            } else {
                channel.close(promise: nil)
            }
        }

        let (ours, theirs) = GlueHandler.matchedPair()

        // For stderr we park a dedicated thread that blocks on readDataToEndOfFile().
        // Using a readabilityHandler + readToEnd() is unreliable on Linux: readToEnd()
        // throws when called from within a readability callback, which would close the
        // SSH channel prematurely and send a ChannelFailureEvent to the client.
        let stderrHandle = handler.stderrPipe.fileHandleForReading
        DispatchQueue.global().async {
            let data = stderrHandle.readDataToEndOfFile()
            guard !data.isEmpty else { return }
            channel.eventLoop.execute {
                var buffer = channel.allocator.buffer(capacity: data.count)
                buffer.writeContiguousBytes(data)
                channel.writeAndFlush(
                    SSHChannelData(type: .stdErr, data: .byteBuffer(buffer)),
                    promise: nil
                )
            }
        }

        // Tracks whether SSH_MSG_CHANNEL_SUCCESS has been sent for this exec request.
        // Once sent, a later failure in the pipeline must NOT send SSH_MSG_CHANNEL_FAILURE
        // (that would be a protocol violation that confuses the client into throwing
        // channelFailure instead of receiving a clean EOF). All accesses occur on the
        // channel's event loop so no locking is needed.
        var channelSuccessSent = false

        channel.pipeline.addHandler(ours).flatMap {
            NIOPipeBootstrap(group: channel.eventLoop)
                .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
                .channelInitializer { pipeChannel in
                    pipeChannel.pipeline.addHandlers(SSHInboundChannelDataWrapper(), SSHOutboundChannelDataUnwrapper(), theirs)
                }.withPipes(
                    inputDescriptor: dup(handler.stdoutPipe.fileHandleForReading.fileDescriptor),
                    outputDescriptor: dup(handler.stdinPipe.fileHandleForWriting.fileDescriptor)
                )
        }.flatMap { pipeChannel -> EventLoopFuture<Channel> in
            self.pipeChannel = pipeChannel
            let start = channel.eventLoop.makePromise(of: Void.self)
            start.completeWithTask {
                do {
                    self.context = try await delegate.start(
                        command: event.command,
                        outputHandler: handler
                    )
                } catch {
                    try await pipeChannel.close(mode: .all)
                }
            }

            return start.futureResult.flatMap {
                if event.wantReply {
                    return channel.triggerUserOutboundEvent(ChannelSuccessEvent()).map {
                        channelSuccessSent = true
                        return pipeChannel
                    }
                } else {
                    return channel.eventLoop.makeSucceededFuture(pipeChannel)
                }
            }
        }.flatMap { pipeChannel in
            successPromise.futureResult.flatMap { code in
                // On Linux, NIOPipeBootstrap may close the pipeChannel itself when the
                // stdout pipe's write end is closed while data is in-flight (EPOLLHUP).
                // By the time succeed() is called the pipe has been fully drained, so
                // ignoring an already-closed error here is safe.
                pipeChannel.close(mode: .all)
                    .flatMapError { _ in pipeChannel.eventLoop.makeSucceededVoidFuture() }
                    .map { code }
            }
        }.flatMap { code in
            channel.triggerUserOutboundEvent(SSHChannelRequestEvent.ExitStatus(exitStatus: code))
        }.whenComplete { result in
            switch result {
            case .success:
                channel.close(promise: nil)
            case .failure:
                // Only send ChannelFailureEvent when the exec setup itself failed (before
                // ChannelSuccessEvent was sent). Sending it after ChannelSuccessEvent is a
                // protocol violation and causes the client to throw channelFailure instead
                // of receiving a clean stream termination.
                if event.wantReply && !channelSuccessSent {
                    channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                        channel.close(promise: nil)
                    }
                } else {
                    channel.close(promise: nil)
                }
            }
        }
    }
}
