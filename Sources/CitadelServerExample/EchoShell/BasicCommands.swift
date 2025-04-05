//===----------------------------------------------------------------------===//
//
// This source file is part of the Citadel open source and the ClamShell project
//
// Copyright (c) 2023 Gregor Feigel and the Citadel project authors
// Licensed under MIT License
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

import Foundation
import NIO
import NIOSSH
import Citadel

// Basic Commands
// Each command must return an array of UINT8 or nil. Streams are currently not supported.

public struct InvokeCommandContext: Sendable {
    public let arguments: [String]
}

public protocol ShellCommand: Sendable {
    var name: String { get }
    var description: String { get }
    
    func invoke(
        invocation: InvokeCommandContext,
        inbound: AsyncStream<ShellClientEvent>.AsyncIterator,
        outbound: ShellOutboundWriter,
        context: SSHShellContext
    ) async throws
}

struct ExitCommand: ShellCommand {
    let name: String = "exit"
    let description: String = "Ends the SSH session."

    func invoke(
        invocation: InvokeCommandContext,
        inbound: AsyncStream<ShellClientEvent>.AsyncIterator,
        outbound: ShellOutboundWriter,
        context: SSHShellContext
    ) async throws {
        outbound.write(ByteBuffer(bytes: Terminal.newLine + Terminal.newLine))
    }
}

struct ClearCommand: ShellCommand {
    let name: String = "clear"
    let description: String = "Clears the screen."

    func invoke(
        invocation: InvokeCommandContext,
        inbound: AsyncStream<ShellClientEvent>.AsyncIterator,
        outbound: ShellOutboundWriter,
        context: SSHShellContext
    ) async throws {
        outbound.write(Terminal.clear())
    }
}

struct WhoAmICommand: ShellCommand {
    let name: String = "whoami"
    let description: String = "Returns the username."

    func invoke(
        invocation: InvokeCommandContext,
        inbound: AsyncStream<ShellClientEvent>.AsyncIterator,
        outbound: ShellOutboundWriter,
        context: SSHShellContext
    ) async throws {
        outbound.write(context.session.username ?? "")
    }
}

struct DateCommand: ShellCommand {
    let name: String = "date"
    let description: String = "Returns the system time."

    func invoke(
        invocation: InvokeCommandContext,
        inbound: AsyncStream<ShellClientEvent>.AsyncIterator,
        outbound: ShellOutboundWriter,
        context: SSHShellContext
    ) async throws {
        let date = Date().getDateFormattedBy("EEE MMM d HH:mm:ss zzz yyyy")
        outbound.write(date)
    }
}