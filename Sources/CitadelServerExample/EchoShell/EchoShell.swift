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
import ColorizeSwift
import Citadel

// Simple shell emulator that returns the user input and offers some basic commands like: help, history, clear, whoami, date and exit.
public struct SimpleShell: ShellDelegate {
    public var message: String = "Welcome to Citadel Server!"
    public var hostname: String = "citadel"
    public var commands: [any ShellCommand] = [
        ExitCommand(),
        ClearCommand(),
        // HistoryCommand(),
        WhoAmICommand(),
        DateCommand(),
        // HelpCommand()
    ]

    public func startShell(
        inbound: AsyncStream<ShellClientEvent>,
        outbound: ShellOutboundWriter,
        context: SSHShellContext
    ) async throws {
        var shell = _SimpleShell(
            commands: commands,
            continuation: outbound,
            context: context,
            hostname: hostname
        )

        var iterator = inbound.makeAsyncIterator()
        outbound.write(message)
        outbound.write(Terminal.newLine)
        outbound.write(shell.pseudoPrompt)

        while let message = await iterator.next() {
            if case .stdin(var input) = message {
                try await shell.writeInput(&input, inbound: iterator)
            }

            if context.isClosed || Task.isCancelled {
                break
            }
        }
    }
}
    
fileprivate struct _SimpleShell {
    let commands: [any ShellCommand]
    let outbound: ShellOutboundWriter
    let context: SSHShellContext
    let hostname: String

    init(
        commands: [any ShellCommand],
        continuation: ShellOutboundWriter,
        context: SSHShellContext,
        hostname: String
    ) {
        self.commands = commands
        self.outbound = continuation
        self.context = context
        self.hostname = hostname
    }

    private var sessionId: UUID = UUID()
    private var currentLine = ByteBuffer()
    private var terminal: Terminal = Terminal()
    
    public mutating func clearLine() { currentLine.clear() }
    
    public mutating func writeInput(
        _ input: inout ByteBuffer,
        inbound: AsyncStream<ShellClientEvent>.AsyncIterator
    ) async throws {
        let view = input.readableBytesView
        if let enterIndex = view.firstIndex(of: Terminal.enter) {
            let size = enterIndex - view.startIndex
            currentLine.writeImmutableBuffer(input.readSlice(length: size)!)

            terminal.resetTrack()

            let inputString = currentLine.readString(length: currentLine.readableBytes)

            if 
                let inputString,
                let command = commands.first(where: { $0.name == inputString })
            {
                outbound.write(Terminal.newLine)
                do {
                    try await command.invoke(
                        // TODO: Actual arguments
                        invocation: InvokeCommandContext(arguments: [inputString]),
                        inbound: inbound,
                        outbound: outbound,
                        context: context
                    )

                    outbound.write(Terminal.newLine)
                } catch {
                    outbound.write(Terminal.newLine)
                    outbound.write("Error: \(error)".red())
                    outbound.write(Terminal.newLine)
                }
                
                outbound.write(pseudoPrompt)
            } else {
                if let inputString {
                    outbound.write(Terminal.newLine)
                    outbound.write("Unknown command: \(inputString)".red())
                }

                // write prompt
                outbound.write(Terminal.newLine)
                outbound.write(pseudoPrompt)
            }

            currentLine.clear()
        } else {
            let input = input.readSlice(length: input.readableBytes)!
            currentLine.writeImmutableBuffer(input)
            outbound.write(input)
        }
            
        //     // check for commands
        //     if let command = commands.first(where: { Array($0.name.utf8) == currentLine }) {
        //         break
        //     }
            
        //     if !currentLine.isEmpty {
        //         // start new line
        //         outbound.write(Terminal.newLine)
                
        //         // echo line
        //         outbound.write(currentLine)
                
        //         currentLine = []
        //     }
            
        // case Terminal.deleteCommand:
        //     if !currentLine.isEmpty {
        //         outbound.write(Terminal.delete())
        //         currentLine = currentLine.dropLast()
        //     }
        // // case Terminal.arrowUp:
        // //     if let output = history.go_back(currentLineCount: currentLine.count) {
        // //         stdout(output.0)
        // //         currentLine = output.1
        // //     }
        // // case Terminal.arrowDown:
        // //     if let output = history.go_forward(currentLineCount: currentLine.count) {
        // //         stdout(output.0)
        // //         currentLine = output.1
        // //     }
        // case Terminal.arrowLeft:
        //     if let output: [UInt8] = terminal.trackMoveLeft(limit: currentLine.count) {
        //         outbound.write(output)
        //     }
        // case Terminal.arrowRight:
        //     if let output = terminal.trackMoveRight(limit: currentLine.count) {
        //         outbound.write(output)
        //     }
        // default:
        //     currentLine.writeImmutableBuffer(input)
        //     outbound.write(input)
        // }
    }
    
    fileprivate var pseudoPrompt: [UInt8] {
        return Array("\(context.session.username ?? "")@\(hostname)".green().utf8) + Array(":~$ ".foregroundColor(.darkViolet).utf8)
    }
}