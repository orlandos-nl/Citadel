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

// Basic Commands
// Each command must return an array of UINT8 or nil. Streams are currently not supported.

public protocol Command {
    var name: String { get }
    var description: String { get }
    func exec(input: [UInt8], session: EchoShellMaster) async throws -> [UInt8]?
}

struct ExitCommand: Command {
    let name: String = "exit"
    let description: String = "ends the SSH session."
    
    func exec(input: [UInt8], session: EchoShellMaster) async throws -> [UInt8]? {
        session.continuation.yield(.stdout(ByteBuffer(bytes: Terminal.new_line + Terminal.new_line)))
        try await session.close()
        return nil
    }
}

struct ClearCommand: Command {
    let name: String = "clear"
    let description: String = "clears the screen."
    
    func exec(input: [UInt8], session: EchoShellMaster) -> [UInt8]? {
        return Terminal.clear()
    }
}

struct HistoryCommand: Command {
    let name: String = "history"
    let description: String = "command history."
    
    func exec(input: [UInt8], session: EchoShellMaster) -> [UInt8]? {
        return session.history.dump()
    }
}

struct WHOAMICommand: Command {
    let name: String = "whoami"
    let description: String = "returns the user name."
    
    func exec(input: [UInt8], session: EchoShellMaster) -> [UInt8]? {
        return Array(session.user_name.utf8)
    }
}

struct DateCommand: Command {
    let name: String = "date"
    let description: String = "returns the system time."
    
    func exec(input: [UInt8], session: EchoShellMaster) -> [UInt8]? {
        return Array(Date().getDateFormattedBy("EEE MMM d HH:mm:ss zzz yyyy").utf8)
    }
}

struct HelpCommand: Command {
    let name: String = "help"
    let description: String = "prints the command description for the available commands."
    
    func exec(input: [UInt8], session: EchoShellMaster) -> [UInt8]? {
        let input: [(String, String)] = session.commands.map({ ($0.name, $0.description) })
        var length: Int = 0
        var container: [String] = []
        
        // retrieves the length of the longest command name
        for n in input {
            if n.0.count > length {
                length = n.0.count
            }
        }
        // merge
        for n in input {
            let fill = length - n.0.count
            container.append(n.0 + Array(repeating: " ", count: fill).joined() + "  -  " + n.1)
        }
        
        return container.map { n in
            Array(n.utf8) + Terminal.new_line
        }
        .reduce([], +)
    }
}

