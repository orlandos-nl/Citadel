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

public final class EchoShellMaster {
    
    public init(continuation: AsyncThrowingStream<ShellServerEvent, Error>.Continuation,
         context: SSHShellContext,
         session_id: UUID = UUID(),
         current_line: [UInt8] = [],
         user_name: String = "usr",
         history: CommandHistory = CommandHistory()) {
        self.continuation = continuation
        self.context = context
        self.session_id = session_id
        self.current_line = current_line
        self.user_name = user_name
        self.history = history
    }

    func close() async throws {
        try await context.close()
    }

    let continuation: AsyncThrowingStream<ShellServerEvent, Error>.Continuation
    let context: SSHShellContext

    private var session_id: UUID = UUID()
    private var current_line: [UInt8] = []
    internal var user_name: String = "usr"
    private var terminal: Terminal = Terminal()
    internal var commands: [Command] = [
        ExitCommand(),
        ClearCommand(),
        HistoryCommand(),
        WHOAMICommand(),
        DateCommand(),
        HelpCommand()
    ]
    
    var history: CommandHistory = CommandHistory()
    
    public func register(command: Command) { commands.append(command) }
    
    public func clear_line() { current_line = [] }

    public func set_usr(_ usr: String?) {
        user_name = usr ?? "usr"
        let output = pseudo_prompt(usr: user_name)
        stdout(output)
    }
    
    public func write_input(_ input: [UInt8]) async throws {
        switch input {
            case Terminal.enter:
                history.zero()
                terminal.reset_track()
                
                var output: [UInt8] = []
                
                // check for commands
                if let command = commands.first(where: { Array($0.name.utf8) == current_line }) {
                    var output: [UInt8] = Terminal.new_line
                    if let command_output = try await command.exec(input: current_line, session: self) {
                        output += command_output
                        output += Terminal.new_line
                        output += pseudo_prompt(usr: user_name)
                        stdout(output)
                    }
                    history.add_line(current_line)
                    current_line = []
                    break
                }
                
                if !current_line.isEmpty {
                    // start new line
                    output += Terminal.new_line
                    
                    // echo line
                    output += current_line
                    
                    history.add_line(current_line)
                    current_line = []
                }
                
                // write prompt
                output += Terminal.new_line
                output += pseudo_prompt(usr: user_name)
                
                stdout(output)
                
            case Terminal.delete_command:
                if !current_line.isEmpty {
                    stdout(Terminal.delete())
                    current_line = current_line.dropLast()
                }
            case Terminal.arrow_up:
                if let output = history.go_back(currentLineCount: current_line.count) {
                    stdout(output.0)
                    current_line = output.1
                }
            case Terminal.arrow_down:
                if let output = history.go_forward(currentLineCount: current_line.count) {
                    stdout(output.0)
                    current_line = output.1
                }
            case Terminal.arrow_left:
                if let output = terminal.tracked_move_left(limit: current_line.count) {
                    stdout(output)
                }
            case Terminal.arrow_right:
                if let output = terminal.tracked_move_right(limit: current_line.count) {
                    stdout(output)
                }
            default:
                current_line.append(contentsOf: input)
                stdout(input)
        }
    }
    
    private func pseudo_prompt(usr: String) -> [UInt8] {
        return [UInt8](Data(("\(usr)@citadel".green()).utf8) + Data((":~$ ".foregroundColor(.darkViolet)).utf8))
    }
    
    private func stdout(_ bytes: [UInt8]) {
        continuation.yield(.stdout(.init(bytes: bytes)))
    }
}

/// Command history is the equivalent to `history` in terminal. It stores the typed input, and allows to move forward and backward in the history.
public struct CommandHistory {
    
    public init(history: [[UInt8]] = [], pointer: Int = -1, previous_length: Int = 0) {
        self.history = history
        self.pointer = pointer
        self.previous_length = previous_length
    }
    
    private var history: [[UInt8]] = []
    private var pointer: Int = -1
    private var previous_length: Int = 0
    
    // Adds the input if it is not equal to the last one. This makes it easier to search the history.
    mutating func add_line(_ line: [UInt8]) {
        if history.last != line {
            history.append(line)
        }
    }
    
    mutating func go_back(currentLineCount: Int) -> ([UInt8], [UInt8])? {
        let index = (history.count - 1) - (pointer + 1)
        
        if index >= 0 && index <= history.count - 1 {
            pointer += 1
            let cmd = history[index]
            
            var delete_count: Int = 0
            delete_count += currentLineCount
            
            var output: [UInt8] = [] //Terminal.move_backwards(char: 5) + cmd
            
            // NOTE: very sketchy
            if delete_count > 0 {
                for _ in 0..<delete_count { output += Terminal.delete() }
            }
            
            output += cmd
            
            return (output, cmd)
        }
        
        return nil
    }
    
    mutating func go_forward(currentLineCount: Int) -> ([UInt8], [UInt8])? {
        let index = (history.count - 1) - (pointer - 1)
        
        if index >= 0 && index <= history.count - 1 {
            let cmd = history[index]
            pointer -= 1
            
            var delete_count: Int = 0
            delete_count += currentLineCount
            
            var output: [UInt8] = []
            
            // NOTE: very sketchy
            if delete_count > 0 {
                for _ in 0..<delete_count { output += Terminal.delete() } // Terminal.move_backwards(char: 5) - does not work
            }
            
            output += cmd
            
            return (output, cmd)
        }
        
        return nil
    }
    
    // `Zero` is needed to reset the internal pointer when pressing the Enter key.
    mutating func zero() {
        pointer = -1
        previous_length = 0
    }
    
    // Converts the history into a terminal printable array of UInt8.
    func dump() -> [UInt8] {
        var output: [UInt8] = []
        for (i,n) in history.enumerated() {
            if i < history.count - 1 {
                output += n + Terminal.new_line
            }
            else {
                output += n
            }
        }
        return output
    }
}
