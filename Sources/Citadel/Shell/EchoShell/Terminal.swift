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

public struct Terminal {
    
    static let enter: [UInt8] = [0x0d]
    static let delete_command: [UInt8] = [127]
    static let new_line: [UInt8] = [0x0a, 0x0d]
    static let arrow_up: [UInt8] = [0x1B, 0x5B, 0x41]
    static let arrow_down: [UInt8] = [0x1B, 0x5B, 0x42]
    static let arrow_left: [UInt8] = [0x1B, 0x5B, 0x44]
    static let arrow_right: [UInt8] = [0x1B, 0x5B, 0x43]
    static let alt_arrow_left: [UInt8] = [0x1B, 0x5B, 0x1B, 0x5B, 0x44]
    static let alt_arrow_right: [UInt8] = [0x1B, 0x5B, 0x1B, 0x5B, 0x43]
    
    @inlinable static func move_backwards(char: UInt8) -> [UInt8] {
        return [0x1B, 0x5B, char, 0x44]
    }
    
    @inlinable static func clear() -> [UInt8] {
        return [0x1B, 0x5B, 0x32, 0x4A, 0x1B, 0x5B, 0x48]
    }
    
    @inlinable static func delete() -> [UInt8] {
        return  [0x1B, 0x5B, 0x44, 0x20, 0x1B, 0x5B, 0x44]
    }
    
    var track_cursor: Int = 0
    
    mutating func tracked_move_left(limit: Int) -> [UInt8]? {
        if track_cursor < limit {
            track_cursor += 1
            return [0x1B, 0x5B, 0x44]
        }
        else { return nil }
    }
    
    mutating func tracked_move_right(limit: Int) -> [UInt8]? {
        if track_cursor > 0 {
            track_cursor -= 1
            return [0x1B, 0x5B, 0x43]
        }
        else { return nil }
    }
    
    mutating func reset_track() { track_cursor = 0 }
}
