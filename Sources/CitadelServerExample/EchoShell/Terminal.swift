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

struct Terminal {
    static let enter: UInt8 = 0x0d
    static let deleteCommand: [UInt8] = [127]
    static let newLine: [UInt8] = [0x0a, 0x0d]
    static let arrowUp: [UInt8] = [0x1B, 0x5B, 0x41]
    static let arrowDown: [UInt8] = [0x1B, 0x5B, 0x42]
    static let arrowLeft: [UInt8] = [0x1B, 0x5B, 0x44]
    static let arrowRight: [UInt8] = [0x1B, 0x5B, 0x43]
    static let altArrowLeft: [UInt8] = [0x1B, 0x5B, 0x1B, 0x5B, 0x44]
    static let altArrowRight: [UInt8] = [0x1B, 0x5B, 0x1B, 0x5B, 0x43]
    
    @inlinable static func moveBackwards(char: UInt8) -> [UInt8] {
        return [0x1B, 0x5B, char, 0x44]
    }
    
    @inlinable static func clear() -> [UInt8] {
        return [0x1B, 0x5B, 0x32, 0x4A, 0x1B, 0x5B, 0x48]
    }
    
    @inlinable static func delete() -> [UInt8] {
        return [0x1B, 0x5B, 0x44, 0x20, 0x1B, 0x5B, 0x44]
    }
    
    var column: Int = 0
    
    mutating func trackMoveLeft(limit: Int) -> [UInt8]? {
        if column < limit {
            column += 1
            return [0x1B, 0x5B, 0x44]
        } else { 
            return nil 
        }
    }
    
    mutating func trackMoveRight(limit: Int) -> [UInt8]? {
        if column > 0 {
            column -= 1
            return [0x1B, 0x5B, 0x43]
        } else { 
            return nil
        }
    }
    
    mutating func resetTrack() { column = 0 }
}
