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
import Crypto
import NIOSSH

public extension NIOSSHPrivateKey {
    init(file: URL = FileManager.default.temporaryDirectory.appendingPathComponent("citadel_ssh_host_key")) throws {
        let hostKeyFile = HostKey(file: file)
        try self.init(ed25519Key: .init(rawRepresentation: hostKeyFile.key))
    }
}

public struct HostKey {
    init(file: URL = FileManager.default.temporaryDirectory.appendingPathComponent("citadel_ssh_host_key")) {
        self.file = file
    }

    let file: URL

    var key: Data {
        get throws {
            if FileManager.default.fileExists(atPath: file.path) {
                return try Data(contentsOf: file)
            } else {
                // generate, store and return new key
                let key: Curve25519.Signing.PrivateKey = .init()
                try key.rawRepresentation.write(to: file)
                return key.rawRepresentation
            }
        }
    }
}

