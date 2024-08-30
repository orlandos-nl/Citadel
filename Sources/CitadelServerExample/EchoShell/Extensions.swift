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

extension Date {   
    func getDateFormattedBy(_ format: String, utc: Bool = true) -> String {
        let dateformat = DateFormatter()
        if utc {
            dateformat.timeZone = TimeZone(identifier: "UTC")
        }
        dateformat.dateFormat = format
        return dateformat.string(from: self)
    }
}
