import Foundation
import XCTest
import Crypto
import Citadel
import NIO

/// OpenSSH ECDSA private keys (`ecdsa-sha2-nistp256/384/521`).
/// The keys below are throwaway vectors generated for this test only - they
/// authenticate nothing.
final class OpenSSHECDSAKeyTests: XCTestCase {

    private let p256 = """
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
            1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRa23aG4sj7RXI1VXqNqwCXZGQ5a3n1
            j2icmd6WIMJzb+0FtoItsxcUdaJQABwtol5ZyLaKHOerJ9QNehWmcpgrAAAAqJBMpbaQTK
            W2AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFrbdobiyPtFcjVV
            eo2rAJdkZDlrefWPaJyZ3pYgwnNv7QW2gi2zFxR1olAAHC2iXlnItooc56sn1A16FaZymC
            sAAAAhAK1VgLgn/t4/wOTbjuNL25bGRLoZGtTDwFUr+hRHMU8pAAAADGNpdGFkZWwtdGVz
            dAECAw==
            -----END OPENSSH PRIVATE KEY-----
            """

    private let p384 = """
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
            1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQQtlFE8HrVfmCyA5t51zcyPWadnAavt
            DzFk5GJ/KMbtGQ/8/Ok5zQjsd5AmW5InBvGXAGTmWJhBkGxYe+BIdYqNlBB4vYt6lmQ0/N
            nTZ3zmWzKxUOnCtrY7xkg92unClh4AAADYw1KteMNSrXgAAAATZWNkc2Etc2hhMi1uaXN0
            cDM4NAAAAAhuaXN0cDM4NAAAAGEELZRRPB61X5gsgObedc3Mj1mnZwGr7Q8xZORifyjG7R
            kP/PzpOc0I7HeQJluSJwbxlwBk5liYQZBsWHvgSHWKjZQQeL2LepZkNPzZ02d85lsysVDp
            wra2O8ZIPdrpwpYeAAAAMQCvBlbeS0zOSHzkhVB6pJtvP4fu5IW47X9JV3ZWECGca92Wvs
            I/tGt/OsD4Why7vpoAAAAMY2l0YWRlbC10ZXN0AQID
            -----END OPENSSH PRIVATE KEY-----
            """

    private let p521 = """
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
            1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQB/tGzj/x26TTy6Dk9ymbDfp00Q9i5
            odPRyHFqDTOJxNzzFw/iBScWD+P0zZLkx0m0S7wmlItqTdlslXCR3eaduzUA7VWn/h5xCf
            5ttxXDBlqf052/wtpxWQFLHv0twifC2ljfDDnOv3UhjEPfCueFORn6jTTDh7Poer6yKvsq
            rKX+JiEAAAEQjFvt5Yxb7eUAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
            AAAIUEAf7Rs4/8duk08ug5Pcpmw36dNEPYuaHT0chxag0zicTc8xcP4gUnFg/j9M2S5MdJ
            tEu8JpSLak3ZbJVwkd3mnbs1AO1Vp/4ecQn+bbcVwwZan9Odv8LacVkBSx79LcInwtpY3w
            w5zr91IYxD3wrnhTkZ+o00w4ez6Hq+sir7Kqyl/iYhAAAAQSbO0DyxJNZTPylT73uwR6Qj
            QNt34jP9zOav2aKCc5dpnkkACg4/z5XUg9axi6P6lv9J2mKMZHlluVNsyXLCPSBNAAAADG
            NpdGFkZWwtdGVzdAECAwQFBgc=
            -----END OPENSSH PRIVATE KEY-----
            """

    private let p256Locked = """
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDGhkt689
            5qHcM0rltyy4bnAAAAGAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
            dHAyNTYAAABBBB5CxY1tcGOyNL/gJKttACXoybs8c1VFF5bF5VPKl14tNstUJ8xkaruXWT
            Lm5PPLKZGZGWbMv6NGeHDhmaOwQyoAAACw0hANbe8ThqU0EbyqJIobErDaSUEdCWgsr4nN
            h+uRpvedQECYZx7EZ7aPgAMEbeKOYSCLV7cwYamlgsxMFskPeWCe8oGbqE1PuQQl1VxmME
            w2RcuKsL3RlL+UI9OOk9gfu4D6F34+phQQZ0jWDgIOcEVMU5l+n4wwjCVs8AGmpLvNapbV
            A0kIiPg5IlL5kD7cGrDkHG+HFIXFtYbSB8lT/xdEilZIcrxN/fzO69GD4LQ=
            -----END OPENSSH PRIVATE KEY-----
            """


    func testParseP256() throws {
        let key = try P256.Signing.PrivateKey(sshP256: p256)
        XCTAssertEqual(key.publicKey.x963Representation.count, 65)
        // The parsed scalar must reproduce the point stored in the key file.
        XCTAssertEqual(Data(base64Encoded: "BFrbdobiyPtFcjVVeo2rAJdkZDlrefWPaJyZ3pYgwnNv7QW2gi2zFxR1olAAHC2iXlnItooc56sn1A16FaZymCs=")!, key.publicKey.x963Representation)
    }

    func testParseP384() throws {
        let key = try P384.Signing.PrivateKey(sshP384: p384)
        XCTAssertEqual(key.publicKey.x963Representation.count, 97)
    }

    func testParseP521() throws {
        let key = try P521.Signing.PrivateKey(sshP521: p521)
        XCTAssertEqual(key.publicKey.x963Representation.count, 133)
    }

    func testParseEncryptedP256() throws {
        let key = try P256.Signing.PrivateKey(
            sshP256: p256Locked, decryptionKey: Data("test-passphrase".utf8))
        XCTAssertEqual(key.publicKey.x963Representation.count, 65)
    }

    func testWrongPassphraseFails() {
        XCTAssertThrowsError(try P256.Signing.PrivateKey(
            sshP256: p256Locked, decryptionKey: Data("not-the-passphrase".utf8)))
    }

    func testCurveMismatchIsRejected() {
        // A P-384 key must not parse as P-256: the embedded curve name differs.
        XCTAssertThrowsError(try P256.Signing.PrivateKey(sshP256: p384))
    }

    func testSignatureRoundTripsAfterParsing() throws {
        let key = try P256.Signing.PrivateKey(sshP256: p256)
        let message = Data("the quick brown fox".utf8)
        let signature = try key.signature(for: message)
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: message))
    }
}
