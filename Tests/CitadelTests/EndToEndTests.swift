@testable import Citadel
import Crypto
import NIO
import NIOSSH
import XCTest

final class AuthDelegate: NIOSSHServerUserAuthenticationDelegate {
    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods
    var handle: @Sendable (NIOSSHUserAuthenticationRequest, EventLoopPromise<NIOSSHUserAuthenticationOutcome>) -> Void

    init(
        supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods,
        handle: @Sendable @escaping (NIOSSHUserAuthenticationRequest, EventLoopPromise<NIOSSHUserAuthenticationOutcome>) -> Void
    ) {
        self.supportedAuthenticationMethods = supportedAuthenticationMethods
        self.handle = handle
    }

    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
        handle(request, responsePromise)
    }
}

final class EndToEndTests: XCTestCase {
    func runTest<ExpectedError: Error & Equatable>(
        credentials: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        expectedError: ExpectedError
    ) async throws {
        try await runTest(
            credentials: credentials,
            hostKeyValidator: hostKeyValidator,
            perform: { _, _ in
                XCTFail("Should never get here")
            },
            matchingError: { error in
                guard let error = error as? ExpectedError else {
                    return false
                }

                return error == expectedError
            },
            expectsFailure: true
        )
    }

    func runTest(
        credentials: SSHAuthenticationMethod = .passwordBased(username: "citadel", password: "test"),
        hostKey: NIOSSHPrivateKey = .init(p521Key: .init()),
        hostKeyValidator: SSHHostKeyValidator = .acceptAnything(),
        perform: (SSHServer, SSHClient) async throws -> Void,
        matchingError matchError: (Error) -> Bool,
        expectsFailure: Bool
    ) async throws {
        let authDelegate = AuthDelegate(supportedAuthenticationMethods: .password) { request, promise in
            switch request.request {
            case .password(.init(password: "test")) where request.username == "citadel":
                promise.succeed(.success)
            default:
                promise.succeed(.failure)
            }
        }
        let server = try await SSHServer.host(
            host: "localhost",
            port: 2222,
            hostKeys: [
                hostKey
            ],
            authenticationDelegate: authDelegate
        )

        do {
            let client = try await SSHClient.connect(
                host: "localhost",
                port: 2222,
                authenticationMethod: credentials,
                hostKeyValidator: hostKeyValidator,
                reconnect: .never
            )

            if expectsFailure {
                XCTFail("Client was not supposed to connect successfully")
            } else {
                try await perform(server, client)
            }

            try await client.close()
        } catch {
            guard matchError(error) else {
                try await server.close()
                throw error
            }
        }

        try await server.close()
    }

    func testServerRejectsPassword() async throws {
        try await runTest(
            credentials: .passwordBased(
                username: "citadel",
                password: "wrong"
            ),
            hostKeyValidator: .acceptAnything(),
            expectedError: SSHClientError.allAuthenticationOptionsFailed
        )
    }

    func testServerRejectsUsername() async throws {
        try await runTest(
            credentials: .passwordBased(
                username: "citadel2",
                password: "test"
            ),
            hostKeyValidator: .acceptAnything(),
            expectedError: SSHClientError.allAuthenticationOptionsFailed
        )
    }

    func testClientRejectsHostKey() async throws {
        try await runTest(
            credentials: .passwordBased(
                username: "citadel",
                password: "test"
            ),
            hostKeyValidator: .trustedKeys([]),
            expectedError: InvalidHostKey()
        )
    }

    func testClientConnectsSuccessfully() async throws {
        try await runTest(
            perform: { _, _ in },
            matchingError: { _ in  false },
            expectsFailure: false
        )
    }

    func testClientRejectsWrongHostKey() async throws {
        let hostKey = NIOSSHPrivateKey(p521Key: .init())
        try await runTest(
            hostKey: hostKey,
            hostKeyValidator: .trustedKeys([
                hostKey.publicKey
            ]),
            perform: { _, _ in },
            matchingError: { _ in  false },
            expectsFailure: false
        )
    }

    func testSimpleSFTP() async throws {
        final class SFTP: SFTPDelegate {
            var didCreateDirectory = false
            func createDirectory(_ filePath: String, withAttributes: SFTPFileAttributes, context: SSHContext) async throws -> SFTPStatusCode {
                XCTAssertEqual(context.username, "citadel")
                XCTAssertEqual(filePath, "/test/citadel/sftp")
                didCreateDirectory = true
                return .ok
            }
        }

        try await runTest(
            perform: { server, client in
                let sftpServer = SFTP()
                server.enableSFTP(withDelegate: sftpServer)
                let sftp = try await client.openSFTP()
                try await sftp.createDirectory(atPath: "/test/citadel/sftp")
                XCTAssertTrue(sftpServer.didCreateDirectory)
            },
            matchingError: { _ in false },
            expectsFailure: false
        )
    }

    func testExecExitCode() async throws {
        final class Exec: ExecDelegate {
            struct CommandContext: ExecCommandContext {
                func terminate() async throws {
                    // Always fine
                }
            }

            var ranCommand = false
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                XCTAssertEqual(command, "ls")
                defer { ranCommand = true }

                if !ranCommand {
                    // First command always fails
                    outputHandler.succeed(exitCode: 1)
                } else {
                    // Successive commmands succeed
                    outputHandler.succeed(exitCode: 0)
                }

                return CommandContext()
            }
        }

        try await runTest(
            perform: { server, client in
                let execServer = Exec()
                server.enableExec(withDelegate: execServer)

                do {
                    _ = try await client.executeCommand("ls")
                    XCTFail("Shouldn't succeed on the first attempt")
                } catch let error as SSHClient.CommandFailed where error.exitCode == 1 {}

                XCTAssertTrue(execServer.ranCommand)

                _ = try await client.executeCommand("ls")
            },
            matchingError: { _ in false },
            expectsFailure: false
        )
    }
}

extension SFTPDelegate {
    func fileAttributes(atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPFileAttributes {
        throw ShouldNotGetHere()
    }

    func openFile(_ filePath: String, withAttributes: Citadel.SFTPFileAttributes, flags: Citadel.SFTPOpenFileFlags, context: Citadel.SSHContext) async throws -> Citadel.SFTPFileHandle {
        throw ShouldNotGetHere()
    }

    func removeFile(_ filePath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }

    func createDirectory(_ filePath: String, withAttributes: Citadel.SFTPFileAttributes, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }

    func removeDirectory(_ filePath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }

    func realPath(for canonicalUrl: String, context: Citadel.SSHContext) async throws -> [Citadel.SFTPPathComponent] {
        throw ShouldNotGetHere()
    }

    func openDirectory(atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPDirectoryHandle {
        throw ShouldNotGetHere()
    }

    func setFileAttributes(to attributes: Citadel.SFTPFileAttributes, atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }

    func addSymlink(linkPath: String, targetPath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }

    func readSymlink(atPath path: String, context: Citadel.SSHContext) async throws -> [Citadel.SFTPPathComponent] {
        throw ShouldNotGetHere()
    }

    func rename(oldPath: String, newPath: String, flags: UInt32, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
        throw ShouldNotGetHere()
    }
}

struct ShouldNotGetHere: Error {
    init() {
        XCTFail("Should not get here")
    }
}
