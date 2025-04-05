import Crypto
import BigInt
import NIO
import XCTest
import Logging
import Citadel
import NIOSSH

final class Citadel2Tests: XCTestCase {
    func withDisconnectTest(perform: (SSHServer, SSHClient) async throws -> ()) async throws {
        struct AuthDelegate: NIOSSHServerUserAuthenticationDelegate {
            let password: String
            
            var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods {
                .password
            }
            
            func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
                switch request.request {
                case .password(.init(password: password)):
                    responsePromise.succeed(.success)
                default:
                    responsePromise.succeed(.failure)
                }
            }
        }
        
        actor CloseHelper {
            var isClosed = false
            
            func close() {
                isClosed = true
            }
        }
        
        let hostKey = NIOSSHPrivateKey(p521Key: .init())
        let password = UUID().uuidString
        
        let server = try await SSHServer.host(
            host: "0.0.0.0",
            port: 2345,
            hostKeys: [
                hostKey
            ],
            authenticationDelegate: AuthDelegate(password: password)
        )
        
        let client = try await SSHClient.connect(
            host: "127.0.0.1",
            port: 2345,
            authenticationMethod: .passwordBased(
                username: "test",
                password: password
            ),
            hostKeyValidator: .trustedKeys([hostKey.publicKey]),
            reconnect: .never
        )
        
        XCTAssertTrue(client.isConnected, "Client is not active")
        
        let helper = CloseHelper()
        client.onDisconnect {
            Task {
                await helper.close()
            }
        }
        
        // Make an exec call that's not handled
        _ = try? await client.executeCommand("test")
        
        try await perform(server, client)
        
        if #available(macOS 13, *) {
            try await Task.sleep(for: .seconds(1))
        } else {
            sleep(1)
        }
        
        let isClosed = await helper.isClosed
        XCTAssertTrue(isClosed, "Connection did not close")
    }
    
    func testOnDisconnectClient() async throws {
        try await withDisconnectTest { server, client in
            try await client.close()
        }
    }
    
    func testSFTPUpload() async throws {
        enum DelegateError: Error {
            case unsupported
        }
        
        final class TestData: @unchecked /* for testing */ Sendable {
            var allDataSent = ByteBuffer()
        }
        
        struct TestError: Error { }
        
        struct SFTPFile: SFTPFileHandle {
            func readFileAttributes() async throws -> Citadel.SFTPFileAttributes {
                return SFTPFileAttributes(size: .init(testData.allDataSent.readableBytes))
            }
            
            func setFileAttributes(to attributes: Citadel.SFTPFileAttributes) async throws {
                throw DelegateError.unsupported
            }
            
            func read(at offset: UInt64, length: UInt32) async throws -> NIOCore.ByteBuffer {
                throw DelegateError.unsupported
            }
            
            let testData: TestData
            
            func close() async throws -> SFTPStatusCode {
                .ok
            }
            
            func write(_ data: ByteBuffer, atOffset offset: UInt64) async throws -> SFTPStatusCode {
                testData.allDataSent.writeImmutableBuffer(data)
                return .ok
            }
        }
        
        struct SFTP: SFTPDelegate {
            func removeFile(_ filePath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
                .permissionDenied
            }
            
            func setFileAttributes(to attributes: Citadel.SFTPFileAttributes, atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
                throw DelegateError.unsupported
            }
            
            func addSymlink(linkPath: String, targetPath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
                throw DelegateError.unsupported
            }

            func rename(oldPath: String, newPath: String, flags: UInt32, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
                throw DelegateError.unsupported
            }

            func readSymlink(atPath path: String, context: Citadel.SSHContext) async throws -> [Citadel.SFTPPathComponent] {
                throw DelegateError.unsupported
            }
            
            func realPath(for canonicalUrl: String, context: Citadel.SSHContext) async throws -> [Citadel.SFTPPathComponent] {
                throw TestError()
            }
            
            func openDirectory(atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPDirectoryHandle {
                throw TestError()
            }
            
            func createDirectory(_ filePath: String, withAttributes: Citadel.SFTPFileAttributes, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
                .permissionDenied
            }
            
            func removeDirectory(_ filePath: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPStatusCode {
                .permissionDenied
            }
            
            let testData: TestData
            
            func fileAttributes(atPath path: String, context: Citadel.SSHContext) async throws -> Citadel.SFTPFileAttributes {
                .all
            }
            
            func openFile(_ filePath: String, withAttributes: Citadel.SFTPFileAttributes, flags: Citadel.SFTPOpenFileFlags, context: Citadel.SSHContext) async throws -> Citadel.SFTPFileHandle {
                SFTPFile(testData: testData)
            }
        }
        
        struct AuthDelegate: NIOSSHServerUserAuthenticationDelegate {
            let supportedKey: NIOSSHPublicKey
            
            let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = [.publicKey]
            
            func requestReceived(request: NIOSSH.NIOSSHUserAuthenticationRequest, responsePromise: NIOCore.EventLoopPromise<NIOSSH.NIOSSHUserAuthenticationOutcome>) {
                switch request.request {
                case .hostBased, .none, .password:
                    return responsePromise.succeed(.failure)
                case .publicKey(let key):
                    guard key.publicKey == supportedKey else {
                        return responsePromise.succeed(.failure)
                    }
                    
                    responsePromise.succeed(.success)
                }
            }
        }
        
        let clientKey = P521.Signing.PrivateKey()
        let clientPrivateKey = NIOSSHPrivateKey(p521Key: clientKey)
        let clientPublicKey = clientPrivateKey.publicKey
        let server = try await SSHServer.host(
            host: "0.0.0.0",
            port: 2222,
            hostKeys: [
                .init(p521Key: P521.Signing.PrivateKey())
            ],
            authenticationDelegate: AuthDelegate(supportedKey: clientPublicKey)
        )
        
        let testData = TestData()
        server.enableSFTP(withDelegate: SFTP(testData: testData))
        
        let client = try await SSHClient.connect(
            host: "127.0.0.1",
            port: 2222,
            authenticationMethod: SSHAuthenticationMethod.p521(
                username: "Joannis",
                privateKey: clientKey
            ),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )
        
        let sftp = try await client.openSFTP()
        let file = try await sftp.openFile(filePath: "/kaas", flags: [.create, .write])
        
        let start: UInt8 = 0x00
        let end: UInt8 = 0x05
        
        for i in start ..< end {
            try await file.write(ByteBuffer(repeating: i, count: 1000))
        }
        
        try await file.close()
        
        for i in start ..< end {
            guard testData.allDataSent.readBytes(length: 1000) == .init(repeating: i, count: 1000) else {
                return XCTFail()
            }
        }
        
        try await client.close()
        try await server.close()
    }
    
    func testRebex() async throws {
        let client = try await SSHClient.connect(
            host: "test.rebex.net",
            authenticationMethod: .passwordBased(username: "demo", password: "password"),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )
        
        let sftp = try await client.openSFTP()
        
        let file = try await sftp.openFile(filePath: "/readme.txt", flags: .read)
        var i = 0
        for _ in 0..<10 {
            _ = try await file.read(from: UInt64(i * 32_768), length: 32_768)
            i += 1
        }
        try await file.close()
    }

    func testConnectToOpenSSHServer() async throws {
        guard
            let host = ProcessInfo.processInfo.environment["SSH_HOST"],
            let _port = ProcessInfo.processInfo.environment["SSH_PORT"],
            let port = Int(_port),
            let username = ProcessInfo.processInfo.environment["SSH_USERNAME"],
            let password = ProcessInfo.processInfo.environment["SSH_PASSWORD"]
        else {
            throw XCTSkip()
        }

        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: .passwordBased(username: username, password: password),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )

        let output = try await client.executeCommand("ls /")
        XCTAssertFalse(String(buffer: output).isEmpty)

        try await client.close()
    }

    @available(macOS 15.0, *)
    func testStdinStream() async throws {
        guard
            let host = ProcessInfo.processInfo.environment["SSH_HOST"],
            let _port = ProcessInfo.processInfo.environment["SSH_PORT"],
            let port = Int(_port),
            let username = ProcessInfo.processInfo.environment["SSH_USERNAME"],
            let password = ProcessInfo.processInfo.environment["SSH_PASSWORD"]
        else {
            throw XCTSkip()
        }

        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: .passwordBased(username: username, password: password),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )

        try await client.withTTY { inbound, outbound in
            try await outbound.write(ByteBuffer(string: "cat"))
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    var a = UInt8(ascii: "a")
                    for try await value in inbound {
                        switch value {
                        case .stdout(let value):
                            for byte in value.readableBytesView {
                                XCTAssertEqual(byte, a)
                                a = a &+ 1
                            }
                        case .stderr(let value):
                            XCTFail("Unexpected stderr: \(String(buffer: value))")
                        }
                    }
                }

                group.addTask {
                    for i: UInt8 in UInt8(ascii: "a") ... UInt8(ascii: "z") {
                        let value = ByteBufferAllocator().buffer(integer: i)
                        try await outbound.write(value)
                    }
                }

                try await group.next()
                group.cancelAll()
            }
        }

        try await client.close()
    }
}
