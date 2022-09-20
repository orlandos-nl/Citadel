import Crypto
import BigInt
import NIO
import XCTest
import Logging
import Citadel
import NIOSSH

final class Citadel2Tests: XCTestCase {
    func testSFTP() async throws {
        enum DelegateError: Error {
            case unsupported
        }
        
        final class TestData {
            var allDataSent = ByteBuffer()
        }
        
        struct SFTPFile: SFTPFileHandle {
            let testData: TestData
            
            func close(promise: EventLoopPromise<SFTPStatusCode>) {
                promise.succeed(.ok)
            }
            
            func write(_ data: ByteBuffer, atOffset offset: UInt64, promise: EventLoopPromise<SFTPStatusCode>) {
                testData.allDataSent.writeImmutableBuffer(data)
                promise.succeed(.ok)
            }
        }
        
        struct SFTP: SFTPDelegate {
            let testData: TestData
            
            func openFile(_ filePath: String, withAttributes: SFTPFileAttributes, flags: SFTPOpenFileFlags) async throws -> SFTPFileHandle {
                SFTPFile(testData: testData)
            }
            
            func fileAttributes(atPath path: String) async throws -> SFTPFileAttributes {
                .all
            }
        }
        
        struct AuthDelegate: NIOSSHServerUserAuthenticationDelegate {
            let supportedKey: NIOSSHPublicKey
            
            let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = [.publicKey]
            
            func requestReceived(request: NIOSSH.NIOSSHUserAuthenticationRequest, responsePromise: NIOCore.EventLoopPromise<NIOSSH.NIOSSHUserAuthenticationOutcome>) {
                switch request.request {
                case .hostBased, .none, .password:
                    return responsePromise.succeed(NIOSSHUserAuthenticationOutcome.failure)
                case .publicKey(let key):
                    guard key.publicKey == supportedKey else {
                        return responsePromise.succeed(NIOSSHUserAuthenticationOutcome.failure)
                    }
                    
                    responsePromise.succeed(NIOSSHUserAuthenticationOutcome.success)
                }
            }
        }
        
        let clientKey = P521.Signing.PrivateKey()
        let clientPrivateKey = NIOSSHPrivateKey(p521Key: clientKey)
        let clientPublicKey = clientPrivateKey.publicKey
        let server = try await SSHServer.host(
            host: "127.0.0.1",
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
        
        try await server.close()
    }
}
