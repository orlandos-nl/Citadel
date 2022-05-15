import Crypto
import BigInt
import NIO
import XCTest
import Logging
//@testable import Citadel
import NIOSSH

final class Citadel2Tests: XCTestCase {
    override class func setUp() {
        XCTAssert(isLoggingConfigured)
    }
    
//    func testBigIntSerialization() {
//        var buffer = ByteBuffer()
//        var bigInt = BigUInt.randomInteger(lessThan: 100_000_000_000)
//
//        buffer.writePositiveMPInt(bigInt.serialize())
//        XCTAssertEqual(buffer.readerIndex, 0)
//        var sameBigInt = buffer.readPositiveMPInt()!
//        XCTAssertEqual(buffer.readableBytes, 0)
//        XCTAssertEqual(bigInt, sameBigInt)
//
//        bigInt = 0x80
//
//        buffer.writePositiveMPInt(bigInt.serialize())
//        XCTAssertNotEqual(buffer.readerIndex, 0)
//        sameBigInt = buffer.readPositiveMPInt()!
//        XCTAssertEqual(buffer.readableBytes, 0)
//        XCTAssertEqual(bigInt, sameBigInt)
//    }
//
//    func testTTY() async throws {
//        let client = try await SSHClient.connect(
//            host: "localhost",
//            authenticationMethod: .passwordBased(username: "sftp_test", password: ""),
//            hostKeyValidator: .acceptAnything(),
//            reconnect: .never
//        )
//
//        var buffer = try await client.executeCommand("echo a")
//        XCTAssertEqual(buffer.getString(at: 0, length: buffer.readableBytes)!, "a\n")
//        buffer = try await client.executeCommand("echo b")
//        XCTAssertEqual(buffer.getString(at: 0, length: buffer.readableBytes)!, "b\n")
//        buffer = try await client.executeCommand("echo c")
//        XCTAssertEqual(buffer.getString(at: 0, length: buffer.readableBytes)!, "c\n")
//    }
//
//    func testMPInt() throws {
//        do {
//            var buffer = ByteBuffer()
//            buffer.writeMPBignum(0)
//            XCTAssertEqual(
//                buffer.readBytes(length: buffer.readableBytes)!,
//                [0,0,0,0]
//            )
//        }
//
//        do {
//            var buffer = ByteBuffer()
//            buffer.writeMPBignum(BigUInt("9a378f9b2e332a7", radix: 16)!)
//            XCTAssertEqual(
//                buffer.readBytes(length: buffer.readableBytes)!,
//                [00, 00, 00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
//            )
//        }
//
//        do {
//            var buffer = ByteBuffer()
//            buffer.writeMPBignum(BigUInt("80", radix: 16)!)
//            XCTAssertEqual(
//                buffer.readBytes(length: buffer.readableBytes)!,
//                [0x00, 0x00, 0x00, 0x02, 0x00, 0x80]
//            )
//        }
//    }
//  
//    func testSFTP() async throws {
////        let rsa = try String(contentsOf: URL(string: "file:///Users/joannisorlandos/.ssh/id_rsa_group_14")!)
////        DiffieHellmanGroup14Sha1.ourKey = try Insecure.RSA.PrivateKey(sshRsa: rsa)
//        
//        NIOSSHAlgorithms.register(
//            publicKey: Insecure.RSA.PublicKey.self,
//            signature: Insecure.RSA.Signature.self
//        )
//        
//        NIOSSHAlgorithms.register(transportProtectionScheme: AES128CTR.self)
//        NIOSSHAlgorithms.register(keyExchangeAlgorithm: DiffieHellmanGroup14Sha1.self)
//        
//        let ssh = try await SSHClient.connect(
//          host: "localhost",
//          authenticationMethod: .passwordBased(username: "sftp_test", password: ""),
//          hostKeyValidator: .acceptAnything(), // It's easy, but you should put your hostkey signature in here
//          reconnect: .never
//        )
//        let sftp = try await ssh.openSFTP(logger: .init(label: "sftp.test"))
//        let tmpfile = "/tmp/sftp_test_\(UUID().uuidString)"
//        try await sftp.withFile(filePath: tmpfile, flags: [.create, .write, .truncate]) {
//            try await $0.write(.init(data: "hello world".data(using: .utf8)!))
//        }
//        try await sftp.withFile(filePath: tmpfile, flags: [.read]) {
//            let data = try await $0.readAll()
//            XCTAssertEqual(String(decoding: data.readableBytesView, as: UTF8.self), "hello world")
//        }
//    }
}

let isLoggingConfigured: Bool = {
    LoggingSystem.bootstrap { label in
        var handler = StreamLogHandler.standardOutput(label: label)
        handler.logLevel = ProcessInfo.processInfo.environment["LOG_LEVEL"].flatMap { Logger.Level(rawValue: $0) } ?? .debug
        return handler
    }
    return true
}()
