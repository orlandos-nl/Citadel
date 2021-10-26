import Crypto
import BigInt
import NIO
import XCTest
@testable import Citadel
import NIOSSH

final class Citadel2Tests: XCTestCase {
    func testBigIntSerialization() {
        var buffer = ByteBuffer()
        var bigInt = BigUInt.randomInteger(lessThan: 100_000_000_000)
        
        buffer.writePositiveMPInt(bigInt.serialize())
        XCTAssertEqual(buffer.readerIndex, 0)
        var sameBigInt = buffer.readPositiveMPInt()!
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(bigInt, sameBigInt)
        
        bigInt = 0x80
        
        buffer.writePositiveMPInt(bigInt.serialize())
        XCTAssertNotEqual(buffer.readerIndex, 0)
        sameBigInt = buffer.readPositiveMPInt()!
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(bigInt, sameBigInt)
    }
    
    func testTTY() async throws {
        let client = try await SSHClient.connect(
            host: "10.211.55.4",
            authenticationMethod: .passwordBased(username: "parallels", password: ""),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )
        
        var buffer = try await client.executeCommand("echo a")
        print(buffer.getString(at: 0, length: buffer.readableBytes)!)
        buffer = try await client.executeCommand("echo b")
        print(buffer.getString(at: 0, length: buffer.readableBytes)!)
        buffer = try await client.executeCommand("echo c")
        print(buffer.getString(at: 0, length: buffer.readableBytes)!)
    }
    
    func testMPInt() throws {
        do {
            var buffer = ByteBuffer()
            buffer.writeMPBignum(0)
            XCTAssertEqual(
                buffer.readBytes(length: buffer.readableBytes)!,
                [0,0,0,0]
            )
        }
        
        do {
            var buffer = ByteBuffer()
            buffer.writeMPBignum(BigUInt("9a378f9b2e332a7", radix: 16)!)
            XCTAssertEqual(
                buffer.readBytes(length: buffer.readableBytes)!,
                [00, 00, 00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
            )
        }
        
        do {
            var buffer = ByteBuffer()
            buffer.writeMPBignum(BigUInt("80", radix: 16)!)
            XCTAssertEqual(
                buffer.readBytes(length: buffer.readableBytes)!,
                [0x00, 0x00, 0x00, 0x02, 0x00, 0x80]
            )
        }
    }
  
    func testSFTP() async throws {
//        let rsa = try String(contentsOf: URL(string: "file:///Users/joannisorlandos/.ssh/id_rsa_group_14")!)
//        DiffieHellmanGroup14Sha1.ourKey = try Insecure.RSA.PrivateKey(sshRsa: rsa)
        
        NIOSSHAlgoritms.register(
            publicKey: Insecure.RSA.PublicKey.self,
            signature: Insecure.RSA.Signature.self
        )
        
        NIOSSHAlgoritms.register(transportProtectionScheme: AES256CTR.self)
        
        NIOSSHAlgoritms.register(keyExchangeAlgorithm: DiffieHellmanGroup14Sha1.self)
        
        let ssh = try await SSHClient.connect(
          host: "10.211.55.4",
          authenticationMethod: .passwordBased(username: "parallels", password: "Zeus@1290"),
          hostKeyValidator: .acceptAnything(), // It's easy, but you should put your hostkey signature in here
          reconnect: .never
        )
        
        do {
            let sftp = try await ssh.openSFTP()
            let file = try await sftp.openFile(filePath: ".bashrc", flags: .read)
            var data = try await file.readAll()
            print(data.readString(length: data.readableBytes)!)
        } catch let error as SFTPMessage.Status {
            print(error)
            XCTFail()
        } catch {
            XCTFail()
        }
    }

//    static var allTests = [
//        ("testBigIntSerialization", testBigIntSerialization),
//    ]
}
