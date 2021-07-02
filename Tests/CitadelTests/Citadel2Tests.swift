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
  
    func testSFTP() throws {
        NIOSSHAlgoritms.register(
            publicKey: Insecure.RSA.PublicKey.self,
            signature: Insecure.RSA.Signature.self
        )
        
        NIOSSHAlgoritms.register(transportProtectionScheme: AES256CTR.self)
        
        NIOSSHAlgoritms.register(keyExchangeAlgorithm: DiffieHellmanGroup1Sha1.self)
        
//        HMAC<SHA1>
        
        let ssh = try SSHClient.connect(
          host: "xyz",
          authenticationMethod: .passwordBased(username: "joannis", password: "spoof"),
          hostKeyValidator: .acceptAnything(), // It's easy, but you should put your hostkey signature in here
          reconnect: .never
        ).wait()
        let sftp = try ssh.openSFTP().wait()
    }

//    static var allTests = [
//        ("testBigIntSerialization", testBigIntSerialization),
//    ]
}
