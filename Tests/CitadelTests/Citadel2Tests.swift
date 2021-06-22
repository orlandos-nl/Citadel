import BigInt
import NIO
import XCTest
@testable import Citadel

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
        let ssh = try SSHClient.connect(
          host: "orlandos.nl",
          authenticationMethod: .passwordBased(username: "<user>", password: "<pass>"),
          hostKeyValidator: .acceptAnything(), // It's easy, but you should put your hostkey signature in here
          reconnect: .never
        ).wait()
        let sftp = try ssh.openSFTP().wait()
        let fileHandle = try sftp.openFile(filePath: "/home/<user>/test", flags: [.write, .create]).wait()
        try fileHandle.write(at: 0, data: ByteBuffer(string: "Hello")).wait()
    }

//    static var allTests = [
//        ("testBigIntSerialization", testBigIntSerialization),
//    ]
}
