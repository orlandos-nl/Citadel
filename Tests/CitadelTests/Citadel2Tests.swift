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

    static var allTests = [
        ("testBigIntSerialization", testBigIntSerialization),
    ]
}
