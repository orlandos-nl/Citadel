import NIO
import XCTest
@testable import Citadel

/// Round-trip tests for `SSH_FXP_EXTENDED` / `SSH_FXP_EXTENDED_REPLY` through the real
/// serializer and parser, using `EmbeddedChannel` — no server required.
final class SFTPExtendedMessageTests: XCTestCase {
    private func roundTrip(_ message: SFTPMessage) throws -> (wire: ByteBuffer, parsed: SFTPMessage) {
        let outbound = EmbeddedChannel(handler: MessageToByteHandler(SFTPMessageSerializer()))
        try outbound.writeOutbound(message)
        let wire = try XCTUnwrap(try outbound.readOutbound(as: ByteBuffer.self))

        let inbound = EmbeddedChannel(handler: ByteToMessageHandler(SFTPMessageParser()))
        try inbound.writeInbound(wire)
        let parsed = try XCTUnwrap(try inbound.readInbound(as: SFTPMessage.self))
        return (wire, parsed)
    }

    func testExtendedRequestRoundTripsThroughSerializerAndParser() throws {
        var payload = ByteBufferAllocator().buffer(capacity: 64)
        for path in ["/a/old.txt", "/a/new.txt"] {
            payload.writeInteger(UInt32(path.utf8.count))
            payload.writeString(path)
        }

        let sent = SFTPMessage.Extended(requestId: 3, name: "posix-rename@openssh.com", payload: payload)
        let (wire, parsed) = try roundTrip(.extended(sent))

        // Wire format: uint32 length · byte 200 (SSH_FXP_EXTENDED) · uint32 request-id · string name · data
        XCTAssertEqual(wire.getInteger(at: wire.readerIndex, as: UInt32.self), UInt32(wire.readableBytes - 4))
        XCTAssertEqual(wire.getInteger(at: wire.readerIndex + 4, as: UInt8.self), SFTPMessageType.extended.rawValue)

        guard case .extended(let received) = parsed else {
            return XCTFail("parsed as \(parsed.debugDescription), expected .extended")
        }
        XCTAssertEqual(received.requestId, sent.requestId)
        XCTAssertEqual(received.name, sent.name)
        XCTAssertEqual(received.payload, payload)
    }

    func testExtendedReplyRoundTripsThroughSerializerAndParser() throws {
        var payload = ByteBufferAllocator().buffer(capacity: 16)
        payload.writeInteger(UInt64(4096)) // e.g. the first field of a statvfs@openssh.com reply
        payload.writeInteger(UInt64(1024))

        let sent = SFTPMessage.ExtendedReply(requestId: 7, payload: payload)
        let (wire, parsed) = try roundTrip(.extendedReply(sent))

        XCTAssertEqual(wire.getInteger(at: wire.readerIndex + 4, as: UInt8.self), SFTPMessageType.extendedReply.rawValue)

        guard case .extendedReply(let received) = parsed else {
            return XCTFail("parsed as \(parsed.debugDescription), expected .extendedReply")
        }
        XCTAssertEqual(received.requestId, sent.requestId)
        XCTAssertEqual(received.payload, payload)
    }

    func testExtendedRequestWithEmptyPayloadRoundTrips() throws {
        let sent = SFTPMessage.Extended(requestId: 9, name: "fsync@openssh.com", payload: ByteBuffer())
        let (_, parsed) = try roundTrip(.extended(sent))

        guard case .extended(let received) = parsed else {
            return XCTFail("parsed as \(parsed.debugDescription), expected .extended")
        }
        XCTAssertEqual(received.requestId, 9)
        XCTAssertEqual(received.name, "fsync@openssh.com")
        XCTAssertEqual(received.payload.readableBytes, 0)
    }
}
