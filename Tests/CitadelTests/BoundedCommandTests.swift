@testable import Citadel
import NIO
import NIOConcurrencyHelpers
import NIOEmbedded
import NIOSSH
import XCTest

final class BoundedCommandTests: XCTestCase {
    func testStdoutOverflowClosesChannel() throws {
        try assertOverflow(stdout: "12345", stderr: "", limit: 4)
    }

    func testStderrOverflowClosesChannel() throws {
        try assertOverflow(stdout: "", stderr: "12345", limit: 4)
    }

    func testStdoutAndStderrShareOneLimit() throws {
        try assertOverflow(stdout: "123", stderr: "45", limit: 4)
    }

    func testZeroLimitRejectsFirstByte() throws {
        try assertOverflow(stdout: "x", stderr: "", limit: 0)
    }

    func testExactLimitReturnsStdout() throws {
        let loop = EmbeddedEventLoop()
        let done = loop.makePromise(of: ByteBuffer.self)
        let channel = EmbeddedChannel(handler: TTYHandler(maxResponseSize: 4, done: done), loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 22)).wait()
        _ = try channel.writeInbound(SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(string: "1234"))))
        XCTAssertTrue(channel.isActive)
        _ = try channel.finish(acceptAlreadyClosed: true)
        XCTAssertEqual(String(buffer: try done.futureResult.wait()), "1234")
    }

    func testExactCombinedLimitPreservesStderrError() throws {
        let loop = EmbeddedEventLoop()
        let done = loop.makePromise(of: ByteBuffer.self)
        let channel = EmbeddedChannel(handler: TTYHandler(maxResponseSize: 4, done: done), loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 22)).wait()
        _ = try channel.writeInbound(SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(string: "12"))))
        _ = try channel.writeInbound(SSHChannelData(type: .stdErr, data: .byteBuffer(ByteBuffer(string: "34"))))
        XCTAssertTrue(channel.isActive)
        _ = try channel.finish(acceptAlreadyClosed: true)
        XCTAssertThrowsError(try done.futureResult.wait()) { XCTAssertTrue($0 is TTYSTDError) }
    }

    func testClosingExecChildInHookPreventsCommandAndPreservesConnection() async throws {
        final class Exec: ExecDelegate, @unchecked Sendable {
            let commands = NIOLockedValueBox<[String]>([])
            struct Context: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                commands.withLockedValue { $0.append(command) }
                outputHandler.succeed(exitCode: 0)
                return Context()
            }
        }
        let fixture = try await makeHookTestServer()
        let exec = Exec()
        fixture.server.enableExec(withDelegate: exec)
        let client = try await SSHClient.connect(to: fixture.settings)
        addTeardownBlock { try? await client.close() }
        let hooked = expectation(description: "Exec child exposed before request")
        do {
            let cancelledOutput = try await client.executeBoundedCommand("must-not-run", maxResponseSize: 1024) { channel in
                XCTAssertTrue(channel.eventLoop.inEventLoop)
                channel.close(promise: nil)
                hooked.fulfill()
            }
            // Handler removal may complete an empty response before the failed exec request.
            // The caller translates intentional closure using its own cancellation state.
            XCTAssertEqual(cancelledOutput.readableBytes, 0)
        } catch { }
        await fulfillment(of: [hooked], timeout: 1)
        XCTAssertTrue(client.isConnected)
        let output = try await client.executeCommand("after-cancel", maxResponseSize: 1024)
        XCTAssertEqual(output.readableBytes, 0)
        XCTAssertEqual(exec.commands.withLockedValue { $0 }, ["after-cancel"])
    }

    private func assertOverflow(stdout: String, stderr: String, limit: Int,
                                file: StaticString = #filePath, line: UInt = #line) throws {
        let loop = EmbeddedEventLoop()
        let done = loop.makePromise(of: ByteBuffer.self)
        let channel = EmbeddedChannel(handler: TTYHandler(maxResponseSize: limit, done: done), loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 22)).wait()
        if !stdout.isEmpty {
            _ = try channel.writeInbound(SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(string: stdout))))
        }
        if !stderr.isEmpty {
            _ = try channel.writeInbound(SSHChannelData(type: .stdErr, data: .byteBuffer(ByteBuffer(string: stderr))))
        }
        XCTAssertFalse(channel.isActive, "Overflow must retire the exec child", file: file, line: line)
        XCTAssertThrowsError(try done.futureResult.wait(), file: file, line: line) {
            guard case CitadelError.commandOutputTooLarge = $0 else {
                return XCTFail("Expected output limit error, got \($0)", file: file, line: line)
            }
        }
        _ = try channel.finish(acceptAlreadyClosed: true)
    }
}
