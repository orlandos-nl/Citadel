@testable import Citadel
import Crypto
import NIO
import NIOConcurrencyHelpers
import NIOEmbedded
@preconcurrency import NIOSSH
import XCTest

final class CancellationHookTests: XCTestCase {
    func testClosingChannelFailsPendingHandshakeWithoutAdvancingTimeout() throws {
        let loop = EmbeddedEventLoop()
        let handshake = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        let channel = EmbeddedChannel(handler: handshake, loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 22)).wait()
        var result: Result<Void, Error>?
        handshake.authenticated.whenComplete { result = $0 }

        try channel.close().wait()
        // EmbeddedChannel completes closeFuture on the next loop turn.
        loop.run()

        guard case .failure(let error)? = result else {
            return XCTFail("Closing the socket must finish authentication before its timer fires")
        }
        XCTAssertEqual(error as? ChannelError, .ioOnClosedChannel)
        loop.advanceTime(by: .seconds(10))
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    func testAuthenticatedHandshakeRemainsSuccessfulAfterCloseAndTimeout() throws {
        let loop = EmbeddedEventLoop()
        let handshake = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        let channel = EmbeddedChannel(handler: handshake, loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 22)).wait()
        channel.pipeline.fireUserInboundEventTriggered(UserAuthSuccessEvent())
        try channel.close().wait()
        loop.advanceTime(by: .seconds(10))
        XCTAssertNoThrow(try handshake.authenticated.wait())
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    func testHandshakeErrorIsPreservedWhenChannelCloses() throws {
        struct Rejected: Error {}
        let loop = EmbeddedEventLoop()
        let handshake = ClientHandshakeHandler(eventLoop: loop, loginTimeout: .seconds(10))
        let channel = EmbeddedChannel(handler: handshake, loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 22)).wait()
        channel.pipeline.fireErrorCaught(Rejected())
        try channel.close().wait()
        loop.advanceTime(by: .seconds(10))
        XCTAssertThrowsError(try handshake.authenticated.wait()) { XCTAssertTrue($0 is Rejected) }
        _ = try channel.finish(acceptAlreadyClosed: true)
    }

    func testDirectHookCanCloseImmediatelyBeforeAuthentication() async throws {
        let fixture = try await makeHookTestServer()
        let hooked = expectation(description: "Socket exposed on its event loop")
        var settings = fixture.settings
        settings.onChannelCreated = { channel in
            XCTAssertTrue(channel.eventLoop.inEventLoop)
            XCTAssertFalse(channel.isActive)
            channel.close(promise: nil)
            hooked.fulfill()
        }

        do {
            let client = try await SSHClient.connect(to: settings)
            XCTFail("An immediately closed socket must not authenticate")
            try? await client.close()
        } catch { }
        await fulfillment(of: [hooked], timeout: 1)
        // Constructing an authentication method is allowed; the server must not receive an offer.
        XCTAssertEqual(fixture.authenticationRequests.withLockedValue { $0 }, 0)
    }

    func testClosingSilentHandshakeSocketReturnsPromptly() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        addTeardownBlock { try await group.shutdownGracefully() }
        let accepted = NIOLockedValueBox<Channel?>(nil)
        let server = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                accepted.withLockedValue { $0 = channel }
                return channel.eventLoop.makeSucceededVoidFuture()
            }.bind(host: "127.0.0.1", port: 0).get()
        addTeardownBlock {
            try? await accepted.withLockedValue { $0 }?.close()
            try await server.close()
        }
        let channelBox = NIOLockedValueBox<Channel?>(nil)
        var settings = hookTestSettings(port: try XCTUnwrap(server.localAddress?.port))
        settings.group = group
        settings.onChannelCreated = { channel in
            XCTAssertTrue(channel.eventLoop.inEventLoop)
            channelBox.withLockedValue { $0 = channel }
            channel.eventLoop.scheduleTask(in: .milliseconds(50)) { channel.close(promise: nil) }
        }
        let start = ContinuousClock.now
        do {
            let client = try await SSHClient.connect(to: settings)
            XCTFail("Silent server cannot authenticate")
            try? await client.close()
        } catch { }
        XCTAssertLessThan(start.duration(to: .now), .seconds(2))
        let channel = try XCTUnwrap(channelBox.withLockedValue { $0 })
        try await channel.closeFuture.get()
        XCTAssertFalse(channel.isActive)
    }

    func testJumpHookClosesSilentDestinationAndPreservesOuterConnection() async throws {
        try await assertJumpClosure(immediately: false)
    }

    func testJumpHookCanCloseImmediatelyAndPreservesOuterConnection() async throws {
        try await assertJumpClosure(immediately: true)
    }

    private func assertJumpClosure(immediately: Bool) async throws {
        struct SilentDestination: DirectTCPIPDelegate {
            func initializeDirectTCPIPChannel(_ channel: Channel, request: SSHChannelType.DirectTCPIP,
                                             context: SSHContext) -> EventLoopFuture<Void> {
                channel.eventLoop.makeSucceededVoidFuture()
            }
        }
        let fixture = try await makeHookTestServer()
        fixture.server.enableDirectTCPIP(withDelegate: SilentDestination())
        let client = try await SSHClient.connect(to: fixture.settings)
        addTeardownBlock { try? await client.close() }
        let hooked = expectation(description: "Forwarded channel exposed exactly once")
        hooked.assertForOverFulfill = true
        let callbackCount = NIOLockedValueBox(0)
        var destination = hookTestSettings(port: 22)
        destination.onChannelCreated = { channel in
            XCTAssertTrue(channel.eventLoop.inEventLoop)
            callbackCount.withLockedValue { $0 += 1 }
            if immediately {
                channel.close(promise: nil)
            } else {
                channel.eventLoop.scheduleTask(in: .milliseconds(50)) { channel.close(promise: nil) }
            }
            hooked.fulfill()
        }
        let start = ContinuousClock.now
        do {
            let nested = try await client.jump(to: destination)
            XCTFail("Silent destination cannot authenticate")
            try? await nested.close()
        } catch { }
        await fulfillment(of: [hooked], timeout: 1)
        XCTAssertLessThan(start.duration(to: .now), .seconds(2))
        XCTAssertTrue(client.isConnected)
        let next = try await client.createDirectTCPIPChannel(using: .init(
            targetHost: "127.0.0.1", targetPort: 22,
            originatorAddress: SocketAddress(ipAddress: "127.0.0.1", port: 0)
        )) { channel in channel.eventLoop.makeSucceededVoidFuture() }
        XCTAssertTrue(next.isActive)
        try await next.close()
        XCTAssertEqual(callbackCount.withLockedValue { $0 }, 1)
    }
}

func hookTestSettings(port: Int) -> SSHClientSettings {
    SSHClientSettings(host: "127.0.0.1", port: port,
                      authenticationMethod: { .passwordBased(username: "citadel", password: "test") },
                      hostKeyValidator: .acceptAnything())
}

struct HookTestServer {
    let server: SSHServer
    let settings: SSHClientSettings
    let authenticationRequests: NIOLockedValueBox<Int>
}

extension XCTestCase {
    func makeHookTestServer() async throws -> HookTestServer {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        addTeardownBlock { try await group.shutdownGracefully() }
        let authenticationRequests = NIOLockedValueBox(0)
        let auth = AuthDelegate(supportedAuthenticationMethods: .password) { request, promise in
            authenticationRequests.withLockedValue { $0 += 1 }
            if request.username == "citadel", case .password(.init(password: "test")) = request.request {
                promise.succeed(.success)
            } else {
                promise.succeed(.failure)
            }
        }
        let server = try await SSHServer.host(host: "127.0.0.1", port: 0,
                                             hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                                             authenticationDelegate: auth, group: group)
        addTeardownBlock { try await server.close() }
        var settings = hookTestSettings(port: try XCTUnwrap(server.channel.localAddress?.port))
        settings.group = group
        return HookTestServer(server: server, settings: settings, authenticationRequests: authenticationRequests)
    }
}
