import NIO
import NIOSSH
import XCTest
@testable import Citadel

/// What an SFTP server can make the client buffer or loop on. Everything here is scripted on the
/// server side so the client's limits are what's under test.
final class SFTPInputBoundsTests: XCTestCase {

    // MARK: - Packet parser

    private func feed(_ bytes: [UInt8]) throws -> SFTPMessage? {
        let channel = EmbeddedChannel(handler: ByteToMessageHandler(SFTPMessageParser()))
        defer { _ = try? channel.finish() }
        try channel.writeInbound(ByteBuffer(bytes: bytes))
        return try channel.readInbound(as: SFTPMessage.self)
    }

    /// `uint32 length, byte type, payload`; the length counts the type byte.
    private func packet(type: UInt8, payload: [UInt8]) -> [UInt8] {
        let length = UInt32(1 + payload.count)
        return [UInt8(length >> 24), UInt8((length >> 16) & 0xff), UInt8((length >> 8) & 0xff), UInt8(length & 0xff), type] + payload
    }

    func testParserDecodesAWellFormedVersionPacket() throws {
        let message = try feed(packet(type: 2, payload: [0, 0, 0, 3]))
        guard case .version = message else {
            return XCTFail("Expected a version message, got \(String(describing: message))")
        }
    }

    func testParserRejectsAZeroLengthInsteadOfWaitingForever() {
        XCTAssertThrowsError(try feed([0, 0, 0, 0, 2])) { error in
            guard case SFTPError.invalidPacketLength(0) = error else {
                return XCTFail("Unexpected error \(error)")
            }
        }
    }

    func testParserRejectsAnAbsurdLengthInsteadOfBufferingTowardsIt() {
        // 4 GiB declared, a few bytes delivered: without a cap the decoder just keeps asking for more.
        XCTAssertThrowsError(try feed([0xff, 0xff, 0xff, 0xff, 104, 0, 0, 0, 1])) { error in
            guard case SFTPError.invalidPacketLength = error else {
                return XCTFail("Unexpected error \(error)")
            }
        }
    }

    // MARK: - Listing loops

    private struct AcceptAnyPassword: NIOSSHServerUserAuthenticationDelegate {
        let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = .password
        func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
            responsePromise.succeed(.success)
        }
    }

    private struct ScriptedSFTP: SFTPDelegate {
        enum Behaviour {
            /// Every realpath answer differs from the question.
            case realPathNeverSettles
            /// A directory with this many entries, one per readdir reply.
            case directoryEntries(Int)
        }
        let behaviour: Behaviour

        struct Listing: SFTPDirectoryHandle {
            let count: Int
            func listFiles(context: SSHContext) async throws -> [SFTPFileListing] {
                (0..<count).map { SFTPFileListing(path: [component("file-\($0)")]) }
            }
        }

        func realPath(for path: String, context: SSHContext) async throws -> [SFTPPathComponent] {
            switch behaviour {
            case .realPathNeverSettles: return [component(path + "/again")]
            case .directoryEntries: return [component(path)]
            }
        }

        func openDirectory(atPath path: String, context: SSHContext) async throws -> SFTPDirectoryHandle {
            guard case .directoryEntries(let count) = behaviour else { throw SFTPError.invalidResponse }
            return Listing(count: count)
        }
    }

    private static func component(_ name: String) -> SFTPPathComponent {
        SFTPPathComponent(filename: name, longname: name, attributes: .none)
    }

    private struct TimedOut: Error {}

    /// Opens an SFTP session against a scripted server on `port` and runs `body` with a time limit.
    /// A loop stuck awaiting the server can't be cancelled, so on timeout the connection is closed
    /// to make it fail.
    private func withScriptedSFTP<T: Sendable>(
        _ behaviour: ScriptedSFTP.Behaviour,
        port: Int,
        seconds: Double = 10,
        _ body: @escaping @Sendable (Citadel.SFTPClient) async throws -> T
    ) async throws -> T {
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let server = try await SSHServer.host(host: "127.0.0.1", port: port, hostKeys: [hostKey], authenticationDelegate: AcceptAnyPassword())
        server.enableSFTP(withDelegate: ScriptedSFTP(behaviour: behaviour))
        defer { Task { try await server.close() } }

        let client = try await SSHClient.connect(
            host: "127.0.0.1", port: port,
            authenticationMethod: .passwordBased(username: "test", password: "test"),
            hostKeyValidator: .trustedKeys([hostKey.publicKey]), reconnect: .never
        )
        defer { Task { try await client.close() } }
        let sftp = try await client.openSFTP()

        return try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await body(sftp) }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                try? await client.close()
                throw TimedOut()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    func testRealPathThatNeverSettlesIsGivenUpOn() async throws {
        do {
            _ = try await withScriptedSFTP(.realPathNeverSettles, port: 2347) { sftp in
                try await sftp.listDirectory(atPath: "/")
            }
            XCTFail("Expected the listing to be refused")
        } catch is TimedOut {
            XCTFail("The realpath loop never ended")
        } catch {
            // Any protocol error is the right outcome.
        }
    }

    func testDirectoryWithMoreEntriesThanAllowedIsRefused() async throws {
        do {
            _ = try await withScriptedSFTP(.directoryEntries(5), port: 2348) { sftp in
                try await sftp.listDirectory(atPath: "/", maximumEntries: 3)
            }
            XCTFail("Expected the listing to be refused")
        } catch SFTPError.directoryListingTooLarge(let limit) {
            XCTAssertEqual(limit, 3)
        }
    }

    func testDirectoryWithinTheLimitIsListedInFull() async throws {
        let names = try await withScriptedSFTP(.directoryEntries(3), port: 2349) { sftp in
            try await sftp.listDirectory(atPath: "/", maximumEntries: 3)
        }
        XCTAssertEqual(names.flatMap(\.components).map(\.filename), ["file-0", "file-1", "file-2"])
    }
}
