import Citadel
import NIO
import NIOSSH
import XCTest

final class CustomAuthenticationDelegateTests: XCTestCase {
    /// Turns down the first password it sees and accepts the second, like a server would when a
    /// client works through a list of credentials.
    private final class SecondPasswordWins: NIOSSHServerUserAuthenticationDelegate, @unchecked Sendable {
        let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = .password
        private var seen = 0

        func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
            seen += 1
            responsePromise.succeed(seen >= 2 ? .success : .failure)
        }
    }

    /// Offers two passwords in turn. NIOSSH asks after each rejection, so the second one is only
    /// ever sent if Citadel passes that second call through.
    private final class TwoPasswords: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
        private var remaining = ["wrong", "right"]
        private(set) var timesAsked = 0

        func nextAuthenticationType(
            availableMethods: NIOSSHAvailableUserAuthenticationMethods,
            nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
        ) {
            timesAsked += 1
            guard !remaining.isEmpty else {
                nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
                return
            }
            nextChallengePromise.succeed(.init(
                username: "test",
                serviceName: "",
                offer: .password(.init(password: remaining.removeFirst()))
            ))
        }
    }

    func testCustomDelegateIsAskedAgainAfterARejectedOffer() async throws {
        let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
        let server = try await SSHServer.host(
            host: "127.0.0.1",
            port: 2346,
            hostKeys: [hostKey],
            authenticationDelegate: SecondPasswordWins()
        )
        defer { Task { try await server.close() } }

        let delegate = TwoPasswords()
        let client = try await SSHClient.connect(
            host: "127.0.0.1",
            port: 2346,
            authenticationMethod: .custom(delegate),
            hostKeyValidator: .trustedKeys([hostKey.publicKey]),
            reconnect: .never
        )

        XCTAssertTrue(client.isConnected, "The second password should have got us in")
        XCTAssertEqual(delegate.timesAsked, 2)
        try await client.close()
    }
}
