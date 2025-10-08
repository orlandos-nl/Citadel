@testable import Citadel
import Crypto
import NIO
import NIOSSH
import XCTest

final class RemotePortForwardTests: XCTestCase {
    /// Test that remote port forward request is sent correctly
    func testRemotePortForwardRequest() async throws {
        // This test requires an SSH server that supports remote port forwarding
        // Check if we have the environment variables set for SSH testing
        guard let host = ProcessInfo.processInfo.environment["SSH_HOST"],
              let portString = ProcessInfo.processInfo.environment["SSH_PORT"],
              let port = Int(portString),
              let username = ProcessInfo.processInfo.environment["SSH_USERNAME"],
              let password = ProcessInfo.processInfo.environment["SSH_PASSWORD"] else {
            throw XCTSkip("SSH environment variables not set (SSH_HOST, SSH_PORT, SSH_USERNAME, SSH_PASSWORD)")
        }

        print("Connecting to SSH server at \(host):\(port)...")

        // Connect to SSH server
        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: .passwordBased(username: username, password: password),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )

        defer {
            Task {
                try? await client.close()
            }
        }

        print("Connected. Requesting remote port forward...")

        // Request remote port forward on a random high port
        // Use port 0 to let the server choose
        let forward = try await client.createRemotePortForward(
            host: "127.0.0.1",
            port: 0  // Let server choose port
        ) { channel, forwardedInfo in
            print("Received forwarded connection from \(forwardedInfo.originatorAddress)")

            // Just close the channel for this test
            return channel.close()
        }

        print("Remote port forward established on port \(forward.boundPort)")

        XCTAssertGreaterThan(forward.boundPort, 0, "Server should have bound to a port")
        XCTAssertEqual(forward.host, "127.0.0.1")

        // Cancel the forward
        print("Canceling remote port forward...")
        try await client.cancelRemotePortForward(forward)
        print("Remote port forward canceled")

        // Note: We can't easily test if the handler is called without setting up
        // a way to connect to the remote port, which would require network access
        // from the test to the SSH server. This is typically done in integration tests.
    }

    /// Test that we can create and cancel multiple forwards
    func testMultipleRemotePortForwards() async throws {
        guard let host = ProcessInfo.processInfo.environment["SSH_HOST"],
              let portString = ProcessInfo.processInfo.environment["SSH_PORT"],
              let port = Int(portString),
              let username = ProcessInfo.processInfo.environment["SSH_USERNAME"],
              let password = ProcessInfo.processInfo.environment["SSH_PASSWORD"] else {
            throw XCTSkip("SSH environment variables not set")
        }

        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: .passwordBased(username: username, password: password),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )

        defer {
            Task {
                try? await client.close()
            }
        }

        // Create first forward
        let forward1 = try await client.createRemotePortForward(
            host: "127.0.0.1",
            port: 0
        ) { channel, _ in
            channel.close()
        }

        XCTAssertGreaterThan(forward1.boundPort, 0)
        print("First forward on port \(forward1.boundPort)")

        // Create second forward - this will replace the handler
        let forward2 = try await client.createRemotePortForward(
            host: "127.0.0.1",
            port: 0
        ) { channel, _ in
            channel.close()
        }

        XCTAssertGreaterThan(forward2.boundPort, 0)
        XCTAssertNotEqual(forward1.boundPort, forward2.boundPort, "Should bind to different ports")
        print("Second forward on port \(forward2.boundPort)")

        // Cancel both
        try await client.cancelRemotePortForward(forward1)
        try await client.cancelRemotePortForward(forward2)

        print("Both forwards canceled")
    }

    /// Test that the SSHRemotePortForward struct works correctly
    func testSSHRemotePortForwardStruct() {
        let forward = SSHRemotePortForward(host: "0.0.0.0", boundPort: 8080)

        XCTAssertEqual(forward.host, "0.0.0.0")
        XCTAssertEqual(forward.boundPort, 8080)
    }
}
