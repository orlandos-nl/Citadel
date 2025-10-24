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
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await client.withRemotePortForward(
                    host: "127.0.0.1",
                    port: 0 // Let server choose port
                ) { forward in
                    XCTAssertGreaterThan(forward.boundPort, 0, "Server should have bound to a port")
                    XCTAssertEqual(forward.host, "127.0.0.1")
                } handleChannel: { channel, forwardedInfo in
                    print("Received forwarded connection from \(forwardedInfo.originatorAddress)")

                    // Just close the channel for this test
                    return channel.close()
                }
            }

            try await Task.sleep(for: .seconds(1))
            group.cancelAll()
        }
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

        // TODO: Confirmation from swift-testing
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<3 {
                group.addTask {
                    try await client.withRemotePortForward(
                        host: "127.0.0.1",
                        port: 0
                    ) { forward in
                        XCTAssertGreaterThan(forward.boundPort, 0, "Server should have bound to a port")
                        XCTAssertEqual(forward.host, "127.0.0.1")
                    } handleChannel: { channel, forwardedInfo in
                        print("Received forwarded connection from \(forwardedInfo.originatorAddress)")

                        // Just close the channel for this test
                        return channel.close()
                    }
                }
            }

            try await Task.sleep(for: .seconds(1))
            group.cancelAll()
        }
    }

    /// Test that the SSHRemotePortForward struct works correctly
    func testSSHRemotePortForwardStruct() {
        let forward = SSHRemotePortForward(host: "0.0.0.0", boundPort: 8080)

        XCTAssertEqual(forward.host, "0.0.0.0")
        XCTAssertEqual(forward.boundPort, 8080)
    }
}
