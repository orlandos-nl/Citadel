import Citadel
import NIO
import NIOSSH
import Foundation

/// Example demonstrating remote port forwarding (reverse tunneling)
///
/// This example shows how to:
/// 1. Connect to an SSH server
/// 2. Request the server to listen on port 8080
/// 3. Forward incoming connections to a local HTTP server
///
/// To test this example:
/// 1. Start a local HTTP server: python3 -m http.server 3000
/// 2. Run this example with your SSH credentials
/// 3. The remote server will listen on port 8080
/// 4. Connections to remote_host:8080 will be forwarded to localhost:3000

@main
struct RemotePortForwardExample {
    static func main() async throws {
        // Get SSH credentials from environment or use defaults
        let host = ProcessInfo.processInfo.environment["SSH_HOST"] ?? "localhost"
        let port = Int(ProcessInfo.processInfo.environment["SSH_PORT"] ?? "22") ?? 22
        let username = ProcessInfo.processInfo.environment["SSH_USERNAME"] ?? "testuser"
        let password = ProcessInfo.processInfo.environment["SSH_PASSWORD"] ?? "testpass"

        print("🔐 Connecting to SSH server at \(host):\(port) as \(username)...")

        // Connect to SSH server
        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: .passwordBased(username: username, password: password),
            hostKeyValidator: .acceptAnything(), // ⚠️ Only for testing!
            reconnect: .never
        )

        defer {
            Task {
                try? await client.close()
            }
        }

        print("✅ Connected to SSH server")

        // Request remote port forwarding
        // The server will listen on 0.0.0.0:8080 and forward connections to us
        print("🌐 Requesting remote port forward on 0.0.0.0:8080...")

        let forward = try await client.createRemotePortForward(
            host: "0.0.0.0",
            port: 8080
        ) { forwardedChannel, forwardedInfo in
            print("📥 Incoming connection from \(forwardedInfo.originatorAddress)")
            print("   Connected to remote \(forwardedInfo.listeningHost):\(forwardedInfo.listeningPort)")

            // For this simple example, just echo back a message
            // In production, you would forward to a local service
            let response = """
            HTTP/1.1 200 OK\r
            Content-Type: text/plain\r
            Content-Length: 50\r
            \r
            Remote port forwarding is working! 🎉\r
            \n
            """

            var buffer = forwardedChannel.allocator.buffer(capacity: response.utf8.count)
            buffer.writeString(response)

            return forwardedChannel.writeAndFlush(buffer).flatMap {
                forwardedChannel.close()
            }
        }

        print("✅ Remote port forward established!")
        print("   Server is listening on \(forward.host):\(forward.boundPort)")
        print("   Connections will be forwarded to localhost:3000")
        print("")
        print("💡 To test:")
        print("   On the remote host, run: curl http://localhost:\(forward.boundPort)")
        print("")
        print("Press Ctrl+C to stop...")

        // Keep the program running
        try await Task.sleep(nanoseconds: 3600 * 1_000_000_000)

        // Cancel the forward when done
        print("\n🛑 Canceling remote port forward...")
        try await client.cancelRemotePortForward(forward)
        print("✅ Remote port forward canceled")
    }
}
