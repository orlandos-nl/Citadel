import Citadel
import NIO
import NIOSSH
import Foundation
import ArgumentParser
import Crypto

/// Example demonstrating remote port forwarding (reverse tunneling)
///
/// This example shows how to:
/// 1. Connect to an SSH server
/// 2. Request the server to listen on a remote port
/// 3. Forward incoming connections to a local HTTP server
@main
struct RemotePortForwardExample: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "remote-forward",
        abstract: "Example demonstrating SSH remote port forwarding (reverse tunneling)",
        discussion: """
            This tool creates a reverse SSH tunnel, making a local service accessible through
            a remote SSH server. When someone connects to the remote server's forwarded port,
            the connection is tunneled back to your local machine.

            Example usage:
              1. Start a local HTTP server: python3 -m http.server 3000
              2. Run this example to forward remote port 8080 to local port 3000
              3. Connect to the remote server's port 8080 to access your local service
            """
    )

    @Option(name: .shortAndLong, help: "SSH server hostname or IP address")
    var host: String

    @Option(name: .shortAndLong, help: "SSH server port")
    var port: Int = 22

    @Option(name: .shortAndLong, help: "SSH username")
    var username: String

    @Option(name: .long, help: "SSH password (⚠️ consider using SSH keys instead)")
    var password: String?

    @Option(name: .long, help: "Path to SSH private key file")
    var privateKey: String?

    @Option(name: .long, help: "Remote host to bind to (0.0.0.0 for all interfaces, localhost for loopback only)")
    var remoteHost: String = "0.0.0.0"

    @Option(name: .long, help: "Remote port to listen on (0 = server chooses)")
    var remotePort: Int = 8080

    @Option(name: .long, help: "Local host to forward connections to")
    var localHost: String = "127.0.0.1"

    @Option(name: .long, help: "Local port to forward connections to")
    var localPort: Int = 3000

    @Flag(name: .long, help: "Accept any host key (⚠️ insecure, only for testing)")
    var insecure: Bool = false

    func run() async throws {
        // Validate authentication method
        guard password != nil || privateKey != nil else {
            throw ValidationError("Either --password or --private-key must be provided")
        }

        // Determine authentication method
        let authMethod: SSHAuthenticationMethod
        if let privateKeyPath = privateKey {
            print("🔑 Using private key authentication from \(privateKeyPath)")
            let keyData = try Data(contentsOf: URL(fileURLWithPath: privateKeyPath))
            let privateKey = try Insecure.RSA.PrivateKey(sshRsa: keyData)
            authMethod = .rsa(username: username, privateKey: privateKey)
        } else if let password = password {
            print("🔑 Using password authentication")
            authMethod = .passwordBased(username: username, password: password)
        } else {
            fatalError("Unreachable")
        }

        // Capture values for use in the handler closure
        let localHost = self.localHost
        let localPort = self.localPort

        // Validate host key validator
        let hostKeyValidator: SSHHostKeyValidator
        if insecure {
            print("⚠️  WARNING: Accepting any host key (insecure mode)")
            hostKeyValidator = .acceptAnything()
        } else {
            // In production, you would use proper host key validation
            print("⚠️  WARNING: Using accept-anything host key validator")
            print("   In production, use proper host key validation!")
            hostKeyValidator = .acceptAnything()
        }

        print("🔐 Connecting to SSH server at \(host):\(port) as \(username)...")

        // Connect to SSH server
        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: authMethod,
            hostKeyValidator: hostKeyValidator,
            reconnect: .never
        )

        defer {
            Task {
                try? await client.close()
            }
        }

        print("✅ Connected to SSH server")
        print("🌐 Requesting remote port forward on \(remoteHost):\(remotePort)...")
        print("   Will forward connections to \(localHost):\(localPort)")

        // This automatically handles bidirectional forwarding
        try await client.runRemotePortForward(
            host: remoteHost,
            port: remotePort,
            forwardingTo: localHost,
            port: localPort
        ) { forward in
            print("✅ Remote port forward established!")
            print("   Remote server is listening on \(forward.host):\(forward.boundPort)")
            print("   Forwarding connections to \(localHost):\(localPort)")
            print("")
            print("💡 To test:")
            print("   curl http://\(host):\(forward.boundPort)")
            print("")

            print("Press Ctrl+C to stop...")
        }

        // Keep the program running
        try await Task.sleep(nanoseconds: .max)
    }
}
