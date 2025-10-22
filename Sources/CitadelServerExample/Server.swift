import Citadel
import Crypto
import Foundation
import NIO
import NIOSSH

@main struct ExampleSSHServer {
    static func main() async throws {
        let privateKey: Curve25519.Signing.PrivateKey
        let privateKeyURL = URL(fileURLWithPath: "./citadel_host_key_ed25519")

        // Read or create a private key
        if let file = try? Data(contentsOf: privateKeyURL) {
            // File exists, read it into a Curve25519 private key
            privateKey = try Curve25519.Signing.PrivateKey(sshEd25519: file)
        } else {
            // File does not exist, create a new Curve25519 private
            privateKey = Curve25519.Signing.PrivateKey()

            // Write the private key to a file
            try privateKey.makeSSHRepresentation().write(to: privateKeyURL, atomically: true, encoding: .utf8)
        }

        let server = try await SSHServer.host(
            host: "localhost",
            port: 2323,
            hostKeys: [
                NIOSSHPrivateKey(ed25519Key: privateKey)
            ],
            authenticationDelegate: LoginHandler(username: "joannis", password: "test")
        )

        server.enableShell(withDelegate: SimpleShell())

        // Enable remote port forwarding with high-level async API
        let forwardDelegate = AsyncRemotePortForwardDelegate(
            allowedHosts: ["0.0.0.0", "127.0.0.1"],
            allowedPorts: [8080, 8081, 8082, 9000]
        ) { channel, clientAddress in
            print("📥 Remote port forward connection from: \(clientAddress)")

            // Echo server example - read and write back
            try await channel.executeThenClose { inbound, outbound in
                var bytesProcessed: UInt64 = 0
                for try await data in inbound {
                    bytesProcessed += UInt64(data.readableBytes)
                    try await outbound.write(data)
                }
                print("✅ Connection closed - processed \(bytesProcessed) bytes")
            }
        }

        server.enableRemotePortForward(withDelegate: forwardDelegate)
        print("✨ SSH Server running on localhost:2323")
        print("   - Shell access enabled (username: joannis, password: test)")
        print("   - Remote port forwarding enabled (allowed ports: 8080-8082, 9000)")
        print("   - Example: ssh -R 8080:localhost:3000 joannis@localhost -p 2323")

        try await server.closeFuture.get()
    }
}

struct LoginHandler: NIOSSHServerUserAuthenticationDelegate {
    let username: String
    let password: String
    
    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods {
        .password
    }
    
    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        if case .password(.init(password: password)) = request.request, request.username == username {
            return responsePromise.succeed(.success)
        }
        
        return responsePromise.succeed(.failure)
    }
}