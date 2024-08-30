import Citadel
import Crypto
import Foundation
import NIO
import NIOFoundationCompat
import NIOSSH
import SwiftTUI

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
        
         server.enableShell(withDelegate: CustomAppShell())
        
        try await server.closeFuture.get()
    }
}

struct MyTerminalView: View {
    var body: some View {
        VStack {
            Text("Hello, world!")
                .background(.red)
                .foregroundColor(.white)
            
            Button("Click me") {
                print("clicked")
            }

            Button("Don't click") {
                print("Clicked anyways")
            }
        }
        .border()
    }
}

final class CustomAppShell: ShellDelegate {
     @MainActor public func startShell(
        inbound: AsyncStream<ShellClientEvent>,
        outbound: ShellOutboundWriter,
        context: SSHShellContext
    ) async throws {
        let app = Application(rootView: MyTerminalView()) { string in
            outbound.write(ByteBuffer(string: string))
        }

        await withTaskGroup(of: Void.self) { group in
            group.addTask { @MainActor in
                for await message in inbound {
                    if case .stdin(let input) = message {
                        app.handleInput(Data(buffer: input))
                    }
                }
            }
            group.addTask { @MainActor in
                for await windowSize in context.windowSize {
                    app.changeWindosSize(to: Size(
                        width: Extended(windowSize.columns),
                        height: Extended(windowSize.rows)
                    ))
                }
            }

            app.draw()
        }
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