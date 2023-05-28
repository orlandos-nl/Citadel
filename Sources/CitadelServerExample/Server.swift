import Citadel
import NIO
import NIOSSH

@main struct ExampleSSHServer {
    static func main() async throws {
        let server = try await SSHServer.host(
            host: "localhost",
            port: 2222,
            hostKeys: [
                .init(p521Key: .init())
            ],
            authenticationDelegate: LoginHandler(username: "joannis", password: "test")
        )
        
        server.enableShell(withDelegate: EchoShell())
        
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

// Simply prints out what the user it typing
// Without this, the user wouldn't see their own input
public struct EchoShell: ShellDelegate {
    public func startShell(
        reading stream: AsyncStream<ShellClientEvent>,
        context: SSHContext
    ) async throws -> AsyncThrowingStream<ShellServerEvent, Error> {
        AsyncThrowingStream { continuation in
            let message = "Hello \(context.username ?? "stranger")"
            continuation.yield(.stdout(ByteBuffer(string: message)))
            
            Task {
                for await message in stream {
                    if case .stdin(let message) = message {
                        var bytes = message.getBytes(at: message.readerIndex, length: message.readableBytes)!
                        var i = bytes.count
                        while i > 0 {
                            i -= 1
                            // Put LF in front of CR
                            if bytes[i] == 0x0d { // CR
                                bytes.insert(0x0a, at: i) // CL
                            }
                        }
                        
                        continuation.yield(.stdout(ByteBuffer(bytes: bytes)))
                    }
                }
                
                continuation.finish()
            }
        }
    }
}
