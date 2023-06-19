import Citadel
import NIO
import NIOSSH

@main struct ExampleSSHServer {
    static func main() async throws {
        let server = try await SSHServer.host(
            host: "localhost",
            port: 2222,
            hostKeys: [
                // .init(p521Key: .init())
                .init() // inits a host key file
            ],
            authenticationDelegate: LoginHandler(username: "joannis", password: "test")
        )
        
         server.enableShell(withDelegate: EchoShell())
        // server.enableShell(withDelegate: TTYShell())
        
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
public struct TTYShell: ShellDelegate {
    public func startShell(
        reading stream: AsyncStream<ShellClientEvent>,
        context: SSHShellContext
    ) async throws -> AsyncThrowingStream<ShellServerEvent, Error> {
        AsyncThrowingStream { continuation in
            let message = "Hello \(context.session.username ?? "stranger")"
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

// Simple shell emulator that returns the user input and offers some basic commands like: help, history, clear, whoami, date and exit.
public struct EchoShell: ShellDelegate {
    public func startShell(reading stream: AsyncStream<ShellClientEvent>,
                           context: SSHShellContext
    ) async throws -> AsyncThrowingStream<ShellServerEvent, Error> {
        AsyncThrowingStream { continuation in
            Task {
                // embedd the EchoShell
                let shell = EchoShellMaster(continuation: continuation,
                                            context: context)
                shell.set_usr(context.session.username)

                for await message in stream {
                    if case .stdin(let input) = message {
                        let bytes = input.getBytes(at: input.readerIndex, length: input.readableBytes)!
                        try await shell.write_input(bytes)
                    }

                    if context.isClosed || Task.isCancelled {
                        break
                    }
                }
                continuation.finish()
            }
        }
    }
}
