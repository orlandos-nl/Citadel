Citadel is a high level API around [NIOSSH](https://github.com/apple/swift-nio-ssh). It makes NIOSSH accessible and easy to adopt, while providing tools otherwise out-of-scope for NIOSSH.

Citadel is in active development by our team or Swift experts. Get in touch with our [Discord Community](https://discord.gg/H6799jh).

## Client Usage

Citadel's `SSHClient` needs a connection to a SSH server first:

```swift
let settings = SSHClientSettings(
    host: "example.com",
    authenticationMethod: { .passwordBased(username: "joannis", password: "s3cr3t") },
    // Please use another validator if at all possible, it's insecure
    // But it's an easy way to try out Citadel
    hostKeyValidator: .acceptAnything()
)
let client = try await SSHClient.connect(to: settings)
```

Using that client, we support a couple types of operations:

### Executing Commands

You can execute a command through SSH using the following code:

```swift
let stdout = try await client.executeCommand("ls -la ~")
```

Additionally, a maximum responsive response size can be set, and `stderr` can be merged with `stdout` so that the answer contains the content of both streams:

```swift
let stdoutAndStderr = try await client.executeCommand("ls -la ~", maxResponseSize: 42, mergeStreams: true)
```

The `executeCommand` function accumulated information into a contiguous `ByteBuffer`. This is useful for non-interactive commands such as `cat` and `ls`.

The `executeCommandPair` function or `executeCommandStream` function can be used to access `stdout` and `stderr` independently. Both functions also accumulate information into contiguous separate `ByteBuffers`.

An example of how executeCommandPair can be used:

```swift
let answer = try await client.executeCommandPair("cat /foo/bar.log")

for try await blob in answer.stdout {
    // do something with blob
}

for try await blob in answer.stderr {
    // do something with blob
}
```

An example of how executeCommandStream can be used:

```swift
let streams = try await client.executeCommandStream("cat /foo/bar.log")

for try await event in streams {
    switch event {
    case .stdout(let stdout):
        // do something with stdout
    case .stderr(let stderr):
        // do something with stderr
    }
}
```

Citadel currently  expose APIs for streaming into a process' `stdin`. only  withPTY and withTTY.

An example of how pty model can be used:

```swift
try await client.withPTY(
    SSHChannelRequestEvent.PseudoTerminalRequest(
        wantReply: true,
        term: "xterm",
        terminalCharacterWidth: 80,
        terminalRowHeight: 24,
        terminalPixelWidth: 0,
        terminalPixelHeight: 0,
        terminalModes: .init([.ECHO: 1])
    )
) { ttyOutput, ttyStdinWriter in
    // ...do something...
}
```

### Jump Hosts

Citadel supports jumping to another Host. First, connect to the jump host:

```swift
let jumpHostSettings = SSHClientSettings(
    host: "jump.example.com",
    authenticationMethod: .passwordBased(username: "joannis", password: "s3cr3t"),
    hostKeyValidator: .acceptAnything()
)
let jumpHostClient = try await SSHClient.connect(to: jumpHostSettings)
```

Then, jump to the target host:

```swift
let targetHostSettings = SSHClientSettings(
    host: "target.example.com",
    authenticationMethod: .passwordBased(username: "joannis", password: "s3cr3t"),
    hostKeyValidator: .acceptAnything()
)
let targetHostClient = try await jumpHostClient.jump(to: targetHostSettings)
```

You can chain multiple jumps this way as well.

### SFTP Client

To begin with SFTP, you must instantiate an SFTPClient based on your SSHClient:

```swift
// Open an SFTP session on the SSH client
let sftp = try await client.openSFTP()

// Get the current working directory
let cwd = try await sftp.getRealPath(atPath: ".")
//Obtain the real path of the directory eg "/opt/vulscan/.. -> /opt"
let truePath = try await sftp.getRealPath(atPath: "/opt/vulscan/..")
// List the contents of the /etc directory
let directoryContents = try await sftp.listDirectory(atPath: "/etc")

// Create a directory
try await sftp.createDirectory(atPath: "/etc/custom-folder")

// Write to a file (using a helper that cleans up the file automatically)
try await sftp.withFile(
    filePath: "/etc/resolv.conf",
    flags: [.read, .write, .forceCreate]
) { file in
    try await file.write(ByteBuffer(string: "Hello, world", at: 0))
}

// Read a file
let data = try await sftp.withFile(
    filePath: "/etc/resolv.conf",
    flags: .read
) { file in
    try await file.readAll()
}

// Close the SFTP session
try await sftp.close()
```

### TCP-IP Forwarding (Proxying)

```swift
// The address that is presented as the locally exposed interface
// This is purely communicated to the SSH server
let address = try SocketAddress(ipAddress: "fe80::1", port: 27017)
let configuredProxyChannel = try await client.createDirectTCPIPChannel(
    using: SSHChannelType.DirectTCPIP(
        targetHost: "localhost", // MongoDB host 
        targetPort: 27017, // MongoDB port
        originatorAddress: address
    )
) { proxyChannel in
  proxyChannel.pipeline.addHandlers(...)
}
```

This will create a channel that is connected to the SSH server, and then forwarded to the target host. This is useful for proxying TCP-IP connections, such as MongoDB, Redis, MySQL, etc.

## Servers

To use Citadel, first you need to create & start an SSH server, using your own authentication delegate:

```swift
import NIOSSH
import Citadel

// Create a custom authentication delegate that uses MongoDB to authenticate users
// This is just an example, you can use any database you want
// You can use public key authentication, password authentication, or both.
struct MyCustomMongoDBAuthDelegate: NIOSSHServerUserAuthenticationDelegate {
    let db: MongoKitten.Database

    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods = [.password, .publicKey]
    
    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
        responsePromise.completeWithTask {
            // Authenticate the user
            guard let user = try await db[User.self].findOne(matching: { user in
                user.$username == username
            }) else {
                // User does not exist
                return .failure
            }

            switch request.request {
            case .hostBased. none:
                // Not supported
                return .failure
            case .publicKey(let publicKey):
                // Check if the public key is correct
                guard publicKey.publicKey == user.publicKey else {
                    return .failure
                }

                return .success
            case .password(let request):
                // Uses Vapor's Bcrypt library to verify the password
                guard try Bcrypt.verify(request.password, created: user.password) else {
                    return .failure
                }
                
                return .success
            }
        }
    }
}
```

Then, create the server:

```swift
let server = try await SSHServer.host(
    host: "0.0.0.0",
    port: 22,
    hostKeys: [
        // This hostkey changes every app boot, it's more practical to use a pre-generated one
        NIOSSHPrivateKey(ed25519Key: .init())
    ],
    authenticationDelegate: MyCustomMongoDBAuthDelegate(db: mongokitten)
)
```

Then, enable the SFTP server or allow executing commands. Don't worry, these commands do not target the host system. You can implement filsystem and shell access yourself! So you get to dictate permissions, where it's actually stored, and do any shenanigans you need:

```swift
server.enableExec(withDelegate: MyExecDelegate())
server.enableSFTP(withDelegate: MySFTPDelegate())
```

If you're running the SSHServer from `main.swift` or an `@main` annotated type, make sure that Swift doesn't exit or `deinit` the server.
A simple solution that is applicable most of the time is to use the server's `closeFuture`.

```swift
try await server.closeFuture.get()
```

### Exec Server

When creating a command execution delegate, simply implement the `ExecDelegate` protocol and the following functions:

```swift
func setEnvironmentValue(_ value: String, forKey key: String) async throws
func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext
```

The `setEnvironmentValue` function adds an environment variable, which you can pass onto child processes. The `start` command simply executed the command "in the shell". How and if you process that command is up to you. The executed `command` is inputted as the first argument, and the second argument (the `ExecOutputHandler`), contains the authenticated user, Pipes for `stdin`, `stdout` and `stderr` as well as some function calls for indicating a process has exited.

Whether you simulate a process, or hook up a real child-process, the requirements are the same. You **must** provide an exit code or throw an error out of the executing function. You can also `fail` on the outputHandler the process using an error. Finally, you'll have to return an `ExecCommandContext` that represents your process. This can receive remote `terminate` signals, or receive a notification that `stdin` was closed through `inputClosed`.

```swift
import Foundation

/// A context that represents a process that is being executed.
/// This can receive remote `terminate` signals, or receive a notification that `stdin` was closed through `inputClosed`.
struct ExecProcessContext: ExecCommandContext {
    let process: Process
    
    func terminate() async throws {
        process.terminate()
    }
    
    func inputClosed() async throws {
        try process.stdin.close()
    }
}

/// An example of a custom ExecDelegate that uses bash as the shell to execute commands
public final class MyExecDelegate: ExecDelegate {
    var environment: [String: String] = [:]

    public func setEnvironmentValue(_ value: String, forKey key: String) async throws {
        // Set the environment variable
        environment[key] = value
    }

    public func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
        // Start the command
        let process = Process()

        // This uses bash as the shell to execute the command
        // You can use any shell you want, or even a custom one
        // This is just an example, you can do whatever you want
        // as long as you provide an exit code
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", command]
        process.environment = environment
        process.standardInput = outputHandler.stdin
        process.standardOutput = outputHandler.stdout
        process.standardError = outputHandler.stderr
        process.terminationHandler = { process in
            // Send the exit code
            outputHandler.exit(code: Int(process.terminationStatus))
        }

        // Start the process
        try process.run()
        return ExecProcessContext(process: process)
    }
}
```

### SFTP Servers

When you implement SFTP in Citadel, you're responsible for taking care of logistics. Be it through a backing MongoDB store, a real filesystem, or your S3 bucket.

## Helpers

The most important helper most people need is OpenSSH key parsing. We support extensions on PrivateKey types such as our own `Insecure.RSA.PrivateKey`, as well as existing SwiftCrypto types like `Curve25519.Signing.PrivateKey`:

```swift
// Parse an OpenSSH RSA private key. This is the same format as the one used by OpenSSH
let sshFile = try String(contentsOf: ..)
let privateKey = try Insecure.RSA.PrivateKey(sshRsa: sshFile)
```

## FAQ

If you can't connect to a server, it's likely that your server uses a deprecated set of algorithms that NIOSSH doesn't support. No worries though, as Citadel does implement these! Don't use these if you don't have to, as they're deprecated for good (security) reasons.

```swift
// Create a new set of algorithms
var algorithms = SSHAlgorithms()

algorithms.transportProtectionSchemes = .add([
    AES128CTR.self
])

algorithms.keyExchangeAlgorithms = .add([
    DiffieHellmanGroup14Sha1.self,
    DiffieHellmanGroup14Sha256.self
])
```

You can then use these in an SSHClient, together with any other potential protocol configuration options:

```swift
// Connect to the server using the new algorithms and a password-based authentication method
let client = try await SSHClient.connect(
    host: "example.com",
    authenticationMethod: .passwordBased(username: "joannis", password: "s3cr3t"),
    hostKeyValidator: .acceptAnything(), // Please use another validator if at all possible, it's insecure
    reconnect: .never,
    algorithms: algorithms,
    protocolOptions: [
        .maximumPacketSize(1 << 20)
    ]
)
```

You can also use `SSHAlgorithms.all` to enable all supported algorithms.

## TODO

A couple of code is held back until further work in SwiftNIO SSH is completed. We're currently working with Apple to resolve these.

- [ ] RSA Authentication (implemented & supported, but in a [fork of NIOSSH](https://github.com/Joannis/swift-nio-ssh-1/pull/1))

## Contributing

I'm happy to accept ideas and PRs for new API's.
