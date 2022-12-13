# Citadel

Citadel is a high level API around [NIOSSH](https://github.com/apple/swift-nio-ssh). It aims to add what's out of scope for NIOSSH, lending code from my private tools.

It features the following helpers:

- [x] TCP-IP forwarding child channels
- [x] Basic SFTP Client
- [x] SFTP Server
- [x] SSH Exec Command Server
- [x] TTY support
- [x] SSH Key format parsing

[Read the docs](https://orlandos.nl/docs/citadel)

## Client Usage

Citadel's `SSHClient` needs a connection to a SSH server first:

```swift
let client = try await SSHClient.connect(
    sshHost: "example.com",
    authenticationMethod: .passwordBased(username: "joannis", password: "s3cr3t"),
    hostKeyValidator: .acceptAnything(), // Please use another validator if at all possible, it's insecure
    reconnect: .never
)
```

Using that client, we support a couple types of operations:

### SSH Proxies

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

### Executing Commands

You can execute a command through SSH using the following code:

```swift
let stdout = try await client.executeCommand("ls -la ~")
```

The `executeCommand` function accumulated information into a contiguous `ByteBuffer`. This is useful for non-interactive commands such as `cat` and `ls`. Citadel currently does not expose APIs for streaming into a process' `stdin` or streaming the `stdout` elsewhere. If you want this, please create an issue.

### SFTP

To begin with SFTP, you must instantiate an SFTPClient based on your SSHClient:

```swift
let sftp = try await client.openSFTP()
```

From here, you can do a variety of filesystem operations:

**Listing a Directory's Contents:**

```swift
let directoryContents = try await sftp.listDirectory(atPath: "/etc")
```

**Creating a directory:**

```swift
try await sftp.createDirectory(atPath: "/etc/custom-folder")
```

**Opening a file:**

```swift
let resolv = try await sftp.openFile(filePath: "/etc/resolv.conf", flags: .read)
```

**Reading a file in bulk:**

```swift
let resolvContents: ByteBuffer = try await resolv.readAll()
```

**Reading a file in chunks:**

```swift
let chunk: ByteBuffer = try await resolv.read(from: index, length: maximumByteCount)
```

**Closing a file:**

```swift
try await resolv.close()
```

Note that this is required if you open the file yourself. If you want Citadel to manage closing the file, use:

```swift
let data = try await sftp.withFile(
    filePath: "/etc/resolv.conf",
    flags: .read
) { file in
    try await file.readAll()
}
```

**Writing to a file:**

```swift
let file = try await sftp.openFile(filePath: "/etc/resolv.conf", flags: [.read, .write, .forceCreate])
let fileWriterIndex = 0
try await file.write(ByteBuffer(string: "Hello, world", at: fileWriterIndex)
```

## Servers

To use Citadel, first you need to create & start an SSH server, using your own authentication delegate:

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

### Exec Server

When creating a command execution delegate, simply implement the `ExecDelegate` protocol and the following functions:

```swift
func setEnvironmentValue(_ value: String, forKey key: String) async throws
func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext
```

The `setEnvironmentValue` function adds an environment variable, which you can pass onto child processes. The `start` command simply executed the command "in the shell". How and if you process that command is up to you. The executed `command` is inputted as the first argument, and the second argument (the `ExecOutputHandler`), contains the authenticated user, Pipes for `stdin`, `stdout` and `stderr` as well as some function calls for indicating a process has exited.

Whether you simulate a process, or hook up a real child-process, the requirements are the same. You **must** provide an exit code or throw an error out of the exeucing function. You can also `fail` on the outputHandler the process using an error. Finally, you'll have to return an `ExecCommandContext` that represents your process. This can receive remote `terminate` signals, or receive a notification that `stdin` was closed through `inputClosed`.

### SFTP Server

When you implement SFTP in Citadel, you're responsible for taking care of logistics. Be it through a backing MongoDB store, a real filesystem, or your S3 bucket.

## Helpers

The most important helper most people need is OpenSSH key parsing. We support extensions on PrivateKey types such as our own `Insecure.RSA.PrivateKey`, as well as existing SwiftCrypto types like `Curve25519.Signing.PrivateKey`:

```swift
let sshFile = try String(contentsOf: ..)
let privateKey = try Insecure.RSA.PrivateKey(sshRsa: sshFile)
```

## FAQ

If you can't connect to a server, it's likely that your server uses a deprecated set of algorithms that NIOSSH doesn't support. No worries though, as Citadel does implement these! Don't use these if you don't have to, as they're deprecated for good (security) reasons.

```swift
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
let client = try await SSHClient.connect(
    sshHost: "example.com",
    authenticationMethod: .passwordBased(username: "joannis", password: "s3cr3t"),
    hostKeyValidator: .acceptAnything(), // Please use another validator if at all possible, it's insecure
    reconnect: .never,
    algorithms: algorithms,
    protocolOptions: [
        .maximumPacketSize(1 << 20)
    ]
)
```

## TODO

A couple of code is held back until further work in SwiftNIO SSH is completed. We're currently working with Apple to resolve these.

- [ ] RSA Authentication (implemented & supported, but in a [fork of NIOSSH](https://github.com/Joannis/swift-nio-ssh-1/pull/1))
- [ ] Much more documentation & tutorials

## Contributing

I'm happy to accept ideas and PRs for new API's.
