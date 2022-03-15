# Citadel

Citadel is a high level API around [NIOSSH](https://github.com/apple/swift-nio-ssh). It aims to add what's out of scope for NIOSSH, lending code from my private tools.

It features the following helpers:

- [x] TCP-IP forwarding child channels
- [x] Basic SFTP Client
- [x] TTY support

## Usage

If you have any questions, [join the Discord](https://discord.gg/RBrYM8C6Pa)

### Supporting Older Cryptography

If you need deprecated crypto support, you can enable Citadel's (or custom) algorithms like so.
This is a global setting and needs to happen before connecting.

```swift
NIOSSHAlgorithms.register(
    publicKey: Insecure.RSA.PublicKey.self,
    signature: Insecure.RSA.Signature.self
)

NIOSSHAlgorithms.register(transportProtectionScheme: AES128CTR.self)
NIOSSHAlgorithms.register(keyExchangeAlgorithm: DiffieHellmanGroup14Sha1.self)
```

### SSH Proxy for MongoKitten

```swift
// - MARK: Fill these in:
let eventloop: EventLoop

// E.G. example.com
let sshHost: String

// Password or public key
let sshCredentials: SSHAuthenticationMethod

// Accept anything, custom validator or predefined keys
let hostKeyValidator: SSHHostKeyValidator

// Use a custom Mongo Connection builder
let pool = MongoSingleConnectionPool(
    eventLoop: eventLoop, 
    // Provide an authenticationSource, as defined by MongoDB. If unknown, likely `admin`
    authenticationSource: settings.authenticationSource ?? "admin",
    // Provide MongoKitten credentials
    credentials: settings.authentication
) { eventLoop in
    // Create a connection boot
    SSHClient.connect(
        sshHost: sshHost,
        authenticationMethod: sshAuthenticationMethod,
        hostKeyValidator: hostKeyValidator
    ).flatMap { sshClient in
        // The address that is presented as the locally exposed interface
        // This is purely communicated to the SSH server
        let address: SocketAddress
        
        do {
            address = try SocketAddress(ipAddress: "fe80::1", port: 27017)
        } catch {
            return sshChannel.eventLoop.makeFailedFuture(SSHClientError.invalidOriginAddress)
        }
        
        return sshClient.createDirectTCPIPChannel(
            using: SSHChannelType.DirectTCPIP(
                targetHost: "localhost", // MongoDB host 
                targetPort: 27017, // MongoDB port
                originatorAddress: address
            )
        )
    }.flatMap { childChannel in
        MongoConnection.addHandlers(to: childChannel, context: context)
    }
}
```

## TODO

A couple of code is held back until further work in SwiftNIO SSH is completed.

- [ ] RSA Authentication (implemented, but in a [fork of NIOSSH](https://github.com/Joannis/swift-nio-ssh-1/pull/1))
- [ ] SSH Key format parsing (just haven't had the time to make a public API yet)

## Contributing

I'm happy to accept ideas and PRs for new API's.
