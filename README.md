# Citadel

Citadel is a high level API around [NIOSSH](https://github.com/apple/swift-nio-ssh). It aims to add what's out of scope for NIOSSH, lending code from my private tools.

It features the following helpers:

- [x] TCP-IP forwarding child channels
- [x] Basic SFTP Client

## Usage

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
    }.flatMap { sshChannel in
        let context = MongoClientContext(logger: .defaultMongoCore)
        
        return sshChannel.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
            // The address that is presented as the locally exposed interface
            // This is purely communicated to the SSH server
            let address: SocketAddress
            
            do {
                address = try SocketAddress(ipAddress: "fe80::1", port: 27017)
            } catch {
                return sshChannel.eventLoop.makeFailedFuture(SSHClientError.invalidOriginAddress)
            }
            
            let promise = sshChannel.eventLoop.makePromise(of: Channel.self)
            
            sshHandler.createChannel(
                promise, 
                channelType: .directTCPIP(
                    SSHChannelType.DirectTCPIP(
                        targetHost: host.hostname, 
                        targetPort: host.port, 
                        originatorAddress: address
                    )
                )
            ) { childChannel, channelType in
                guard case .directTCPIP = channelType else {
                    return sshChannel.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                }
                
                return childChannel.pipeline.addHandler(DataToBufferCodec()).flatMap {
                    MongoConnection.addHandlers(to: childChannel, context: context)
                }
            }
            
            return promise.futureResult.map { childChannel in
                return MongoConnection(channel: childChannel, context: context)
            }
        }
    }
}
```

## TODO

A couple of code is held back until further work in SwiftNIO SSH is completed.

- [ ] RSA Authentication (implemented, but in a [fork of NIOSSH](https://github.com/Joannis/swift-nio-ssh-1/pull/1))
- [ ] SSH Key format parsing (just haven't had the time to make a public API yet)

## Contributing

I'm happy to accept ideas and PRs for new API's.
