import NIO
import NIOSSH
import Crypto

/// Represents an authentication method.
public final class SSHAuthenticationMethod: NIOSSHClientUserAuthenticationDelegate {
    private enum Implementation {
        case custom(NIOSSHClientUserAuthenticationDelegate)
        case user(String, offer: NIOSSHUserAuthenticationOffer.Offer)
    }
    
    private let allImplementations: [Implementation]
    private var implementations: [Implementation]
    
    internal init(
        username: String,
        offer: NIOSSHUserAuthenticationOffer.Offer
    ) {
        self.allImplementations = [.user(username, offer: offer)]
        self.implementations = allImplementations
    }
    
    internal init(
        custom: NIOSSHClientUserAuthenticationDelegate
    ) {
        self.allImplementations = [.custom(custom)]
        self.implementations = allImplementations
    }

    /// Offers are tried in order: each one is used when the server rejects the
    /// previous. Lets a key be offered under several signature algorithms.
    internal init(
        username: String,
        offers: [NIOSSHUserAuthenticationOffer.Offer]
    ) {
        self.allImplementations = offers.map { .user(username, offer: $0) }
        self.implementations = allImplementations
    }

    /// Creates a password based authentication method.
    /// - Parameters:
    ///  - username: The username to authenticate with.
    /// - password: The password to authenticate with.
    public static func passwordBased(username: String, password: String) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .password(.init(password: password)))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func rsa(username: String, privateKey: Insecure.RSA.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(custom: privateKey))))
    }

    /// Public key authentication with an RSA key, using the RFC 8332 SHA-2
    /// signature algorithms.
    ///
    /// `ssh-rsa` (SHA-1) has been off by default in OpenSSH's
    /// `PubkeyAcceptedAlgorithms` since 8.8, so `rsa(username:privateKey:)`
    /// cannot authenticate against a stock modern server. This offers
    /// `rsa-sha2-512` then `rsa-sha2-256`, and finally plain `ssh-rsa` when
    /// `includeSHA1Fallback` is set, for servers predating RFC 8332.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The RSA private key to authenticate with.
    ///   - includeSHA1Fallback: Also offer legacy `ssh-rsa`. Defaults to `true`.
    public static func rsaSHA2(
        username: String,
        privateKey: Insecure.RSA.PrivateKey,
        includeSHA1Fallback: Bool = true
    ) -> SSHAuthenticationMethod {
        var offers: [NIOSSHUserAuthenticationOffer.Offer] = [
            .privateKey(.init(privateKey: .init(custom: Insecure.RSA.SHA2PrivateKey<RSASHA2_512>(privateKey)))),
            .privateKey(.init(privateKey: .init(custom: Insecure.RSA.SHA2PrivateKey<RSASHA2_256>(privateKey)))),
        ]
        if includeSHA1Fallback {
            offers.append(.privateKey(.init(privateKey: .init(custom: privateKey))))
        }
        return SSHAuthenticationMethod(username: username, offers: offers)
    }

    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func ed25519(username: String, privateKey: Curve25519.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p256(username: String, privateKey: P256.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p256Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p384(username: String, privateKey: P384.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p384Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p521(username: String, privateKey: P521.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p521Key: privateKey))))
    }
    
    public static func custom(_ auth: NIOSSHClientUserAuthenticationDelegate) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(custom: auth)
    }
    
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        if implementations.isEmpty {
            nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
            return
        }
        
        let implementation = implementations.removeFirst()

        switch implementation {
        case .user(let username, offer: let offer):
            switch offer {
            case .password:
                guard availableMethods.contains(.password) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPasswordAuthentication)
                    return
                }
            case .hostBased:
                guard availableMethods.contains(.hostBased) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedHostBasedAuthentication)
                    return
                }
            case .privateKey:
                guard availableMethods.contains(.publicKey) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPrivateKeyAuthentication)
                    return
                }
            case .none:
                ()
            }
            
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: offer))
        case .custom(let implementation):
            implementation.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
        }
    }
}
