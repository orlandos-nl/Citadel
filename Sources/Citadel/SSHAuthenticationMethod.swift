import NIO
import NIOSSH
import Crypto

/// A simple keyboard-interactive delegate that responds with a stored password.
final class PasswordKeyboardInteractiveDelegate: NIOSSHKeyboardInteractiveDelegate {
    let password: String

    init(password: String) {
        self.password = password
    }

    func respondToKeyboardInteractiveChallenge(
        name: String,
        instruction: String,
        prompts: [NIOSSHKeyboardInteractivePrompt]
    ) -> [String] {
        // Simple: return the stored password for each prompt
        return prompts.map { _ in self.password }
    }
}

/// Represents an authentication method.
public final class SSHAuthenticationMethod: NIOSSHClientUserAuthenticationDelegate {
    private enum Implementation {
        case custom(NIOSSHClientUserAuthenticationDelegate)
        case user(String, offer: NIOSSHUserAuthenticationOffer.Offer)
    }

    private let allImplementations: [Implementation]
    private var implementations: [Implementation]
    private var enableKeyboardInteractiveFallback: Bool = false

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

    /// Creates a password based authentication method.
    /// When the server doesn't support `password` auth but supports `keyboard-interactive`,
    /// the method will automatically fall back to keyboard-interactive with the same password.
    /// - Parameters:
    ///  - username: The username to authenticate with.
    /// - password: The password to authenticate with.
    public static func passwordBased(username: String, password: String) -> SSHAuthenticationMethod {
        let method = SSHAuthenticationMethod(username: username, offer: .password(.init(password: password)))
        method.enableKeyboardInteractiveFallback = true
        return method
    }

    /// Creates a password based authentication method WITHOUT keyboard-interactive fallback.
    /// - Parameters:
    ///  - username: The username to authenticate with.
    /// - password: The password to authenticate with.
    public static func passwordBasedStrict(username: String, password: String) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .password(.init(password: password)))
    }

    /// Creates a public key based authentication method.
    /// - Parameters:
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func rsa(username: String, privateKey: Insecure.RSA.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(custom: privateKey))))
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
            case .password(let passwordOffer):
                if !availableMethods.contains(.password) {
                    // Password auth not supported by server.
                    // Fall back to keyboard-interactive if enabled and available.
                    if enableKeyboardInteractiveFallback && availableMethods.contains(.keyboardInteractive) {
                        let kiDelegate = PasswordKeyboardInteractiveDelegate(password: passwordOffer.password)
                        let kiOffer: NIOSSHUserAuthenticationOffer.Offer = .keyboardInteractive(.init(delegate: kiDelegate))
                        nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: kiOffer))
                        return
                    }
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
            case .keyboardInteractive:
                guard availableMethods.contains(.keyboardInteractive) else {
                    nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
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
