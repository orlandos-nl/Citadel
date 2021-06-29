import NIO
import NIOSSH
import Crypto

public struct SSHAuthenticationMethod: NIOSSHClientUserAuthenticationDelegate {
    private let username: String
    private let offer: NIOSSHUserAuthenticationOffer.Offer
    
    internal init(
        username: String,
        offer: NIOSSHUserAuthenticationOffer.Offer
    ) {
        self.username = username
        self.offer = offer
    }
    
    public static func passwordBased(username: String, password: String) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .password(.init(password: password)))
    }
    
    public static func rsa(username: String, privateKey: Insecure.RSA.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(custom: privateKey))))
    }
    
    public static func ed25519(username: String, privateKey: Curve25519.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey))))
    }
    
    public static func p256(username: String, privateKey: P256.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p256Key: privateKey))))
    }
    
    public static func p384(username: String, privateKey: P384.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p384Key: privateKey))))
    }
    
    public static func p521(username: String, privateKey: P521.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p521Key: privateKey))))
    }
    
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
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
    }
}
