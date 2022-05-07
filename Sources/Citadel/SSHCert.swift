import CCryptoBoringSSL
import BigInt
import Foundation
import Crypto
import NIO
import NIOSSH

struct InvalidKey: Error {}

extension ED25519.PrivateKey {
    public convenience init(sshEd25519 data: Data) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshEd25519: string)
        } else {
            throw InvalidKey()
        }
    }
    
    public convenience init(sshEd25519 key: String) throws {
        let openSSHKey = try OpenSSH.PrivateKey<ED25519>.init(string: key)
        try self.init(rawRepresentation: openSSHKey.privateKey.rawRepresentation)
    }
}

extension Insecure.RSA.PrivateKey {
    public convenience init(sshRsa data: Data) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshRsa: string)
        } else {
            throw InvalidKey()
        }
    }
    
    public convenience init(sshRsa key: String) throws {
        let privateKey = try OpenSSH.PrivateKey<Insecure.RSA>.init(string: key).privateKey
        let publicKey = privateKey.publicKey as! Insecure.RSA.PublicKey
        
        // Copy, so that our values stored in `privateKey` aren't freed when exciting the initializers scope
        let modulus = CCryptoBoringSSL_BN_new()!
        let publicExponent = CCryptoBoringSSL_BN_new()!
        let privateExponent = CCryptoBoringSSL_BN_new()!
        
        CCryptoBoringSSL_BN_copy(modulus, publicKey.modulus)
        CCryptoBoringSSL_BN_copy(publicExponent, publicKey.publicExponent)
        CCryptoBoringSSL_BN_copy(privateExponent, privateKey.privateExponent)
        
        self.init(privateExponent: privateExponent, publicExponent: publicExponent, modulus: modulus)
    }
}
