import CCryptoBoringSSL
import BigInt
import Foundation
import Crypto
import NIO
import NIOSSH

struct InvalidKey: Error {}

extension Curve25519.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Curve25519.Signing.PublicKey {
        guard var publicKeyBuffer = buffer.readSSHBuffer() else {
            throw InvalidKey()
        }
        
        return try self.init(rawRepresentation: publicKeyBuffer.readBytes(length: publicKeyBuffer.readableBytes)!)
    }
    
    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeData(self.rawRepresentation)
    }
}

extension Curve25519.Signing.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = Curve25519.Signing.PublicKey
    static var publicKeyPrefix: String { "ssh-ed25519" }
    static var privateKeyPrefix: String { "ssh-ed25519" }
    static var keyType: OpenSSH.KeyType { .sshED25519 }
    
    public init(sshEd25519 data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshEd25519: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidKey()
        }
    }
    
    public init(sshEd25519 key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<Curve25519.Signing.PrivateKey>.init(string: key, decryptionKey: decryptionKey).privateKey
    }
}

extension Insecure.RSA.PublicKey: ByteBufferConvertible {
    func write(to buffer: inout ByteBuffer) {
        let _: Int = self.write(to: &buffer)
    }
}

extension Insecure.RSA.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = Insecure.RSA.PublicKey
    
    static var publicKeyPrefix: String { "ssh-rsa" }
    static var privateKeyPrefix: String { "ssh-rsa" }
    static var keyType: OpenSSH.KeyType { .sshRSA }
    
    public convenience init(sshRsa data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshRsa: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidKey()
        }
    }
    
    public convenience init(sshRsa key: String, decryptionKey: Data? = nil) throws {
        let privateKey = try OpenSSH.PrivateKey<Insecure.RSA.PrivateKey>.init(string: key, decryptionKey: decryptionKey).privateKey
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
