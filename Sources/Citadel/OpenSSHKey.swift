import CCryptoBoringSSL
import BigInt
import Foundation
import NIO
import Crypto
import NIOSSH

protocol ReadableFromBuffer {
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

protocol OpenSSHKeyProtocol {
    static var keyType: OpenSSH.KeyType { get }
    associatedtype PublicKey: NIOSSHPublicKeyProtocol
    associatedtype PrivateKey: NIOSSHPrivateKeyProtocol, ReadableFromBuffer
}

extension OpenSSHKeyProtocol {
    static var keyType: OpenSSH.KeyType {
        .init(rawValue: PrivateKey.keyPrefix)!
    }
}

extension Insecure.RSA.PrivateKey: ReadableFromBuffer {
    static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard
            let nBytesLength = buffer.readInteger(as: UInt32.self),
            let nBytes = buffer.readBytes(length: Int(nBytesLength)),
            let eBytesLength = buffer.readInteger(as: UInt32.self),
            let eBytes = buffer.readBytes(length: Int(eBytesLength)),
            let dLength = buffer.readInteger(as: UInt32.self),
            let dBytes = buffer.readBytes(length: Int(dLength)),
            let iqmpLength = buffer.readInteger(as: UInt32.self),
            let _ = buffer.readData(length: Int(iqmpLength)),
            let pLength = buffer.readInteger(as: UInt32.self),
            let _ = buffer.readData(length: Int(pLength)),
            let qLength = buffer.readInteger(as: UInt32.self),
            let _ = buffer.readData(length: Int(qLength))
        else {
            throw InvalidKey()
        }
        
        let privateExponent = CCryptoBoringSSL_BN_bin2bn(dBytes, dBytes.count, nil)!
        let publicExponent = CCryptoBoringSSL_BN_bin2bn(eBytes, eBytes.count, nil)!
        let modulus = CCryptoBoringSSL_BN_bin2bn(nBytes, nBytes.count, nil)!

        return self.init(privateExponent: privateExponent, publicExponent: publicExponent, modulus: modulus)
    }
}

extension ED25519.PrivateKey: ReadableFromBuffer {
    static func read(from buffer: inout ByteBuffer) throws -> Self {
        guard
            let publicKeyLength = buffer.readInteger(as: UInt32.self),
            let publicKey = buffer.readBytes(length: Int(publicKeyLength))
        else {
            throw InvalidKey()
        }

        guard
            let privateKeyLength = buffer.readInteger(as: UInt32.self),
            let privateKey = buffer.readBytes(length: Int(privateKeyLength)),
            Array(privateKey[32...]) == publicKey
        else {
            throw InvalidKey()
        }
        
        return try Self.init(rawRepresentation: privateKey[..<32])
    }
}

extension Insecure.RSA: OpenSSHKeyProtocol {}

extension ED25519: OpenSSHKeyProtocol {}

enum OpenSSH {
    enum Cipher: String {
        case none
    }
    
    enum KDF: String {
        case none
    }
    
    enum KeyType: String {
        case sshRSA = "ssh-rsa"
        case sshED25519 = "ssh-ed25519"
    }
    
    struct PrivateKey<SSHKey: OpenSSHKeyProtocol> {
        let cipher: Cipher
        let kdf: KDF
        let numberOfKeys: Int
        let publicKey: SSHKey.PublicKey
        let privateKey: SSHKey.PrivateKey
        let comment: String
        
        var keyType: KeyType {
            SSHKey.keyType
        }
    }
}

extension OpenSSH.PrivateKey {
    init(string key: String) throws {
        var key = key.replacingOccurrences(of: "\n", with: "")
        
        guard
            key.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"),
            key.hasSuffix("-----END OPENSSH PRIVATE KEY-----")
        else {
            throw InvalidKey()
        }
        
        key.removeLast("-----END OPENSSH PRIVATE KEY-----".utf8.count)
        key.removeFirst("-----BEGIN OPENSSH PRIVATE KEY-----".utf8.count)
        
        guard let data = Data(base64Encoded: key) else {
            throw InvalidKey()
        }
        
        var buffer = ByteBuffer(data: data)
        
        guard
            buffer.readString(length: "openssh-key-v1".utf8.count) == "openssh-key-v1",
            buffer.readInteger(as: UInt8.self) == 0x00
        else {
            throw InvalidKey()
        }
            
        self.cipher = try OpenSSH.Cipher(from: &buffer)
        self.kdf = try OpenSSH.KDF(from: &buffer)
        
        guard
            let numberOfKeys = buffer.readInteger(as: UInt32.self),
            numberOfKeys == 1 // # of keys always one
        else {
            throw InvalidKey()
        }
        
        self.numberOfKeys = Int(numberOfKeys)
        
        guard
            let publicKeyBufferLength = buffer.readInteger(as: UInt32.self).map(Int.init),
            var publicKeyBuffer = buffer.readSlice(length: publicKeyBufferLength)
        else {
            throw InvalidKey()
        }
        
        let publicKeyType = try OpenSSH.KeyType(from: &publicKeyBuffer)
        guard publicKeyType.rawValue == SSHKey.PublicKey.publicKeyPrefix else { throw InvalidKey() }
        
        self.publicKey = try SSHKey.PublicKey.read(from: &publicKeyBuffer)
        
        guard
            let privateKeyBufferLength = buffer.readInteger(as: UInt32.self).map(Int.init),
            var privateKeyBuffer = buffer.readSlice(length: privateKeyBufferLength),
            let _ = privateKeyBuffer.readInteger(as: UInt64.self) // read random int/checksum
        else {
            throw InvalidKey()
        }
        
        let privateKeyType = try OpenSSH.KeyType(from: &privateKeyBuffer)
        guard
            privateKeyType.rawValue == SSHKey.PrivateKey.keyPrefix,
            privateKeyType == publicKeyType
        else {
            throw InvalidKey()
        }
        
        self.privateKey = try SSHKey.PrivateKey.read(from: &privateKeyBuffer)
        
        guard let comment = privateKeyBuffer.readSSHString() else { throw InvalidKey() }
        self.comment = comment
        
        let paddingLength = privateKeyBuffer.readableBytes
        let maxPadding: [UInt8] = [1, 2, 3, 4, 5, 6, 7]
        let expectedPadding = Array(maxPadding[0..<paddingLength])
        guard
            paddingLength < 8,
            let padding = privateKeyBuffer.readBytes(length: paddingLength),
            padding == expectedPadding
        else {
            throw InvalidKey()
        }
    }
}

extension OpenSSH.Cipher {
    init(from buffer: inout ByteBuffer) throws {
        guard
            let cipherName = buffer.readSSHString(),
            let cipher = Self(rawValue: cipherName)
        else {
            throw InvalidKey()
        }
        self = cipher
    }
}

extension OpenSSH.KDF {
    init(from buffer: inout ByteBuffer) throws {
        guard
            let kdfName = buffer.readSSHString(),
            let kdf = Self(rawValue: kdfName),
            buffer.readInteger(as: UInt32.self) == 0 // KDF (currently only none kdf)
        else {
            throw InvalidKey()
        }
        self = kdf
    }
}

extension OpenSSH.KeyType {
    init(from buffer: inout ByteBuffer) throws {
        guard
            let cipherName = buffer.readSSHString(),
            let cipher = Self(rawValue: cipherName)
        else {
            throw InvalidKey()
        }
        self = cipher
    }
}
