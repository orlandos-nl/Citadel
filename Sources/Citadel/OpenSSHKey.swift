import CCryptoBoringSSL
import BigInt
import Foundation
import NIO
import Crypto
import CCitadelBcrypt
import NIOSSH

// Noteable links:
// https://dnaeon.github.io/openssh-private-key-binary-format/

internal protocol ParsableFromByteBuffer {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self
}

protocol OpenSSHPrivateKey: ParsableFromByteBuffer {
    static var privateKeyPrefix: String { get }
    static var publicKeyPrefix: String { get }
    static var keyType: OpenSSH.KeyType { get }
    
    associatedtype PublicKey: ParsableFromByteBuffer
}

extension Insecure.RSA.PrivateKey: ParsableFromByteBuffer {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
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

extension Curve25519.Signing.PrivateKey: ParsableFromByteBuffer {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        guard let publicKey = buffer.readSSHBuffer() else {
            throw InvalidKey()
        }

        guard
            var buffer = buffer.readSSHBuffer(),
            let privateKeyBytes = buffer.readBytes(length: 32),
            let publicKeyBytes = buffer.readSlice(length: buffer.readerIndex),
            publicKeyBytes == publicKey
        else {
            throw InvalidKey()
        }
        
        return try Self.init(rawRepresentation: privateKeyBytes)
    }
}

extension ByteBuffer {
    mutating func decryptAES(
        cipher: UnsafePointer<EVP_CIPHER>,
        key: [UInt8],
        iv: [UInt8]
    ) throws {
        guard self.readableBytes % 16 == 0 else {
            throw InvalidKey()
        }
        
        let context = CCryptoBoringSSL_EVP_CIPHER_CTX_new()
        defer { CCryptoBoringSSL_EVP_CIPHER_CTX_free(context) }
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            context,
            cipher,
            key,
            iv,
            0
        ) == 1 else {
            throw OpenSSH.KeyError.cryptoError
        }
        
        try self.withUnsafeMutableReadableBytes { buffer in
            var byteBufferPointer = buffer.bindMemory(to: UInt8.self).baseAddress!
            try withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 16) { decryptedBuffer in
                for _ in 0..<buffer.count / 16 {
                    guard CCryptoBoringSSL_EVP_Cipher(
                        context,
                        decryptedBuffer.baseAddress!,
                        byteBufferPointer,
                        16
                    ) == 1 else {
                        throw CitadelError.cryptographicError
                    }
                    
                    byteBufferPointer.assign(from: decryptedBuffer.baseAddress!, count: 16)
                    // Move the pointer forward to the next block
                    byteBufferPointer += 16
                }
            }
        }
    }
}

enum OpenSSH {
    enum KeyError: Error {
        case missingDecryptionKey, cryptoError
    }
    
    enum Cipher: String {
        case none
        case aes128ctr = "aes128-ctr"
        case aes256ctr = "aes256-ctr"
        
        var keyLength: Int {
            switch self {
            case .none:
                return 0
            case .aes128ctr:
                return 16
            case .aes256ctr:
                return 32
            }
        }
        
        var ivLength: Int {
            switch self {
            case .none:
                return 0
            case .aes128ctr, .aes256ctr:
                return 16
            }
        }
        
        func decryptBuffer(
            _ buffer: inout ByteBuffer,
            key: [UInt8],
            iv: [UInt8]
        ) throws {
            switch self {
            case .none:
                ()
            case .aes128ctr:
                try buffer.decryptAES(cipher: CCryptoBoringSSL_EVP_aes_128_ctr(), key: key, iv: iv)
            case .aes256ctr:
                try buffer.decryptAES(cipher: CCryptoBoringSSL_EVP_aes_256_ctr(), key: key, iv: iv)
            }
        }
    }
    
    enum KDF {
        enum KDFType: String {
            case none, bcrypt
        }
        
        case none
        case bcrypt(salt: ByteBuffer, iterations: UInt32)
        
        func withKeyAndIV<T>(
            cipher: Cipher,
            basedOnDecryptionKey decryptionKey: Data?,
            perform: (_ key: [UInt8], _ iv: [UInt8]) throws -> T
        ) throws -> T {
            switch self {
            case .none:
                return try perform([], [])
            case .bcrypt(var salt, let iterations):
                guard let decryptionKey = decryptionKey else {
                    throw KeyError.missingDecryptionKey
                }
                
                return try decryptionKey.withUnsafeBytes { decryptionKey in
                    let salt = salt.readBytes(length: salt.readableBytes)!
                    var key = [UInt8](repeating: 0, count: cipher.keyLength + cipher.ivLength)
                    guard bcrypt_pbkdf(
                        decryptionKey.baseAddress!,
                        decryptionKey.count,
                        salt,
                        salt.count,
                        &key,
                        cipher.keyLength + cipher.ivLength,
                        iterations
                    ) == 0 else {
                        throw KeyError.cryptoError
                    }
                    
                    return try perform(Array(key[..<cipher.keyLength]), Array(key[cipher.keyLength...]))
                }
            }
        }
    }
    
    enum KeyType: String {
        case sshRSA = "ssh-rsa"
        case sshED25519 = "ssh-ed25519"
    }
    
    struct PrivateKey<SSHKey: OpenSSHPrivateKey> {
        let cipher: Cipher
        let kdf: KDF
        let numberOfKeys: Int
        let publicKey: SSHKey.PublicKey
        let privateKey: SSHKey
        let comment: String
        
        var keyType: KeyType {
            SSHKey.keyType
        }
    }
}

extension OpenSSH.PrivateKey {
    init(string key: String, decryptionKey: Data? = nil) throws {
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
            
        let cipher = try OpenSSH.Cipher(consuming: &buffer)
        self.cipher = cipher
        let kdf = try OpenSSH.KDF(consuming: &buffer)
        self.kdf = kdf
        
        guard
            let numberOfKeys = buffer.readInteger(as: UInt32.self),
            numberOfKeys == 1 // # of keys always one
        else {
            throw InvalidKey()
        }
        
        self.numberOfKeys = Int(numberOfKeys)
        
        guard var publicKeyBuffer = buffer.readSSHBuffer() else {
            throw InvalidKey()
        }
        
        let publicKeyType = try OpenSSH.KeyType(consuming: &publicKeyBuffer)
        guard publicKeyType.rawValue == SSHKey.publicKeyPrefix else { throw InvalidKey() }
        
        self.publicKey = try SSHKey.PublicKey.read(consuming: &publicKeyBuffer)
        
        guard var privateKeyBuffer = buffer.readSSHBuffer() else {
            throw InvalidKey()
        }
        
        try kdf.withKeyAndIV(
            cipher: cipher,
            basedOnDecryptionKey: decryptionKey
        ) { key, iv -> Void in
            try cipher.decryptBuffer(&privateKeyBuffer, key: key, iv: iv)
        }
        
        guard let checksum = privateKeyBuffer.readInteger(as: UInt64.self)  else {
            throw InvalidKey()
        }
        
        let privateKeyType = try OpenSSH.KeyType(consuming: &privateKeyBuffer)
        guard
            privateKeyType.rawValue == SSHKey.privateKeyPrefix,
            privateKeyType == publicKeyType
        else {
            throw InvalidKey()
        }
        
        self.privateKey = try SSHKey.read(consuming: &privateKeyBuffer)
        
        guard let comment = privateKeyBuffer.readSSHString() else { throw InvalidKey() }
        self.comment = comment
        
        let paddingLength = privateKeyBuffer.readableBytes
        guard
            paddingLength < 16,
            let padding = privateKeyBuffer.readBytes(length: paddingLength)
        else {
            throw InvalidKey()
        }
        
        for i in 1..<paddingLength {
            guard padding[i - 1] == UInt8(i) else {
                throw InvalidKey()
            }
        }
    }
}

extension OpenSSH.Cipher {
    init(consuming buffer: inout ByteBuffer) throws {
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
    init(consuming buffer: inout ByteBuffer) throws {
        guard
            let kdfName = buffer.readSSHString(),
            let kdf = KDFType(rawValue: kdfName),
            var options = buffer.readSSHBuffer()
        else {
            throw InvalidKey()
        }
        
        switch kdf {
        case .none:
            guard options.readableBytes == 0 else {
                throw InvalidKey()
            }
            
            self = .none
        case .bcrypt:
            guard
                let salt = options.readSSHBuffer(),
                let rounds: UInt32 = options.readInteger(),
                rounds < 18
            else {
                throw InvalidKey()
            }
            
            self = .bcrypt(salt: salt, iterations: rounds)
        }
    }
}

extension OpenSSH.KeyType {
    init(consuming buffer: inout ByteBuffer) throws {
        guard
            let keyName = buffer.readSSHString(),
            let keyType = Self(rawValue: keyName)
        else {
            throw InvalidKey()
        }
        self = keyType
    }
}
