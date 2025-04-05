import CCryptoBoringSSL
import BigInt
import Foundation
import NIO
import Crypto
import CCitadelBcrypt
import NIOSSH

// Noteable links:
// https://dnaeon.github.io/openssh-private-key-binary-format/

internal protocol ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self
    func write(to buffer: inout ByteBuffer) -> Int
}

protocol OpenSSHPrivateKey: ByteBufferConvertible {
    static var privateKeyPrefix: String { get }
    static var publicKeyPrefix: String { get }
    static var keyType: OpenSSH.KeyType { get }
    
    associatedtype PublicKey: ByteBufferConvertible
}

extension RSA.PrivateKey: ByteBufferConvertible {
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
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        let privateExponent = CCryptoBoringSSL_BN_bin2bn(dBytes, dBytes.count, nil)!
        let publicExponent = CCryptoBoringSSL_BN_bin2bn(eBytes, eBytes.count, nil)!
        let modulus = CCryptoBoringSSL_BN_bin2bn(nBytes, nBytes.count, nil)!

        return self.init(privateExponent: privateExponent, publicExponent: publicExponent, modulus: modulus)
    }
    
    func write(to buffer: inout ByteBuffer) -> Int {
        0
    }
}

extension Curve25519.Signing.PrivateKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        guard let publicKey = buffer.readSSHBuffer() else {
            throw InvalidOpenSSHKey.missingPublicKeyBuffer
        }
        
        guard var privateKey = buffer.readSSHBuffer() else {
            throw InvalidOpenSSHKey.missingPrivateKeyBuffer
        }
        
        guard
            let privateKeyBytes = privateKey.readBytes(length: 32),
            let publicKeyBytes = privateKey.readSlice(length: privateKey.readableBytes)
        else {
            throw InvalidOpenSSHKey.missingPublicKeyInPrivateKey
        }
        
        guard publicKeyBytes == publicKey else {
            throw InvalidOpenSSHKey.invalidPublicKeyInPrivateKey
        }
        
        return try Self.init(rawRepresentation: privateKeyBytes)
    }
    
    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        let n = buffer.writeSSHString(publicKey.rawRepresentation)
        return n + buffer.writeCompositeSSHString { buffer in
            let n = buffer.writeData(self.rawRepresentation)
            return n + buffer.writeData(self.publicKey.rawRepresentation)
        }
    }
    
    /// Creates a new OpenSSH formatted private key
    public func makeSSHRepresentation(comment: String = "") -> String {
        let allocator = ByteBufferAllocator()
        
        var buffer = allocator.buffer(capacity: Int(UInt16.max))
        buffer.reserveCapacity(Int(UInt16.max))
        
        buffer.writeString("openssh-key-v1")
        buffer.writeInteger(0x00 as UInt8)
        
        buffer.writeSSHString("none") // cipher
        buffer.writeSSHString("none") // kdf
        buffer.writeSSHString([UInt8]()) // kdf options
        
        buffer.writeInteger(1 as UInt32)
        
        var publicKeyBuffer = allocator.buffer(capacity: Int(UInt8.max))
        publicKeyBuffer.writeSSHString("ssh-ed25519")
        publicKeyBuffer.writeCompositeSSHString { buffer in
            publicKey.write(to: &buffer)
        }
        buffer.writeSSHString(&publicKeyBuffer)
        
        var privateKeyBuffer = allocator.buffer(capacity: Int(UInt8.max))
        
        // checksum
        let checksum = UInt32.random(in: .min ... .max)
        privateKeyBuffer.writeInteger(checksum)
        privateKeyBuffer.writeInteger(checksum)
        
        privateKeyBuffer.writeSSHString("ssh-ed25519")
        write(to: &privateKeyBuffer)
        privateKeyBuffer.writeSSHString(comment) // comment
        let neededBytes = UInt8(OpenSSH.Cipher.none.blockSize - (privateKeyBuffer.writerIndex % OpenSSH.Cipher.none.blockSize))
        if neededBytes > 0 {
            for i in 1...neededBytes {
                privateKeyBuffer.writeInteger(i)
            }
        }
        buffer.writeSSHString(&privateKeyBuffer)
        
        let base64 = buffer.readData(length: buffer.readableBytes)!.base64EncodedString()
        
        var string = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        string += base64
        string += "\n"
        string += "-----END OPENSSH PRIVATE KEY-----\n"
        
        return string
    }
}

extension ByteBuffer {
    mutating func decryptAES(
        cipher: UnsafePointer<EVP_CIPHER>,
        key: [UInt8],
        iv: [UInt8]
    ) throws {
        guard self.readableBytes % 16 == 0 else {
            throw InvalidOpenSSHKey.invalidPadding
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
                    
                    byteBufferPointer.update(from: decryptedBuffer.baseAddress!, count: 16)
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
        
        var blockSize: Int {
            switch self {
            case .none:
                return 8
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
                
                guard _SHA512.didInit else {
                    fatalError("Internal library error")
                }
                
                return try decryptionKey.withUnsafeBytes { decryptionKey in
                    let salt = salt.readBytes(length: salt.readableBytes)!
                    var key = [UInt8](repeating: 0, count: cipher.keyLength + cipher.ivLength)
                    guard citadel_bcrypt_pbkdf(
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
            throw InvalidOpenSSHKey.invalidOpenSSHBoundary
        }
        
        key.removeLast("-----END OPENSSH PRIVATE KEY-----".utf8.count)
        key.removeFirst("-----BEGIN OPENSSH PRIVATE KEY-----".utf8.count)
        
        guard let data = Data(base64Encoded: key) else {
            throw InvalidOpenSSHKey.invalidBase64Payload
        }
        
        var buffer = ByteBuffer(data: data)
        
        guard
            buffer.readString(length: "openssh-key-v1".utf8.count) == "openssh-key-v1",
            buffer.readInteger(as: UInt8.self) == 0x00
        else {
            throw InvalidOpenSSHKey.invalidOpenSSHPrefix
        }
            
        let cipher = try OpenSSH.Cipher(consuming: &buffer)
        self.cipher = cipher
        let kdf = try OpenSSH.KDF(consuming: &buffer)
        self.kdf = kdf
        
        guard
            let numberOfKeys = buffer.readInteger(as: UInt32.self),
            numberOfKeys == 1 // # of keys always one
        else {
            throw InvalidOpenSSHKey.unsupportedFeature(.multipleKeys)
        }
        
        self.numberOfKeys = Int(numberOfKeys)
        
        guard var publicKeyBuffer = buffer.readSSHBuffer() else {
            throw InvalidOpenSSHKey.missingPublicKeyBuffer
        }
        
        let publicKeyType = try OpenSSH.KeyType(consuming: &publicKeyBuffer)
        guard publicKeyType.rawValue == SSHKey.publicKeyPrefix else {
            throw InvalidOpenSSHKey.invalidPublicKeyPrefix
        }

        self.publicKey = try SSHKey.PublicKey.read(consuming: &publicKeyBuffer)
        
        guard var privateKeyBuffer = buffer.readSSHBuffer() else {
            throw InvalidOpenSSHKey.missingPrivateKeyBuffer
        }
        
        try kdf.withKeyAndIV(
            cipher: cipher,
            basedOnDecryptionKey: decryptionKey
        ) { key, iv -> Void in
            try cipher.decryptBuffer(&privateKeyBuffer, key: key, iv: iv)
        }
        
        guard
            let check0 = privateKeyBuffer.readInteger(as: UInt32.self),
            let check1 = privateKeyBuffer.readInteger(as: UInt32.self),
            check0 == check1
        else {
            throw InvalidOpenSSHKey.invalidCheck
        }

        let privateKeyType = try OpenSSH.KeyType(consuming: &privateKeyBuffer)
        guard
            privateKeyType.rawValue == SSHKey.privateKeyPrefix,
            privateKeyType == publicKeyType
        else {
            throw InvalidOpenSSHKey.invalidPublicKeyInPrivateKey
        }
        
        self.privateKey = try SSHKey.read(consuming: &privateKeyBuffer)
        
        guard let comment = privateKeyBuffer.readSSHString() else {
            throw InvalidOpenSSHKey.missingComment
        }
        self.comment = comment
        
        let paddingLength = privateKeyBuffer.readableBytes
        
        guard
            paddingLength < cipher.blockSize,
            let padding = privateKeyBuffer.readBytes(length: paddingLength)
        else {
            throw InvalidOpenSSHKey.invalidPadding
        }
        
        if paddingLength == 0 {
            return
        }
        
        for i in 1..<paddingLength {
            guard padding[i - 1] == UInt8(i) else {
                throw InvalidOpenSSHKey.invalidPadding
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
            throw InvalidOpenSSHKey.unsupportedFeature(.unsupportedCipher)
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
            throw InvalidOpenSSHKey.unsupportedFeature(.unsupportedKDF)
        }
        
        switch kdf {
        case .none:
            guard options.readableBytes == 0 else {
                throw InvalidOpenSSHKey.unexpectedKDFNoneOptions
            }
            
            self = .none
        case .bcrypt:
            guard
                let salt = options.readSSHBuffer(),
                let rounds: UInt32 = options.readInteger(),
                rounds < 18
            else {
                throw InvalidOpenSSHKey.invalidOrUnsupportedBCryptConfig
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
            throw InvalidOpenSSHKey.unsupportedFeature(.unsupportedPublicKeyType)
        }
        self = keyType
    }
}
