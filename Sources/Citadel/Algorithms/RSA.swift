import NIO
import NIOFoundationCompat
import BigInt
import NIOSSH
import CCryptoBoringSSL
import Foundation
import Crypto

public enum RSA<Group: DiffieHellman.Group, Hash: DiffieHellman.HashFunction> {}

extension Insecure {
    public typealias RSA = Citadel.RSA<DiffieHellman.Group14, Insecure.SHA1>
}

extension RSA {
    public final class PublicKey: NIOSSHPublicKeyProtocol {
        public static var publicKeyPrefix: String { Hash.rsaName }
        public static var keyExchangeAlgorithms: [String] {
            switch Hash.self {
            case is Insecure.SHA1.Type:
                return ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]
            case is SHA256.Type:
                return ["diffie-hellman-group1-sha256", "diffie-hellman-group14-sha256"]
            case is SHA512.Type:
                return ["diffie-hellman-group1-sha512", "diffie-hellman-group14-sha512"]
            default:
                return []
            }
        }

        // PublicExponent e
        internal let publicExponent: UnsafeMutablePointer<BIGNUM>
        
        // Modulus n
        internal let modulus: UnsafeMutablePointer<BIGNUM>
        
        deinit {
            CCryptoBoringSSL_BN_free(modulus)
            CCryptoBoringSSL_BN_free(publicExponent)
        }
        
        public var rawRepresentation: Data {
            var buffer = ByteBuffer()
            buffer.writeMPBignum(publicExponent)
            buffer.writeMPBignum(modulus)
            return buffer.readData(length: buffer.readableBytes)!
        }
        
        enum PubkeyParseError: Error {
            case invalidInitialSequence, invalidAlgorithmIdentifier, invalidSubjectPubkey, forbiddenTrailingData, invalidRSAPubkey
        }
        
        public init(publicExponent: UnsafeMutablePointer<BIGNUM>, modulus: UnsafeMutablePointer<BIGNUM>) {
            self.publicExponent = publicExponent
            self.modulus = modulus
        }
        
        public func encrypt<D: DataProtocol>(for message: D) throws -> EncryptedMessage {
//            let message = BigUInt(Data(message))
//
//            guard message > .zero && message <= modulus - 1 else {
//                throw RSAError.messageRepresentativeOutOfRange
//            }
//
//            let result = message.power(publicExponent, modulus: modulus)
//            return EncryptedMessage(rawRepresentation: result.serialize())
            throw CitadelError.unsupported
        }
        
        public func isValidSignature<D: DataProtocol>(_ signature: Signature, for digest: D) -> Bool {
            let context = CCryptoBoringSSL_RSA_new()
            defer { CCryptoBoringSSL_RSA_free(context) }

            // Copy, so that our local `self.modulus` isn't freed by RSA_free
            let modulus = CCryptoBoringSSL_BN_new()!
            let publicExponent = CCryptoBoringSSL_BN_new()!
            
            CCryptoBoringSSL_BN_copy(modulus, self.modulus)
            CCryptoBoringSSL_BN_copy(publicExponent, self.publicExponent)
            guard CCryptoBoringSSL_RSA_set0_key(
                context,
                modulus,
                publicExponent,
                nil
            ) == 1 else {
                return false
            }
            
            var clientSignature = [UInt8](repeating: 0, count: 20)
            let digest = Array(digest)
            CCryptoBoringSSL_SHA1(digest, digest.count, &clientSignature)
            
            let signature = Array(signature.rawRepresentation)
            return CCryptoBoringSSL_RSA_verify(
                NID_sha1,
                clientSignature,
                20,
                signature,
                signature.count,
                context
            ) == 1
        }
        
        public func isValidSignature<D>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool where D : DataProtocol {
            guard let signature = signature as? Signature else {
                return false
            }
            
            return isValidSignature(signature, for: data)
        }
        
        public func write(to buffer: inout ByteBuffer) -> Int {
            // For ssh-rsa, the format is public exponent `e` followed by modulus `n`
            var writtenBytes = 0
            writtenBytes += buffer.writeMPBignum(publicExponent)
            writtenBytes += buffer.writeMPBignum(modulus)
            return writtenBytes
        }
        
        static func read(consuming buffer: inout ByteBuffer) throws -> PublicKey {
            try read(from: &buffer)
        }
        
        public static func read(from buffer: inout ByteBuffer) throws -> PublicKey {
            guard
                var publicExponent = buffer.readSSHBuffer(),
                var modulus = buffer.readSSHBuffer()
            else {
                throw RSAError(message: "Invalid signature format")
            }
            
            let publicExponentBytes = publicExponent.readBytes(length: publicExponent.readableBytes)!
            let modulusBytes = modulus.readBytes(length: modulus.readableBytes)!
            return .init(
                publicExponent: CCryptoBoringSSL_BN_bin2bn(publicExponentBytes, publicExponentBytes.count, nil),
                modulus: CCryptoBoringSSL_BN_bin2bn(modulusBytes, modulusBytes.count, nil)
            )
        }
    }
    
    public struct EncryptedMessage: ContiguousBytes {
        public let rawRepresentation: Data
        
        public init<D>(rawRepresentation: D) where D : DataProtocol {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try rawRepresentation.withUnsafeBytes(body)
        }
    }
    
    public struct Signature: ContiguousBytes, NIOSSHSignatureProtocol {
        public static var signaturePrefix: String { Hash.rsaName }

        public let rawRepresentation: Data
        
        public init<D>(rawRepresentation: D) where D : DataProtocol {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try rawRepresentation.withUnsafeBytes(body)
        }
        
        public func write(to buffer: inout ByteBuffer) -> Int {
            // For SSH-RSA, the key format is the signature without lengths or paddings
            return buffer.writeSSHString(rawRepresentation)
        }
        
        public static func read(from buffer: inout ByteBuffer) throws -> Signature {
            guard let buffer = buffer.readSSHBuffer() else {
                throw RSAError(message: "Invalid signature format")
            }
            
            return Signature(rawRepresentation: buffer.getData(at: 0, length: buffer.readableBytes)!)
        }
    }
    
    public final class PrivateKey: NIOSSHPrivateKeyProtocol {

        public static var keyPrefix: String { Hash.rsaName }

        // Private Exponent
        internal let privateExponent: UnsafeMutablePointer<BIGNUM>
        
        // Public Exponent e
        internal let _publicKey: PublicKey
        
        public var publicKey: NIOSSHPublicKeyProtocol {
            _publicKey
        }
        
        public init(privateExponent: UnsafeMutablePointer<BIGNUM>, publicExponent: UnsafeMutablePointer<BIGNUM>, modulus: UnsafeMutablePointer<BIGNUM>) {
            self.privateExponent = privateExponent
            self._publicKey = PublicKey(publicExponent: publicExponent, modulus: modulus)
        }
        
        deinit {
            CCryptoBoringSSL_BN_free(privateExponent)
        }

        public init() {
            let privateKey = CCryptoBoringSSL_BN_new()!
            let publicKey = CCryptoBoringSSL_BN_new()!
            let group = CCryptoBoringSSL_BN_bin2bn(Group.prime, Group.prime.count, nil)!
            let generator = CCryptoBoringSSL_BN_bin2bn(Group.generator, Group.generator.count, nil)!
            let bignumContext = CCryptoBoringSSL_BN_CTX_new()

            CCryptoBoringSSL_BN_rand(privateKey, 256 * 8 - 1, 0, /*-1*/BN_RAND_BOTTOM_ANY)
            CCryptoBoringSSL_BN_mod_exp(publicKey, generator, privateKey, group, bignumContext)
            let eBytes = Group.publicExponent
            let e = CCryptoBoringSSL_BN_bin2bn(eBytes, eBytes.count, nil)!

            CCryptoBoringSSL_BN_CTX_free(bignumContext)
            CCryptoBoringSSL_BN_free(generator)
            CCryptoBoringSSL_BN_free(group)

            self.privateExponent = privateKey
            self._publicKey = PublicKey(
                publicExponent: e,
                modulus: publicKey
            )
        }

        public convenience init(bits: Int = 2047, publicExponent e: BigUInt = 65537) {
            self.init()
        }
        
        public func signature<D: DataProtocol>(for message: D) throws -> Signature {
            let context = CCryptoBoringSSL_RSA_new()
            defer { CCryptoBoringSSL_RSA_free(context) }

            // Copy, so that our local `self.modulus` isn't freed by RSA_free
            let modulus = CCryptoBoringSSL_BN_new()!
            let publicExponent = CCryptoBoringSSL_BN_new()!
            let privateExponent = CCryptoBoringSSL_BN_new()!
            
            CCryptoBoringSSL_BN_copy(modulus, self._publicKey.modulus)
            CCryptoBoringSSL_BN_copy(publicExponent, self._publicKey.publicExponent)
            CCryptoBoringSSL_BN_copy(privateExponent, self.privateExponent)
            guard CCryptoBoringSSL_RSA_set0_key(
                context,
                modulus,
                publicExponent,
                privateExponent
            ) == 1 else {
                throw CitadelError.signingError
            }
            
            let hash = Array(Insecure.SHA1.hash(data: message))
            let out = UnsafeMutablePointer<UInt8>.allocate(capacity: 4096)
            defer { out.deallocate() }
            var outLength: UInt32 = 4096
            let result = CCryptoBoringSSL_RSA_sign(
                NID_sha1,
                hash,
                UInt32(hash.count),
                out,
                &outLength,
                context
            )
            
            guard result == 1 else {
                throw CitadelError.signingError
            }
            
            return Signature(rawRepresentation: Data(bytes: out, count: Int(outLength)))
        }
        
        public func signature<D>(for data: D) throws -> NIOSSHSignatureProtocol where D : DataProtocol {
            return try self.signature(for: data) as Signature
        }
        
        public func decrypt(_ message: EncryptedMessage) throws -> Data {
//            let signature = BigUInt(message.rawRepresentation)
//
//            switch storage {
//            case let .privateExponent(privateExponent, modulus):
//                guard signature >= .zero && signature <= privateExponent else {
//                    throw RSAError.ciphertextRepresentativeOutOfRange
//                }
//
//                return signature.power(privateExponent, modulus: modulus).serialize()
//            }
            throw CitadelError.unsupported
        }
        
        internal func generatedSharedSecret(with publicKey: PublicKey, modulus: BigUInt) -> Data {
            let secret = CCryptoBoringSSL_BN_new()
            defer { CCryptoBoringSSL_BN_free(secret) }
            
            let ctx = CCryptoBoringSSL_BN_CTX_new()
            defer { CCryptoBoringSSL_BN_CTX_free(ctx) }
            
            let group = CCryptoBoringSSL_BN_bin2bn(Group.prime, Group.prime.count, nil)!
            defer { CCryptoBoringSSL_BN_free(group) }
            CCryptoBoringSSL_BN_mod_exp(
                secret,
                publicKey.modulus,
                privateExponent,
                group,
                ctx
            )
            
            var array = [UInt8]()
            array.reserveCapacity(Int(CCryptoBoringSSL_BN_num_bytes(secret)))
            CCryptoBoringSSL_BN_bn2bin(secret, &array)
            return Data(array)
        }
    }
}

public struct RSAError: Error {
    let message: String
    
    static let messageRepresentativeOutOfRange = RSAError(message: "message representative out of range")
    static let ciphertextRepresentativeOutOfRange = RSAError(message: "ciphertext representative out of range")
    static let signatureRepresentativeOutOfRange = RSAError(message: "signature representative out of range")
    static let invalidPem = RSAError(message: "invalid PEM")
    static let pkcs1Error = RSAError(message: "PKCS1Error")
}

extension BigUInt {
    public static func randomPrime(bits: Int) -> BigUInt {
        while true {
            var privateExponent = BigUInt.randomInteger(withExactWidth: bits)
            privateExponent |= 1
            
            if privateExponent.isPrime() {
                return privateExponent
            }
        }
    }
    
    fileprivate init(boringSSL bignum: UnsafeMutablePointer<BIGNUM>) {
        var data = [UInt8](repeating: 0, count: Int(CCryptoBoringSSL_BN_num_bytes(bignum)))
        CCryptoBoringSSL_BN_bn2bin(bignum, &data)
        self.init(Data(data))
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func readPositiveMPInt() -> BigUInt? {
        guard
            let length = readInteger(as: UInt32.self),
            let data = readData(length: Int(length))
        else {
            return nil
        }
        
        return BigUInt(data)
    }
    
    @discardableResult
    mutating func writePositiveMPInt<Buffer: Collection>(_ value: Buffer) -> Int where Buffer.Element == UInt8 {
        // A positive MPInt must have its high bit set to zero, and not have leading zero bytes unless it needs that
        // high bit set to zero. We address this by dropping all the leading zero bytes in the collection first.
        let trimmed = value.drop(while: { $0 == 0 })
        let needsLeadingZero = ((trimmed.first ?? 0) & 0x80) == 0x80

        // Now we write the length.
        var writtenBytes: Int

        if needsLeadingZero {
            writtenBytes = self.writeInteger(UInt32(trimmed.count + 1))
            writtenBytes += self.writeInteger(UInt8(0))
        } else {
            writtenBytes = self.writeInteger(UInt32(trimmed.count))
        }

        writtenBytes += self.writeBytes(trimmed)
        return writtenBytes
    }
    
    /// Writes the given bytes as an SSH string at the writer index. Moves the writer index forward.
    @discardableResult
    mutating func writeSSHString<Buffer: Collection>(_ value: Buffer) -> Int where Buffer.Element == UInt8 {
        let writtenBytes = self.setSSHString(value, at: self.writerIndex)
        self.moveWriterIndex(forwardBy: writtenBytes)
        return writtenBytes
    }
    
    /// Sets the given bytes as an SSH string at the given offset. Does not mutate the writer index.
    @discardableResult
    mutating func setSSHString<Buffer: Collection>(_ value: Buffer, at offset: Int) -> Int where Buffer.Element == UInt8 {
        // RFC 4251 § 5:
        //
        // > Arbitrary length binary string.  Strings are allowed to contain
        // > arbitrary binary data, including null characters and 8-bit
        // > characters.  They are stored as a uint32 containing its length
        // > (number of bytes that follow) and zero (= empty string) or more
        // > bytes that are the value of the string.  Terminating null
        // > characters are not used.
        let lengthLength = self.setInteger(UInt32(value.count), at: offset)
        let valueLength = self.setBytes(value, at: offset + lengthLength)
        return lengthLength + valueLength
    }
    
    /// Sets the readable bytes of a ByteBuffer as an SSH string at the given offset. Does not mutate the writer index.
    @discardableResult
    mutating func setSSHString(_ value: ByteBuffer, at offset: Int) -> Int {
        // RFC 4251 § 5:
        //
        // > Arbitrary length binary string.  Strings are allowed to contain
        // > arbitrary binary data, including null characters and 8-bit
        // > characters.  They are stored as a uint32 containing its length
        // > (number of bytes that follow) and zero (= empty string) or more
        // > bytes that are the value of the string.  Terminating null
        // > characters are not used.
        let lengthLength = self.setInteger(UInt32(value.readableBytes), at: offset)
        let valueLength = self.setBuffer(value, at: offset + lengthLength)
        return lengthLength + valueLength
    }
}
