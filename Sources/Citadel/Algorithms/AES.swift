import CCryptoBoringSSL
import Foundation
import Crypto
import NIO
import NIOSSH

public final class AES128CTR: NIOSSHTransportProtection {
    private enum Mac {
        case sha1, sha256, sha512
    }
    
    public static let macNames = [
        "hmac-sha1",
        "hmac-sha2-256",
        "hmac-sha2-512"
    ]
    public static let cipherBlockSize = 16
    public static let cipherName = "aes128-ctr"
    public var macBytes: Int {
        keySizes.macKeySize
    }
    
    public static func keySizes(forMac mac: String?) throws -> ExpectedKeySizes {
        let macKeySize: Int
        
        switch mac {
        case "hmac-sha1":
            macKeySize = Insecure.SHA1.byteCount
        case "hmac-sha2-256":
            macKeySize = SHA256.byteCount
        case "hmac-sha2-512":
            macKeySize = SHA512.byteCount
        default:
            throw CitadelError.invalidMac
        }
        
        return ExpectedKeySizes(
            ivSize: 16,
            encryptionKeySize: 16, // 128 bits
            macKeySize: macKeySize
        )
    }
    
    private var keys: NIOSSHSessionKeys
    private var decryptionContext: UnsafeMutablePointer<EVP_CIPHER_CTX>
    private var encryptionContext: UnsafeMutablePointer<EVP_CIPHER_CTX>
    private let mac: Mac
    private let keySizes: ExpectedKeySizes
    
    public init(initialKeys: NIOSSHSessionKeys, mac: String?) throws {
        let keySizes = try Self.keySizes(forMac: mac)
        
        guard
            initialKeys.outboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8,
            initialKeys.inboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8
        else {
            throw CitadelError.invalidKeySize
        }
        
        switch mac {
        case "hmac-sha1":
            self.mac = .sha1
        case "hmac-sha2-256":
            self.mac = .sha256
        case "hmac-sha2-512":
            self.mac = .sha512
        default:
            throw CitadelError.invalidMac
        }

        self.keys = initialKeys
        self.keySizes = keySizes
        self.encryptionContext = CCryptoBoringSSL_EVP_CIPHER_CTX_new()
        self.decryptionContext = CCryptoBoringSSL_EVP_CIPHER_CTX_new()
        
        let outboundEncryptionKey = initialKeys.outboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            let outboundEncryptionKey = Array(buffer.bindMemory(to: UInt8.self))
            assert(outboundEncryptionKey.count == keySizes.encryptionKeySize)
            return outboundEncryptionKey
        }
        
        let inboundEncryptionKey = initialKeys.inboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            let inboundEncryptionKey = Array(buffer.bindMemory(to: UInt8.self))
            assert(inboundEncryptionKey.count == keySizes.encryptionKeySize)
            return inboundEncryptionKey
        }
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            encryptionContext,
            CCryptoBoringSSL_EVP_aes_128_ctr(),
            outboundEncryptionKey,
            initialKeys.initialOutboundIV,
            1
        ) == 1 else {
            throw CitadelError.cryptographicError
        }
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            decryptionContext,
            CCryptoBoringSSL_EVP_aes_128_ctr(),
            inboundEncryptionKey,
            initialKeys.initialInboundIV,
            0
        ) == 1 else {
            throw CitadelError.cryptographicError
        }
    }
    
    public func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        guard
            newKeys.outboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8,
            newKeys.inboundEncryptionKey.bitCount == keySizes.encryptionKeySize * 8
        else {
            throw CitadelError.invalidKeySize
        }

        self.keys = newKeys
        
        let outboundEncryptionKey = newKeys.outboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            let outboundEncryptionKey = Array(buffer.bindMemory(to: UInt8.self))
            assert(outboundEncryptionKey.count == keySizes.encryptionKeySize)
            return outboundEncryptionKey
        }
        
        let inboundEncryptionKey = newKeys.inboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            let inboundEncryptionKey = Array(buffer.bindMemory(to: UInt8.self))
            assert(inboundEncryptionKey.count == keySizes.encryptionKeySize)
            return inboundEncryptionKey
        }
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            encryptionContext,
            CCryptoBoringSSL_EVP_aes_128_ctr(),
            outboundEncryptionKey,
            newKeys.initialOutboundIV,
            1
        ) == 1 else {
            throw CitadelError.cryptographicError
        }
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            decryptionContext,
            CCryptoBoringSSL_EVP_aes_128_ctr(),
            inboundEncryptionKey,
            newKeys.initialInboundIV,
            0
        ) == 1 else {
            throw CitadelError.cryptographicError
        }
    }
    
    public func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        // For us, decrypting the first block is very easy: do nothing. The length bytes are already
        // unencrypted!
        guard source.readableBytes >= 16 else {
            throw CitadelError.invalidKeySize
        }
        
        try source.readWithUnsafeMutableReadableBytes { source in
            let source = source.bindMemory(to: UInt8.self)
            let out = UnsafeMutablePointer<UInt8>.allocate(capacity: Self.cipherBlockSize)
            defer { out.deallocate() }
            
            guard CCryptoBoringSSL_EVP_Cipher(
                decryptionContext,
                out,
                source.baseAddress!,
                Self.cipherBlockSize
            ) == 1 else {
                throw CitadelError.cryptographicError
            }
            
            memcpy(source.baseAddress!, out, Self.cipherBlockSize)
            return 0
        }
    }
    
    public func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        switch mac {
        case .sha1:
            return try _decryptAndVerifyRemainingPacket(&source, hash: Insecure.SHA1.self, sequenceNumber: sequenceNumber)
        case .sha256:
            return try _decryptAndVerifyRemainingPacket(&source, hash: SHA256.self, sequenceNumber: sequenceNumber)
        case .sha512:
            return try _decryptAndVerifyRemainingPacket(&source, hash: SHA512.self, sequenceNumber: sequenceNumber)
        }
    }
    
    internal func _decryptAndVerifyRemainingPacket<H: HashFunction>(_ source: inout ByteBuffer, hash: H.Type, sequenceNumber: UInt32) throws -> ByteBuffer {
        // The first 4 bytes are the length. The last 16 are the tag. Everything else is ciphertext. We expect
        // that the ciphertext is a clean multiple of the block size, and to be non-zero.
        guard
            var plaintext = source.readBytes(length: 16),
            let ciphertext = source.readBytes(length: source.readableBytes - keySizes.macKeySize),
            let macHash = source.readBytes(length: keySizes.macKeySize),
            ciphertext.count % Self.cipherBlockSize == 0
        else {
            // The only way this fails is if the payload doesn't match this encryption scheme.
            throw CitadelError.invalidEncryptedPacketLength
        }

        if !ciphertext.isEmpty {
            // Ok, let's try to decrypt this data.
            plaintext += try ciphertext.withUnsafeBufferPointer { ciphertext -> [UInt8] in
                let ciphertextPointer = ciphertext.baseAddress!
                
                return try [UInt8](
                    unsafeUninitializedCapacity: ciphertext.count,
                    initializingWith: { plaintext, count in
                    let plaintextPointer = plaintext.baseAddress!
                    
                    while count < ciphertext.count {
                        guard CCryptoBoringSSL_EVP_Cipher(
                            decryptionContext,
                            plaintextPointer + count,
                            ciphertextPointer + count,
                            Self.cipherBlockSize
                        ) == 1 else {
                            throw CitadelError.cryptographicError
                        }
                        
                        count += Self.cipherBlockSize
                    }
                })
            }
            
            // All good! A quick soundness check to verify that the length of the plaintext is ok.
            guard plaintext.count % Self.cipherBlockSize == 0 else {
                throw CitadelError.invalidDecryptedPlaintextLength
            }
        }
        
        func test(sequenceNumber: UInt32) -> Bool {
            var hmac = Crypto.HMAC<H>(key: keys.inboundMACKey)
            withUnsafeBytes(of: sequenceNumber.bigEndian) { buffer in
                hmac.update(data: buffer)
            }
            hmac.update(data: plaintext)
            
            return hmac.finalize().withUnsafeBytes { buffer -> Bool in
                let buffer = Array(buffer.bindMemory(to: UInt8.self))
                return buffer == macHash
            }
        }
        
        if !test(sequenceNumber: sequenceNumber) {
            throw CitadelError.invalidMac
        }
        
        plaintext.removeFirst(4)
        let paddingLength = Int(plaintext.removeFirst())
        
        guard paddingLength < plaintext.count else {
            throw CitadelError.invalidDecryptedPlaintextLength
        }
        
        plaintext.removeLast(paddingLength)
        
        return ByteBuffer(bytes: plaintext)
    }
    
    public func encryptPacket(
        _ packet: NIOSSHEncryptablePayload,
        to outboundBuffer: inout ByteBuffer,
        sequenceNumber: UInt32
    ) throws {
        switch mac {
        case .sha1:
            try _encryptPacket(packet, to: &outboundBuffer, hashFunction: Insecure.SHA1.self, sequenceNumber: sequenceNumber)
        case .sha256:
            try _encryptPacket(packet, to: &outboundBuffer, hashFunction: SHA256.self, sequenceNumber: sequenceNumber)
        case .sha512:
            try _encryptPacket(packet, to: &outboundBuffer, hashFunction: SHA512.self, sequenceNumber: sequenceNumber)
        }
    }
    
    internal func _encryptPacket<H: HashFunction>(
        _ packet: NIOSSHEncryptablePayload,
        to outboundBuffer: inout ByteBuffer,
        hashFunction: H.Type,
        sequenceNumber: UInt32
    ) throws {
        // Keep track of where the length is going to be written.
        let packetLengthIndex = outboundBuffer.writerIndex
        let packetLengthLength = MemoryLayout<UInt32>.size
        let packetPaddingIndex = outboundBuffer.writerIndex + packetLengthLength
        let packetPaddingLength = MemoryLayout<UInt8>.size

        outboundBuffer.moveWriterIndex(forwardBy: packetLengthLength + packetPaddingLength)

        // First, we write the packet.
        let payloadBytes = outboundBuffer.writeEncryptablePayload(packet)

        // Ok, now we need to pad. The rules for padding for AES GCM are:
        //
        // 1. We must pad out such that the total encrypted content (padding length byte,
        //     plus content bytes, plus padding bytes) is a multiple of the block size.
        // 2. At least 4 bytes of padding MUST be added.
        // 3. This padding SHOULD be random.
        //
        // Note that, unlike other protection modes, the length is not encrypted, and so we
        // must exclude it from the padding calculation.
        //
        // So we check how many bytes we've already written, use modular arithmetic to work out
        // how many more bytes we need, and then if that's fewer than 4 we add a block size to it
        // to fill it out.
        let headerLength = packetLengthLength + packetPaddingLength
        var encryptedBufferSize = headerLength + payloadBytes
        let writtenBytes = headerLength + payloadBytes
        var paddingLength = Self.cipherBlockSize - (writtenBytes % Self.cipherBlockSize)
        if paddingLength < 4 {
            paddingLength += Self.cipherBlockSize
        }
        
        if headerLength + payloadBytes + paddingLength < Self.cipherBlockSize {
            paddingLength = Self.cipherBlockSize - headerLength - payloadBytes
        }

        // We now want to write that many padding bytes to the end of the buffer. These are supposed to be
        // random bytes. We're going to get those from the system random number generator.
        encryptedBufferSize += outboundBuffer.writeSSHPaddingBytes(count: paddingLength)
        precondition(encryptedBufferSize % Self.cipherBlockSize == 0, "Incorrectly counted buffer size; got \(encryptedBufferSize)")

        // We now know the length: it's going to be "encrypted buffer size". The length does not include the tag, so don't add it.
        // Let's write that in. We also need to write the number of padding bytes in.
        outboundBuffer.setInteger(UInt32(encryptedBufferSize - packetLengthLength), at: packetLengthIndex)
        outboundBuffer.setInteger(UInt8(paddingLength), at: packetPaddingIndex)

        // Ok, nice! Now we need to encrypt the data. We pass the length field as additional authenticated data, and the encrypted
        // payload portion as the data to encrypt. We know these views will be valid, so we forcibly unwrap them: if they're invalid,
        // our math was wrong and we cannot recover.
        let plaintext = outboundBuffer.getBytes(at: packetLengthIndex, length: encryptedBufferSize)!
        assert(plaintext.count % Self.cipherBlockSize == 0)
        
        var hmac = Crypto.HMAC<H>(key: keys.outboundMACKey)
        withUnsafeBytes(of: sequenceNumber.bigEndian) { buffer in
            hmac.update(data: buffer)
        }
        hmac.update(data: plaintext)
        let macHash = hmac.finalize()
        
        let ciphertext = try plaintext.withUnsafeBufferPointer { plaintext -> [UInt8] in
            let plaintextPointer = plaintext.baseAddress!
            
            return try [UInt8](unsafeUninitializedCapacity: plaintext.count) { ciphertext, count in
                let ciphertextPointer = ciphertext.baseAddress!
                
                while count < encryptedBufferSize {
                    guard CCryptoBoringSSL_EVP_Cipher(
                        encryptionContext,
                        ciphertextPointer + count,
                        plaintextPointer + count,
                        Self.cipherBlockSize
                    ) == 1 else {
                        throw CitadelError.cryptographicError
                    }
                    
                    count += Self.cipherBlockSize
                }
            }
        }

        assert(ciphertext.count == plaintext.count)
        // We now want to overwrite the portion of the bytebuffer that contains the plaintext with the ciphertext, and then append the
        // tag.
        outboundBuffer.setBytes(ciphertext, at: packetLengthIndex)
        outboundBuffer.writeContiguousBytes(macHash)
    }
    
    deinit {
        CCryptoBoringSSL_EVP_CIPHER_CTX_free(encryptionContext)
        CCryptoBoringSSL_EVP_CIPHER_CTX_free(decryptionContext)
    }
}

extension ByteBuffer {
    /// Prepends the given Data to this ByteBuffer.
    ///
    /// Will crash if there isn't space in the front of this buffer, so please ensure there is!
    fileprivate mutating func prependBytes(_ bytes: [UInt8]) {
        self.moveReaderIndex(to: self.readerIndex - bytes.count)
        self.setContiguousBytes(bytes, at: self.readerIndex)
    }
}
