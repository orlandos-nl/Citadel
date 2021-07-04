import CCryptoBoringSSL
import Foundation
import Crypto
import NIO
import CryptoSwift
import NIOSSH

enum CitadelError: Error {
    case invalidKeySize
    case invalidEncryptedPacketLength
    case invalidDecryptedPlaintextLength
    case insufficientPadding, excessPadding
    case invalidMac
}

public final class AES256CTR: NIOSSHTransportProtection {
    public static let macName: String? = "hmac-sha1"
    public static let cipherBlockSize = AES.blockSize
    public static let cipherName = "aes128-ctr"
    
    public static let keySizes = ExpectedKeySizes(
        ivSize: 16,
        encryptionKeySize: 16, // 128 bits
        macKeySize: 20 // HAMC-SHA-1
    )
    
    public let macBytes = 20 // HAMC-SHA-1
    private var keys: NIOSSHSessionKeys
    private var decryptionContext: UnsafeMutablePointer<EVP_CIPHER_CTX>
    private var encryptionContext: UnsafeMutablePointer<EVP_CIPHER_CTX>
    
    public init(initialKeys: NIOSSHSessionKeys) throws {
        guard
            initialKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8,
            initialKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8
        else {
            throw CitadelError.invalidKeySize
        }

        self.keys = initialKeys
        
        self.encryptionContext = CCryptoBoringSSL_EVP_CIPHER_CTX_new()
        self.decryptionContext = CCryptoBoringSSL_EVP_CIPHER_CTX_new()
        
        let outboundEncryptionKey = initialKeys.outboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            let outboundEncryptionKey = Array(buffer.bindMemory(to: UInt8.self))
            assert(outboundEncryptionKey.count == Self.keySizes.encryptionKeySize)
            return outboundEncryptionKey
        }
        
        let inboundEncryptionKey = initialKeys.inboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            let inboundEncryptionKey = Array(buffer.bindMemory(to: UInt8.self))
            assert(inboundEncryptionKey.count == Self.keySizes.encryptionKeySize)
            return inboundEncryptionKey
        }
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            encryptionContext,
            CCryptoBoringSSL_EVP_aes_128_ctr(),
            outboundEncryptionKey,
            initialKeys.initialOutboundIV,
            1
        ) == 1 else {
            #warning("Throw error")
            fatalError()
        }
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            decryptionContext,
            CCryptoBoringSSL_EVP_aes_128_ctr(),
            inboundEncryptionKey,
            initialKeys.initialInboundIV,
            1
        ) == 1 else {
            #warning("Throw error")
            fatalError()
        }
    }
    
    public func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        guard
            newKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8,
            newKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8
        else {
            throw CitadelError.invalidKeySize
        }

        self.keys = newKeys
        
        let outboundEncryptionKey = newKeys.outboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            let outboundEncryptionKey = Array(buffer.bindMemory(to: UInt8.self))
            assert(outboundEncryptionKey.count == Self.keySizes.encryptionKeySize)
            return outboundEncryptionKey
        }
        
        let inboundEncryptionKey = newKeys.inboundEncryptionKey.withUnsafeBytes { buffer -> [UInt8] in
            let inboundEncryptionKey = Array(buffer.bindMemory(to: UInt8.self))
            assert(inboundEncryptionKey.count == Self.keySizes.encryptionKeySize)
            return inboundEncryptionKey
        }
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            encryptionContext,
            CCryptoBoringSSL_EVP_aes_256_ctr(),
            outboundEncryptionKey,
            newKeys.initialOutboundIV,
            1
        ) == 1 else {
            #warning("Throw error")
            fatalError()
        }
        
        guard CCryptoBoringSSL_EVP_CipherInit(
            decryptionContext,
            CCryptoBoringSSL_EVP_aes_256_ctr(),
            inboundEncryptionKey,
            newKeys.initialInboundIV,
            1
        ) == 1 else {
            #warning("Throw error")
            fatalError()
        }
    }
    
    public func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        // For us, decrypting the first block is very easy: do nothing. The length bytes are already
        // unencrypted!
        guard source.readableBytes >= 16 else {
            throw CitadelError.invalidKeySize
        }
        
        try source.withUnsafeMutableReadableBytes { source in
            let source = source.bindMemory(to: UInt8.self)
            fatalError()
//            let decrypted = try inboundAES.decrypt(Array(source[0..<16]))
//            source.baseAddress!.assign(from: decrypted, count: 16)
        }
    }
    
    public func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        var plaintext: [UInt8]
        var macHash: [UInt8]

        // Establish a nested scope here to avoid the byte buffer views causing an accidental CoW.
        do {
            // The first 4 bytes are the length. The last 16 are the tag. Everything else is ciphertext. We expect
            // that the ciphertext is a clean multiple of the block size, and to be non-zero.
            guard
                let lengthView = source.readSlice(length: 4)?.readableBytesView,
                let ciphertextView = source.readBytes(length: source.readableBytes - macBytes),
                let mac = source.readBytes(length: macBytes),
                ciphertextView.count > 0, ciphertextView.count % Self.cipherBlockSize == 0
            else {
                // The only way this fails is if the payload doesn't match this encryption scheme.
                throw CitadelError.invalidEncryptedPacketLength
            }

            // Ok, let's try to decrypt this data.
//            plaintext = try inboundAES.decrypt(ciphertextView)
            fatalError()
            macHash = mac
            
            // All good! A quick soundness check to verify that the length of the plaintext is ok.
            guard plaintext.count % Self.cipherBlockSize == 0, plaintext.count == ciphertextView.count else {
                throw CitadelError.invalidDecryptedPlaintextLength
            }
        }
        
        // Ok, we want to write the plaintext back into the buffer. This contains the padding length byte and the padding
        // bytes, so we want to strip those. We write back into the buffer and then slice the return value out because
        // it's highly likely that the source buffer is held uniquely, which means we can avoid an allocation.
        try plaintext.removePaddingBytes()
        source.prependBytes(plaintext)
        
        // This slice read must succeed, as we just wrote in that many bytes.
        let result = source.readSlice(length: plaintext.count)!
        
        var hmac = Crypto.HMAC<Crypto.Insecure.SHA1>(key: keys.inboundMACKey)
        fatalError()
//        decryptionSequenceNumber._cVarArgEncoding.withUnsafeBytes { buffer in
//            hmac.update(data: buffer)
//        }
        hmac.update(data: result.readableBytesView)
        
        let isValid = hmac.finalize().withUnsafeBytes { buffer -> Bool in
            let buffer = Array(buffer.bindMemory(to: UInt8.self))
            return buffer == macHash
        }
        
        if !isValid {
            throw CitadelError.invalidMac
        }
        
        return result
    }
    
    public func encryptPacket(
        _ packet: NIOSSHEncryptablePayload,
        to outboundBuffer: inout ByteBuffer,
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
        
        var hmac = Crypto.HMAC<Crypto.Insecure.SHA1>(key: keys.outboundMACKey)
        sequenceNumber._cVarArgEncoding.withUnsafeBytes { buffer in
            hmac.update(data: buffer)
        }
        hmac.update(data: plaintext)
        let macHash = hmac.finalize()
        
        let ciphertext = plaintext.withUnsafeBufferPointer { plaintext -> [UInt8] in
            let plaintextPointer = plaintext.baseAddress!
            
            return [UInt8](unsafeUninitializedCapacity: plaintext.count) { ciphertext, count in
                let ciphertextPointer = ciphertext.baseAddress!
                
                while count < encryptedBufferSize {
                    guard CCryptoBoringSSL_EVP_Cipher(
                        encryptionContext,
                        ciphertextPointer + count,
                        plaintextPointer + count,
                        16
                    ) == 1 else {
                        fatalError()
                    }
                    
                    count += 16
                }
            }
        }

        assert(ciphertext.count == plaintext.count)
        // We now want to overwrite the portion of the bytebuffer that contains the plaintext with the ciphertext, and then append the
        // tag.
        outboundBuffer.setBytes(ciphertext, at: packetLengthIndex)
        print(Array(macHash), macHash.byteCount)
        outboundBuffer.writeContiguousBytes(macHash)
    }
    
    deinit {
        CCryptoBoringSSL_EVP_CIPHER_CTX_free(encryptionContext)
        CCryptoBoringSSL_EVP_CIPHER_CTX_free(decryptionContext)
    }
}

extension Array where Element == UInt8 {
    /// Removes the padding bytes from a Data object.
    fileprivate mutating func removePaddingBytes() throws {
        guard let paddingLength = self.first, paddingLength >= 4 else {
            throw CitadelError.insufficientPadding
        }

        // We're going to slice out the content bytes. To do that, can simply find the end index of the content, and confirm it's
        // not walked off the front of the buffer. If it has, there's too much padding and an error has occurred.
        let contentStartIndex = self.index(after: self.startIndex)
        guard let contentEndIndex = self.index(self.endIndex, offsetBy: -Int(paddingLength), limitedBy: contentStartIndex) else {
            throw CitadelError.excessPadding
        }

        self = Array(self[contentStartIndex ..< contentEndIndex])
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
