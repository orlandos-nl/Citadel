import CCryptoBoringSSL
import Foundation
import BigInt
import NIO
import NIOSSH
import Crypto

public struct DiffieHellmanGroup14Sha256: NIOSSHKeyExchangeAlgorithmProtocol {
    public static let keyExchangeInitMessageId: UInt8 = 30
    public static let keyExchangeReplyMessageId: UInt8 = 31
    
    public static let keyExchangeAlgorithmNames: [Substring] = ["diffie-hellman-group14-sha256"]
    
    private var previousSessionIdentifier: ByteBuffer?
    private var ourRole: SSHConnectionRole
    private var theirKey: Insecure.RSA.PublicKey?
    private var sharedSecret: Data?
    public let ourKey: Insecure.RSA.PrivateKey
    public static var ourKey: Insecure.RSA.PrivateKey?
    
    private struct _KeyExchangeResult {
        var sessionID: ByteBuffer
        var exchangeHash: SHA256.Digest
        var keys: NIOSSHSessionKeys
    }
    
    public init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.previousSessionIdentifier = previousSessionIdentifier
        self.ourKey = Self.ourKey ?? Insecure.RSA.PrivateKey()
    }
    
    public func initiateKeyExchangeClientSide(allocator: ByteBufferAllocator) -> ByteBuffer {
        var buffer = allocator.buffer(capacity: 256)
        
        buffer.writeBignum(ourKey._publicKey.modulus)
        return buffer
    }
    
    public mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: ByteBuffer,
        serverHostKey: NIOSSHPrivateKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, NIOSSHKeyExchangeServerReply) {
        // With that, we have enough to finalize the key exchange.
        let kexResult = try self.finalizeKeyExchange(
            theirKeyBytes: message,
            initialExchangeBytes: &initialExchangeBytes,
            serverHostKey: serverHostKey.publicKey,
            allocator: allocator,
            expectedKeySizes: expectedKeySizes
        )
        
        // We should now sign the exchange hash.
        let exchangeHashSignature = try serverHostKey.sign(digest: kexResult.exchangeHash)
        
        // Ok, time to write the final message. We need to write our public key into it.
        // The largest key we're likely to end up with here is 256 bytes.
        var publicKeyBytes = allocator.buffer(capacity: 256)
        _ = self.ourKey.publicKey.write(to: &publicKeyBytes)
        
        // Now we have all we need.
        let responseMessage = NIOSSHKeyExchangeServerReply(
            hostKey: serverHostKey.publicKey,
            publicKey: publicKeyBytes,
            signature: exchangeHashSignature
        )
        
        return (KeyExchangeResult(sessionID: kexResult.sessionID, keys: kexResult.keys), responseMessage)
    }
    
    public mutating func receiveServerKeyExchangePayload(serverKeyExchangeMessage: NIOSSHKeyExchangeServerReply, initialExchangeBytes: inout ByteBuffer, allocator: ByteBufferAllocator, expectedKeySizes: ExpectedKeySizes) throws -> KeyExchangeResult {
        let kexResult = try self.finalizeKeyExchange(theirKeyBytes: serverKeyExchangeMessage.publicKey,
                                                     initialExchangeBytes: &initialExchangeBytes,
                                                     serverHostKey: serverKeyExchangeMessage.hostKey,
                                                     allocator: allocator,
                                                     expectedKeySizes: expectedKeySizes)
        
        // We can now verify signature over the exchange hash.
        guard serverKeyExchangeMessage.hostKey.isValidSignature(serverKeyExchangeMessage.signature, for: kexResult.exchangeHash) else {
            throw CitadelError.invalidSignature
        }
        
        // Great, all done here.
        return KeyExchangeResult(
            sessionID: kexResult.sessionID,
            keys: kexResult.keys
        )
    }
    
    private mutating func finalizeKeyExchange(theirKeyBytes f: ByteBuffer,
                                              initialExchangeBytes: inout ByteBuffer,
                                              serverHostKey: NIOSSHPublicKey,
                                              allocator: ByteBufferAllocator,
                                              expectedKeySizes: ExpectedKeySizes) throws -> _KeyExchangeResult {
        let f = f.getBytes(at: 0, length: f.readableBytes)!
        
        let serverPublicKey = CCryptoBoringSSL_BN_bin2bn(f, f.count, nil)!
        defer { CCryptoBoringSSL_BN_free(serverPublicKey) }
        let secret = CCryptoBoringSSL_BN_new()!
        let serverHostKeyBN = CCryptoBoringSSL_BN_new()
        defer { CCryptoBoringSSL_BN_free(serverHostKeyBN) }
        
        var buffer = ByteBuffer()
        serverHostKey.write(to: &buffer)
        buffer.readWithUnsafeReadableBytes { buffer in
            let buffer = buffer.bindMemory(to: UInt8.self)
            CCryptoBoringSSL_BN_bin2bn(buffer.baseAddress!, buffer.count, serverHostKeyBN)
            return buffer.count
        }
        
        let ctx = CCryptoBoringSSL_BN_CTX_new()
        defer { CCryptoBoringSSL_BN_CTX_free(ctx) }
        
        let group = CCryptoBoringSSL_BN_bin2bn(dh14p, dh14p.count, nil)
        defer { CCryptoBoringSSL_BN_free(group) }
        
        guard CCryptoBoringSSL_BN_mod_exp(
            secret,
            serverPublicKey,
            ourKey.privateExponent,
            group,
            ctx
        ) == 1 else {
            throw CitadelError.cryptographicError
        }
        
        var sharedSecret = [UInt8]()
        sharedSecret.reserveCapacity(Int(CCryptoBoringSSL_BN_num_bytes(secret)))
        CCryptoBoringSSL_BN_bn2bin(secret, &sharedSecret)
        
        self.sharedSecret = Data(sharedSecret)
        
        func hexEncodedString(array: [UInt8]) -> String {
            return array.map { String(format: "%02hhx", $0) }.joined()
        }
        
        //var offset = initialExchangeBytes.writerIndex
        initialExchangeBytes.writeCompositeSSHString {
            serverHostKey.write(to: &$0)
        }
        
        //offset = initialExchangeBytes.writerIndex
        switch self.ourRole {
        case .client:
            initialExchangeBytes.writeMPBignum(ourKey._publicKey.modulus)
            //offset = initialExchangeBytes.writerIndex
            initialExchangeBytes.writeMPBignum(serverPublicKey)
        case .server:
            initialExchangeBytes.writeMPBignum(serverPublicKey)
            initialExchangeBytes.writeMPBignum(ourKey._publicKey.modulus)
        }
        
        // Ok, now finalize the exchange hash. If we don't have a previous session identifier at this stage, we do now!
        initialExchangeBytes.writeMPBignum(secret)
        
        let exchangeHash = SHA256.hash(data: initialExchangeBytes.readableBytesView)
        
        let sessionID: ByteBuffer
        if let previousSessionIdentifier = self.previousSessionIdentifier {
            sessionID = previousSessionIdentifier
        } else {
            var hashBytes = allocator.buffer(capacity: SHA256.byteCount)
            hashBytes.writeContiguousBytes(exchangeHash)
            sessionID = hashBytes
        }
        
        // Now we can generate the keys.
        let keys = self.generateKeys(secret: secret, exchangeHash: exchangeHash, sessionID: sessionID, expectedKeySizes: expectedKeySizes)
        
        // All done!
        return _KeyExchangeResult(sessionID: sessionID, exchangeHash: exchangeHash, keys: keys)
    }
    
    private func generateKeys(secret: UnsafeMutablePointer<BIGNUM>, exchangeHash: SHA256.Digest, sessionID: ByteBuffer, expectedKeySizes: ExpectedKeySizes) -> NIOSSHSessionKeys {
        // Cool, now it's time to generate the keys. In my ideal world I'd have a mechanism to handle this digest securely, but this is
        // not available in CryptoKit so we're going to spill these keys all over the heap and the stack. This isn't ideal, but I don't
        // think the risk is too bad.
        //
        // We generate these as follows:
        //
        // - Initial IV client to server: HASH(K || H || "A" || session_id)
        //    (Here K is encoded as mpint and "A" as byte and session_id as raw
        //    data.  "A" means the single character A, ASCII 65).
        // - Initial IV server to client: HASH(K || H || "B" || session_id)
        // - Encryption key client to server: HASH(K || H || "C" || session_id)
        // - Encryption key server to client: HASH(K || H || "D" || session_id)
        // - Integrity key client to server: HASH(K || H || "E" || session_id)
        // - Integrity key server to client: HASH(K || H || "F" || session_id)
        
        func calculateSha1SymmetricKey(letter: UInt8, expectedKeySize size: Int) -> SymmetricKey {
            SymmetricKey(data: calculateSha256Key(letter: letter, expectedKeySize: size))
        }
        
        func calculateSha256Key(letter: UInt8, expectedKeySize size: Int) -> [UInt8] {
            var result = [UInt8]()
            var hashInput = ByteBuffer()
            
            while result.count < size {
                hashInput.moveWriterIndex(to: 0)
                hashInput.writeMPBignum(secret)
                hashInput.writeBytes(exchangeHash)
                
                if !result.isEmpty {
                    hashInput.writeBytes(result)
                } else {
                    hashInput.writeInteger(letter)
                    hashInput.writeBytes(sessionID.readableBytesView)
                }
                
                result += SHA256.hash(data: hashInput.readableBytesView)
            }
            
            result.removeLast(result.count - size)
            return result
        }
        
        switch self.ourRole {
        case .client:
            return NIOSSHSessionKeys(
                initialInboundIV: calculateSha256Key(letter: UInt8(ascii: "B"), expectedKeySize: expectedKeySizes.ivSize),
                initialOutboundIV: calculateSha256Key(letter: UInt8(ascii: "A"), expectedKeySize: expectedKeySizes.ivSize),
                inboundEncryptionKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "D"), expectedKeySize: expectedKeySizes.encryptionKeySize),
                outboundEncryptionKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "C"), expectedKeySize: expectedKeySizes.encryptionKeySize),
                inboundMACKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "F"), expectedKeySize: expectedKeySizes.macKeySize),
                outboundMACKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "E"), expectedKeySize: expectedKeySizes.macKeySize))
        case .server:
            return NIOSSHSessionKeys(
                initialInboundIV: calculateSha256Key(letter: UInt8(ascii: "A"), expectedKeySize: expectedKeySizes.ivSize),
                initialOutboundIV: calculateSha256Key(letter: UInt8(ascii: "B"), expectedKeySize: expectedKeySizes.ivSize),
                inboundEncryptionKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "C"), expectedKeySize: expectedKeySizes.encryptionKeySize),
                outboundEncryptionKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "D"), expectedKeySize: expectedKeySizes.encryptionKeySize),
                inboundMACKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "E"), expectedKeySize: expectedKeySizes.macKeySize),
                outboundMACKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "F"), expectedKeySize: expectedKeySizes.macKeySize))
        }
    }
}
