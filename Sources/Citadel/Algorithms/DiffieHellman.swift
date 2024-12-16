import CCryptoBoringSSL
import Foundation
import BigInt
import NIO
import NIOSSH
import Crypto

public enum DiffieHellman {
    public enum Group14: DiffieHellman.Group {
        public static let groupName = "group14"
        public static let generator: [UInt8] = [ 0x02 ]
        public static let publicExponent: [UInt8] = [ 0x01, 0x00, 0x01 ]
        public static let prime: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
            0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
            0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
            0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
            0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
            0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
            0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
            0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
            0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
            0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
            0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
            0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
            0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
            0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
            0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
            0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
            0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
            0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
            0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
            0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
            0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
            0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
            0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
            0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
            0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
            0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
            0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
            0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
            0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
            0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ]
    }

    public protocol Group {
        static var groupName: String { get }
        static var generator: [UInt8] { get }
        static var publicExponent: [UInt8] { get }
        static var prime: [UInt8] { get }
    }

    public protocol HashFunction: Crypto.HashFunction {
        static var dhName: String { get }
        static var rsaName: String { get }
    }

    public struct KeyExchange<Group: DiffieHellman.Group, Hash: DiffieHellman.HashFunction>: NIOSSHKeyExchangeAlgorithmProtocol {
        public static var keyExchangeInitMessageId: UInt8 { 30 }
        public static var keyExchangeReplyMessageId: UInt8 { 31 }

        public static var keyExchangeAlgorithmNames: [Substring] {
            ["diffie-hellman-\(Group.groupName)-\(Hash.dhName)"]
        }

        private var previousSessionIdentifier: ByteBuffer?
        private var ourRole: SSHConnectionRole
        private var theirKey: RSA<Group, Hash>.PublicKey?
        private var sharedSecret: Data?
        public let ourKey: RSA<Group, Hash>.PrivateKey

        private struct _KeyExchangeResult {
            var sessionID: ByteBuffer
            var exchangeHash: Hash.Digest
            var keys: NIOSSHSessionKeys
        }

        public init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
            self.ourRole = ourRole
            self.previousSessionIdentifier = previousSessionIdentifier
            self.ourKey = RSA<Group, Hash>.PrivateKey()
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

            let group = CCryptoBoringSSL_BN_bin2bn(Group.prime, Group.prime.count, nil)
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

            let exchangeHash = Hash.hash(data: initialExchangeBytes.readableBytesView)

            let sessionID: ByteBuffer
            if let previousSessionIdentifier = self.previousSessionIdentifier {
                sessionID = previousSessionIdentifier
            } else {
                var hashBytes = allocator.buffer(capacity: Hash.Digest.byteCount)
                hashBytes.writeContiguousBytes(exchangeHash)
                sessionID = hashBytes
            }

            // Now we can generate the keys.
            let keys = self.generateKeys(secret: secret, exchangeHash: exchangeHash, sessionID: sessionID, expectedKeySizes: expectedKeySizes)

            // All done!
            return _KeyExchangeResult(sessionID: sessionID, exchangeHash: exchangeHash, keys: keys)
        }

        private func generateKeys(secret: UnsafeMutablePointer<BIGNUM>, exchangeHash: Hash.Digest, sessionID: ByteBuffer, expectedKeySizes: ExpectedKeySizes) -> NIOSSHSessionKeys {
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
                SymmetricKey(data: calculateSha1Key(letter: letter, expectedKeySize: size))
            }

            func calculateSha1Key(letter: UInt8, expectedKeySize size: Int) -> [UInt8] {
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

                    result += Insecure.SHA1.hash(data: hashInput.readableBytesView)
                }

                result.removeLast(result.count - size)
                return result
            }

            switch self.ourRole {
            case .client:
                return NIOSSHSessionKeys(
                    initialInboundIV: calculateSha1Key(letter: UInt8(ascii: "B"), expectedKeySize: expectedKeySizes.ivSize),
                    initialOutboundIV: calculateSha1Key(letter: UInt8(ascii: "A"), expectedKeySize: expectedKeySizes.ivSize),
                    inboundEncryptionKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "D"), expectedKeySize: expectedKeySizes.encryptionKeySize),
                    outboundEncryptionKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "C"), expectedKeySize: expectedKeySizes.encryptionKeySize),
                    inboundMACKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "F"), expectedKeySize: expectedKeySizes.macKeySize),
                    outboundMACKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "E"), expectedKeySize: expectedKeySizes.macKeySize))
            case .server:
                return NIOSSHSessionKeys(
                    initialInboundIV: calculateSha1Key(letter: UInt8(ascii: "A"), expectedKeySize: expectedKeySizes.ivSize),
                    initialOutboundIV: calculateSha1Key(letter: UInt8(ascii: "B"), expectedKeySize: expectedKeySizes.ivSize),
                    inboundEncryptionKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "C"), expectedKeySize: expectedKeySizes.encryptionKeySize),
                    outboundEncryptionKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "D"), expectedKeySize: expectedKeySizes.encryptionKeySize),
                    inboundMACKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "E"), expectedKeySize: expectedKeySizes.macKeySize),
                    outboundMACKey: calculateSha1SymmetricKey(letter: UInt8(ascii: "F"), expectedKeySize: expectedKeySizes.macKeySize))
            }
        }
    }
}

extension Insecure.SHA1: DiffieHellman.HashFunction {
    public static var dhName: String { "sha1" }
    public static var rsaName: String { "ssh-rsa" }
}

extension SHA256: DiffieHellman.HashFunction {
    public static var dhName: String { "sha256" }
    public static var rsaName: String { "rsa-sha2-256" }
}

extension SHA512: DiffieHellman.HashFunction {
    public static var dhName: String { "sha512" }
    public static var rsaName: String { "rsa-sha2-512" }
}

public typealias DiffieHellmanGroup14Sha1 = DiffieHellman.KeyExchange<DiffieHellman.Group14, Insecure.SHA1>
public typealias DiffieHellmanGroup14Sha256 = DiffieHellman.KeyExchange<DiffieHellman.Group14, SHA256>
public typealias DiffieHellmanGroup14Sha512 = DiffieHellman.KeyExchange<DiffieHellman.Group14, SHA512>
