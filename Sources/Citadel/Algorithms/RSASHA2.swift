import NIO
import NIOSSH
import CCryptoBoringSSL
import Foundation
import Crypto

// RFC 8332 signature algorithms for RSA keys: `rsa-sha2-256` / `rsa-sha2-512`.
//
// Citadel's `Insecure.RSA` types sign with SHA-1 and name themselves `ssh-rsa`.
// OpenSSH 8.8 (2021) dropped `ssh-rsa` from the default
// PubkeyAcceptedAlgorithms, so an RSA key can no longer authenticate against a
// stock modern server. The key material is identical - only the signature hash
// and the algorithm name change - so these types wrap the existing key and
// re-label it.

/// Hash variant for an RFC 8332 RSA signature.
public protocol RSASHA2Variant: Sendable {
    /// Wire name, used both as the public key algorithm and the signature type.
    static var algorithmName: String { get }
    /// BoringSSL NID for the digest.
    static var nid: Int32 { get }
    static func digest<D: DataProtocol>(_ data: D) -> [UInt8]
}

public enum RSASHA2_256: RSASHA2Variant {
    public static let algorithmName = "rsa-sha2-256"
    public static let nid = NID_sha256
    public static func digest<D: DataProtocol>(_ data: D) -> [UInt8] {
        Array(SHA256.hash(data: Data(data)))
    }
}

public enum RSASHA2_512: RSASHA2Variant {
    public static let algorithmName = "rsa-sha2-512"
    public static let nid = NID_sha512
    public static func digest<D: DataProtocol>(_ data: D) -> [UInt8] {
        Array(SHA512.hash(data: Data(data)))
    }
}

extension Insecure.RSA {

    /// An RSA signature carrying an RFC 8332 algorithm name.
    public struct SHA2Signature<Variant: RSASHA2Variant>: ContiguousBytes, NIOSSHSignatureProtocol {
        public static var signaturePrefix: String { Variant.algorithmName }

        public let rawRepresentation: Data

        public init<D>(rawRepresentation: D) where D: DataProtocol {
            self.rawRepresentation = Data(rawRepresentation)
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try rawRepresentation.withUnsafeBytes(body)
        }

        public func write(to buffer: inout ByteBuffer) -> Int {
            buffer.writeSSHString(rawRepresentation)
        }

        public static func read(from buffer: inout ByteBuffer) throws -> Self {
            guard let buffer = buffer.readSSHBuffer() else {
                throw RSAError(message: "Invalid signature format")
            }
            return .init(rawRepresentation: buffer.getData(at: 0, length: buffer.readableBytes)!)
        }
    }

    /// The same RSA public key (`e`, `n` on the wire) under an RFC 8332 name.
    public final class SHA2PublicKey<Variant: RSASHA2Variant>: NIOSSHPublicKeyProtocol {
        public static var publicKeyPrefix: String { Variant.algorithmName }

        internal let base: PublicKey

        internal init(base: PublicKey) {
            self.base = base
        }

        public var rawRepresentation: Data { base.rawRepresentation }

        /// Wire body is identical to `ssh-rsa`: mpint e, mpint n. Only the
        /// algorithm name written around it differs.
        public func write(to buffer: inout ByteBuffer) -> Int {
            base.write(to: &buffer)
        }

        public static func read(from buffer: inout ByteBuffer) throws -> Self {
            .init(base: try PublicKey.read(from: &buffer))
        }

        public func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool {
            guard let signature = signature as? SHA2Signature<Variant> else { return false }

            let context = CCryptoBoringSSL_RSA_new()
            defer { CCryptoBoringSSL_RSA_free(context) }

            // Copy: RSA_free would otherwise free the key's own bignums.
            let modulus = CCryptoBoringSSL_BN_new()!
            let publicExponent = CCryptoBoringSSL_BN_new()!
            CCryptoBoringSSL_BN_copy(modulus, base.modulus)
            CCryptoBoringSSL_BN_copy(publicExponent, base.publicExponent)
            guard CCryptoBoringSSL_RSA_set0_key(context, modulus, publicExponent, nil) == 1 else {
                return false
            }

            let digest = Variant.digest(data)
            let signatureBytes = Array(signature.rawRepresentation)
            return CCryptoBoringSSL_RSA_verify(
                Variant.nid,
                digest,
                digest.count,
                signatureBytes,
                signatureBytes.count,
                context
            ) == 1
        }
    }

    /// An RSA private key that signs with SHA-2 and offers itself as
    /// `rsa-sha2-256` / `rsa-sha2-512`.
    public final class SHA2PrivateKey<Variant: RSASHA2Variant>: NIOSSHPrivateKeyProtocol {
        public static var keyPrefix: String { Variant.algorithmName }

        private let base: PrivateKey

        public init(_ base: PrivateKey) {
            self.base = base
        }

        public var publicKey: NIOSSHPublicKeyProtocol {
            SHA2PublicKey<Variant>(base: base._publicKey)
        }

        public func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
            let context = CCryptoBoringSSL_RSA_new()
            defer { CCryptoBoringSSL_RSA_free(context) }

            let modulus = CCryptoBoringSSL_BN_new()!
            let publicExponent = CCryptoBoringSSL_BN_new()!
            let privateExponent = CCryptoBoringSSL_BN_new()!
            CCryptoBoringSSL_BN_copy(modulus, base._publicKey.modulus)
            CCryptoBoringSSL_BN_copy(publicExponent, base._publicKey.publicExponent)
            CCryptoBoringSSL_BN_copy(privateExponent, base.privateExponent)
            guard CCryptoBoringSSL_RSA_set0_key(context, modulus, publicExponent, privateExponent) == 1 else {
                throw CitadelError.signingError
            }

            let digest = Variant.digest(data)
            let out = UnsafeMutablePointer<UInt8>.allocate(capacity: 4096)
            defer { out.deallocate() }
            var outLength: UInt32 = 4096
            guard CCryptoBoringSSL_RSA_sign(
                Variant.nid,
                digest,
                digest.count,
                out,
                &outLength,
                context
            ) == 1 else {
                throw CitadelError.signingError
            }

            return SHA2Signature<Variant>(rawRepresentation: Data(bytes: out, count: Int(outLength)))
        }
    }
}
