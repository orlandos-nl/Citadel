import Foundation
import NIO
import Crypto

// OpenSSH private keys for the NIST curves (`ecdsa-sha2-nistp256/384/521`).
//
// NIOSSH already signs with P256/P384/P521 and `SSHAuthenticationMethod` already
// exposes `.p256`/`.p384`/`.p521` — the only missing piece was reading the key
// out of an OpenSSH key file, so an ECDSA key could not be used at all.
//
// Layout (RFC 5656 §3.1, as embedded by OpenSSH):
//   public:   string "ecdsa-sha2-nistpXXX", string curve, string Q
//   private:  string "ecdsa-sha2-nistpXXX", string curve, string Q, mpint d
// Q is the uncompressed point (0x04 || X || Y), i.e. CryptoKit's x9.63 form.

extension OpenSSH {
    enum ECDSA {
        /// Reads `string curve, string Q` and checks the curve matches.
        static func readPublicComponents(
            _ buffer: inout ByteBuffer,
            expectedCurve: String
        ) throws -> Data {
            guard let curve = buffer.readSSHString(), curve == expectedCurve else {
                throw InvalidOpenSSHKey.invalidPublicKeyPrefix
            }
            guard let point = buffer.readSSHBuffer(),
                  let bytes = point.getBytes(at: 0, length: point.readableBytes) else {
                throw InvalidOpenSSHKey.missingPublicKeyBuffer
            }
            return Data(bytes)
        }

        /// Reads the private half and returns (scalar `d`, point `Q`).
        static func readPrivateComponents(
            _ buffer: inout ByteBuffer,
            expectedCurve: String,
            scalarByteCount: Int
        ) throws -> (scalar: Data, point: Data) {
            let point = try readPublicComponents(&buffer, expectedCurve: expectedCurve)

            guard let scalarBuffer = buffer.readSSHBuffer(),
                  let scalarBytes = scalarBuffer.getBytes(at: 0, length: scalarBuffer.readableBytes) else {
                throw InvalidOpenSSHKey.missingPrivateKeyBuffer
            }

            // `d` is an mpint: it may carry a leading 0x00 when the high bit is
            // set, or be short when the top bytes are zero. CryptoKit wants
            // exactly the curve's scalar width, big-endian.
            var scalar = scalarBytes.drop { $0 == 0 }
            guard scalar.count <= scalarByteCount else {
                throw InvalidOpenSSHKey.invalidLayout
            }
            if scalar.count < scalarByteCount {
                scalar = ([UInt8](repeating: 0, count: scalarByteCount - scalar.count) + scalar)[...]
            }
            return (Data(scalar), point)
        }

        /// The private scalar must actually belong to the advertised point;
        /// mirrors the check the Ed25519 reader performs.
        static func verify(point: Data, matches derived: Data) throws {
            guard point == derived else {
                throw InvalidOpenSSHKey.invalidPublicKeyInPrivateKey
            }
        }
    }
}

// MARK: - P-256

extension P256.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        let point = try OpenSSH.ECDSA.readPublicComponents(&buffer, expectedCurve: "nistp256")
        return try Self(x963Representation: point)
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        // Citadel's String overload of writeSSHString returns Void; count the
        // 4-byte length prefix ourselves.
        buffer.writeSSHString("nistp256")
        return 4 + "nistp256".utf8.count + buffer.writeSSHString(x963Representation)
    }
}

extension P256.Signing.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = P256.Signing.PublicKey
    static var privateKeyPrefix: String { "ecdsa-sha2-nistp256" }
    static var publicKeyPrefix: String { "ecdsa-sha2-nistp256" }
    static var keyType: OpenSSH.KeyType { .ecdsaP256 }

    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        let (scalar, point) = try OpenSSH.ECDSA.readPrivateComponents(
            &buffer, expectedCurve: "nistp256", scalarByteCount: 32)
        let key = try Self(rawRepresentation: scalar)
        try OpenSSH.ECDSA.verify(point: point, matches: key.publicKey.x963Representation)
        return key
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        var written = publicKey.write(to: &buffer)
        written += buffer.writeSSHString(rawRepresentation)
        return written
    }

    /// Creates a P-256 private key from an OpenSSH private key string.
    /// - Parameters:
    ///   - key: The OpenSSH private key string.
    ///   - decryptionKey: The passphrase, if the key is encrypted.
    public init(sshP256 key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<Self>(string: key, decryptionKey: decryptionKey).privateKey
    }
}

// MARK: - P-384

extension P384.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        let point = try OpenSSH.ECDSA.readPublicComponents(&buffer, expectedCurve: "nistp384")
        return try Self(x963Representation: point)
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        // Citadel's String overload of writeSSHString returns Void; count the
        // 4-byte length prefix ourselves.
        buffer.writeSSHString("nistp384")
        return 4 + "nistp384".utf8.count + buffer.writeSSHString(x963Representation)
    }
}

extension P384.Signing.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = P384.Signing.PublicKey
    static var privateKeyPrefix: String { "ecdsa-sha2-nistp384" }
    static var publicKeyPrefix: String { "ecdsa-sha2-nistp384" }
    static var keyType: OpenSSH.KeyType { .ecdsaP384 }

    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        let (scalar, point) = try OpenSSH.ECDSA.readPrivateComponents(
            &buffer, expectedCurve: "nistp384", scalarByteCount: 48)
        let key = try Self(rawRepresentation: scalar)
        try OpenSSH.ECDSA.verify(point: point, matches: key.publicKey.x963Representation)
        return key
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        var written = publicKey.write(to: &buffer)
        written += buffer.writeSSHString(rawRepresentation)
        return written
    }

    /// Creates a P-384 private key from an OpenSSH private key string.
    public init(sshP384 key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<Self>(string: key, decryptionKey: decryptionKey).privateKey
    }
}

// MARK: - P-521

extension P521.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        let point = try OpenSSH.ECDSA.readPublicComponents(&buffer, expectedCurve: "nistp521")
        return try Self(x963Representation: point)
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        // Citadel's String overload of writeSSHString returns Void; count the
        // 4-byte length prefix ourselves.
        buffer.writeSSHString("nistp521")
        return 4 + "nistp521".utf8.count + buffer.writeSSHString(x963Representation)
    }
}

extension P521.Signing.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = P521.Signing.PublicKey
    static var privateKeyPrefix: String { "ecdsa-sha2-nistp521" }
    static var publicKeyPrefix: String { "ecdsa-sha2-nistp521" }
    static var keyType: OpenSSH.KeyType { .ecdsaP521 }

    // P-521 scalars are 66 bytes (521 bits rounded up).
    static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        let (scalar, point) = try OpenSSH.ECDSA.readPrivateComponents(
            &buffer, expectedCurve: "nistp521", scalarByteCount: 66)
        let key = try Self(rawRepresentation: scalar)
        try OpenSSH.ECDSA.verify(point: point, matches: key.publicKey.x963Representation)
        return key
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        var written = publicKey.write(to: &buffer)
        written += buffer.writeSSHString(rawRepresentation)
        return written
    }

    /// Creates a P-521 private key from an OpenSSH private key string.
    public init(sshP521 key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<Self>(string: key, decryptionKey: decryptionKey).privateKey
    }
}
