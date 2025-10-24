import Foundation
import NIOCore

/// Represents supported SSH key types that can be detected from key strings.
///
/// A `struct` is used instead of a public `enum` so new algorithms can be
/// added later without breaking source or ABI stability.
public struct SSHKeyType: RawRepresentable, Equatable, Hashable, CaseIterable, CustomStringConvertible, Sendable {
    
    // MARK: Backing storage for the algorithms currently bundled with Citadel.
    internal enum BackingKeyType: String, CaseIterable, Sendable {
        case rsa        = "ssh-rsa"
        case ed25519    = "ssh-ed25519"
        case ecdsaP256  = "ecdsa-sha2-nistp256"
        case ecdsaP384  = "ecdsa-sha2-nistp384"
        case ecdsaP521  = "ecdsa-sha2-nistp521"
    }
    
    // MARK: RawRepresentable
    let backing: BackingKeyType
    public var rawValue: String { backing.rawValue }
    
    public init?(rawValue: String) {
        guard let backing = BackingKeyType(rawValue: rawValue) else { return nil }
        self.backing = backing
    }
    
    // Internal convenience initialiser
    internal init(backing: BackingKeyType) {
        self.backing = backing
    }
    
    // MARK: CaseIterable
    public static var allCases: [SSHKeyType] {
        BackingKeyType.allCases.map(SSHKeyType.init(backing:))
    }
    
    // MARK: Human-readable description (mirrors previous behaviour)
    public var description: String {
        switch backing {
        case .rsa:        return "RSA"
        case .ed25519:    return "ED25519"
        case .ecdsaP256:  return "ECDSA P-256"
        case .ecdsaP384:  return "ECDSA P-384"
        case .ecdsaP521:  return "ECDSA P-521"
        }
    }
    
    // MARK: Statically known key types
    public static let rsa        = SSHKeyType(backing: .rsa)
    public static let ed25519    = SSHKeyType(backing: .ed25519)
    public static let ecdsaP256  = SSHKeyType(backing: .ecdsaP256)
    public static let ecdsaP384  = SSHKeyType(backing: .ecdsaP384)
    public static let ecdsaP521  = SSHKeyType(backing: .ecdsaP521)
}


/// Errors that can occur during SSH key type detection.
public enum SSHKeyDetectionError: LocalizedError, Equatable {
    case invalidKeyFormat(reason: String? = nil)
    case unsupportedKeyType(type: String? = nil)
    case invalidPrivateKeyFormat
    case malformedKey
    case encryptedPrivateKey              // key is encrypted, no pass-phrase handled yet
    case passphraseRequired               // caller gave none
    case incorrectPassphrase              // caller gave one, but it was wrong

    // Equality only cares about the *case*, not the associated text.
    public static func == (lhs: SSHKeyDetectionError, rhs: SSHKeyDetectionError) -> Bool {
        switch (lhs, rhs) {
        case (.invalidKeyFormat,       .invalidKeyFormat),
             (.unsupportedKeyType,     .unsupportedKeyType),
             (.invalidPrivateKeyFormat,.invalidPrivateKeyFormat),
             (.malformedKey,           .malformedKey),
             (.encryptedPrivateKey,    .encryptedPrivateKey),
             (.passphraseRequired,     .passphraseRequired),
             (.incorrectPassphrase,    .incorrectPassphrase):
            return true
        default:
            return false
        }
    }

    public var errorDescription: String? {
        switch self {
        case .invalidKeyFormat(let reason):
            return "The key string is not in a valid SSH-key format" + (reason.map { ": \($0)" } ?? "")
        case .unsupportedKeyType(let type):
            return "The key type is not supported" + (type.map { " (raw value: \($0))" } ?? "")
        case .invalidPrivateKeyFormat:
            return "The private key format is invalid or corrupted"
        case .malformedKey:
            return "The key string is malformed"
        case .encryptedPrivateKey:
            return "The private key is encrypted"
        case .passphraseRequired:
            return "A passphrase is required to decrypt the private key"
        case .incorrectPassphrase:
            return "The provided passphrase is incorrect"
        }
    }
}

/// High-level utility for detecting SSH key types from their string representation.
public enum SSHKeyDetection {
    
    /// Detects the type of an SSH public key from its string representation.
    /// 
    /// This function supports standard OpenSSH public key format:
    /// - Public keys: Standard OpenSSH public key format (e.g., "ssh-rsa AAAAB3... user@host")
    ///
    /// - Parameter keyString: The SSH public key as a string
    /// - Returns: The detected SSH key type
    /// - Throws: `SSHKeyDetectionError` if the key format is invalid or unsupported
    ///
    /// Example usage:
    /// ```swift
    /// let publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@example.com"
    /// let keyType = try SSHKeyDetection.detectPublicKeyType(from: publicKey)
    /// print(keyType) // .rsa
    /// ```
    public static func detectPublicKeyType(from keyString: String) throws -> SSHKeyType {
        let trimmedKey = keyString.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Check for public key formats
        for keyType in SSHKeyType.allCases {
            let prefix = keyType.rawValue + " "
            if trimmedKey.hasPrefix(prefix) {
                // Validate that there's actually content after the prefix
                let remainder = String(trimmedKey.dropFirst(prefix.count))
                if !remainder.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    return keyType
                }
            }
        }
        
        throw SSHKeyDetectionError.invalidKeyFormat(reason: "The key string does not match any known SSH public key format.")
    }
    
    /// Detects the type of an SSH private key from its string representation.
    /// 
    /// This function supports OpenSSH private key format:
    /// - Private keys: OpenSSH private key format (PEM-style with -----BEGIN OPENSSH PRIVATE KEY-----)
    ///
    /// - Parameter keyString: The SSH private key as a string
    /// - Returns: The detected SSH key type
    /// - Throws: `SSHKeyDetectionError` if the key format is invalid or unsupported
    ///
    /// Example usage:
    /// ```swift
    /// let privateKey = """
    /// -----BEGIN OPENSSH PRIVATE KEY-----
    /// b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW...
    /// -----END OPENSSH PRIVATE KEY-----
    /// """
    /// let keyType = try SSHKeyDetection.detectPrivateKeyType(from: privateKey)
    /// print(keyType) // .ed25519
    /// ```
    public static func detectPrivateKeyType(from keyString: String) throws -> SSHKeyType {
        let trimmedKey = keyString.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Verify it's an OpenSSH private key format
        guard trimmedKey.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----") else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        return try parseOpenSSHPrivateKey(from: trimmedKey)
    }
    
    /// Detects the type of an OpenSSH private key by parsing its structure.
    private static func parseOpenSSHPrivateKey(from keyString: String) throws -> SSHKeyType {
        var keyContent = keyString.replacingOccurrences(of: "\n", with: "")
        
        guard
            keyContent.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"),
            keyContent.hasSuffix("-----END OPENSSH PRIVATE KEY-----")
        else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        // Extract the base64 content
        keyContent.removeLast("-----END OPENSSH PRIVATE KEY-----".count)
        keyContent.removeFirst("-----BEGIN OPENSSH PRIVATE KEY-----".count)
        
        guard let data = Data(base64Encoded: keyContent) else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        // Parse the OpenSSH private key format
        return try parseOpenSSHPrivateKeyType(from: data)
    }
    
    /// Parses the OpenSSH private key format to extract the key type.
    private static func parseOpenSSHPrivateKeyType(from data: Data) throws -> SSHKeyType {
        var offset = 0
        
        // Check magic bytes "openssh-key-v1\0"
        let magic = "openssh-key-v1\0".utf8
        guard data.starts(with: magic) else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        offset += magic.count
        
        // Skip cipher name length + cipher name
        guard let cipherNameLength = readUInt32(from: data, at: &offset) else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        offset += Int(cipherNameLength)
        
        // Skip KDF name length + KDF name
        guard let kdfNameLength = readUInt32(from: data, at: &offset) else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        offset += Int(kdfNameLength)
        
        // Skip KDF options length + KDF options
        guard let kdfOptionsLength = readUInt32(from: data, at: &offset) else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        offset += Int(kdfOptionsLength)
        
        // Number of keys (should be 1)
        guard let numberOfKeys = readUInt32(from: data, at: &offset),
              numberOfKeys == 1 else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        // Public key length (we don't need the value, just need to advance past it)
        guard readUInt32(from: data, at: &offset) != nil else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        // Public key data starts here - first thing is the key type
        guard let keyTypeLength = readUInt32(from: data, at: &offset) else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        guard offset + Int(keyTypeLength) <= data.count else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        let keyTypeData = data.subdata(in: offset..<(offset + Int(keyTypeLength)))
        guard let keyTypeString = String(data: keyTypeData, encoding: .utf8) else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        guard let keyType = SSHKeyType(rawValue: keyTypeString) else {
            throw SSHKeyDetectionError.unsupportedKeyType(type: keyTypeString)
        }
        
        return keyType
    }
    
    /// Helper function to read a 32-bit unsigned integer from data.
    private static func readUInt32(from data: Data, at offset: inout Int) -> UInt32? {
        // Fast path: require the 4 bytes to be present.
        guard offset + 4 <= data.count else { return nil }

        // Wrap just the slice we need so we don’t copy the whole array.
        var buf = ByteBuffer(bytes: data[offset ..< offset + 4])
        guard let value: UInt32 = buf.readInteger(endianness: .big) else { return nil }

        offset += 4
        return value
    }
}
