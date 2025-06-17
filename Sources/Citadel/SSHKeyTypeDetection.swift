import Foundation

/// Represents supported SSH key types that can be detected from key strings.
public enum SSHKeyType: String, CaseIterable {
    case rsa = "ssh-rsa"
    case ed25519 = "ssh-ed25519"
    case ecdsaP256 = "ecdsa-sha2-nistp256"
    case ecdsaP384 = "ecdsa-sha2-nistp384"
    case ecdsaP521 = "ecdsa-sha2-nistp521"
    
    /// Human-readable description of the key type
    public var description: String {
        switch self {
        case .rsa:
            return "RSA"
        case .ed25519:
            return "ED25519"
        case .ecdsaP256:
            return "ECDSA P-256"
        case .ecdsaP384:
            return "ECDSA P-384"
        case .ecdsaP521:
            return "ECDSA P-521"
        }
    }
}

/// Errors that can occur during SSH key type detection.
public enum SSHKeyDetectionError: Error {
    case invalidKeyFormat
    case unsupportedKeyType
    case invalidPrivateKeyFormat
    case malformedKey
    
    public var localizedDescription: String {
        switch self {
        case .invalidKeyFormat:
            return "The provided key string is not in a valid SSH key format"
        case .unsupportedKeyType:
            return "The key type is not supported"
        case .invalidPrivateKeyFormat:
            return "The private key format is invalid or corrupted"
        case .malformedKey:
            return "The key string is malformed"
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
        
        throw SSHKeyDetectionError.invalidKeyFormat
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
            key.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"),
            key.hasSuffix("-----END OPENSSH PRIVATE KEY-----")
        else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        // Extract the base64 content
        key.removeLast("-----END OPENSSH PRIVATE KEY-----".count)
        key.removeFirst("-----BEGIN OPENSSH PRIVATE KEY-----".count)
        
        guard let data = Data(base64Encoded: key) else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        // Parse the OpenSSH private key format
        return try parseOpenSSHPrivateKeyType(from: data)
    }
    
    /// Parses the OpenSSH private key format to extract the key type.
    private static func parseOpenSSHPrivateKeyType(from data: Data) throws -> SSHKeyType {
        var offset = 0
        
        // Check magic bytes "openssh-key-v1\0"
        let magic = "openssh-key-v1\0".data(using: .utf8)!
        guard data.count >= magic.count else {
            throw SSHKeyDetectionError.invalidPrivateKeyFormat
        }
        
        let magicBytes = data.subdata(in: 0..<magic.count)
        guard magicBytes == magic else {
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
            throw SSHKeyDetectionError.unsupportedKeyType
        }
        
        return keyType
    }
    
    /// Helper function to read a 32-bit unsigned integer from data.
    private static func readUInt32(from data: Data, at offset: inout Int) -> UInt32? {
        guard offset + 4 <= data.count else { return nil }
        
        let value = data.subdata(in: offset..<(offset + 4)).withUnsafeBytes { bytes in
            bytes.load(as: UInt32.self).bigEndian
        }
        offset += 4
        return value
    }
}
