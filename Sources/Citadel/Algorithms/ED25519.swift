import NIO
import NIOFoundationCompat
import BigInt
import NIOSSH
import CCryptoBoringSSL
import Foundation
import Crypto

public enum ED25519 {
    public final class PublicKey: NIOSSHPublicKeyProtocol {
        public static let publicKeyPrefix = "ssh-ed25519"
        
        private let baseKey: Curve25519.Signing.PublicKey

        public var rawRepresentation: Data {
            baseKey.rawRepresentation
        }
        
        internal init<D: ContiguousBytes>(rawRepresentation data: D) throws {
            self.baseKey = try Curve25519.Signing.PublicKey(rawRepresentation: data)
        }
        
        public func isValidSignature<D>(_ signature: Signature, for digest: D) -> Bool where D: DataProtocol {
            return baseKey.isValidSignature(signature.rawRepresentation, for: digest)
        }

        public func isValidSignature<D>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool where D : DataProtocol {
            guard let signature = signature as? Signature else {
                return false
            }
            
            return isValidSignature(signature, for: data)
        }

        public func write(to buffer: inout ByteBuffer) -> Int {
            return buffer.writeData(self.rawRepresentation)
        }

        public static func read(from buffer: inout ByteBuffer) throws -> Self {
            guard
                let pubKeyLength = buffer.readInteger(as: UInt32.self),
                let pubKeyData = buffer.readBytes(length: Int(pubKeyLength))
            else {
                throw InvalidKey()
            }
            
            return try self.init(rawRepresentation: pubKeyData)
        }
    }
    
    public struct Signature: NIOSSHSignatureProtocol {
        public static let signaturePrefix = "ssh-ed25519"
        
        public var rawRepresentation: Data
        
        public init<D>(rawRepresentation: D) where D: DataProtocol {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        public func write(to buffer: inout ByteBuffer) -> Int {
            return buffer.writeSSHString(rawRepresentation)
        }
        
        public static func read(from buffer: inout ByteBuffer) throws -> Signature {
            guard let buffer = buffer.readSSHBuffer() else {
                throw ED25519Error(message: "Invalid signature format")
            }
            
            return Signature(rawRepresentation: buffer.getData(at: 0, length: buffer.readableBytes)!)
        }
    }

    public final class PrivateKey: NIOSSHPrivateKeyProtocol {
        public static let keyPrefix = "ssh-ed25519"
        
        private let baseKey: Curve25519.Signing.PrivateKey
        
        internal init<D: ContiguousBytes>(rawRepresentation data: D) throws {
            self.baseKey = try Curve25519.Signing.PrivateKey(rawRepresentation: data)
        }

        public var publicKey: NIOSSHPublicKeyProtocol {
            try! PublicKey(rawRepresentation: baseKey.publicKey.rawRepresentation)
        }
        
        public var rawRepresentation: Data {
            baseKey.rawRepresentation
        }

        public func signature<D>(for data: D) throws -> NIOSSHSignatureProtocol where D : DataProtocol {
            Signature(rawRepresentation: data)
        }
    }
}

public struct ED25519Error: Error {
    let message: String
}
