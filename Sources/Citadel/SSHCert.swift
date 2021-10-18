import CCryptoBoringSSL
import BigInt
import Foundation
import Crypto
import NIO
import NIOSSH

struct InvalidKey: Error {}

extension Insecure.RSA.PrivateKey {
    public convenience init(sshRsa data: Data) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshRsa: string)
        } else {
            throw InvalidKey()
        }
    }
    
    public convenience init(sshRsa key: String) throws {
        var key = key.replacingOccurrences(of: "\n", with: "")
        
        guard
            key.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"),
            key.hasSuffix("-----END OPENSSH PRIVATE KEY-----")
        else {
            throw InvalidKey()
        }
        
        key.removeLast("-----END OPENSSH PRIVATE KEY-----".utf8.count)
        key.removeFirst("-----BEGIN OPENSSH PRIVATE KEY-----".utf8.count)
        
        guard let data = Data(base64Encoded: key) else {
            throw InvalidKey()
        }
        
        var buffer = ByteBuffer(data: data)
        
        guard
            buffer.readString(length: "openssh-key-v1".utf8.count) == "openssh-key-v1",
            buffer.readInteger(as: UInt8.self) == 0x00,
            buffer.readInteger(as: UInt32.self) == 4, // Cipher Name
            buffer.readString(length: 4) == "none", // Cipher Name
            buffer.readInteger(as: UInt32.self) == 4, // KDF Name
            buffer.readString(length: 4) == "none", // KDF Name
            buffer.readInteger(as: UInt32.self) == 0, // KDF,
            buffer.readInteger(as: UInt32.self) == 1 // # of keys
        else {
            throw InvalidKey()
        }
        
        guard
            let publicKeyLength = buffer.readInteger(as: UInt32.self),
            var publicKeyBuffer = buffer.readSlice(length: Int(publicKeyLength)),
            let publicKeyTypeLength = publicKeyBuffer.readInteger(as: UInt32.self),
            let publicKeyType = publicKeyBuffer.readString(length: Int(publicKeyTypeLength))
        else {
            throw InvalidKey()
        }
        
        guard publicKeyType == "ssh-rsa" else {
            throw InvalidKey()
        }
        
        guard
            let eLength = publicKeyBuffer.readInteger(as: UInt32.self),
            let eData = publicKeyBuffer.readData(length: Int(eLength)),
            let nLength = publicKeyBuffer.readInteger(as: UInt32.self),
            let nData = publicKeyBuffer.readData(length: Int(nLength))
        else {
            throw InvalidKey()
        }

        let _ = BigUInt(eData) // e
        let _ = BigUInt(nData) // n

        guard
            let privateKeyLength = buffer.readInteger(as: UInt32.self),
            var privateKeyBuffer = buffer.readSlice(length: Int(privateKeyLength))
        else {
            throw InvalidKey()
        }
        
        guard
            let _ = privateKeyBuffer.readInteger(as: UInt64.self),
            let privateKeyTypeLength = privateKeyBuffer.readInteger(as: UInt32.self),
            let privateKeyType = privateKeyBuffer.readString(length: Int(privateKeyTypeLength)),
            privateKeyType == publicKeyType
        else {
            throw InvalidKey()
        }
        
        guard
            let nBytesLength = privateKeyBuffer.readInteger(as: UInt32.self),
            let nBytes = privateKeyBuffer.readBytes(length: Int(nBytesLength)),
            let eBytesLength = privateKeyBuffer.readInteger(as: UInt32.self),
            let eBytes = privateKeyBuffer.readBytes(length: Int(eBytesLength)),
            let dLength = privateKeyBuffer.readInteger(as: UInt32.self),
            let dBytes = privateKeyBuffer.readBytes(length: Int(dLength)),
            let iqmpLength = privateKeyBuffer.readInteger(as: UInt32.self),
            let _ = privateKeyBuffer.readData(length: Int(iqmpLength)),
            let pLength = privateKeyBuffer.readInteger(as: UInt32.self),
            let _ = privateKeyBuffer.readData(length: Int(pLength)),
            let qLength = privateKeyBuffer.readInteger(as: UInt32.self),
            let _ = privateKeyBuffer.readData(length: Int(qLength)),
            let commentLength = privateKeyBuffer.readInteger(as: UInt32.self),
            let _ = privateKeyBuffer.readString(length: Int(commentLength))
        else {
            throw InvalidKey()
        }
        
        let privateExponent = CCryptoBoringSSL_BN_bin2bn(dBytes, dBytes.count, nil)!
        let publicExponent = CCryptoBoringSSL_BN_bin2bn(eBytes, eBytes.count, nil)!
        let modulus = CCryptoBoringSSL_BN_bin2bn(nBytes, nBytes.count, nil)!

        self.init(privateExponent: privateExponent, publicExponent: publicExponent, modulus: modulus)
    }
}
