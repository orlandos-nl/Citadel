//
//  File.swift
//  
//
//  Created by Jaap Wijnen on 03/05/2022.
//

import Foundation
import XCTest
import Crypto
import Citadel
import _CryptoExtras
import NIOSSH
import NIO
import Logging
import BigInt

enum SSHServerError: Error {
    case invalidCommand
    case invalidDataType
    case invalidChannelType
    case alreadyListening
    case notListening
}

final class KeyTests: XCTestCase {
    func testRSAPrivateKey() throws {
        let key = """
            -----BEGIN OPENSSH PRIVATE KEY-----
            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
            -----END OPENSSH PRIVATE KEY-----
            """
        
        let privateKey = try Insecure.RSA.PrivateKey(sshRsa: key)
        XCTAssertNotNil(privateKey)
        
        let openSSHPrivateKey = try Insecure.RSA.PrivateKey(sshRsa: key)
        XCTAssertNotNil(openSSHPrivateKey)
    }
    
    func testEncryptedED25519PrivateKey() throws {
        let key = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBQRAFCo9
        /vv0icX60s6O6UAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBrez0rdYqROdkIA
        qvSrLoYFO1KVEidE4wclxivVKMbmAAAAoA9dkA6h2tAtANBP9RzyKvgrw5JKVJLVHfvZRQ
        8d3ttvy7WOs15y8lL/SdHiCyRukkKOPRd02zqx5g6WSmXZ0dKho/aMMO+58cIxsbCmMePT
        HaJvuQjIx6DIEoQyq83rQeVngk5rgvgou2jgHy/35C1AHtUysH4DIcltmrU3rvMF8i2GL4
        Od3cZL5cIOQVsmAZS6t3oL+GVeVOMFCqGFxjc=
        -----END OPENSSH PRIVATE KEY-----
        """
        
        let privateKey = try Curve25519.Signing.PrivateKey(sshEd25519: key, decryptionKey: "example".data(using: .utf8)!)
        XCTAssertNotNil(privateKey)
        
        let openSSHPrivateKey = try Curve25519.Signing.PrivateKey(sshEd25519: key, decryptionKey: "example".data(using: .utf8)!)
        XCTAssertNotNil(openSSHPrivateKey)
    }
    
    func testED25519PrivateKey() throws {
        let key = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACAi19yxbgtZH0Y26GZGr2vyVErGFskeOY9HwHLxYbmkAwAAAKAPNV8QDzVf
        EAAAAAtzc2gtZWQyNTUxOQAAACAi19yxbgtZH0Y26GZGr2vyVErGFskeOY9HwHLxYbmkAw
        AAAED3UDHB29MB7vQDpb7PGFjEMAYT9FzpnadYWrCPSUma5SLX3LFuC1kfRjboZkava/JU
        SsYWyR45j0fAcvFhuaQDAAAAHGphYXBASmFhcHMtTWFjQm9vay1Qcm8ubG9jYWwB
        -----END OPENSSH PRIVATE KEY-----
        """
        
        let privateKey = try Curve25519.Signing.PrivateKey(sshEd25519: key)
        XCTAssertNotNil(privateKey)
        
        let openSSHPrivateKey = try Curve25519.Signing.PrivateKey(sshEd25519: key)
        XCTAssertNotNil(openSSHPrivateKey)
    }
    
    func testED25519PrivateKeyWithoutSpacing() throws {
        let key = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAi19yxbgtZH0Y26GZGr2vyVErGFskeOY9HwHLxYbmkAwAAAKAPNV8QDzVfEAAAAAtzc2gtZWQyNTUxOQAAACAi19yxbgtZH0Y26GZGr2vyVErGFskeOY9HwHLxYbmkAwAAAED3UDHB29MB7vQDpb7PGFjEMAYT9FzpnadYWrCPSUma5SLX3LFuC1kfRjboZkava/JUSsYWyR45j0fAcvFhuaQDAAAAHGphYXBASmFhcHMtTWFjQm9vay1Qcm8ubG9jYWwB
        -----END OPENSSH PRIVATE KEY-----
        """
        
        let privateKey = try Curve25519.Signing.PrivateKey(sshEd25519: key)
        XCTAssertNotNil(privateKey)
        
        let key2 = privateKey.makeSSHRepresentation(comment: "jaap@Jaaps-MacBook-Pro.local")
        let privateKey2 = try Curve25519.Signing.PrivateKey(sshEd25519: key2)
        XCTAssertEqual(privateKey.rawRepresentation, privateKey2.rawRepresentation)
    }
    
    func testSSHKeyTypeDetection() throws {
        // Test RSA public key detection
        let rsaPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDD+BHa+uJzAU7CyKrjUIBndqBvyN test@example.com"
        let rsaKeyType = try SSHKeyDetection.detectPublicKeyType(from: rsaPublicKey)
        XCTAssertEqual(rsaKeyType, .rsa)
        XCTAssertEqual(rsaKeyType.description, "RSA")
        
        // Test ED25519 public key detection
        let ed25519PublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICLXXLFuC1kfRjboZkava/JUSsYWyR45j0fAcvFhuaQD test@example.com"
        let ed25519KeyType = try SSHKeyDetection.detectPublicKeyType(from: ed25519PublicKey)
        XCTAssertEqual(ed25519KeyType, .ed25519)
        XCTAssertEqual(ed25519KeyType.description, "ED25519")
        
        // Test ECDSA P-256 public key detection
        let ecdsaP256PublicKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK test@example.com"
        let ecdsaP256KeyType = try SSHKeyDetection.detectPublicKeyType(from: ecdsaP256PublicKey)
        XCTAssertEqual(ecdsaP256KeyType, .ecdsaP256)
        XCTAssertEqual(ecdsaP256KeyType.description, "ECDSA P-256")
        
        // Test ECDSA P-384 public key detection
        let ecdsaP384PublicKey = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBK test@example.com"
        let ecdsaP384KeyType = try SSHKeyDetection.detectPublicKeyType(from: ecdsaP384PublicKey)
        XCTAssertEqual(ecdsaP384KeyType, .ecdsaP384)
        XCTAssertEqual(ecdsaP384KeyType.description, "ECDSA P-384")
        
        // Test ECDSA P-521 public key detection
        let ecdsaP521PublicKey = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBK test@example.com"
        let ecdsaP521KeyType = try SSHKeyDetection.detectPublicKeyType(from: ecdsaP521PublicKey)
        XCTAssertEqual(ecdsaP521KeyType, .ecdsaP521)
        XCTAssertEqual(ecdsaP521KeyType.description, "ECDSA P-521")
    }
    
    func testSSHKeyTypeDetectionWithWhitespace() throws {
        // Test that detection works with leading/trailing whitespace
        let keyWithWhitespace = "  \n\t ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDD+BHa test@example.com \n  "
        let keyType = try SSHKeyDetection.detectPublicKeyType(from: keyWithWhitespace)
        XCTAssertEqual(keyType, .rsa)
    }
    
    func testSSHKeyTypeDetectionErrors() {
        // Test invalid key format
        let invalidKey = "invalid-key-format"
        XCTAssertThrowsError(try SSHKeyDetection.detectPublicKeyType(from: invalidKey)) { error in
            XCTAssertTrue(error is SSHKeyDetectionError)
            if let sshError = error as? SSHKeyDetectionError {
                XCTAssertEqual(sshError, .invalidKeyFormat())
            }
        }
        
        // Test empty string
        XCTAssertThrowsError(try SSHKeyDetection.detectPublicKeyType(from: ""))
        
        // Test key type prefix without content
        let emptyKey = "ssh-rsa "
        XCTAssertThrowsError(try SSHKeyDetection.detectPublicKeyType(from: emptyKey))
        
        // Test invalid private key format
        let invalidPrivateKey = """
        -----BEGIN INVALID PRIVATE KEY-----
        invalid-content
        -----END INVALID PRIVATE KEY-----
        """
        XCTAssertThrowsError(try SSHKeyDetection.detectPrivateKeyType(from: invalidPrivateKey)) { error in
            XCTAssertTrue(error is SSHKeyDetectionError)
        }
        
        // Test malformed OpenSSH private key (missing end marker)
        let malformedPrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ
        """
        XCTAssertThrowsError(try SSHKeyDetection.detectPrivateKeyType(from: malformedPrivateKey))
    }
    
    func testSSHKeyTypeAllCases() {
        // Ensure all key types are covered
        let expectedTypes: Set<SSHKeyType> = [.rsa, .ed25519, .ecdsaP256, .ecdsaP384, .ecdsaP521]
        let allCases = Set(SSHKeyType.allCases)
        XCTAssertEqual(allCases, expectedTypes)
        
        // Test that all key types have descriptions
        for keyType in SSHKeyType.allCases {
            XCTAssertFalse(keyType.description.isEmpty)
        }
    }
    
    func testSSHPrivateKeyTypeDetection() throws {
        // Test ED25519 private key detection
        let ed25519PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACCUyt900D1i2/S69QmQiIwvYayx4Jr/666F1u7aJCyAyAAAAJB0ywhAdMsI
        QAAAAAtzc2gtZWQyNTUxOQAAACCUyt900D1i2/S69QmQiIwvYayx4Jr/666F1u7aJCyAyA
        AAAECapB+VUTcuar7jVPfBgleHuadfu/+7P07PSPeqz+P1yJTK33TQPWLb9Lr1CZCIjC9h
        rLHgmv/rroXW7tokLIDIAAAAC3lvdUBleGFtcGxlAQI=
        -----END OPENSSH PRIVATE KEY-----
        """
        let ed25519KeyType = try SSHKeyDetection.detectPrivateKeyType(from: ed25519PrivateKey)
        XCTAssertEqual(ed25519KeyType, .ed25519)
        
        // Test RSA 4096 private key detection
        let rsa4096PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        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
        -----END OPENSSH PRIVATE KEY-----
        """
        let rsa4096KeyType = try SSHKeyDetection.detectPrivateKeyType(from: rsa4096PrivateKey)
        XCTAssertEqual(rsa4096KeyType, .rsa)
        
        // Test ECDSA P-256 private key detection
        let ecdsa256PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
        1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQR/G9rJovBSvdkd9XoGNURImI5vQP/2
        w7TQNb/b8hGI5oq844XjI7V4j8XDwjqlcNfeD7gqoHf8ekpmL4EUtzYaAAAAqFZzBpBWcw
        aQAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH8b2smi8FK92R31
        egY1REiYjm9A//bDtNA1v9vyEYjmirzjheMjtXiPxcPCOqVw194PuCqgd/x6SmYvgRS3Nh
        oAAAAgPV1jW6vy45i2F3WBFirMPgiJU7FgIl4rJy264fkhPU4AAAALeW91QGV4YW1wbGUB
        AgMEBQ==
        -----END OPENSSH PRIVATE KEY-----
        """
        let ecdsa256KeyType = try SSHKeyDetection.detectPrivateKeyType(from: ecdsa256PrivateKey)
        XCTAssertEqual(ecdsa256KeyType, .ecdsaP256)
        
        // Test ECDSA P-384 private key detection
        let ecdsa384PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
        1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQTbanVgBsim5t0MwvPHpmbupOibZFVU
        a9Teahi4S4YZsvEob0eX9wYSEA2VF6MNKCDM0wQFtm0tk/5vgG0vqSaqjefgXCsov7mFDx
        BW0Trg0YqULpUlRR9l9f12TyZm050AAADY3IaN69yGjesAAAATZWNkc2Etc2hhMi1uaXN0
        cDM4NAAAAAhuaXN0cDM4NAAAAGEE22p1YAbIpubdDMLzx6Zm7qTom2RVVGvU3moYuEuGGb
        LxKG9Hl/cGEhANlRejDSggzNMEBbZtLZP+b4BtL6kmqo3n4FwrKL+5hQ8QVtE64NGKlC6V
        JUUfZfX9dk8mZtOdAAAAMQDtslLX7WTAyAIiTxRVtOl9WXp/GKn9agJIJ0/qOpuRaYGLtk
        w3LPjfQfpJT1dh9CUAAAALeW91QGV4YW1wbGUBAgME
        -----END OPENSSH PRIVATE KEY-----
        """
        let ecdsa384KeyType = try SSHKeyDetection.detectPrivateKeyType(from: ecdsa384PrivateKey)
        XCTAssertEqual(ecdsa384KeyType, .ecdsaP384)
        
        // Test ECDSA P-521 private key detection
        let ecdsa521PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
        1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQAuwrbbKlzQliuu1AmBtr9N7xG1Qic
        MqizNJa5zWWnm9rvBvQwIl0u6NDmUMVTnLxscnk9hXARGaLnn2ufhGhrDWkBujkMnwfGy7
        f/eIIOmWwdoMh/fbam5qMtOgNIp5QO9I70QstcHF62ankrtmcgBZtdCBsvHAuIfL6IK2ts
        BgG7cvMAAAEQktYcEpLWHBIAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
        AAAIUEALsK22ypc0JYrrtQJgba/Te8RtUInDKoszSWuc1lp5va7wb0MCJdLujQ5lDFU5y8
        bHJ5PYVwERmi559rn4Roaw1pAbo5DJ8Hxsu3/3iCDplsHaDIf322puajLToDSKeUDvSO9E
        LLXBxetmp5K7ZnIAWbXQgbLxwLiHy+iCtrbAYBu3LzAAAAQgETL+ZErb1c9FwcOKtIuXgy
        pS4OdBd4Il5mUSzCwJ/PKWO0L+KRTthlNrwZTRxrdGIsjonmEEoIh9kLfGM3Tpa0YQAAAA
        t5b3VAZXhhbXBsZQECAwQFBgc=
        -----END OPENSSH PRIVATE KEY-----
        """
        let ecdsa521KeyType = try SSHKeyDetection.detectPrivateKeyType(from: ecdsa521PrivateKey)
        XCTAssertEqual(ecdsa521KeyType, .ecdsaP521)
    }
}
