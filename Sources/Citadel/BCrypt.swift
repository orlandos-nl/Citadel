import CCryptoBoringSSL
import Foundation
import Crypto

// Because we don't want to bundle our own SHA512 implementation with BCrypt, we're providing it to the C library
@_silgen_name("citadel_crypto_hash_sha512") func _hashSHA512(
    output: UnsafeMutablePointer<UInt8>,
    input: UnsafePointer<UInt8>,
    inputLength: Int
) {
    CCryptoBoringSSL_EVP_Digest(input, Int(inputLength), output, nil, CCryptoBoringSSL_EVP_sha512(), nil)
}
