import CCryptoBoringSSL
import CCitadelBcrypt
import Foundation
import Crypto

// Because we don't want to bundle our own SHA512 implementation with BCrypt, we're providing it to the C library
enum _SHA512 {
    static let didInit: Bool = {
        citadel_set_crypto_hash_sha512 { output, input, inputLength in
            CCryptoBoringSSL_EVP_Digest(input, Int(inputLength), output, nil, CCryptoBoringSSL_EVP_sha512(), nil)
        }
        return true
    }()
}
