import CCryptoBoringSSL
import Foundation
import BigInt
import NIO
import NIOSSH
import Crypto

let generator2: [UInt8] = [ 0x02 ]
let dh14PublicExponent: [UInt8] = [ 0x01, 0x00, 0x01 ]
let dh14p: [UInt8] = [
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

extension SymmetricKey {
    /// Creates a symmetric key by truncating a given digest.
    static func truncatingDigest<D: Digest>(_ digest: D, length: Int) -> SymmetricKey {
        assert(length <= D.byteCount)
        return digest.withUnsafeBytes { bodyPtr in
            SymmetricKey(data: UnsafeRawBufferPointer(rebasing: bodyPtr.prefix(length)))
        }
    }
}

extension HashFunction {
    mutating func update(byte: UInt8) {
        withUnsafeBytes(of: byte) { bytePtr in
            assert(bytePtr.count == 1, "Why is this 8 bit integer so large?")
            self.update(bufferPointer: bytePtr)
        }
    }
}

extension ByteBuffer {
    /// See: https://tools.ietf.org/html/rfc4251#section-4.1
    ///
    /// Represents multiple precision integers in two's complement format,
    /// stored as a string, 8 bits per byte, MSB first.  Negative numbers
    /// have the value 1 as the most significant bit of the first byte of
    /// the data partition.  If the most significant bit would be set for
    /// a positive number, the number MUST be preceded by a zero byte.
    /// Unnecessary leading bytes with the value 0 or 255 MUST NOT be
    /// included.  The value zero MUST be stored as a string with zero
    /// bytes of data.
    ///
    /// By convention, a number that is used in modular computations in
    /// Z_n SHOULD be represented in the range 0 <= x < n.
    @discardableResult
    mutating func writeMPBignum(_ bignum: BigUInt) -> Int {
        let mpIntSizeOffset = writerIndex
        reserveCapacity(minimumWritableBytes: 4 + ((bignum.bitWidth + 7) / 8))
        moveWriterIndex(forwardBy: 4)
        let size = writeBignum(bignum)
        setInteger(UInt32(size), at: mpIntSizeOffset)
        return 4 + size
    }
    
    @discardableResult
    mutating func writeBignum(_ bignum: BigUInt) -> Int {
        var size = (bignum.bitWidth + 7) / 8
        writeWithUnsafeMutableBytes(minimumWritableBytes: Int(size + 1)) { buffer in
            let buffer = buffer.bindMemory(to: UInt8.self)
            
            buffer.baseAddress!.pointee = 0
            
            let serialized = Array(bignum.serialize())
            (buffer.baseAddress! + 1)
                .update(from: serialized, count: serialized.count)
            
            if buffer[1] & 0x80 != 0 {
                size += 1
            } else {
                memmove(buffer.baseAddress!, buffer.baseAddress! + 1, Int(size))
            }
            
            return Int(size)
        }
        
        return Int(size)
    }
    
    @discardableResult
    mutating func writeMPBignum(_ bignum: UnsafePointer<BIGNUM>) -> Int {
        let projectedSize = 4 + Int(CCryptoBoringSSL_BN_num_bytes(bignum))
        reserveCapacity(minimumWritableBytes: projectedSize)
        let mpIntSizeOffset = writerIndex
        moveWriterIndex(forwardBy: 4)
        let size = writeBignum(bignum)
        setInteger(UInt32(size), at: mpIntSizeOffset)
        return 4 + size
    }
    
    @discardableResult
    mutating func writeBignum(_ bignum: UnsafePointer<BIGNUM>) -> Int {
        var size = (CCryptoBoringSSL_BN_num_bits(bignum) + 7) / 8
        writeWithUnsafeMutableBytes(minimumWritableBytes: Int(size + 1)) { buffer in
            let buffer = buffer.bindMemory(to: UInt8.self)
            
            buffer.baseAddress!.pointee = 0
            
            CCryptoBoringSSL_BN_bn2bin(bignum, buffer.baseAddress! + 1)
            
            if buffer[1] & 0x80 != 0 {
                size += 1
            } else {
                memmove(buffer.baseAddress!, buffer.baseAddress! + 1, Int(size))
            }
            
            return Int(size)
        }
        
        return Int(size)
    }
}

extension HashFunction {
    fileprivate mutating func updateAsMPInt(sharedSecret: Data) {
        sharedSecret.withUnsafeBytes { secretBytesPtr in
            var secretBytesPtr = secretBytesPtr[...]
            
            // Here we treat this shared secret as an mpint by just treating these bytes as an unsigned
            // fixed-length integer in network byte order, as suggested by draft-ietf-curdle-ssh-curves-08,
            // and "prepending" it with a 32-bit length field. Note that instead of prepending, we just make
            // another call to update the hasher.
            //
            // Note that, as the integer is _unsigned_, it must be positive. That means we need to check the
            // top bit, because the SSH mpint format requires that the top bit only be set if the number is
            // negative. However, note that the SSH mpint format _also_ requires that we strip any leading
            // _unnecessary_ zero bytes. That means we have a small challenge.
            //
            // We address this by counting the number of zero bytes at the front of this pointer, and then
            // looking at the top bit of the _next_ byte. If the number of zero bytes at the front of this pointer
            // is 0, and the top bit of the next byte is 1, we hash an _extra_ zero byte before we hash the rest
            // of the body: we can put this zero byte into the buffer we've reserved for the length.
            //
            // If the number of zero bytes at the front of this pointer is more than 0, and the top bit of the
            // next byte is 1, we remove all but 1 of the zero bytes, and treat the rest as the body.
            //
            // Finally, if the number of zero bytes at the front of this pointer is more than 0, and the top
            // bit of the next byte is not 1, we remove all of the leading zero bytes, and treat the rest as the
            // body.
            guard let firstNonZeroByteIndex = secretBytesPtr.firstIndex(where: { $0 != 0 }) else {
                // Special case, this is the all zero secret. We shouldn't be able to hit this, as we check that this is a strong
                // secret above. Time to bail.
                preconditionFailure("Attempting to encode the all-zero secret as an mpint!")
            }
            let numberOfZeroBytes = firstNonZeroByteIndex - secretBytesPtr.startIndex
            let topBitOfFirstNonZeroByteIsSet = secretBytesPtr[firstNonZeroByteIndex] & 0x80 == 0x80
            
            // We need to hash a few extra bytes: specifically, we need a 4 byte length in network byte order,
            // and maybe a fifth as a zero byte.
            var lengthHelper = SharedSecretLengthHelper()
            
            switch (numberOfZeroBytes, topBitOfFirstNonZeroByteIsSet) {
            case (0, false):
                // This is the easy case, we just treat the whole thing as the body.
                lengthHelper.length = UInt8(secretBytesPtr.count)
                lengthHelper.useExtraZeroByte = false
            case (0, true):
                // This is an annoying case, we need to add a zero byte to the front.
                lengthHelper.length = UInt8(secretBytesPtr.count + 1)
                lengthHelper.useExtraZeroByte = true
            case (_, false):
                // Strip off all the leading zero bytes.
                secretBytesPtr = secretBytesPtr.dropFirst(numberOfZeroBytes)
                lengthHelper.length = UInt8(secretBytesPtr.count)
                lengthHelper.useExtraZeroByte = false
            case(_, true):
                // Strip off all but one of the leading zero bytes.
                secretBytesPtr = secretBytesPtr.dropFirst(numberOfZeroBytes - 1)
                lengthHelper.length = UInt8(secretBytesPtr.count)
                lengthHelper.useExtraZeroByte = false
            }
            
            // Now generate the hash.
            lengthHelper.update(hasher: &self)
            self.update(bufferPointer: UnsafeRawBufferPointer(rebasing: secretBytesPtr))
        }
    }
}

/// A helper structure that allows us to hash in the extra bytes required to represent our shared secret as an mpint.
///
/// An mpint is an SSH string, meaning that it is prefixed by a 4-byte length field. Additionally, in cases where the top
/// bit of our shared secret is set (50% of the time), that length also needs to be followed by an extra zero bit. To
/// avoid copying our shared secret into public memory, we fiddle about with those extra bytes in this structure, and
/// pass an interior pointer to it into the hasher in order to give good hashing performance.
private struct SharedSecretLengthHelper {
    // We need a 4 byte length in network byte order, and an optional fifth bit. As Curve25519 shared secrets are always
    // 32 bytes long (before the mpint transformation), we only ever actually need to modify one of these bytes:
    // the 4th.
    private var backingBytes = (UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0))
    
    /// Whether we should hash an extra zero byte.
    var useExtraZeroByte: Bool = false
    
    /// The length to encode.
    var length: UInt8 {
        get {
            self.backingBytes.3
        }
        set {
            self.backingBytes.3 = newValue
        }
    }
    
    // Remove the elementwise initializer.
    init() {}
    
    func update<Hasher: HashFunction>(hasher: inout Hasher) {
        withUnsafeBytes(of: self.backingBytes) { bytesPtr in
            precondition(bytesPtr.count == 5)
            
            let bytesToHash: UnsafeRawBufferPointer
            if self.useExtraZeroByte {
                bytesToHash = bytesPtr
            } else {
                bytesToHash = UnsafeRawBufferPointer(rebasing: bytesPtr.prefix(4))
            }
            
            hasher.update(bufferPointer: bytesToHash)
        }
    }
}

extension ByteBuffer {
    /// Many functions in SSH write composite data structures into an SSH string. This is a tricky thing to express
    /// without confining all of those functions to writing strings directly, which is pretty uncool. Instead, we can
    /// wrap the body into this function, which will take the returned total length and use that as the string length.
    @discardableResult
    mutating func writeCompositeSSHString(_ compositeFunction: (inout ByteBuffer) throws -> Int) rethrows -> Int {
        // Reserve 4 bytes for the length.
        let originalWriterIndex = self.writerIndex
        self.moveWriterIndex(forwardBy: 4)
        
        var writtenLength: Int
        do {
            writtenLength = try compositeFunction(&self)
        } catch {
            // Oops, it all went wrong, put the writer index back.
            self.moveWriterIndex(to: originalWriterIndex)
            throw error
        }
        
        // Ok, now we're going to write the length.
        writtenLength += self.setInteger(UInt32(writtenLength), at: originalWriterIndex)
        return writtenLength
    }
}
