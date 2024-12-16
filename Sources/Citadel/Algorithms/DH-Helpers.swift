import CCryptoBoringSSL
import Foundation
import BigInt
import NIO
import NIOSSH
import Crypto

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
                .assign(from: serialized, count: serialized.count)
            
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
