import NIO

private let maxBufferSize = 32768
public struct SFTPFile {
    let handle: ByteBuffer
    let client: SFTPClient
    
    public func readChunk(from offset: UInt64 = 0, length: UInt32) async throws -> ByteBuffer {
        try await client.readFile(handle: handle, offset: offset, length: Swift.min(length, UInt32(maxBufferSize)))
    }
    
    public func readAll(maxLength: Int = .max) async throws -> ByteBuffer {
        var buffer = ByteBuffer()

        while buffer.readableBytes < maxLength {
            let nextChunkSize = Swift.min(maxLength - buffer.readableBytes, maxBufferSize)
            var inboundData = try await readChunk(
                from: UInt64(buffer.writerIndex),
                length: UInt32(nextChunkSize)
            )
            
            buffer.writeBuffer(&inboundData)
                               
            if inboundData.readableBytes < nextChunkSize {
                return buffer
            }
        }

        return buffer
    }
    
    public func writeChunk(at offset: UInt64 = 0, data buffer: ByteBuffer) async throws {
        var buffer = buffer
        
        while buffer.readableBytes > 0 {
            let slice = buffer.readSlice(length: Swift.min(maxBufferSize, buffer.readableBytes))!
            
            try await client.writeFileChunk(
                handle: handle,
                data: slice,
                offset: offset + UInt64(buffer.readerIndex)
            )
        }
    }
}
