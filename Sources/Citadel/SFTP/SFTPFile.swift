import NIO

public struct SFTPFile {
    let handle: ByteBuffer
    let client: SFTPClient
    
    public func readChunk(from offset: UInt64 = 0, length: UInt32) -> EventLoopFuture<ByteBuffer> {
        client.readFile(handle: handle, offset: offset, length: length)
    }
    
    public func readAll() -> EventLoopFuture<ByteBuffer> {
        var buffer = ByteBuffer()

        func next() -> EventLoopFuture<Void> {
            self.readChunk(from: UInt64(buffer.writerIndex), length: .max).flatMap { inboundData in
                var inboundData = inboundData
                if buffer.writeBuffer(&inboundData) == 0 {
                    return self.client.channel.eventLoop.makeSucceededVoidFuture()
                }

                return next()
            }.recover { _ in }
        }

        return next().map {
            buffer
        }
    }
    
    public func writeChunk(at offset: UInt64 = 0, data: ByteBuffer) -> EventLoopFuture<Void> {
        
        client.writeFile(handle: handle, data: data, offset: offset)
    }
}
