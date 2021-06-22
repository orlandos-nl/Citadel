import NIO

public struct SFTPFile {
    let handle: ByteBuffer
    let client: SFTPClient
    
    public func read(from offset: UInt64 = 0, length: UInt32) -> EventLoopFuture<ByteBuffer> {
        client.readFile(handle: handle, offset: offset, length: length)
    }
    
    public func write(from offset: UInt64 = 0, length: UInt32, data: ByteBuffer) -> EventLoopFuture<Void> {
        client.writeFile(handle: handle, data: data, offset: offset, length: length)
    }
}
