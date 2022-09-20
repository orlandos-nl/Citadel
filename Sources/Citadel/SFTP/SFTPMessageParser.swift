import NIO

struct SFTPMessageParser: ByteToMessageDecoder {
    typealias InboundOut = SFTPMessage
    
    mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        let oldReaderIndex = buffer.readerIndex
        
        guard
            let length = buffer.readInteger(as: UInt32.self),
            let typeByte = buffer.readInteger(as: UInt8.self),
            var payload = buffer.readSlice(length: Int(length) - 1) // 1 for the already parsed type
        else {
            buffer.moveReaderIndex(to: oldReaderIndex)
            return .needMoreData
        }
        
        guard let type = SFTPMessageType(rawValue: typeByte) else {
            throw SFTPError.unknownMessage
        }
        
        let message: SFTPMessage
        
        switch type {
        case .initialize:
            guard let version = payload.readInteger(as: UInt32.self) else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .initialize(.init(version: .init(version)))
        case .version:
            guard let version = payload.readInteger(as: UInt32.self) else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            var extensionData = [(String, String)]()
            
            while payload.readableBytes > 0 {
                guard
                    let key = payload.readSSHString(),
                    let value = payload.readSSHString()
                else {
                    throw SFTPError.invalidPayload(type: type)
                }
                
                extensionData.append((key, value))
            }
            
            message = .version(
                .init(
                    version: .init(version),
                    extensionData: extensionData
                )
            )
        case .openFile:
            guard
                let requestId = payload.readInteger(as: UInt32.self),
                let filePath = payload.readSSHString(),
                let pFlags = payload.readInteger(as: UInt32.self),
                let attributes = payload.readSFTPFileAttributes()
            else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .openFile(
                .init(
                    requestId: requestId,
                    filePath: filePath,
                    pFlags: SFTPOpenFileFlags(rawValue: pFlags),
                    attributes: attributes
                )
            )
        case .closeFile:
            guard
                let requestId = payload.readInteger(as: UInt32.self),
                let handle = payload.readSSHBuffer()
            else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .closeFile(
                .init(
                    requestId: requestId,
                    handle: handle
                )
            )
        case .read:
            guard
                let requestId = payload.readInteger(as: UInt32.self),
                let handle = payload.readSSHBuffer(),
                let offset = payload.readInteger(as: UInt64.self),
                let length = payload.readInteger(as: UInt32.self)
            else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .read(
                .init(
                    requestId: requestId,
                    handle: handle,
                    offset: offset,
                    length: length
                )
            )
        case .write:
            guard
                let requestId = payload.readInteger(as: UInt32.self),
                let handle = payload.readSSHBuffer(),
                let offset = payload.readInteger(as: UInt64.self),
                let data = payload.readSSHBuffer()
            else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .write(
                .init(
                    requestId: requestId,
                    handle: handle,
                    offset: offset,
                    data: data
                )
            )
        case .status:
            guard
                let requestId = payload.readInteger(as: UInt32.self),
                let errorCode = payload.readInteger(as: UInt32.self),
                let errorMessage = payload.readSSHString(),
                let languageTag = payload.readSSHString()
            else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .status(
                .init(
                    requestId: requestId,
                    errorCode: .init(errorCode),
                    message: errorMessage,
                    languageTag: languageTag
                )
            )
        case .handle:
            guard
                let requestId = payload.readInteger(as: UInt32.self),
                let handle = payload.readSSHBuffer()
            else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .handle(
                .init(
                    requestId: requestId,
                    handle: handle.slice()
                )
            )
        case .data:
            guard
                let requestId = payload.readInteger(as: UInt32.self),
                let data = payload.readSSHBuffer()
            else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .data(
                .init(
                    requestId: requestId,
                    data: data.slice()
                )
            )
        case .stat:
            guard
                let requestId = payload.readInteger(as: UInt32.self),
                let path = payload.readSSHString()
            else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .stat(
                .init(
                    requestId: requestId,
                    path: path
                )
            )
        case .mkdir:
            guard
                let requestId = payload.readInteger(as: UInt32.self),
                let path = payload.readSSHString(),
                let attributes = payload.readSFTPFileAttributes()
            else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .mkdir(
                .init(
                    requestId: requestId,
                    filePath: path,
                    attributes: attributes
                )
            )
        case .lstat:
            guard
                let requestId = payload.readInteger(as: UInt32.self),
                let path = payload.readSSHString()
            else {
                throw SFTPError.invalidPayload(type: type)
            }
            
            message = .lstat(
                .init(
                    requestId: requestId,
                    path: path
                )
            )
        case .name, .attributes, .fstat, .setstat, .fsetstat, .opendir, .readdir, .remove, .rmdir,
             .realpath, .readlink, .symlink, .extended, .extendedReply:
            print(type)
            throw SFTPError.invalidPayload(type: type)
        }
        
        context.fireChannelRead(wrapInboundOut(message))
        return .continue
    }
}
