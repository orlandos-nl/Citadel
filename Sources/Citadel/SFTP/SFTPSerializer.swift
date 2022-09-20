import NIO

final class SFTPMessageSerializer: MessageToByteEncoder {
    typealias OutboundIn = SFTPMessage
    
    func encode(data: SFTPMessage, out: inout ByteBuffer) throws {
        let lengthIndex = out.writerIndex
        out.moveWriterIndex(forwardBy: 4)
        
        switch data {
        case .initialize(let initialize):
            out.writeInteger(SFTPMessage.Initialize.id.rawValue)
            out.writeInteger(initialize.version.rawValue)
        case .version(let version):
            out.writeInteger(SFTPMessage.Version.id.rawValue)
            out.writeInteger(version.version.rawValue)
            
            for (key, value) in version.extensionData {
                out.writeSSHString(key)
                out.writeSSHString(value)
            }
        case .openFile(let openFile):
            out.writeInteger(SFTPMessage.OpenFile.id.rawValue)
            out.writeInteger(openFile.requestId)
            out.writeSSHString(openFile.filePath)
            out.writeInteger(openFile.pFlags.rawValue)
            out.writeSFTPFileAttribues(openFile.attributes)
        case .closeFile(var closeFile):
            out.writeInteger(SFTPMessage.CloseFile.id.rawValue)
            out.writeInteger(closeFile.requestId)
            out.writeSSHString(&closeFile.handle)
        case .read(var read):
            out.writeInteger(SFTPMessage.ReadFile.id.rawValue)
            out.writeInteger(read.requestId)
            out.writeSSHString(&read.handle)
            out.writeInteger(read.offset)
            out.writeInteger(read.length)
        case .write(var write):
            out.writeInteger(SFTPMessage.WriteFile.id.rawValue)
            out.writeInteger(write.requestId)
            out.writeSSHString(&write.handle)
            out.writeInteger(write.offset)
            out.writeSSHString(&write.data)
        case .handle(var handle):
            out.writeInteger(SFTPMessage.Handle.id.rawValue)
            out.writeInteger(handle.requestId)
            out.writeSSHString(&handle.handle)
        case .status(let status):
            out.writeInteger(SFTPMessage.Status.id.rawValue)
            out.writeInteger(status.requestId)
            out.writeInteger(status.errorCode.rawValue)
            out.writeSSHString(status.message)
            out.writeSSHString(status.languageTag)
        case .data(var data):
            out.writeInteger(SFTPMessage.FileData.id.rawValue)
            out.writeInteger(data.requestId)
            out.writeSSHString(&data.data)
        case .mkdir(let mkdir):
            out.writeInteger(SFTPMessage.MkDir.id.rawValue)
            out.writeInteger(mkdir.requestId)
            out.writeSSHString(mkdir.filePath)
            out.writeSFTPFileAttribues(mkdir.attributes)
        case .stat(let stat):
            out.writeInteger(SFTPMessage.Stat.id.rawValue)
            out.writeInteger(stat.requestId)
            out.writeSSHString(stat.path)
        case .lstat(let lstat):
            out.writeInteger(SFTPMessage.LStat.id.rawValue)
            out.writeInteger(lstat.requestId)
            out.writeSSHString(lstat.path)
        case .attributes(let fstat):
            out.writeInteger(SFTPMessage.Attributes.id.rawValue)
            out.writeInteger(fstat.requestId)
            out.writeSFTPFileAttribues(fstat.attributes)
        }
        
        let length = out.writerIndex - lengthIndex - 4
        out.setInteger(UInt32(length), at: lengthIndex)
    }
}
