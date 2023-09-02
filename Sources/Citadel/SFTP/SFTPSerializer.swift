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
            out.writeSFTPFileAttributes(openFile.attributes)
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
            out.writeSFTPFileAttributes(mkdir.attributes)
        case .rmdir(let rmdir):
            out.writeInteger(SFTPMessage.RmDir.id.rawValue)
            out.writeInteger(rmdir.requestId)
            out.writeSSHString(rmdir.filePath)
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
            out.writeSFTPFileAttributes(fstat.attributes)
        case .realpath(let realPath):
            out.writeInteger(SFTPMessage.RealPath.id.rawValue)
            out.writeInteger(realPath.requestId)
            out.writeSSHString(realPath.path)
        case .name(let name):
            out.writeInteger(SFTPMessage.Name.id.rawValue)
            out.writeInteger(name.requestId)
            out.writeInteger(name.count)
            
            for component in name.components {
                out.writeSSHString(component.filename)
                out.writeSSHString(component.longname)
                out.writeSFTPFileAttributes(component.attributes)
            }
        case .opendir(let opendir):
            out.writeInteger(SFTPMessage.OpenDir.id.rawValue)
            out.writeInteger(opendir.requestId)
            out.writeSSHString(opendir.handle)
        case .readdir(var readdir):
            out.writeInteger(SFTPMessage.ReadDir.id.rawValue)
            out.writeInteger(readdir.requestId)
            out.writeSSHString(&readdir.handle)
        case .fstat(var fstat):
            out.writeInteger(SFTPMessage.FileStat.id.rawValue)
            out.writeInteger(fstat.requestId)
            out.writeSSHString(&fstat.handle)
        case .remove(let remove):
            out.writeInteger(SFTPMessage.Remove.id.rawValue)
            out.writeInteger(remove.requestId)
            out.writeSSHString(remove.filename)
        case .fsetstat(var fsetstat):
            out.writeInteger(SFTPMessage.FileSetStat.id.rawValue)
            out.writeInteger(fsetstat.requestId)
            out.writeSSHString(&fsetstat.handle)
            out.writeSFTPFileAttributes(fsetstat.attributes)
        case .setstat(let setstat):
            out.writeInteger(SFTPMessage.SetStat.id.rawValue)
            out.writeInteger(setstat.requestId)
            out.writeSSHString(setstat.path)
            out.writeSFTPFileAttributes(setstat.attributes)
        case .symlink(let symlink):
            out.writeInteger(SFTPMessage.Symlink.id.rawValue)
            out.writeInteger(symlink.requestId)
            out.writeSSHString(symlink.linkPath)
            out.writeSSHString(symlink.targetPath)
        case .readlink(let readlink):
            out.writeInteger(SFTPMessage.Symlink.id.rawValue)
            out.writeInteger(readlink.requestId)
            out.writeSSHString(readlink.path)
        case .rename(let rename):
            out.writeInteger(SFTPMessage.Rename.id.rawValue)
            out.writeInteger(rename.requestId)
            out.writeSSHString(rename.oldPath)
            out.writeSSHString(rename.newPath)
            out.writeInteger(rename.flags)
        }
        
        let length = out.writerIndex - lengthIndex - 4
        out.setInteger(UInt32(length), at: lengthIndex)
    }
}
