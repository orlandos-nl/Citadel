enum SSHClientError: Error {
    case unsupportedPasswordAuthentication, unsupportedPrivateKeyAuthentication, unsupportedHostBasedAuthentication
    case channelCreationFailed
}

enum SSHChannelError: Error {
    case invalidDataType
}

enum SSHExecError: Error {
    case commandExecFailed
    case invalidChannelType
    case invalidData
}

enum SFTPError: Error {
    case unknownMessage
    case invalidPayload(type: SFTPMessageType)
    case invalidResponse
    case noResponseTarget
    case connectionClosed
    case missingResponse
    case fileHandleInvalid
    case errorStatus(SFTPMessage.Status)
    case unsupportedVersion(SFTPProtocolVersion)
}
