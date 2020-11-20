enum SSHClientError: Error {
    case unsupportedPasswordAuthentication, unsupportedPrivateKeyAuthentication, unsupportedHostBasedAuthentication
    case channelCreationFailed
}

enum SSHChannelError: Error {
    case invalidDataType
}

enum SFTPError: Error {
    case unknownMessage
    case invalidPayload(type: SFTPMessageType)
    case invalidResponse
    case noResponseTarget
    case connectionClosed
}
