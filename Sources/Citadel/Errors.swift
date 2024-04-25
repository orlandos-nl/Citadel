enum SSHClientError: Error {
    case unsupportedPasswordAuthentication, unsupportedPrivateKeyAuthentication, unsupportedHostBasedAuthentication
    case channelCreationFailed
    case allAuthenticationOptionsFailed
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

enum CitadelError: Error {
    case invalidKeySize
    case invalidEncryptedPacketLength
    case invalidDecryptedPlaintextLength
    case insufficientPadding, excessPadding
    case invalidMac
    case cryptographicError
    case invalidSignature
    case signingError
    case unsupported
    case unauthorized
    case commandOutputTooLarge
    case channelCreationFailed
    case channelFailure
}

public struct AuthenticationFailed: Error, Equatable {}