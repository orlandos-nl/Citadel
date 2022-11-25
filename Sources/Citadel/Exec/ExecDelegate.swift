import Foundation

public protocol ExecCommandContext {
    func terminate() async throws
}

public struct ExecOutputHandler {
    public let username: String?
    public let stdinPipe = Pipe()
    public let stdoutPipe = Pipe()
    public let stderrPipe = Pipe()
    
    let onSuccess: (Int) -> ()
    let onFailure: (Error) -> ()
    
    public func succeed(exitCode: Int) {
        onSuccess(exitCode)
    }
    
    public func fail(_ error: Error) {
        onFailure(error)
    }
}

public protocol ExecDelegate: AnyObject {
    func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext
    func setEnvironmentValue(_ value: String, forKey key: String) async throws
}
