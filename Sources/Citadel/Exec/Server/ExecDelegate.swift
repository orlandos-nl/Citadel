import Foundation

public protocol ExecCommandContext {
    func terminate() async throws
    func inputClosed() async throws
}

extension ExecCommandContext {
    public func inputClosed() async throws { }
}

public struct ExecExitContext {
    
}

public final class ExecOutputHandler {
    public typealias ExitHandler = @Sendable (ExecExitContext) -> ()
    
    public let username: String?
    public let stdinPipe = Pipe()
    public let stdoutPipe = Pipe()
    public let stderrPipe = Pipe()
    
    var onExit: ExitHandler?
    let onSuccess: (Int) -> ()
    let onFailure: (Error) -> ()
    
    init(username: String?, onSuccess: @escaping (Int) -> (), onFailure: @escaping (Error) -> ()) {
        self.username = username
        self.onSuccess = onSuccess
        self.onFailure = onFailure
    }
    
    public func succeed(exitCode: Int) {
        onSuccess(exitCode)
    }
    
    public func fail(_ error: Error) {
        onFailure(error)
    }
    
    public func onExit(_ handle: @escaping ExitHandler) {
        self.onExit = handle
    }
}

public protocol ExecDelegate: AnyObject, Sendable {
    func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext
    func setEnvironmentValue(_ value: String, forKey key: String) async throws
}
