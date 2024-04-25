import Citadel

let client = try await SSHClient.connect(
    host: "localhost", 
    port: 2323,
    authenticationMethod: .passwordBased(username: "test", password: "test"),
    hostKeyValidator: .acceptAnything(),
    reconnect: .never
)

let result = try await client.executeCommand("echo 'Hello, World!'")
print(String(buffer: result))