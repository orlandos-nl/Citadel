# Remote Port Forwarding Example

This example demonstrates how to use Citadel's remote port forwarding feature (also known as reverse tunneling).

## What is Remote Port Forwarding?

Remote port forwarding allows you to expose a local service through a remote SSH server. When someone connects to a port on the remote server, that connection is forwarded back through the SSH tunnel to your local machine.

**Use cases:**
- Expose a local web server for testing
- Share a local development database
- Bypass firewalls (expose services behind NAT)
- Remote debugging and development

## Quick Start

### 1. Set up a local service

Start a simple HTTP server on your local machine:

```bash
# Terminal 1 - Start a local HTTP server
python3 -m http.server 3000
```

### 2. Run the example

```bash
# Terminal 2 - Run the remote port forward example
cd Examples/RemotePortForwardExample

# Run with password authentication
swift run remote-forward \
  --host your-ssh-server.com \
  --username your-username \
  --password your-password

# Or with SSH key authentication (recommended)
swift run remote-forward \
  --host your-ssh-server.com \
  --username your-username \
  --private-key ~/.ssh/id_rsa
```

### 3. Test the connection

```bash
# Terminal 3 - On the remote server or from another machine
curl http://your-ssh-server.com:8080
# You should see the directory listing from your local python server!
```

## How It Works

1. The example connects to your SSH server
2. It requests the server to listen on port 8080 (remote port forward)
3. When someone connects to `remote-server:8080`, the SSH server opens a "forwarded-tcpip" channel
4. The example receives this connection and forwards it to `localhost:3000`
5. Data flows bidirectionally: remote client ↔ SSH tunnel ↔ local service

## Code Walkthrough

```swift
// Request remote port forwarding
let forward = try await client.createRemotePortForward(
    host: "0.0.0.0",      // Listen on all interfaces
    port: 8080            // Port to listen on (0 = server chooses)
) { forwardedChannel, forwardedInfo in
    // This closure is called for each incoming connection

    // Connect to your local service
    return ClientBootstrap(group: forwardedChannel.eventLoop)
        .connect(host: "127.0.0.1", port: 3000)
        .flatMap { localChannel in
            // Set up bidirectional data forwarding
            // forwardedChannel ↔ localChannel
        }
}

print("Listening on remote port: \(forward.boundPort)")

// Later, cancel the forward
try await client.cancelRemotePortForward(forward)
```

## Command-Line Options

```bash
swift run remote-forward --help
```

**Required options:**
- `--host`, `-h`: SSH server hostname or IP address
- `--username`, `-u`: SSH username
- `--password` OR `--private-key`: Authentication credentials

**Optional options:**
- `--port`, `-p`: SSH server port (default: 22)
- `--remote-host`: Remote host to bind to (default: 0.0.0.0)
- `--remote-port`: Remote port to listen on (default: 8080, 0 = server chooses)
- `--local-host`: Local host to forward connections to (default: 127.0.0.1)
- `--local-port`: Local port to forward connections to (default: 3000)
- `--insecure`: Accept any host key (⚠️ insecure, only for testing)

## Testing Without a Remote Server

If you don't have a remote SSH server, you can test locally:

### Option 1: Use Docker

```bash
# Start an SSH server in Docker
docker run -d -p 2222:2222 \
  -e USER_NAME=testuser \
  -e USER_PASSWORD=testpass \
  -e PASSWORD_ACCESS=true \
  lscr.io/linuxserver/openssh-server:latest

# Run the example
swift run remote-forward \
  --host localhost \
  --port 2222 \
  --username testuser \
  --password testpass \
  --insecure
```

### Option 2: Use local SSH server (macOS)

```bash
# Enable SSH on macOS (if not already enabled)
sudo systemsetup -setremotelogin on

# Run the example
swift run remote-forward \
  --host localhost \
  --username $(whoami) \
  --password your-mac-password \
  --insecure
```

## Common Issues

### "Address already in use"

The remote port is already bound. Choose a different port:

```swift
let forward = try await client.createRemotePortForward(
    host: "0.0.0.0",
    port: 8081  // Try a different port
) { ... }
```

### "Connection refused" when testing

Make sure:
1. Your local service is running (`python3 -m http.server 3000`)
2. The remote port forward is established (check example output)
3. You're connecting to the correct remote host and port

### "Permission denied" for port < 1024

On most systems, binding to ports below 1024 requires root privileges. Use a higher port:

```swift
let forward = try await client.createRemotePortForward(
    host: "0.0.0.0",
    port: 8080  // Use ports >= 1024
) { ... }
```

## Advanced Usage

### Custom port mappings

```bash
# Forward remote port 8080 to local service on port 5000
swift run remote-forward \
  --host ssh-server.com \
  --username user \
  --password pass \
  --remote-port 8080 \
  --local-port 5000

# Let the server choose the remote port
swift run remote-forward \
  --host ssh-server.com \
  --username user \
  --password pass \
  --remote-port 0
```

### Forward to different local services based on the connection

For advanced routing logic, modify the handler in the source code:

```swift
let forward = try await client.createRemotePortForward(
    host: "0.0.0.0",
    port: 8080
) { channel, info in
    // You can inspect info.originatorAddress to route connections differently
    let localPort: Int

    if info.originatorAddress.ipAddress == "10.0.0.1" {
        localPort = 3000  // Route to service A
    } else {
        localPort = 4000  // Route to service B
    }

    return ClientBootstrap(group: channel.eventLoop)
        .connect(host: "127.0.0.1", port: localPort)
        .flatMap { ... }
}
```

### Handle multiple port forwards

```swift
// Note: Only one handler can be active at a time per client
// The handler receives all forwarded connections and must dispatch them

// Create multiple forwards
let web = try await client.createRemotePortForward(host: "0.0.0.0", port: 8080) { ... }
let api = try await client.createRemotePortForward(host: "0.0.0.0", port: 8081) { ... }

// The second call replaces the handler, so you need to check the port inside:
let forward = try await client.createRemotePortForward(
    host: "0.0.0.0",
    port: 0
) { channel, info in
    switch info.listeningPort {
    case 8080:
        // Forward to web service
        return connectTo(channel, localPort: 3000)
    case 8081:
        // Forward to API service
        return connectTo(channel, localPort: 4000)
    default:
        return channel.close()
    }
}
```

