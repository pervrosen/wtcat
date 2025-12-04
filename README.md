# wtcat - WebTransport CLI Client

[![Crates.io](https://img.shields.io/crates/v/wtcat.svg)](https://crates.io/crates/wtcat)
[![Documentation](https://docs.rs/wtcat/badge.svg)](https://docs.rs/wtcat)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/crates/d/wtcat.svg)](https://crates.io/crates/wtcat)

**wtcat** is a WebTransport CLI client for testing and debugging, similar to how `wscat` is used for WebSocket connections. It provides an easy way to connect to WebTransport servers, test authentication, and monitor real-time message streams.

## Features

- 🚀 **Simple WebTransport connections** - Connect to any WebTransport server
- 🔐 **Flexible authentication** - Support for JWT tokens, username/password, or no auth
- 📤 **Custom payloads** - Send arbitrary JSON messages on connection
- 📡 **Real-time streaming** - Monitor server messages in real-time
- 🔧 **JSON mode** - Pipe output to `jq` and other tools
- 🔒 **TLS options** - Support for self-signed certificates (development)
- ⚡ **QUIC/HTTP3** - Built on modern WebTransport protocol

## Installation

### From crates.io

```bash
cargo install wtcat
```

### From source

```bash
git clone https://github.com/pervrosen/wtcat.git
cd wtcat
cargo install --path .
```

## Quick Start

### Basic connection (no auth)

```bash
wtcat --url https://localhost:4433 --no-auth -k
```

### With JWT token

```bash
wtcat --url https://localhost:4433 --token "your-jwt-token" -k
```

### With username/password authentication

```bash
wtcat --url https://localhost:4433 \
  --username admin \
  --password password \
  --auth-url https://api.example.com/auth/login \
  -k
```

### JSON mode (pipeable to jq)

```bash
wtcat --url https://localhost:4433 --token "token" -j -k | jq '.type'
```

## Usage

```
wtcat - WebTransport CLI client for testing (like wscat for WebSocket)

Usage: wtcat [OPTIONS] --url <URL>

Options:
  -u, --url <URL>
          WebTransport server URL (e.g., https://localhost:4433 or https://localhost:4433/wt)

  -t, --token <TOKEN>
          JWT token for authentication (optional)

      --username <USERNAME>
          Username for authentication (requires --password and --auth-url)

  -p, --password <PASSWORD>
          Password for authentication (requires --username and --auth-url)

      --auth-url <AUTH_URL>
          Authentication endpoint URL (e.g., https://api.example.com/auth/login)
          Required when using --username and --password

  -s, --send <SEND>
          Custom JSON payload to send on connection (e.g., '{"subscribe": "updates"}')

      --no-auth
          Skip authentication - connect without sending auth message

  -k, --insecure
          Skip TLS certificate verification (for self-signed certs)

  -j, --json
          Output only JSON (no decorative text, pipeable to jq)

      --auth-timeout <AUTH_TIMEOUT>
          Timeout for authentication response in seconds [default: 10]

  -h, --help
          Print help

  -V, --version
          Print version
```

## Examples

### 1. Test local development server

```bash
wtcat --url https://localhost:4433/wt \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --insecure
```

### 2. Connect with custom auth endpoint

```bash
wtcat --url https://wt.example.com:4433 \
  --username developer \
  --password dev123 \
  --auth-url https://api.example.com/auth/login
```

### 3. Send custom JSON payload

```bash
wtcat --url https://localhost:4433 \
  --send '{"type":"subscribe","channel":"updates"}' \
  --insecure \
  --no-auth
```

### 4. Monitor and filter JSON messages with jq

```bash
# Extract specific fields from all messages
wtcat --url https://localhost:4433 -t $TOKEN -j -k | jq '.timestamp'

# Filter messages by type
wtcat --url https://localhost:4433 -t $TOKEN -j -k | jq 'select(.type == "price_update")'

# Pretty print specific fields
wtcat --url https://localhost:4433 -t $TOKEN -j -k | jq '{type, value, timestamp}'
```

### 5. Testing different servers

```bash
# Connect to production server (with valid cert)
wtcat --url https://wt.production.com:443 --token $TOKEN

# Connect to staging (self-signed cert)
wtcat --url https://wt.staging.com:4433 --token $TOKEN -k

# Connect without any auth
wtcat --url https://test.local:4433 --no-auth -k
```

## Authentication

wtcat supports multiple authentication methods:

### 1. JWT Token (Direct)

Provide a JWT token directly if you already have one:

```bash
wtcat --url https://localhost:4433 --token "your-jwt-token"
```

### 2. Username/Password

Let wtcat fetch a JWT token for you by authenticating against an HTTP API:

```bash
wtcat --url https://localhost:4433 \
  --username admin \
  --password secret \
  --auth-url https://api.example.com/auth/login
```

The auth endpoint should:
- Accept `POST` requests with JSON: `{"username": "...", "password": "..."}`
- Return JSON with one of: `token`, `access_token`, or `jwt` field

### 3. Custom Payload

Send a custom JSON authentication message:

```bash
wtcat --url https://localhost:4433 \
  --send '{"auth_type":"bearer","credentials":"xyz123"}'
```

### 4. No Authentication

Connect without sending any authentication message:

```bash
wtcat --url https://localhost:4433 --no-auth
```

## TLS Certificate Verification

### Development (Self-Signed Certificates)

Use the `-k` or `--insecure` flag to skip certificate verification:

```bash
wtcat --url https://localhost:4433 -k --no-auth
```

⚠️ **Warning**: Only use `--insecure` for development with self-signed certificates. Never use it in production!

### Production (Valid Certificates)

For production servers with CA-signed certificates, simply omit the `-k` flag:

```bash
wtcat --url https://wt.example.com:443 --token $TOKEN
```

## JSON Output Mode

Use `-j` or `--json` to output only JSON messages without decorative text. Perfect for piping to other tools:

```bash
# Basic JSON output
wtcat --url https://localhost:4433 -t $TOKEN -j -k

# With jq for filtering
wtcat --url https://localhost:4433 -t $TOKEN -j -k | jq '.value'

# Save to file
wtcat --url https://localhost:4433 -t $TOKEN -j -k > messages.jsonl

# Process with other tools
wtcat --url https://localhost:4433 -t $TOKEN -j -k | grep "error"
```

## Troubleshooting

### Connection refused

```
Error: Connection refused (os error 61)
```

**Solution**: Ensure the WebTransport server is running and accessible at the specified URL and port.

### Certificate verification failed

```
Error: invalid peer certificate: UnknownIssuer
```

**Solution**: Use the `--insecure` flag for self-signed certificates:

```bash
wtcat --url https://localhost:4433 -k --no-auth
```

### Authentication timeout

```
❌ Timeout waiting for authentication response (10s)
```

**Solutions**:
- Check if the server is responding to authentication requests
- Verify your token is valid and not expired
- Increase timeout with `--auth-timeout 30`
- Try with `--no-auth` to test basic connectivity first

### ALPN protocol mismatch

```
Error: peer doesn't support any known protocol
```

**Solution**: The server must support HTTP/3 ALPN protocol (`h3`). Ensure your server is configured for WebTransport/HTTP3.

## How It Works

wtcat uses the QUIC protocol (HTTP/3) to establish WebTransport connections:

```
┌─────────┐                          ┌─────────┐
│  wtcat  │                          │ Server  │
└────┬────┘                          └────┬────┘
     │                                    │
     │  1. QUIC connection (TLS 1.3)    │
     │──────────────────────────────────>│
     │                                    │
     │  2. Open bidirectional stream     │
     │──────────────────────────────────>│
     │                                    │
     │  3. Send auth/custom message      │
     │──────────────────────────────────>│
     │                                    │
     │  4. Receive response              │
     │<──────────────────────────────────│
     │                                    │
     │  5. Stream messages               │
     │<══════════════════════════════════│
     │  (real-time updates)              │
     │                                    │
```

## Comparison: wtcat vs wscat

| Feature | wtcat (WebTransport) | wscat (WebSocket) |
|---------|---------------------|-------------------|
| Protocol | QUIC/HTTP3 | TCP/HTTP1.1 or HTTP/2 |
| Encryption | TLS 1.3 (mandatory) | Optional (ws/wss) |
| Latency | Lower (0-RTT) | Higher |
| Head-of-line blocking | No | Yes |
| Multiplexing | Native | Via HTTP/2 |
| Mobile-friendly | Yes (survives IP changes) | No |
| Browser support | ~75% (2025) | ~98% |

## Development

### Building from source

```bash
git clone https://github.com/pervrosen/wtcat.git
cd wtcat
cargo build --release
```

### Running tests

```bash
cargo test
```

### Development mode

```bash
cargo run -- --url https://localhost:4433 --no-auth -k
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [wscat](https://github.com/websockets/wscat) for WebSocket
- Built with [Quinn](https://github.com/quinn-rs/quinn) - Rust QUIC implementation
- Uses [rustls](https://github.com/rustls/rustls) for TLS

## Related Projects

- **wscat** - WebSocket testing tool
- **websocat** - Advanced WebSocket client
- **curl** - HTTP client (supports HTTP/3 in newer versions)
- **h2load** - HTTP/2 and HTTP/3 load testing tool

## Support

- 📖 [Documentation](https://docs.rs/wtcat)
- 🐛 [Issue Tracker](https://github.com/pervrosen/wtcat/issues)
- 💬 [Discussions](https://github.com/pervrosen/wtcat/discussions)

---

Made with ❤️ by the Rust community
