//! wtcat - WebTransport CLI Client
//!
//! PURPOSE: Generic WebTransport testing tool similar to wscat for WebSockets
//!
//! EXPECTED OUTCOME:
//! - Connect to any WebTransport server
//! - Optional authentication (JWT or custom)
//! - Send and receive messages
//! - Stream real-time updates
//!
//! EXAMPLES:
//! ```bash
//! # Simple connection without auth
//! wtcat --url https://localhost:4433
//!
//! # With JWT token
//! wtcat --url https://localhost:4433 --token "your-jwt-token"
//!
//! # With custom auth endpoint
//! wtcat --url https://localhost:4433 --username admin --password pass --auth-url https://api.example.com/auth/login
//!
//! # Send custom JSON payload on connect
//! wtcat --url https://localhost:4433 --send '{"subscribe": "updates"}'
//!
//! # JSON mode for piping to jq
//! wtcat --url https://localhost:4433 --json | jq
//! ```
use std::error::Error;
use std::sync::Arc;
use clap::Parser;
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::AsyncWriteExt;
use serde_json::json;

#[derive(Parser, Debug)]
#[command(name = "wtcat")]
#[command(version)]
#[command(about = "WebTransport CLI client for testing (like wscat for WebSocket)", long_about = None)]
struct Args {
    /// WebTransport server URL (e.g., https://localhost:4433 or https://localhost:4433/wt)
    #[arg(short, long)]
    url: String,

    /// JWT token for authentication (optional)
    #[arg(short, long)]
    token: Option<String>,

    /// Username for authentication (requires --password and --auth-url)
    #[arg(long)]
    username: Option<String>,

    /// Password for authentication (requires --username and --auth-url)
    #[arg(short = 'p', long)]
    password: Option<String>,

    /// Authentication endpoint URL (e.g., https://api.example.com/auth/login)
    /// Required when using --username and --password
    #[arg(long)]
    auth_url: Option<String>,

    /// Custom JSON payload to send on connection (e.g., '{"subscribe": "updates"}')
    #[arg(short, long)]
    send: Option<String>,

    /// Skip authentication - connect without sending auth message
    #[arg(long)]
    no_auth: bool,

    /// Skip TLS certificate verification (for self-signed certs)
    #[arg(short = 'k', long)]
    insecure: bool,

    /// Output only JSON (no decorative text, pipeable to jq)
    #[arg(short = 'j', long)]
    json: bool,

    /// Timeout for authentication response in seconds
    #[arg(long, default_value = "10")]
    auth_timeout: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let json_mode = args.json;

    if !json_mode {
        println!("🚀 wtcat - WebTransport CLI Client");
        println!("===================================");
    }

    // Validate arguments
    if let (Some(_), Some(_), None) = (&args.username, &args.password, &args.auth_url) {
        eprintln!("❌ Error: --auth-url is required when using --username and --password");
        std::process::exit(1);
    }

    // Get JWT token if username/password provided
    let token = match (&args.token, &args.username, &args.password, &args.auth_url) {
        (Some(t), _, _, _) => {
            if !json_mode {
                println!("✅ Using provided JWT token");
            }
            Some(t.clone())
        }
        (None, Some(username), Some(password), Some(auth_url)) => {
            if !json_mode {
                println!("🔐 Authenticating with username/password...");
            }
            Some(authenticate_and_get_token(username, password, auth_url, json_mode).await?)
        }
        _ => None,
    };

    // Parse URL to extract host and port
    let url = args.url.trim_start_matches("https://").trim_start_matches("http://");
    let server_addr = if url.contains(':') {
        url.split('/').next().unwrap().to_string()
    } else {
        format!("{}:4433", url.split('/').next().unwrap())
    };

    if !json_mode {
        println!("🌐 Connecting to: {}", server_addr);
        if args.no_auth {
            println!("⚡ No authentication mode");
        }
    }

    // Initialize rustls CryptoProvider
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Create client configuration
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    if args.insecure {
        if !json_mode {
            println!("⚠️  WARNING: TLS certificate verification DISABLED");
        }
        // Create a verifier that accepts any certificate
        crypto
            .dangerous()
            .set_certificate_verifier(Arc::new(SkipServerVerification));
    }

    // Set ALPN protocols for HTTP/3 (WebTransport)
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
    ));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // Connect to server
    if !json_mode {
        println!("🔌 Establishing QUIC connection...");
    }

    // Resolve hostname to socket address
    use std::net::ToSocketAddrs;
    let resolved_addr = server_addr
        .to_socket_addrs()?
        .next()
        .ok_or("Failed to resolve server address")?;

    let connection = endpoint
        .connect(resolved_addr, "localhost")?
        .await?;

    if !json_mode {
        println!("✅ Connected! Opening bidirectional stream...");
    }

    // Open a bidirectional stream
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send initial message if not in no-auth mode
    if !args.no_auth {
        let message = if let Some(custom) = args.send {
            // Use custom JSON payload
            if !json_mode {
                println!("📤 Sending custom payload...");
            }
            custom
        } else if let Some(token) = token {
            // Send token-based auth (try to be smart about format)
            if !json_mode {
                println!("📤 Sending authentication...");
            }
            // Default format that works with many servers
            json!({"token": token}).to_string()
        } else {
            // No auth info, but not in no-auth mode - warn user
            if !json_mode {
                println!("⚡ No authentication credentials provided, connecting anyway...");
            }
            String::new()
        };

        if !message.is_empty() {
            send.write_all(message.as_bytes()).await?;
            send.write_all(b"\n").await?;
            send.flush().await?;
        }

        // Read response if we sent something
        if !message.is_empty() {
            let mut buffer = vec![0u8; 4096];
            let read_result = tokio::time::timeout(
                std::time::Duration::from_secs(args.auth_timeout),
                recv.read(&mut buffer)
            ).await;

            match read_result {
                Ok(Ok(Some(n))) => {
                    if n == 0 {
                        eprintln!("❌ Connection closed by server after sending message");
                        return Ok(());
                    }
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    if !json_mode {
                        println!("📥 Server response: {}", response);
                    }

                    // Try to detect error responses
                    if response.contains("\"error\"") || response.contains("\"status\":\"error\"") {
                        eprintln!("❌ Server returned an error: {}", response);
                        return Ok(());
                    }

                    if !json_mode {
                        println!("✅ Connection established!");
                    }
                }
                Ok(Ok(None)) => {
                    eprintln!("❌ Connection closed by server after sending message");
                    return Ok(());
                }
                Ok(Err(e)) => {
                    eprintln!("❌ Read error: {:?}", e);
                    return Ok(());
                }
                Err(_) => {
                    if !json_mode {
                        println!("⏰ No response from server (timeout {}s) - continuing to listen...", args.auth_timeout);
                    }
                }
            }
        }
    } else if !json_mode {
        println!("✅ Connected without authentication!");
    }

    // Listen for messages
    if !json_mode {
        println!("📡 Listening for messages...\n");
        println!("─────────────────────────────────────────────");
    }

    let mut buffer = vec![0u8; 4096];
    let mut message_count = 0;

    loop {
        let n = recv.read(&mut buffer).await?;

        match n {
            Some(0) | None => {
                if !json_mode {
                    println!("\n🔌 Connection closed by server");
                }
                break;
            }
            Some(n) => {
                let message = String::from_utf8_lossy(&buffer[..n]);

                // Handle multiple concatenated JSON objects (some servers send multiple updates)
                let json_objects = if message.contains("}{") {
                    // Multiple JSON objects concatenated - split them
                    let mut objects = Vec::new();
                    let mut current = String::new();
                    let mut depth = 0;

                    for ch in message.chars() {
                        current.push(ch);
                        match ch {
                            '{' => depth += 1,
                            '}' => {
                                depth -= 1;
                                if depth == 0 {
                                    objects.push(current.trim().to_string());
                                    current.clear();
                                }
                            }
                            _ => {}
                        }
                    }
                    objects
                } else {
                    // Single message (could be JSON or plain text)
                    vec![message.to_string()]
                };

                // Process each message
                for msg in json_objects {
                    message_count += 1;

                    // Try to parse as JSON for pretty printing
                    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&msg) {
                        if json_mode {
                            // JSON mode: output only the raw JSON, one per line
                            println!("{}", serde_json::to_string(&json_value)?);
                        } else {
                            // Normal mode: pretty print with decorations
                            println!("\n📨 Message #{}: {}", message_count, serde_json::to_string_pretty(&json_value)?);
                        }
                    } else {
                        // Not JSON - print as plain text
                        if json_mode {
                            // In JSON mode, wrap plain text in JSON object
                            println!("{}", json!({"text": msg}));
                        } else {
                            println!("\n📨 Message #{}: {}", message_count, msg);
                        }
                    }
                }

                if !json_mode {
                    println!("─────────────────────────────────────────────");
                }
            }
        }
    }

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    if !json_mode {
        println!("\n👋 Disconnected. Received {} messages.", message_count);
    }
    Ok(())
}

/// Authenticate with a server and get JWT token
async fn authenticate_and_get_token(
    username: &str,
    password: &str,
    auth_url: &str,
    json_mode: bool,
) -> Result<String, Box<dyn Error>> {
    let client = reqwest::Client::new();

    // Call the login endpoint
    let response = client
        .post(auth_url)
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Authentication failed: {}", response.status()).into());
    }

    // Try to extract token from response (support common formats)
    let response_text = response.text().await?;
    let response_json: serde_json::Value = serde_json::from_str(&response_text)?;

    // Try common token field names
    let token = response_json["token"]
        .as_str()
        .or_else(|| response_json["access_token"].as_str())
        .or_else(|| response_json["jwt"].as_str())
        .ok_or("Could not find token in response (looked for 'token', 'access_token', 'jwt')")?;

    if !json_mode {
        println!("✅ Obtained JWT token");
    }

    Ok(token.to_string())
}

/// Certificate verifier that accepts any certificate (for testing with self-signed certs)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
