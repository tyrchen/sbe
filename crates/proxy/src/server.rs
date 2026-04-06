use std::{net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tracing::{debug, info, warn};

use crate::{allowlist::DomainAllowlist, error::ProxyError};

/// A domain-filtering HTTP CONNECT proxy server.
///
/// Binds to `127.0.0.1` on an ephemeral port. Sandboxed processes connect through
/// this proxy via `HTTP_PROXY`/`HTTPS_PROXY` env vars. The proxy checks the target
/// domain against an allowlist before establishing the upstream tunnel.
pub struct ProxyServer {
    listener: TcpListener,
    allowlist: Arc<DomainAllowlist>,
    shutdown_rx: watch::Receiver<bool>,
}

impl ProxyServer {
    /// Create and bind a new proxy server. Returns the server and its bound port.
    pub async fn bind(
        allowlist: DomainAllowlist,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(Self, u16), ProxyError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(ProxyError::Bind)?;
        let port = listener.local_addr().map_err(ProxyError::Bind)?.port();

        info!(port, "sbe proxy listening");

        Ok((
            Self {
                listener,
                allowlist: Arc::new(allowlist),
                shutdown_rx,
            },
            port,
        ))
    }

    /// Run the proxy server until shutdown is signaled.
    pub async fn run(self) -> Result<(), ProxyError> {
        let mut shutdown = self.shutdown_rx;

        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    let (stream, addr): (TcpStream, SocketAddr) = result.map_err(ProxyError::Accept)?;
                    let allowlist = Arc::clone(&self.allowlist);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, addr, &allowlist).await {
                            debug!(error = %e, "proxy connection error");
                        }
                    });
                }
                _ = shutdown.changed() => {
                    info!("sbe proxy shutting down");
                    break;
                }
            }
        }
        Ok(())
    }
}

/// Handle a single proxy connection.
///
/// Reads the HTTP request line, determines the method, and dispatches accordingly.
/// Only CONNECT is supported (for HTTPS tunneling). Other methods are rejected.
async fn handle_connection(
    client: TcpStream,
    addr: SocketAddr,
    allowlist: &DomainAllowlist,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Wrap in BufReader to read request line and headers
    let mut client = BufReader::new(client);

    // Read the request line
    let mut request_line = String::new();
    client.read_line(&mut request_line).await?;
    let request_line = request_line.trim().to_owned();

    if request_line.is_empty() {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        client
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Ok(());
    }

    let method = parts[0].to_uppercase();
    let target = parts[1].to_owned();

    if method == "CONNECT" {
        handle_connect(client, addr, &target, allowlist).await
    } else {
        client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            .await?;
        warn!(method = %method, addr = %addr, "rejected non-CONNECT request");
        Ok(())
    }
}

/// Handle an HTTP CONNECT tunnel request.
async fn handle_connect(
    mut client: BufReader<TcpStream>,
    addr: SocketAddr,
    target: &str,
    allowlist: &DomainAllowlist,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse host:port
    let (host, port) = parse_host_port(target)?;

    // Consume remaining request headers (until empty line)
    let mut header_line = String::new();
    loop {
        header_line.clear();
        client.read_line(&mut header_line).await?;
        if header_line.trim().is_empty() {
            break;
        }
    }

    // Check domain against allowlist
    if !allowlist.is_allowed(&host) {
        warn!(
            host = %host,
            port = port,
            client = %addr,
            "blocked connection to non-allowed domain"
        );
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nsbe: \
             domain '{host}' is not in the allowlist\n"
        );
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    // Connect to upstream
    let upstream_addr = format!("{host}:{port}");
    let mut upstream = TcpStream::connect(&upstream_addr).await.map_err(|e| {
        Box::new(ProxyError::UpstreamConnect {
            host: host.clone(),
            port,
            source: e,
        })
    })?;

    // Send 200 Connection Established
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    client.flush().await?;

    debug!(host = %host, port = port, client = %addr, "tunnel established");

    // Forward any buffered data to upstream
    let buffered = client.buffer().to_vec();
    if !buffered.is_empty() {
        upstream.write_all(&buffered).await?;
    }

    // Unwrap the BufReader to get the underlying TcpStream for bidirectional copy
    let mut client_stream = client.into_inner();

    // Bidirectional copy until either side closes
    let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut upstream).await;

    Ok(())
}

/// Parse "host:port" from a CONNECT target string.
fn parse_host_port(
    target: &str,
) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    // Handle [ipv6]:port
    if let Some(bracket_end) = target.find("]:") {
        let host = target[1..bracket_end].to_owned();
        let port: u16 = target[bracket_end + 2..].parse()?;
        return Ok((host, port));
    }

    let mut parts = target.rsplitn(2, ':');
    let port_str = parts.next().ok_or("missing port")?;
    let host = parts.next().ok_or("missing host")?;
    let port: u16 = port_str.parse()?;
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_parse_host_port() {
        let (host, port) = parse_host_port("registry.npmjs.org:443").unwrap();
        assert_eq!(host, "registry.npmjs.org");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_should_parse_host_port_8000() {
        let (host, port) = parse_host_port("evil.com:8000").unwrap();
        assert_eq!(host, "evil.com");
        assert_eq!(port, 8000);
    }
}
