/// Errors from the sbe proxy server.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Failed to bind the TCP listener.
    #[error("failed to bind proxy listener: {0}")]
    Bind(#[source] std::io::Error),

    /// Failed to accept a connection.
    #[error("failed to accept connection: {0}")]
    Accept(#[source] std::io::Error),

    /// Failed to connect to upstream.
    #[error("failed to connect to upstream {host}:{port}: {source}")]
    UpstreamConnect {
        host: String,
        port: u16,
        source: std::io::Error,
    },
}
