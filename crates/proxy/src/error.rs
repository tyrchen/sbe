/// Errors from the sbe proxy server.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("invalid proxy configuration: {0}")]
    Config(String),

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

    #[error("proxy protocol error: {0}")]
    Protocol(String),

    #[error("proxy request exceeded {0} limit")]
    Limit(&'static str),

    #[error("proxy operation timed out while reading {0}")]
    Timeout(&'static str),

    #[error("proxy authentication failed")]
    Unauthorized,

    #[error("proxy destination rejected: {0}")]
    Destination(String),

    #[error("proxy I/O: {0}")]
    Io(#[from] std::io::Error),
}
