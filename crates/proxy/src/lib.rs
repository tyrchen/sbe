//! sbe-proxy: Domain-filtering HTTP CONNECT proxy for the sbe sandbox.
//!
//! Runs outside the sandbox, filtering outbound connections by domain allowlist.
//! The sandboxed process is forced through this proxy via HTTP_PROXY/HTTPS_PROXY
//! environment variables, while SBPL blocks all direct outbound connections.

pub mod allowlist;
pub mod error;
pub mod server;

pub use server::ProxyServer;
