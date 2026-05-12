use std::path::PathBuf;

/// Errors that can occur in sbe-core.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Failed to determine the user's home directory.
    #[error("could not determine home directory")]
    NoHomeDir,

    /// Failed to read or parse a configuration file.
    #[error("failed to load config from {path}: {source}")]
    ConfigLoad {
        path: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// An extended profile references a base that does not exist.
    #[error("profile '{child}' extends unknown profile '{base}'")]
    UnknownBaseProfile { child: String, base: String },

    /// No ecosystem could be detected and no --profile was given.
    #[error(
        "could not detect ecosystem from command '{command}' or working directory; use --profile"
    )]
    DetectionFailed { command: String },

    /// The backend cannot be constructed on this host (e.g., missing kernel
    /// feature, missing binary). The orchestrator surfaces this directly.
    #[error("sandbox backend unavailable: {reason}")]
    BackendUnavailable { reason: String },

    /// The requested profile cannot be enforced on the current kernel and
    /// `allowDegraded` was not set. Includes the missing capability name so
    /// the user can either upgrade or opt-in.
    #[error(
        "sandbox backend cannot enforce '{capability}' on this kernel (use --allow-degraded to \
         proceed without it): {detail}"
    )]
    BackendDegraded {
        capability: &'static str,
        detail: String,
    },

    /// A backend-time lint rejected the resolved profile (e.g., an exec
    /// allowlist subpath that would re-enable `sudo`).
    #[error("profile lint failed: {0}")]
    ProfileLint(String),

    /// I/O failure while preparing or running the sandboxed process.
    #[error("sandbox I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Backend-specific error from `landlock`, `seccompiler`, or similar.
    #[error("sandbox backend error: {0}")]
    Backend(String),
}
