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
}
