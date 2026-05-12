//! macOS execution path: write SBPL to tempfile, spawn `sandbox-exec`.

use std::{collections::HashMap, os::unix::fs::PermissionsExt, process::ExitStatus};

use tempfile::NamedTempFile;
use tokio::process::Command;
use tracing::debug;

use crate::{error::CoreError, profile::SandboxProfile, sandbox::macos::sbpl};

/// Spawn the user command under `sandbox-exec` and wait for it to exit.
pub(super) async fn run_sandboxed(
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
    command: &[String],
    extra_env: &HashMap<String, String>,
) -> Result<ExitStatus, CoreError> {
    let sbpl_text = sbpl::generate(profile, proxy_port);
    let sbpl_file = write_sbpl_tempfile(&sbpl_text).await?;
    let sbpl_path = sbpl_file.path().to_path_buf();
    debug!(path = %sbpl_path.display(), "wrote SBPL profile");

    let program = command
        .first()
        .ok_or_else(|| CoreError::Backend("empty command vector".to_owned()))?;

    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-f").arg(&sbpl_path);
    cmd.arg(program);
    cmd.args(&command[1..]);

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let status = cmd
        .status()
        .await
        .map_err(|e| CoreError::Backend(format!("failed to spawn sandbox-exec: {e}")))?;

    // sbpl_file dropped here — tempfile is unlinked.
    drop(sbpl_file);
    Ok(status)
}

async fn write_sbpl_tempfile(content: &str) -> Result<NamedTempFile, CoreError> {
    let file = NamedTempFile::with_prefix("sbe-")
        .map_err(|e| CoreError::Backend(format!("failed to create SBPL temp file: {e}")))?;

    tokio::fs::write(file.path(), content)
        .await
        .map_err(|e| CoreError::Backend(format!("failed to write SBPL temp file: {e}")))?;

    let perms = std::fs::Permissions::from_mode(0o400);
    tokio::fs::set_permissions(file.path(), perms)
        .await
        .map_err(|e| CoreError::Backend(format!("failed to set SBPL file permissions: {e}")))?;

    Ok(file)
}
