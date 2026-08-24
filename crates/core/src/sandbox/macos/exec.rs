//! macOS execution path: write SBPL to tempfile, spawn `sandbox-exec`.

use std::{collections::HashMap, io::Write, os::unix::fs::PermissionsExt, process::ExitStatus};

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
    pid_tx: Option<tokio::sync::oneshot::Sender<u32>>,
) -> Result<ExitStatus, CoreError> {
    let sbpl_text = sbpl::generate(profile, proxy_port)?;
    let sbpl_file = write_sbpl_tempfile(&sbpl_text)?;
    let sbpl_path = sbpl_file.path().to_path_buf();
    debug!(path = %sbpl_path.display(), "wrote SBPL profile");

    let validation = Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(&sbpl_path)
        .arg("/usr/bin/true")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| CoreError::Backend(format!("failed to validate SBPL profile: {e}")))?;
    if !validation.status.success() {
        return Err(CoreError::Backend(format!(
            "SBPL profile validation failed: {}",
            String::from_utf8_lossy(&validation.stderr).trim()
        )));
    }

    let program = command
        .first()
        .ok_or_else(|| CoreError::Backend("empty command vector".to_owned()))?;

    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-f").arg(&sbpl_path);
    cmd.arg(program);
    cmd.args(&command[1..]);

    cmd.env_clear();
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());
    cmd.kill_on_drop(true);

    // Mark every ambient descriptor close-on-exec while preserving Tokio's
    // internal exec-error pipe until the successful exec boundary.
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max_fd = if max_fd > 0 {
        max_fd.min(libc::c_int::MAX as libc::c_long) as libc::c_int
    } else {
        1024
    };
    // SAFETY: fcntl is async-signal-safe and this closure does not allocate.
    unsafe {
        cmd.pre_exec(move || {
            for fd in 3..max_fd {
                if libc::fcntl(fd, libc::F_GETFD) >= 0
                    && libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| CoreError::Backend(format!("failed to spawn sandbox-exec: {e}")))?;
    if let (Some(sender), Some(pid)) = (pid_tx, child.id()) {
        let _ = sender.send(pid);
    }
    let status = child
        .wait()
        .await
        .map_err(|e| CoreError::Backend(format!("failed to wait for sandbox-exec: {e}")))?;

    // sbpl_file dropped here — tempfile is unlinked.
    drop(sbpl_file);
    Ok(status)
}

fn write_sbpl_tempfile(content: &str) -> Result<NamedTempFile, CoreError> {
    let mut file = NamedTempFile::with_prefix("sbe-")
        .map_err(|e| CoreError::Backend(format!("failed to create SBPL temp file: {e}")))?;
    file.as_file_mut()
        .write_all(content.as_bytes())
        .map_err(|e| CoreError::Backend(format!("failed to write SBPL temp file: {e}")))?;
    let perms = std::fs::Permissions::from_mode(0o400);
    file.as_file()
        .set_permissions(perms)
        .map_err(|e| CoreError::Backend(format!("failed to set SBPL file permissions: {e}")))?;
    Ok(file)
}
