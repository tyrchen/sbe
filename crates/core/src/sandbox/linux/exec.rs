//! Linux execution uses a single-threaded launcher mode in the current SBE
//! executable. Policy compilation and installation happen in that fresh
//! process before any Tokio runtime or worker thread exists.

#![allow(unsafe_code)] // audited prctl/close_range calls in launcher

use std::{
    collections::HashMap,
    io::{Read, Seek, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{ExitCode, ExitStatus},
};

use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, process::Command};

use super::{landlock, probe, seccomp};
use crate::{
    error::CoreError,
    profile::{NetworkMode, SandboxProfile},
    sandbox::{BackendOptions, linux::probe::ProbeResult},
};

const LAUNCHER_MARKER: &str = "__sbe_linux_launcher";
const MAX_LAUNCHER_POLICY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_LAUNCHER_STATUS_BYTES: u64 = 64 * 1024;
const FIRST_LAUNCHER_FD: RawFd = 198;
const LAUNCHER_POLICY_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LauncherPayload {
    version: u32,
    profile: SandboxProfile,
    // These compiler-only fields are intentionally omitted from public
    // profile inspection, so the launcher envelope carries them explicitly.
    first_user_allow_write: usize,
    first_user_allow_exec: usize,
    first_user_allow_read: usize,
    ephemeral_write_exec: Vec<std::path::PathBuf>,
    proxy_port: Option<u16>,
    command: Vec<String>,
    environment: HashMap<String, String>,
    options: BackendOptions,
}

/// Parent-side asynchronous wrapper: write a private bounded payload and
/// spawn the current executable in its pre-runtime launcher mode.
pub(super) async fn run_sandboxed(
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
    command: &[String],
    extra_env: &HashMap<String, String>,
    probe: &ProbeResult,
    options: BackendOptions,
    pid_tx: Option<tokio::sync::oneshot::Sender<u32>>,
) -> Result<ExitStatus, CoreError> {
    enforce_network_capability(profile, probe, options)?;
    profile.validate_security_invariants()?;
    if command.is_empty() {
        return Err(CoreError::Backend("empty command vector".to_owned()));
    }

    let payload = LauncherPayload {
        version: LAUNCHER_POLICY_VERSION,
        profile: profile.clone(),
        first_user_allow_write: profile.first_user_allow_write,
        first_user_allow_exec: profile.first_user_allow_exec,
        first_user_allow_read: profile.first_user_allow_read,
        ephemeral_write_exec: profile.ephemeral_write_exec.clone(),
        proxy_port,
        command: command.to_vec(),
        environment: extra_env.clone(),
        options,
    };
    let encoded = serde_json::to_vec(&payload)
        .map_err(|error| CoreError::Backend(format!("serialize launcher policy: {error}")))?;
    if encoded.len() as u64 > MAX_LAUNCHER_POLICY_BYTES {
        return Err(CoreError::ProfileLint(
            "resolved launcher policy exceeds 2 MiB".to_owned(),
        ));
    }

    // An unlinked file descriptor avoids exposing environment values and the
    // effective policy through a pathname readable by another same-user
    // process. Only the dedicated launcher inherits this descriptor.
    let mut policy = tempfile::tempfile()
        .map_err(|error| CoreError::Backend(format!("create launcher policy: {error}")))?;
    policy.write_all(&encoded).map_err(CoreError::Io)?;
    policy.sync_all().map_err(CoreError::Io)?;
    policy.rewind().map_err(CoreError::Io)?;

    let policy_fd = duplicate_cloexec(policy.as_raw_fd(), FIRST_LAUNCHER_FD)?;
    let (status_parent, status_child) = UnixStream::pair().map_err(CoreError::Io)?;
    status_parent.set_nonblocking(true).map_err(CoreError::Io)?;
    let status_fd = duplicate_cloexec(status_child.as_raw_fd(), FIRST_LAUNCHER_FD)?;

    let executable = std::env::current_exe()
        .map_err(|error| CoreError::Backend(format!("resolve current executable: {error}")))?;
    let mut launcher = Command::new(executable);
    launcher
        .arg(LAUNCHER_MARKER)
        .arg(policy_fd.as_raw_fd().to_string())
        .arg(status_fd.as_raw_fd().to_string());
    launcher.env_clear();
    launcher.stdin(std::process::Stdio::inherit());
    launcher.stdout(std::process::Stdio::inherit());
    launcher.stderr(std::process::Stdio::inherit());
    launcher.kill_on_drop(true);
    let inherited_policy_fd = policy_fd.as_raw_fd();
    let inherited_status_fd = status_fd.as_raw_fd();
    // SAFETY: the closure performs only two async-signal-safe fcntl calls and
    // constructs no Rust values on its success path. The descriptors were
    // duplicated before spawning so they cannot alias Tokio's exec-error pipe.
    unsafe {
        launcher.as_std_mut().pre_exec(move || {
            clear_cloexec(inherited_policy_fd)?;
            clear_cloexec(inherited_status_fd)?;
            Ok(())
        });
    }
    let mut child = launcher
        .spawn()
        .map_err(|error| CoreError::Backend(format!("spawn Linux launcher: {error}")))?;
    drop(policy_fd);
    drop(status_fd);
    drop(status_child);
    if let (Some(sender), Some(pid)) = (pid_tx, child.id()) {
        let _ = sender.send(pid);
    }

    // EOF means the status descriptor was closed atomically by the target's
    // successful exec. Any bytes are a bounded launcher setup error, which is
    // distinct from the target itself choosing exit status 126.
    let status_stream = tokio::net::UnixStream::from_std(status_parent)
        .map_err(|error| CoreError::Backend(format!("open launcher status channel: {error}")))?;
    let mut status_message = Vec::new();
    status_stream
        .take(MAX_LAUNCHER_STATUS_BYTES + 1)
        .read_to_end(&mut status_message)
        .await
        .map_err(|error| CoreError::Backend(format!("read launcher status: {error}")))?;
    if status_message.len() as u64 > MAX_LAUNCHER_STATUS_BYTES {
        return Err(CoreError::Backend(
            "Linux launcher returned an oversized status message".to_owned(),
        ));
    }
    if !status_message.is_empty() {
        let _ = child.wait().await;
        return Err(CoreError::Backend(format!(
            "Linux launcher failed before exec: {}",
            String::from_utf8_lossy(&status_message)
        )));
    }

    child
        .wait()
        .await
        .map_err(|error| CoreError::Backend(format!("wait for Linux launcher: {error}")))
}

fn duplicate_cloexec(fd: RawFd, minimum: RawFd) -> Result<OwnedFd, CoreError> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
    if duplicated < 0 {
        return Err(CoreError::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn clear_cloexec(fd: RawFd) -> std::io::Result<()> {
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Return `Some` only for the internal launcher invocation. This must be
/// called by `main` before creating the Tokio runtime.
pub fn maybe_run_launcher() -> Option<ExitCode> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new(LAUNCHER_MARKER)) {
        return None;
    }
    let Some(policy_fd) = arguments
        .next()
        .and_then(|fd| fd.to_str()?.parse::<RawFd>().ok())
    else {
        eprintln!("sbe launcher: missing or invalid policy descriptor");
        return Some(ExitCode::from(126));
    };
    let Some(status_fd) = arguments
        .next()
        .and_then(|fd| fd.to_str()?.parse::<RawFd>().ok())
    else {
        eprintln!("sbe launcher: missing or invalid status descriptor");
        return Some(ExitCode::from(126));
    };
    if arguments.next().is_some() {
        eprintln!("sbe launcher: unexpected arguments");
        return Some(ExitCode::from(126));
    }
    Some(match launcher_main(policy_fd) {
        Ok(never) => never,
        Err(error) => {
            eprintln!("sbe launcher: {error}");
            write_launcher_error(status_fd, &error);
            ExitCode::from(126)
        }
    })
}

#[allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the internal launcher deliberately runs before any Tokio runtime exists"
)]
fn launcher_main(policy_fd: RawFd) -> Result<ExitCode, CoreError> {
    let mut policy = unsafe { std::fs::File::from_raw_fd(policy_fd) };
    let metadata = policy.metadata().map_err(CoreError::Io)?;
    if !metadata.is_file() || metadata.len() > MAX_LAUNCHER_POLICY_BYTES {
        return Err(CoreError::ProfileLint(
            "invalid launcher policy descriptor".to_owned(),
        ));
    }
    let mut encoded = Vec::new();
    std::io::Read::by_ref(&mut policy)
        .take(MAX_LAUNCHER_POLICY_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(CoreError::Io)?;
    if encoded.len() as u64 > MAX_LAUNCHER_POLICY_BYTES {
        return Err(CoreError::ProfileLint(
            "launcher policy exceeds 2 MiB".to_owned(),
        ));
    }
    let payload: LauncherPayload = serde_json::from_slice(&encoded)
        .map_err(|error| CoreError::Backend(format!("parse launcher policy: {error}")))?;
    if payload.version != LAUNCHER_POLICY_VERSION {
        return Err(CoreError::Backend(format!(
            "unsupported launcher policy version {}",
            payload.version
        )));
    }
    let mut profile = payload.profile;
    profile.first_user_allow_write = payload.first_user_allow_write;
    profile.first_user_allow_exec = payload.first_user_allow_exec;
    profile.first_user_allow_read = payload.first_user_allow_read;
    profile.ephemeral_write_exec = payload.ephemeral_write_exec;
    profile.validate_structural_security_invariants()?;

    let live_probe = probe::run()?;
    enforce_network_capability(&profile, &live_probe, payload.options)?;
    let compiled_landlock =
        landlock::compile(&profile, payload.proxy_port, &live_probe, payload.options)?;
    let compiled_seccomp =
        seccomp::compile(&profile, payload.proxy_port, &live_probe, payload.options)?;

    let program = payload
        .command
        .first()
        .ok_or_else(|| CoreError::Backend("empty launcher command".to_owned()))?;
    let mut target = std::process::Command::new(program);
    target.args(&payload.command[1..]);
    target.env_clear();
    target.envs(&payload.environment);
    target.stdin(std::process::Stdio::inherit());
    target.stdout(std::process::Stdio::inherit());
    target.stderr(std::process::Stdio::inherit());

    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(CoreError::Io(std::io::Error::last_os_error()));
    }
    compiled_landlock
        .ruleset
        .restrict_self()
        .map_err(|error| CoreError::Backend(format!("install Landlock policy: {error}")))?;
    seccompiler::apply_filter_all_threads(&compiled_seccomp.kill)
        .map_err(|error| CoreError::Backend(format!("install seccomp kill filter: {error}")))?;
    seccompiler::apply_filter_all_threads(&compiled_seccomp.errno)
        .map_err(|error| CoreError::Backend(format!("install seccomp errno filter: {error}")))?;

    mark_ambient_fds_close_on_exec()?;
    let error = target.exec();
    Err(CoreError::Backend(format!(
        "exec sandboxed command '{}': {error}",
        program
    )))
}

#[allow(
    clippy::disallowed_types,
    reason = "the pre-runtime launcher reports setup failure through a raw synchronous descriptor"
)]
fn write_launcher_error(status_fd: RawFd, error: &CoreError) {
    let mut status = unsafe { std::fs::File::from_raw_fd(status_fd) };
    let message = error.to_string();
    let bounded = &message.as_bytes()[..message.len().min(MAX_LAUNCHER_STATUS_BYTES as usize)];
    let _ = status.write_all(bounded);
}

fn mark_ambient_fds_close_on_exec() -> Result<(), CoreError> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS) | Some(libc::EINVAL)
    ) {
        return Err(CoreError::Io(error));
    }
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max_fd = if max_fd > 0 {
        max_fd.min(libc::c_int::MAX as libc::c_long)
    } else {
        1024
    };
    for fd in 3..max_fd as libc::c_int {
        let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
        if open && unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(CoreError::Io(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

fn enforce_network_capability(
    profile: &SandboxProfile,
    probe: &ProbeResult,
    options: BackendOptions,
) -> Result<(), CoreError> {
    if matches!(
        profile.network_mode,
        NetworkMode::AllowAll | NetworkMode::DenyAll
    ) {
        // DenyAll is fully enforced by the unconditional seccomp socket(2)
        // rule and does not depend on Landlock's ABI-v4 TCP port mediation.
        return Ok(());
    }
    if profile.network_mode == NetworkMode::Proxy && !options.allow_insecure_network {
        return Err(CoreError::BackendDegraded {
            capability: "strict-domain-egress",
            detail: "Linux Landlock authorizes destination ports, not destination addresses. A \
                     malicious child can bypass the CONNECT proxy. Use \
                     --allow-insecure-linux-network only if that risk is acceptable."
                .to_owned(),
        });
    }
    if probe.abi.supports_net_port_filter() {
        if profile.network_mode == NetworkMode::Proxy {
            eprintln!(
                "sbe: WARNING: insecure Linux network compatibility active; the domain proxy is \
                 bypassable and only its destination port is kernel-enforced"
            );
        }
        return Ok(());
    }
    if options.allow_insecure_network {
        eprintln!(
            "sbe: WARNING: this kernel cannot enforce TCP destination ports; network confinement \
             is not guaranteed"
        );
        return Ok(());
    }
    Err(CoreError::BackendDegraded {
        capability: "landlock-net-connect-tcp",
        detail: format!(
            "kernel ABI is {}; Landlock ABI v4 or newer is required",
            probe.abi.as_str()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Ecosystem;
    use std::path::PathBuf;

    #[test]
    fn strict_proxy_mode_refuses_port_only_linux_confinement() {
        let profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/work/project"),
        );
        let probe = ProbeResult {
            kernel: "test".to_owned(),
            abi: super::super::probe::LandlockAbi::V9,
        };
        let error =
            enforce_network_capability(&profile, &probe, BackendOptions::default()).unwrap_err();
        assert!(format!("{error}").contains("strict-domain-egress"));
    }

    #[test]
    fn insecure_network_compatibility_requires_explicit_option() {
        let profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/work/project"),
        );
        let probe = ProbeResult {
            kernel: "test".to_owned(),
            abi: super::super::probe::LandlockAbi::V9,
        };
        assert!(
            enforce_network_capability(
                &profile,
                &probe,
                BackendOptions {
                    allow_insecure_network: true,
                    ..BackendOptions::default()
                },
            )
            .is_ok()
        );
    }

    #[test]
    fn deny_all_does_not_require_landlock_v4_port_filtering() {
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/work/project"),
        );
        profile.allow_domains.clear();
        profile.recompute_network_mode();
        assert_eq!(profile.network_mode, NetworkMode::DenyAll);
        let probe = ProbeResult {
            kernel: "test".to_owned(),
            abi: super::super::probe::LandlockAbi::V3,
        };

        assert!(enforce_network_capability(&profile, &probe, BackendOptions::default()).is_ok());
    }

    #[test]
    fn launcher_envelope_preserves_policy_compiler_metadata() {
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/work/project"),
        );
        let private = PathBuf::from("/tmp/sbe-private");
        profile
            .allow_write
            .push(crate::config::SandboxPath::dir(private.clone()));
        profile
            .allow_exec
            .push(crate::config::SandboxPath::dir(private.clone()));
        profile.ephemeral_write_exec.push(private.clone());

        let payload = LauncherPayload {
            version: LAUNCHER_POLICY_VERSION,
            profile: profile.clone(),
            first_user_allow_write: profile.first_user_allow_write,
            first_user_allow_exec: profile.first_user_allow_exec,
            first_user_allow_read: profile.first_user_allow_read,
            ephemeral_write_exec: profile.ephemeral_write_exec.clone(),
            proxy_port: None,
            command: vec!["/bin/true".to_owned()],
            environment: HashMap::new(),
            options: BackendOptions::default(),
        };
        let encoded = serde_json::to_vec(&payload).unwrap();
        let decoded: LauncherPayload = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.version, LAUNCHER_POLICY_VERSION);
        assert_eq!(
            decoded.first_user_allow_write,
            profile.first_user_allow_write
        );
        assert_eq!(decoded.first_user_allow_exec, profile.first_user_allow_exec);
        assert_eq!(decoded.first_user_allow_read, profile.first_user_allow_read);
        assert_eq!(decoded.ephemeral_write_exec, vec![private]);

        let mut roundtrip = decoded.profile;
        roundtrip.first_user_allow_write = decoded.first_user_allow_write;
        roundtrip.first_user_allow_exec = decoded.first_user_allow_exec;
        roundtrip.first_user_allow_read = decoded.first_user_allow_read;
        roundtrip.ephemeral_write_exec = decoded.ephemeral_write_exec;
        roundtrip.validate_security_invariants().unwrap();
    }
}
