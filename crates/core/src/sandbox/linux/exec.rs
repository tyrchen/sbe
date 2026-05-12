//! Linux execution path: spawn the user command and apply Landlock +
//! seccomp inside `pre_exec` before `execve`.
//!
//! The `pre_exec` closure obeys the hard invariants from §6:
//! - no heap allocation
//! - no FD opens (all FDs preopened in [`super::landlock::compile`])
//! - no tokio / tracing / logger calls
//! - exactly three syscalls: prctl, landlock_restrict_self, seccomp.

#![allow(unsafe_code)] // pre_exec closure is the single justified unsafe site

use std::{collections::HashMap, process::ExitStatus};

use tokio::process::Command;

use super::{landlock, seccomp};
use crate::{
    error::CoreError,
    profile::SandboxProfile,
    sandbox::{BackendOptions, linux::probe::ProbeResult},
};

/// Compile policy, spawn child, return its exit status.
pub(super) async fn run_sandboxed(
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
    command: &[String],
    extra_env: &HashMap<String, String>,
    probe: &ProbeResult,
    options: BackendOptions,
) -> Result<ExitStatus, CoreError> {
    // 1. Gate: refuse-by-default if profile wants net filter but kernel can't
    enforce_network_capability(profile, proxy_port, probe, options)?;

    // 2. Compile all policy artifacts in the parent.
    let compiled_landlock = landlock::compile(profile, proxy_port, probe, options)?;
    let compiled_seccomp = seccomp::compile(profile, proxy_port, probe, options)?;

    let program = command
        .first()
        .ok_or_else(|| CoreError::Backend("empty command vector".to_owned()))?
        .clone();
    let mut cmd = Command::new(&program);
    cmd.args(&command[1..]);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    // Move policy artifacts into the closure by value. The `ruleset` and
    // `program` types both hold their resources internally; we do nothing
    // in the closure but call the kernel APIs.
    //
    // `restrict_self` takes the ruleset by value but `pre_exec` is `FnMut`,
    // so we wrap in `Option::take()` to consume on the (single) call. If the
    // closure is invoked more than once we surface a stable error.
    let landlock::CompiledLandlock { ruleset } = compiled_landlock;
    let seccomp::CompiledSeccomp { program: bpf } = compiled_seccomp;
    let mut ruleset_slot = Some(ruleset);

    // SAFETY: see §6. The closure performs only three syscalls and never
    // allocates, opens an FD, or reads tokio state.
    unsafe {
        cmd.pre_exec(move || {
            // 1. PR_SET_NO_NEW_PRIVS — required for unprivileged seccomp.
            let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // 2. Apply Landlock — consumes the preopened ruleset FD.
            let ruleset = ruleset_slot
                .take()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::Other))?;
            ruleset
                .restrict_self()
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))?;
            // 3. Apply seccomp with TSYNC.
            seccompiler::apply_filter_all_threads(&bpf)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))?;
            Ok(())
        });
    }

    let status = cmd
        .status()
        .await
        .map_err(|e| CoreError::Backend(format!("failed to spawn sandboxed command: {e}")))?;

    Ok(status)
}

/// §13 D1: refuse to start when the kernel can't honour the profile's
/// network expectations, unless the user opted in via `allow_degraded`.
fn enforce_network_capability(
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
    probe: &ProbeResult,
    options: BackendOptions,
) -> Result<(), CoreError> {
    if probe.abi.supports_net_port_filter() {
        return Ok(());
    }
    if profile.allow_all_network {
        return Ok(());
    }

    let needs_net_filter =
        profile.enable_proxy || !profile.allow_domains.is_empty() || proxy_port.is_some();
    if !needs_net_filter {
        return Ok(());
    }

    if options.allow_degraded {
        tracing::warn!(
            abi = probe.abi.as_str(),
            "Landlock ABI <v4 detected; falling back to seccomp connect() arg filter — egress \
             port pinning is best-effort. Continuing under --allow-degraded."
        );
        return Ok(());
    }

    Err(CoreError::BackendDegraded {
        capability: "landlock-net-connect-tcp",
        detail: format!(
            "kernel ABI is {} but the resolved profile requires TCP egress pinning. Upgrade to a \
             kernel with Landlock ABI v4 (Linux 6.7+) or pass --allow-degraded to proceed with a \
             best-effort seccomp arg-filter.",
            probe.abi.as_str()
        ),
    })
}
