//! Linux sandbox backend — Landlock LSM + seccomp-bpf.
//!
//! Layout mirrors the spec (§7):
//! - [`probe`]   — kernel version + Landlock ABI detection.
//! - [`policy`]  — deterministic YAML rendering for `--dry-run` / inspect.
//! - [`landlock`] — `SandboxProfile` → Landlock [`Ruleset`] with pre-opened FDs.
//! - [`seccomp`] — `SandboxProfile` → seccomp `BpfProgram` bytes.
//! - [`exec`]    — single-threaded launcher and target exec lifecycle.
//!
//! [`Ruleset`]: ::landlock::Ruleset

mod exec;
mod landlock;
pub mod policy;
mod probe;
mod seccomp;

use std::{collections::HashMap, process::ExitStatus};

pub use exec::maybe_run_launcher;
pub use probe::ProbeResult;

use crate::{
    error::CoreError,
    profile::SandboxProfile,
    sandbox::{BackendInfo, BackendOptions, SandboxBackend, SecurityMode},
};

/// Linux backend wrapping Landlock + seccomp-bpf.
#[derive(Debug)]
pub struct LinuxSandbox {
    info: BackendInfo,
    options: BackendOptions,
    security_mode: SecurityMode,
    probe: ProbeResult,
}

impl LinuxSandbox {
    /// Probe the kernel and construct the backend. Returns
    /// [`CoreError::BackendUnavailable`] on kernels older than 5.13.
    pub fn new() -> Result<Self, CoreError> {
        Self::new_with_options(BackendOptions::default())
    }

    /// Constructor with capability-specific runtime options.
    pub fn new_with_options(options: BackendOptions) -> Result<Self, CoreError> {
        Self::new_with_mode(options, SecurityMode::Standard)
    }

    /// Constructor variant that selects the product-level security contract.
    pub fn new_with_mode(
        options: BackendOptions,
        security_mode: SecurityMode,
    ) -> Result<Self, CoreError> {
        let probe = probe::run()?;
        let features = probe.features();
        let info = BackendInfo {
            name: "landlock+seccomp",
            kernel: probe.kernel.clone(),
            features,
        };
        Ok(Self {
            info,
            options,
            security_mode,
            probe,
        })
    }

    /// Borrow the live probe — used by `render_policy` and `exec`.
    pub fn probe(&self) -> &ProbeResult {
        &self.probe
    }
}

impl SandboxBackend for LinuxSandbox {
    fn name(&self) -> &'static str {
        self.info.name
    }

    fn info(&self) -> &BackendInfo {
        &self.info
    }

    fn render_policy(
        &self,
        profile: &SandboxProfile,
        proxy_port: Option<u16>,
    ) -> Result<String, CoreError> {
        Ok(policy::render(
            profile,
            proxy_port,
            &self.probe,
            self.options,
            self.security_mode,
        ))
    }

    fn run(
        &self,
        profile: &SandboxProfile,
        proxy_port: Option<u16>,
        command: &[String],
        extra_env: &HashMap<String, String>,
        pid_tx: Option<tokio::sync::oneshot::Sender<u32>>,
    ) -> impl std::future::Future<Output = Result<ExitStatus, CoreError>> + Send {
        let probe = self.probe.clone();
        let options = self.options;
        let security_mode = self.security_mode;
        let profile = profile.clone();
        let command = command.to_vec();
        let extra_env = extra_env.clone();
        async move {
            exec::run_sandboxed(
                &profile,
                proxy_port,
                &command,
                &extra_env,
                &probe,
                options,
                security_mode,
                pid_tx,
            )
            .await
        }
    }
}
