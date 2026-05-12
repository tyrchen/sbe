//! Linux sandbox backend — Landlock LSM + seccomp-bpf.
//!
//! Layout mirrors the spec (§7):
//! - [`probe`]   — kernel version + Landlock ABI detection.
//! - [`policy`]  — deterministic YAML rendering for `--dry-run` / inspect.
//! - [`landlock`] — `SandboxProfile` → Landlock [`Ruleset`] with pre-opened FDs.
//! - [`seccomp`] — `SandboxProfile` → seccomp `BpfProgram` bytes.
//! - [`exec`]    — `Command::pre_exec` wiring (alloc-free closure).
//!
//! [`Ruleset`]: ::landlock::Ruleset

mod exec;
mod landlock;
pub mod policy;
mod probe;
mod seccomp;

use std::{collections::HashMap, process::ExitStatus};

pub use probe::ProbeResult;

use crate::{
    error::CoreError,
    profile::SandboxProfile,
    sandbox::{BackendInfo, BackendOptions, SandboxBackend},
};

/// Linux backend wrapping Landlock + seccomp-bpf.
#[derive(Debug)]
pub struct LinuxSandbox {
    info: BackendInfo,
    options: BackendOptions,
    probe: ProbeResult,
}

impl LinuxSandbox {
    /// Probe the kernel and construct the backend. Returns
    /// [`CoreError::BackendUnavailable`] on kernels older than 5.13.
    pub fn new() -> Result<Self, CoreError> {
        Self::new_with_options(BackendOptions::default())
    }

    /// Constructor with runtime options ([`BackendOptions::allow_degraded`]
    /// surfaces here).
    pub fn new_with_options(options: BackendOptions) -> Result<Self, CoreError> {
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

    fn render_policy(&self, profile: &SandboxProfile, proxy_port: Option<u16>) -> String {
        policy::render(profile, proxy_port, &self.probe, self.options)
    }

    fn run(
        &self,
        profile: &SandboxProfile,
        proxy_port: Option<u16>,
        command: &[String],
        extra_env: &HashMap<String, String>,
    ) -> impl std::future::Future<Output = Result<ExitStatus, CoreError>> + Send {
        let probe = self.probe.clone();
        let options = self.options;
        let profile = profile.clone();
        let command = command.to_vec();
        let extra_env = extra_env.clone();
        async move {
            exec::run_sandboxed(&profile, proxy_port, &command, &extra_env, &probe, options).await
        }
    }
}
