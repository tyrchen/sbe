//! Platform-specific sandbox backends.
//!
//! [`SandboxBackend`] is the seam between the orchestrator and the kernel.
//! Backends are selected at compile time via `cfg(target_os = "...")` and
//! re-exported as [`Sandbox`] — callers outside this module never name the
//! platform-specific type.
//!
//! ## Construction contract
//!
//! Every backend exposes `pub fn new() -> Result<Self, CoreError>`.
//! Construction performs the kernel/feature probe; the resulting
//! [`BackendInfo`] is stable for the lifetime of the instance.
//! If the platform cannot host the backend at all (kernel <5.13 on Linux,
//! `sandbox-exec` missing on macOS), construction fails with
//! [`CoreError::BackendUnavailable`] — no degraded silent path.

use std::{collections::HashMap, process::ExitStatus};

use crate::{error::CoreError, profile::SandboxProfile};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosSandbox as Sandbox;
#[cfg(target_os = "macos")]
pub use macos::sbpl;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxSandbox as Sandbox;
#[cfg(target_os = "linux")]
pub use linux::policy;

/// A platform-specific sandbox backend.
///
/// Implementations turn a resolved [`SandboxProfile`] into kernel-enforced
/// restrictions on a spawned child process. The orchestrator holds the
/// concrete `Sandbox` re-export (never `dyn SandboxBackend`); object safety
/// is intentionally not required.
pub trait SandboxBackend: Send + Sync {
    /// Human-readable backend identifier, e.g. `"sandbox-exec"` or
    /// `"landlock+seccomp"`. Surfaced in `sbe inspect` output and audit logs.
    fn name(&self) -> &'static str;

    /// What this backend can enforce on the current kernel/host. Populated
    /// during construction (`Self::new` performs the kernel probe); this
    /// accessor is infallible.
    fn info(&self) -> &BackendInfo;

    /// Render the resolved policy for `--dry-run` and `sbe inspect`. Output
    /// must be deterministic and platform-stable so tests can assert on
    /// substrings.
    ///
    /// - macOS: canonical SBPL Scheme document.
    /// - Linux: a YAML document listing the Landlock ruleset, the seccomp action table, the proxy
    ///   env, and the resolved [`BackendFeatures`].
    fn render_policy(&self, profile: &SandboxProfile, proxy_port: Option<u16>) -> String;

    /// Run the user command under the sandbox and return its exit status.
    ///
    /// The backend owns the per-invocation lifecycle: compile profile →
    /// platform artifact (SBPL tempfile / Ruleset+BpfProgram), spawn child
    /// with policy applied before `execve`, wait, clean up.
    ///
    /// Proxy lifecycle, audit logging, config resolution and exit-code
    /// mapping live in the orchestrator. `extra_env` is the
    /// orchestrator-merged environment (proxy vars + `profile.env`).
    fn run(
        &self,
        profile: &SandboxProfile,
        proxy_port: Option<u16>,
        command: &[String],
        extra_env: &HashMap<String, String>,
    ) -> impl std::future::Future<Output = Result<ExitStatus, CoreError>> + Send;
}

/// What a backend can enforce on the current kernel/host.
#[derive(Debug, Clone)]
pub struct BackendInfo {
    /// Backend identifier; matches [`SandboxBackend::name`].
    pub name: &'static str,
    /// Kernel version string for diagnostics; e.g. "Darwin 24.6.0" or "Linux 6.8.0".
    pub kernel: String,
    /// Feature flags resolved from the live kernel probe.
    pub features: BackendFeatures,
}

/// Granular feature bits derived from the kernel probe.
#[derive(Debug, Clone, Copy, Default)]
pub struct BackendFeatures {
    /// FS write allowlist enforceable.
    pub fs_write: bool,
    /// FS read denylist enforceable.
    pub fs_read: bool,
    /// Per-path exec allowlist enforceable.
    pub exec_allowlist: bool,
    /// Outbound TCP can be pinned to specific port(s).
    pub net_port_filter: bool,
    /// `--audit` streaming of violation events supported.
    pub audit_stream: bool,
}

/// Runtime knobs the CLI feeds into `Sandbox::new_with_options`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BackendOptions {
    /// Proceed even when the backend cannot fully enforce the requested
    /// profile (e.g., Landlock without ABI v4 net support). The backend
    /// prints a single warning line naming the missing capability.
    pub allow_degraded: bool,
}
