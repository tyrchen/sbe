//! macOS sandbox backend — `sandbox-exec` / Seatbelt Profile Language.

mod exec;
pub mod sbpl;

use std::{collections::HashMap, path::Path, process::ExitStatus};

use crate::{
    error::CoreError,
    profile::SandboxProfile,
    sandbox::{BackendFeatures, BackendInfo, BackendOptions, SandboxBackend},
};

/// macOS backend wrapping `/usr/bin/sandbox-exec`.
#[derive(Debug)]
pub struct MacosSandbox {
    info: BackendInfo,
}

impl MacosSandbox {
    /// Construct the backend after verifying `sandbox-exec` is available.
    pub fn new() -> Result<Self, CoreError> {
        Self::new_with_options(BackendOptions::default())
    }

    /// Constructor variant that takes [`BackendOptions`]; macOS ignores
    /// `allow_degraded` because there is no degraded path on this platform.
    pub fn new_with_options(_options: BackendOptions) -> Result<Self, CoreError> {
        if !Path::new("/usr/bin/sandbox-exec").exists() {
            return Err(CoreError::BackendUnavailable {
                reason: "sandbox-exec not found at /usr/bin/sandbox-exec; this may indicate \
                         System Integrity Protection (SIP) issues or a non-standard macOS \
                         installation"
                    .to_owned(),
            });
        }

        let kernel = kernel_version();
        let info = BackendInfo {
            name: "sandbox-exec",
            kernel,
            features: BackendFeatures {
                fs_write: true,
                fs_read: true,
                exec_allowlist: true,
                net_port_filter: true,
                audit_stream: true,
            },
        };
        Ok(Self { info })
    }
}

impl SandboxBackend for MacosSandbox {
    fn name(&self) -> &'static str {
        self.info.name
    }

    fn info(&self) -> &BackendInfo {
        &self.info
    }

    fn render_policy(&self, profile: &SandboxProfile, proxy_port: Option<u16>) -> String {
        sbpl::generate(profile, proxy_port)
    }

    fn run(
        &self,
        profile: &SandboxProfile,
        proxy_port: Option<u16>,
        command: &[String],
        extra_env: &HashMap<String, String>,
    ) -> impl std::future::Future<Output = Result<ExitStatus, CoreError>> + Send {
        exec::run_sandboxed(profile, proxy_port, command, extra_env)
    }
}

#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
fn kernel_version() -> String {
    // `uname -sr` runs once at construction; see `linux/probe.rs` for the
    // matching note. std::process::Command avoids touching the tokio runtime.
    if let Ok(output) = std::process::Command::new("uname").arg("-sr").output()
        && let Ok(text) = String::from_utf8(output.stdout)
    {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    "Darwin (unknown)".to_owned()
}
