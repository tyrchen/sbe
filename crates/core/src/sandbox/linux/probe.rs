//! Kernel feature probe — runs once at backend construction.
//!
//! Surfaces:
//! - Kernel string (`uname -sr`) for diagnostics.
//! - Effective Landlock ABI from the running kernel (raw probe syscall).
//! - Derived [`BackendFeatures`].

use crate::{error::CoreError, sandbox::BackendFeatures};

/// Landlock ABI tiers we care about. Each tier maps to a kernel range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LandlockAbi {
    /// Kernel cannot host Landlock at all (<5.13).
    Unsupported,
    /// 5.13–5.18 — base path-beneath rules.
    V1,
    /// 5.19 — `LANDLOCK_ACCESS_FS_REFER`.
    V2,
    /// 6.2 — `LANDLOCK_ACCESS_FS_TRUNCATE`.
    V3,
    /// 6.7 — TCP bind/connect by port.
    V4,
    /// 6.10 — `LANDLOCK_ACCESS_FS_IOCTL_DEV`.
    V5,
    /// 6.12+ — abstract-unix-socket / signal scoping.
    V6,
}

impl LandlockAbi {
    /// Whether the ABI can pin TCP egress to specific ports.
    pub fn supports_net_port_filter(self) -> bool {
        self >= Self::V4
    }

    /// Whether the ABI supports `LANDLOCK_ACCESS_FS_TRUNCATE`.
    pub fn supports_truncate(self) -> bool {
        self >= Self::V3
    }

    /// Whether the ABI supports `LANDLOCK_ACCESS_FS_IOCTL_DEV`.
    pub fn supports_ioctl_dev(self) -> bool {
        self >= Self::V5
    }

    /// Display string used in policy rendering.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::V3 => "v3",
            Self::V4 => "v4",
            Self::V5 => "v5",
            Self::V6 => "v6",
        }
    }
}

impl From<i64> for LandlockAbi {
    fn from(value: i64) -> Self {
        match value {
            ..=0 => Self::Unsupported,
            1 => Self::V1,
            2 => Self::V2,
            3 => Self::V3,
            4 => Self::V4,
            5 => Self::V5,
            _ => Self::V6,
        }
    }
}

/// Outcome of the kernel probe.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// `uname -sr` output, e.g. `"Linux 6.8.0-azure"`.
    pub kernel: String,
    /// Live Landlock ABI on the running kernel.
    pub abi: LandlockAbi,
}

impl ProbeResult {
    /// Derived backend features.
    pub fn features(&self) -> BackendFeatures {
        BackendFeatures {
            fs_write: self.abi >= LandlockAbi::V1,
            fs_read: self.abi >= LandlockAbi::V1,
            exec_allowlist: self.abi >= LandlockAbi::V1,
            net_port_filter: self.abi.supports_net_port_filter(),
            audit_stream: true,
        }
    }
}

/// Probe the kernel and return the resolved [`ProbeResult`].
///
/// Errors with [`CoreError::BackendUnavailable`] if Landlock is missing
/// entirely — by design, sbe refuses to silently downgrade.
pub fn run() -> Result<ProbeResult, CoreError> {
    let kernel = kernel_version();
    let abi = detect_abi();
    if abi == LandlockAbi::Unsupported {
        return Err(CoreError::BackendUnavailable {
            reason: format!(
                "Landlock LSM required (kernel ≥5.13). Detected: {kernel}. Build the kernel with \
                 CONFIG_SECURITY_LANDLOCK=y or run on a newer host."
            ),
        });
    }
    Ok(ProbeResult { kernel, abi })
}

#[cfg(target_os = "linux")]
fn detect_abi() -> LandlockAbi {
    // `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` is
    // documented as a side-effect-free probe call: it returns the supported
    // ABI level (>=1) on success and never creates a ruleset or alters any
    // process state. Wrapping it in a tiny scoped `unsafe` here keeps the
    // surface narrow and avoids pulling in another transitive dep.
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    // SAFETY: passing NULL/0/VERSION matches the kernel's documented
    // version-probe convention; the kernel returns the ABI integer and does
    // not touch userspace memory.
    #[allow(unsafe_code)]
    let raw = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    LandlockAbi::from(raw as i64)
}

#[cfg(not(target_os = "linux"))]
fn detect_abi() -> LandlockAbi {
    LandlockAbi::Unsupported
}

#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
fn kernel_version() -> String {
    // Spawning `uname -sr` is a one-shot synchronous side-task that runs
    // during backend construction, before the tokio executor is needed.
    // Using std::process::Command keeps this off the runtime and lets
    // probing happen in non-async test contexts.
    if let Ok(output) = std::process::Command::new("uname").arg("-sr").output()
        && let Ok(text) = String::from_utf8(output.stdout)
    {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    "Linux (unknown)".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_order_abi_tiers() {
        assert!(LandlockAbi::V4 > LandlockAbi::V3);
        assert!(LandlockAbi::V1 > LandlockAbi::Unsupported);
        assert!(LandlockAbi::V6 >= LandlockAbi::V4);
    }

    #[test]
    fn test_should_report_net_filter_capability() {
        assert!(!LandlockAbi::V1.supports_net_port_filter());
        assert!(!LandlockAbi::V3.supports_net_port_filter());
        assert!(LandlockAbi::V4.supports_net_port_filter());
        assert!(LandlockAbi::V6.supports_net_port_filter());
    }

    #[test]
    fn test_should_map_raw_abi_values() {
        assert_eq!(LandlockAbi::from(0), LandlockAbi::Unsupported);
        assert_eq!(LandlockAbi::from(-1), LandlockAbi::Unsupported);
        assert_eq!(LandlockAbi::from(1), LandlockAbi::V1);
        assert_eq!(LandlockAbi::from(4), LandlockAbi::V4);
        assert_eq!(LandlockAbi::from(99), LandlockAbi::V6);
    }
}
