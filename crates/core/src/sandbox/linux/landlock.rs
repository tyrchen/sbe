//! Compile a [`SandboxProfile`] into a Landlock [`Ruleset`].
//!
//! All path FDs that the kernel needs are opened in the **parent** here
//! (§6 D2) and packaged in [`CompiledLandlock`]. The `pre_exec` closure
//! issues only the `landlock_restrict_self` syscall — no allocation, no FD
//! opens.
//!
//! The compiler also enforces two backend-time lints required by §8:
//! - `allow_exec` subpath entries that overlap privilege-escalation binaries (sudo, su, …) are
//!   rejected.
//! - `deny_read` is sealed as a forbidden list — when later code tries to broaden `allow_read`, an
//!   overlap with `forbidden_reads` is rejected.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    PathFd, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr,
};

use crate::{
    config::SandboxPath,
    error::CoreError,
    profile::SandboxProfile,
    sandbox::{
        BackendOptions,
        linux::probe::{LandlockAbi, ProbeResult},
    },
};

/// Curated baseline read-allowlist anchors. The Linux profile YAML extends
/// this with per-OS additions; here we keep the system-essentials list that
/// the orchestrator always grants, regardless of ecosystem.
///
/// Listed paths are read-only — Landlock writes are still gated by
/// `allow_write`.
pub const READ_ALLOWLIST_ANCHORS: &[&str] = &[
    // Dynamic linker, NSS, system config
    "/etc", "/lib", "/lib32", "/lib64", "/usr", "/proc", "/sys", // Temp
    "/tmp", "/var/tmp", // Devices we explicitly allow
    "/dev",
];

/// Privilege-escalation binaries that must never appear under an
/// `allow_exec` subpath. The lint refuses to build the ruleset if a
/// user-supplied profile would re-enable any of these via a directory rule.
const PRIVILEGE_ESCALATION_BINARIES: &[&str] = &[
    "/usr/bin/sudo",
    "/bin/sudo",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/pkexec",
    "/usr/bin/doas",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/sg",
    "/usr/bin/passwd",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/bin/mount",
    "/bin/umount",
];

/// FS read access flags applied to the curated read allowlist.
fn read_access(abi: ABI) -> BitFlags<AccessFs> {
    AccessFs::from_read(abi)
}

/// FS write access flags applied to `allow_write`.
fn write_access(abi: ABI) -> BitFlags<AccessFs> {
    // From_all includes read+write+exec+make_*+ioctl_dev+truncate; sufficient
    // for an unrestricted "this directory tree is owned by the build" rule.
    AccessFs::from_all(abi)
}

/// FS execute access flags applied to `allow_exec`.
fn exec_access(abi: ABI) -> BitFlags<AccessFs> {
    BitFlags::from(AccessFs::Execute) | AccessFs::from_read(abi)
}

fn highest_abi(probe: &ProbeResult) -> ABI {
    // Land on the highest ABI the running kernel actually supports; the
    // `landlock` crate uses CompatLevel::BestEffort below to silently elide
    // bits the kernel doesn't recognise.
    match probe.abi {
        LandlockAbi::Unsupported => ABI::V1,
        LandlockAbi::V1 => ABI::V1,
        LandlockAbi::V2 => ABI::V2,
        LandlockAbi::V3 => ABI::V3,
        LandlockAbi::V4 => ABI::V4,
        LandlockAbi::V5 => ABI::V5,
        LandlockAbi::V6 => ABI::V6,
    }
}

/// A ready-to-apply Landlock ruleset. Built in the parent; the wrapped
/// [`RulesetCreated`] holds all preopened path FDs internally.
pub struct CompiledLandlock {
    /// `restrict_self` consumes this in the child.
    pub ruleset: RulesetCreated,
}

impl std::fmt::Debug for CompiledLandlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledLandlock").finish_non_exhaustive()
    }
}

/// Compile the profile and return either a [`CompiledLandlock`] or an
/// error explaining which lint/probe step failed.
pub fn compile(
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
    probe: &ProbeResult,
    options: BackendOptions,
) -> Result<CompiledLandlock, CoreError> {
    // 1. Lints.
    lint_allow_exec_for_priv_escalation(profile, options)?;
    let forbidden_reads = build_forbidden_reads(profile)?;

    // 2. Resolve read-allowlist (curated anchors + extra paths from profile).
    let read_paths = build_read_paths(profile, &forbidden_reads)?;

    let abi = highest_abi(probe);
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?;
    let ruleset = if probe.abi.supports_net_port_filter() && !profile.allow_all_network {
        ruleset.handle_access(AccessNet::ConnectTcp)?
    } else {
        ruleset
    };

    let mut created = ruleset.create()?.set_no_new_privs(true);

    // Read allowlist
    created = add_path_rules(created, &read_paths, read_access(abi))?;

    // Write allowlist
    let write_paths: Vec<PathBuf> = profile
        .allow_write
        .iter()
        .map(|sp| sp.path.clone())
        .collect();
    created = add_path_rules(created, &write_paths, write_access(abi))?;

    // Exec allowlist (read+exec); covers shared libraries too.
    let exec_paths: Vec<PathBuf> = profile
        .allow_exec
        .iter()
        .map(|sp| sp.path.clone())
        .collect();
    created = add_path_rules(created, &exec_paths, exec_access(abi))?;

    // Net rules — only on v4+. Loopback (proxy) or :443 fallback.
    if probe.abi.supports_net_port_filter() && !profile.allow_all_network {
        if let Some(port) = proxy_port {
            created = created.add_rule(NetPort::new(port, AccessNet::ConnectTcp))?;
        } else if !profile.enable_proxy {
            created = created.add_rule(NetPort::new(443, AccessNet::ConnectTcp))?;
        }
    }

    Ok(CompiledLandlock { ruleset: created })
}

fn add_path_rules(
    mut created: RulesetCreated,
    paths: &[PathBuf],
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated, CoreError> {
    for path in paths {
        // Skip paths that don't exist on the host: Landlock requires open()
        // on the path, and OpenAt failures here would otherwise abort the
        // whole sandbox. We log via tracing for diagnostics.
        let fd = match PathFd::new(path) {
            Ok(fd) => fd,
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "skipping missing landlock path");
                continue;
            }
        };
        created = created.add_rule(PathBeneath::new(fd, access))?;
    }
    Ok(created)
}

fn build_forbidden_reads(profile: &SandboxProfile) -> Result<BTreeSet<PathBuf>, CoreError> {
    let mut set = BTreeSet::new();
    for sp in &profile.deny_read {
        set.insert(sp.path.clone());
    }
    Ok(set)
}

fn build_read_paths(
    _profile: &SandboxProfile,
    forbidden: &BTreeSet<PathBuf>,
) -> Result<Vec<PathBuf>, CoreError> {
    let mut out: Vec<PathBuf> = READ_ALLOWLIST_ANCHORS.iter().map(PathBuf::from).collect();

    // The profile carries the per-ecosystem read additions in
    // `allow_write` and `allow_exec` — those already grant read implicitly.
    // The forbidden list seals anything the user named under `deny_read`;
    // refuse to build if any anchor overlaps a forbidden entry.
    for anchor in &out {
        for f in forbidden {
            if path_is_under(f, anchor) {
                return Err(CoreError::ProfileLint(format!(
                    "denyRead path '{}' is under baseline read-allowlist anchor '{}'; the \
                     Landlock backend cannot subtract reads from a granted subtree. Either remove \
                     the denyRead entry, override the anchor via a custom profile, or accept that \
                     paths under '{}' are readable on Linux.",
                    f.display(),
                    anchor.display(),
                    anchor.display(),
                )));
            }
        }
    }

    // Merge any user-added read paths (carried via SandboxProfile.allow_write
    // and allow_exec already; we don't read user-supplied "allowRead" because
    // the SandboxProfile struct doesn't expose it directly — the per-OS
    // defaults YAML embeds the same anchors).
    out.sort();
    out.dedup();
    Ok(out)
}

fn lint_allow_exec_for_priv_escalation(
    profile: &SandboxProfile,
    options: BackendOptions,
) -> Result<(), CoreError> {
    if options.allow_degraded {
        return Ok(());
    }

    for sp in &profile.allow_exec {
        if !is_subpath(sp) {
            continue;
        }
        for binary in PRIVILEGE_ESCALATION_BINARIES {
            let bin_path = Path::new(binary);
            if path_is_under(bin_path, &sp.path) {
                return Err(CoreError::ProfileLint(format!(
                    "allowExec entry '{}' (directory) covers privilege-escalation binary '{}'. \
                     This would defeat the threat model. Replace with explicit per-binary entries \
                     or pass --allow-degraded if you know what you are doing.",
                    sp.path.display(),
                    binary,
                )));
            }
        }
    }
    Ok(())
}

fn is_subpath(sp: &SandboxPath) -> bool {
    use crate::config::PathKind;
    matches!(sp.kind, PathKind::Subpath)
}

fn path_is_under(candidate: &Path, anchor: &Path) -> bool {
    candidate == anchor || candidate.starts_with(anchor)
}

impl From<landlock::RulesetError> for CoreError {
    fn from(err: landlock::RulesetError) -> Self {
        CoreError::Backend(format!("landlock ruleset error: {err}"))
    }
}

impl From<landlock::AddRulesError> for CoreError {
    fn from(err: landlock::AddRulesError) -> Self {
        CoreError::Backend(format!("landlock add_rules error: {err}"))
    }
}

impl From<landlock::AddRuleError<AccessFs>> for CoreError {
    fn from(err: landlock::AddRuleError<AccessFs>) -> Self {
        CoreError::Backend(format!("landlock add_rule (fs) error: {err}"))
    }
}

impl From<landlock::AddRuleError<AccessNet>> for CoreError {
    fn from(err: landlock::AddRuleError<AccessNet>) -> Self {
        CoreError::Backend(format!("landlock add_rule (net) error: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        config::{PathKind, SandboxPath},
        detect::Ecosystem,
    };

    #[test]
    fn test_should_reject_priv_escalation_subpath() {
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/home/test/pwd"),
        );
        profile.allow_exec.push(SandboxPath {
            path: PathBuf::from("/usr/bin"),
            kind: PathKind::Subpath,
        });
        let err =
            lint_allow_exec_for_priv_escalation(&profile, BackendOptions::default()).unwrap_err();
        assert!(format!("{err}").contains("privilege-escalation"));
    }

    #[test]
    fn test_should_pass_priv_escalation_with_allow_degraded() {
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/home/test/pwd"),
        );
        profile.allow_exec.push(SandboxPath {
            path: PathBuf::from("/usr/bin"),
            kind: PathKind::Subpath,
        });
        let res = lint_allow_exec_for_priv_escalation(
            &profile,
            BackendOptions {
                allow_degraded: true,
            },
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_should_reject_forbidden_read_overlap() {
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/home/test/pwd"),
        );
        // deny_read entry beneath /etc baseline anchor → must lint.
        profile.deny_read.clear();
        profile.deny_read.push(SandboxPath {
            path: PathBuf::from("/etc/ssh"),
            kind: PathKind::Subpath,
        });
        let forbidden = build_forbidden_reads(&profile).unwrap();
        let err = build_read_paths(&profile, &forbidden).unwrap_err();
        assert!(format!("{err}").contains("denyRead"));
    }
}
