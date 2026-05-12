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
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/usr",
    "/proc",
    "/sys",
    // Temp
    "/tmp",
    "/var/tmp",
    // Devices we explicitly allow
    "/dev",
    // systemd-resolved stub on Ubuntu/Debian/Fedora: /etc/resolv.conf is a
    // symlink to /run/systemd/resolve/stub-resolv.conf. Landlock follows
    // symlinks to the canonical path, so the resolver can't read the
    // nameserver list without granting read on the symlink target.
    //
    // We name the SPECIFIC files used by the libc resolver rather than the
    // whole directory. The directory also contains
    // `/run/systemd/resolve/io.systemd.Resolve` — a varlink Unix-domain
    // socket. Landlock pre-ABI v6 does NOT gate UDS connect by path-based
    // access, so granting read on the directory enables a build script to
    // connect to the varlink endpoint and ask systemd-resolved to perform
    // arbitrary DNS lookups, bypassing the HTTP CONNECT proxy's domain
    // allowlist. Narrow to the two read-only stub files.
    "/run/systemd/resolve/stub-resolv.conf",
    "/run/systemd/resolve/resolv.conf",
];

/// Baseline writable paths injected into every Linux ruleset.
///
/// Matches the macOS SBPL writer's `/private/tmp` / `/private/var/folders`
/// injection: build toolchains (cc, ld, cargo) need to drop temp files in
/// `/tmp` or `/var/tmp`, and a sandbox that allows execution but not
/// temp-file creation breaks almost every compiler. `/dev/null` and
/// `/dev/zero` are routinely targeted by `Stdio::null()` in build scripts.
const BASELINE_WRITE_PATHS: &[&str] = &["/tmp", "/var/tmp", "/dev/null", "/dev/zero", "/dev/shm"];

/// Privilege-escalation binaries that must never appear under an
/// `allow_exec` subpath. The lint refuses to build the ruleset if a
/// user-supplied profile would re-enable any of these via a directory rule.
const PRIVILEGE_ESCALATION_BINARIES: &[&str] = &[
    // Direct UID change
    "/usr/bin/sudo",
    "/bin/sudo",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/runuser",
    "/usr/sbin/runuser",
    "/usr/bin/gosu",
    "/usr/local/bin/gosu",
    "/usr/bin/doas",
    "/usr/local/bin/doas",
    "/usr/bin/pkexec",
    // Account / shell modification
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/sg",
    "/usr/bin/passwd",
    "/usr/bin/gpasswd",
    // Capability / namespace manipulation (NNP defangs setuid but some
    // of these are file-cap-based and can still raise privs).
    "/usr/bin/capsh",
    "/usr/sbin/capsh",
    "/usr/bin/setpriv",
    "/usr/bin/nsenter",
    "/usr/bin/unshare",
    "/usr/sbin/unshare",
    // systemd / DBus-mediated escalation
    "/usr/bin/systemd-run",
    "/usr/bin/machinectl",
    "/usr/bin/pkttyagent",
    "/usr/bin/dbus-launch",
    // Filesystem mount manipulation
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/bin/mount",
    "/bin/umount",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
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
    if options.allow_degraded {
        // §13 D1: --allow-degraded is a single flag that bypasses
        // *three* unrelated checks (priv-esc subpath lint, denyRead
        // forbidden-list seal, ABI-v4 net-filter gate). Surface every
        // bypass explicitly so users can't accidentally lose unrelated
        // defenses while reaching for the flag to fix a kernel-version
        // problem.
        tracing::warn!(
            "--allow-degraded ACTIVE: the following Linux sandbox checks are DISABLED for this \
             run: (1) privilege-escalation subpath lint (allowExec subpaths can include \
             sudo/su/pkexec/etc.); (2) denyRead forbidden-list seal \
             (allowRead/allowWrite/allowExec may overlap denyRead paths); (3) \
             refuse-on-missing-Landlock-ABI-v4 (kernel may run without per-port TCP filter). \
             Re-run without --allow-degraded for full enforcement."
        );
    }

    // 1. Lints.
    lint_allow_exec_for_priv_escalation(profile, options)?;
    let forbidden_reads = build_forbidden_reads(profile)?;
    lint_forbidden_reads_against_grants(profile, &forbidden_reads, options)?;

    // 2. Resolve read-allowlist (curated anchors + extra paths from profile).
    let read_paths = build_read_paths(profile, &forbidden_reads, options)?;

    let abi = highest_abi(probe);
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?;
    let ruleset = if probe.abi.supports_net_port_filter() && !profile.allow_all_network {
        ruleset.handle_access(AccessNet::ConnectTcp)?
    } else {
        ruleset
    };

    // `set_no_new_privs(false)` here because the pre_exec closure issues the
    // prctl explicitly. Calling it twice is harmless but contradicts the §6
    // invariant that the closure performs exactly the documented syscalls.
    let mut created = ruleset.create()?.set_no_new_privs(false);

    // Read allowlist
    created = add_path_rules(created, &read_paths, read_access(abi))?;

    // Write allowlist: ensure each writable directory exists before opening
    // an FD — Landlock can't grant a rule on a non-existent path, and
    // tools like npm/cargo expect their cache dirs to be writable
    // even on first invocation. We chmod 0700 so secrets in $HOME stay
    // private.
    let write_paths: Vec<PathBuf> = profile
        .allow_write
        .iter()
        .map(|sp| sp.path.clone())
        .chain(BASELINE_WRITE_PATHS.iter().map(PathBuf::from))
        .collect();
    ensure_writable_dirs(&write_paths);
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
        // Refuse symlinks. A pre-existing symlink along this path lets an
        // attacker redirect the Landlock grant onto a target of their
        // choosing — e.g. an earlier build leaves ~/.npm → ~/.ssh, and the
        // next sbe invocation hands write access on ~/.ssh to the
        // sandboxed process. Landlock's PathFd::new uses File::open which
        // follows symlinks; we screen with symlink_metadata first.
        if is_symlink(path) {
            return Err(CoreError::ProfileLint(format!(
                "Landlock allowlist entry '{}' is a symlink. Refusing to open it — a symlink lets \
                 an attacker redirect the grant onto a target of their choosing. Replace the \
                 entry with the canonical target path or remove the symlink before re-running sbe.",
                path.display(),
            )));
        }

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

#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
fn is_symlink(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Create any missing directories from `allow_write` so Landlock can open
/// an FD on each one. We mode-0700 directories under $HOME to protect
/// secrets; paths outside $HOME (e.g. `/tmp`, `/var/tmp`) are left alone.
///
/// Crucial: we use [`std::fs::symlink_metadata`] (does NOT follow
/// symlinks) rather than `Path::exists` (DOES follow) so a pre-existing
/// symlink like `~/.npm → ~/.ssh` doesn't make us conclude "already
/// there" and silently grant Landlock write on the link target later.
/// If the entry itself is a symlink, we leave it alone — `add_path_rules`
/// will refuse to open it and the build aborts.
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
fn ensure_writable_dirs(paths: &[PathBuf]) {
    use std::os::unix::fs::PermissionsExt;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    for p in paths {
        // If a real dir already exists at this path, nothing to do.
        // If a symlink exists, do NOT mkdir into it — add_path_rules will
        // reject it.
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() => {
                tracing::warn!(
                    path = %p.display(),
                    "allow_write entry is a symlink; refusing to materialize. add_path_rules \
                     will reject this entry."
                );
                continue;
            }
            Ok(_) => continue, // real file or dir already exists
            Err(_) => { /* doesn't exist — fall through to mkdir */ }
        }

        // Best-effort recursive create. If any ancestor is a symlink the
        // create can land on an attacker-chosen target — we accept that
        // for the mkdir step but add_path_rules's PathFd::new will still
        // follow the symlink at open time, so the rule itself is what we
        // gate via is_symlink() at the entry level.
        let _ = std::fs::create_dir_all(p);
        if let Some(h) = home.as_ref()
            && p.starts_with(h)
            && let Ok(meta) = std::fs::symlink_metadata(p)
            && !meta.file_type().is_symlink()
            && meta.file_type().is_dir()
        {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            let _ = std::fs::set_permissions(p, perms);
        }
    }
}

fn build_forbidden_reads(profile: &SandboxProfile) -> Result<BTreeSet<PathBuf>, CoreError> {
    let mut set = BTreeSet::new();
    for sp in &profile.deny_read {
        set.insert(sp.path.clone());
    }
    Ok(set)
}

/// Reject any `allow_write` / `allow_exec` entry that overlaps a `denyRead`
/// path. Landlock grants on write_access ([`AccessFs::from_all`]) and
/// exec_access ([`AccessFs::Execute`] | [`AccessFs::from_read`]) **both
/// imply read**, so without this lint a user who writes
///   profiles.node.allowWrite: ["~/"]
/// would silently broaden read access onto every denyRead path under
/// `~/`. The `denyRead` field was billed as a sealed forbidden-list in
/// §8 of the spec — that promise is only valid if we lint all grant
/// fields, not just `allow_read`.
fn lint_forbidden_reads_against_grants(
    profile: &SandboxProfile,
    forbidden: &BTreeSet<PathBuf>,
    options: BackendOptions,
) -> Result<(), CoreError> {
    if options.allow_degraded {
        return Ok(());
    }
    // For each grant field that implies read, check no entry covers a
    // forbidden path. `path_is_under` is "f is under anchor", i.e. anchor
    // would expose f.
    for (field, paths) in [
        ("allowWrite", &profile.allow_write),
        ("allowExec", &profile.allow_exec),
        ("allowRead", &profile.allow_read),
    ] {
        for sp in paths {
            for f in forbidden {
                if path_is_under(f, &sp.path) {
                    return Err(CoreError::ProfileLint(format!(
                        "denyRead path '{}' is under {} entry '{}'. Landlock grants on allowWrite \
                         and allowExec also imply read, so this would silently expose the denied \
                         path. Either narrow the {} entry, remove the denyRead entry, or pass \
                         --allow-degraded if you understand the threat model.",
                        f.display(),
                        field,
                        sp.path.display(),
                        field,
                    )));
                }
            }
        }
    }
    Ok(())
}

fn build_read_paths(
    profile: &SandboxProfile,
    _forbidden: &BTreeSet<PathBuf>,
    _options: BackendOptions,
) -> Result<Vec<PathBuf>, CoreError> {
    // Lint already ran in `lint_forbidden_reads_against_grants` (covers
    // allow_read alongside allow_write and allow_exec). Here we just
    // assemble the baseline anchors + per-profile read extensions.
    let mut out: Vec<PathBuf> = READ_ALLOWLIST_ANCHORS.iter().map(PathBuf::from).collect();
    for sp in &profile.allow_read {
        out.push(sp.path.clone());
    }
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
    fn test_should_not_lint_baseline_anchor_overlap() {
        // §8: the seal is a "promise to never *silently broaden* a path that
        // overlaps denyRead". Baseline anchors (/etc, /tmp, /lib, …) are
        // documented in the README as readable, so they don't count as a
        // user-broadening event — the lint only inspects per-profile
        // allow_read / allow_write / allow_exec entries.
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/home/test/pwd"),
        );
        profile.deny_read.clear();
        profile.deny_read.push(SandboxPath {
            path: PathBuf::from("/etc/ssh"),
            kind: PathKind::Subpath,
        });
        let forbidden = build_forbidden_reads(&profile).unwrap();
        let lint =
            lint_forbidden_reads_against_grants(&profile, &forbidden, BackendOptions::default());
        assert!(lint.is_ok(), "baseline anchor overlap must not lint");
        let res = build_read_paths(&profile, &forbidden, BackendOptions::default());
        assert!(res.is_ok());
    }

    #[test]
    fn test_should_reject_forbidden_read_overlap_with_user_allow_read() {
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/home/test/pwd"),
        );
        profile.deny_read.clear();
        profile.deny_read.push(SandboxPath {
            path: PathBuf::from("/home/test/.ssh"),
            kind: PathKind::Subpath,
        });
        // User config tries to grant ~/ as readable — overlaps denyRead.
        profile.allow_read.push(SandboxPath {
            path: PathBuf::from("/home/test"),
            kind: PathKind::Subpath,
        });
        let forbidden = build_forbidden_reads(&profile).unwrap();
        let err =
            lint_forbidden_reads_against_grants(&profile, &forbidden, BackendOptions::default())
                .unwrap_err();
        assert!(format!("{err}").contains("denyRead"));
        assert!(format!("{err}").contains("allowRead"));
    }

    /// C2: a user who broadens read-access via allowWrite (not allowRead)
    /// must still trip the denyRead seal. The Landlock write_access bitmask
    /// includes read_file/read_dir, so without this check the
    /// "sealed forbidden-list" promise is bypassable trivially.
    #[test]
    fn test_should_reject_forbidden_read_overlap_with_allow_write() {
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/home/test/pwd"),
        );
        profile.deny_read.clear();
        profile.deny_read.push(SandboxPath {
            path: PathBuf::from("/home/test/.ssh"),
            kind: PathKind::Subpath,
        });
        profile.allow_write.push(SandboxPath {
            path: PathBuf::from("/home/test"),
            kind: PathKind::Subpath,
        });
        let forbidden = build_forbidden_reads(&profile).unwrap();
        let err =
            lint_forbidden_reads_against_grants(&profile, &forbidden, BackendOptions::default())
                .unwrap_err();
        assert!(format!("{err}").contains("denyRead"));
        assert!(format!("{err}").contains("allowWrite"));
    }

    /// Same path-class attack but via allowExec. Landlock exec_access
    /// includes from_read so a directory under allowExec is read-visible.
    #[test]
    fn test_should_reject_forbidden_read_overlap_with_allow_exec() {
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/home/test/pwd"),
        );
        profile.deny_read.clear();
        profile.deny_read.push(SandboxPath {
            path: PathBuf::from("/home/test/.aws/credentials"),
            kind: PathKind::Literal,
        });
        profile.allow_exec.push(SandboxPath {
            path: PathBuf::from("/home/test/.aws"),
            kind: PathKind::Subpath,
        });
        let forbidden = build_forbidden_reads(&profile).unwrap();
        let err =
            lint_forbidden_reads_against_grants(&profile, &forbidden, BackendOptions::default())
                .unwrap_err();
        assert!(format!("{err}").contains("allowExec"));
    }

    #[test]
    fn test_should_bypass_forbidden_read_overlap_under_allow_degraded() {
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/home/test/pwd"),
        );
        profile.deny_read.clear();
        profile.deny_read.push(SandboxPath {
            path: PathBuf::from("/home/test/.ssh"),
            kind: PathKind::Subpath,
        });
        profile.allow_write.push(SandboxPath {
            path: PathBuf::from("/home/test"),
            kind: PathKind::Subpath,
        });
        let forbidden = build_forbidden_reads(&profile).unwrap();
        let res = lint_forbidden_reads_against_grants(
            &profile,
            &forbidden,
            BackendOptions {
                allow_degraded: true,
            },
        );
        assert!(res.is_ok(), "allow_degraded should bypass the seal lint");
    }
}
