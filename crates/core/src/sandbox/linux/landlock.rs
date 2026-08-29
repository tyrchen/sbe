//! Compile a [`SandboxProfile`] into a Landlock [`Ruleset`].
//!
//! All path FDs that the kernel needs are opened in SBE's single-threaded
//! internal launcher and packaged in [`CompiledLandlock`]. No complex policy
//! work occurs in the multithreaded parent's `pre_exec` closure.

#![allow(unsafe_code)] // audited openat2/mkdirat descriptor traversal
//!
//! The compiler also enforces two backend-time lints required by §8:
//! - `allow_exec` subpath entries that overlap privilege-escalation binaries (sudo, su, …) are
//!   rejected.
//! - `deny_read` is sealed as a forbidden list — when later code tries to broaden `allow_read`, an
//!   overlap with `forbidden_reads` is rejected.

use std::{
    collections::BTreeSet,
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
};

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, Scope,
};

use crate::{
    config::SandboxPath,
    error::CoreError,
    profile::{NetworkMode, SandboxProfile},
    sandbox::{
        BackendOptions, SecurityMode,
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
    "/sys",
    // Named devices only; never expose the complete /dev tree.
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    // systemd-resolved stub on Ubuntu/Debian/Fedora: /etc/resolv.conf is a
    // symlink to /run/systemd/resolve/stub-resolv.conf. Landlock follows
    // symlinks to the canonical path, so the resolver can't read the
    // nameserver list without granting read on the symlink target.
    //
    // We name the SPECIFIC files used by the libc resolver rather than the
    // whole directory. The directory also contains
    // `/run/systemd/resolve/io.systemd.Resolve` — a varlink Unix-domain
    // socket. Landlock pre-ABI v9 does NOT gate UDS connect by path-based
    // access, so granting read on the directory enables a build script to
    // connect to the varlink endpoint and ask systemd-resolved to perform
    // arbitrary DNS lookups, bypassing the HTTP CONNECT proxy's domain
    // allowlist. Narrow to the two read-only stub files.
    "/run/systemd/resolve/stub-resolv.conf",
    "/run/systemd/resolve/resolv.conf",
];

/// Public procfs data needed by common runtimes. `/proc` itself is
/// deliberately not granted: doing so would expose `/proc/$PPID/environ` and
/// undo the child environment allowlist.
pub const PROC_READ_ALLOWLIST_ANCHORS: &[&str] = &[
    "/proc/cpuinfo",
    "/proc/filesystems",
    "/proc/loadavg",
    "/proc/meminfo",
    "/proc/stat",
    "/proc/sys",
    "/proc/uptime",
    "/proc/version",
];

/// Baseline writable paths injected into every Linux ruleset.
///
/// Named device files required by ordinary command-line programs. Temporary
/// storage is supplied by the private per-invocation path in the profile.
const BASELINE_WRITE_PATHS: &[&str] = &["/dev/null", "/dev/zero"];
const MAX_CARVED_READ_ENTRIES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UntrustedSymlinkBehavior {
    Follow,
    Reject,
    Skip,
}

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

/// Data-only read rights. `AccessFs::from_read()` also contains `Execute`,
/// which would silently turn broad read anchors such as `/usr` into broad
/// executable grants and defeat the explicit exec allowlist.
fn read_access(_abi: ABI) -> BitFlags<AccessFs> {
    BitFlags::from(AccessFs::ReadFile) | AccessFs::ReadDir
}

fn read_directory_access(_abi: ABI) -> BitFlags<AccessFs> {
    BitFlags::from(AccessFs::ReadDir)
}

/// FS write access flags applied to `allow_write`.
fn write_access(abi: ABI) -> BitFlags<AccessFs> {
    // `from_write()` also includes device ioctl from ABI v5 and Unix-socket
    // resolution from ABI v9. Neither is ordinary file mutation authority:
    // ioctl could operate on a granted device and ResolveUnix could connect
    // to a pre-existing local service in a persistent writable tree.
    let mut access = AccessFs::from_write(abi);
    access.remove(AccessFs::IoctlDev | AccessFs::ResolveUnix);
    access
}

/// Per-run private roots additionally support Unix-domain sockets used by
/// compilers and build coordinators. The root is mode 0700 and deleted after
/// the invocation, so it cannot name an ambient or persistent local service.
fn ephemeral_write_access(abi: ABI) -> BitFlags<AccessFs> {
    write_access(abi) | (AccessFs::from_all(abi) & AccessFs::ResolveUnix)
}

/// FS execute access flags applied to `allow_exec`.
fn exec_access(abi: ABI) -> BitFlags<AccessFs> {
    BitFlags::from(AccessFs::Execute) | read_access(abi)
}

fn highest_abi(probe: &ProbeResult) -> ABI {
    // Land on the highest ABI the running kernel actually supports. The
    // ruleset uses HardRequirement below, so promised rights cannot be
    // silently elided.
    match probe.abi {
        LandlockAbi::Unsupported => ABI::V1,
        LandlockAbi::V1 => ABI::V1,
        LandlockAbi::V2 => ABI::V2,
        LandlockAbi::V3 => ABI::V3,
        LandlockAbi::V4 => ABI::V4,
        LandlockAbi::V5 => ABI::V5,
        LandlockAbi::V6 => ABI::V6,
        LandlockAbi::V7 => ABI::V7,
        LandlockAbi::V8 => ABI::V8,
        LandlockAbi::V9 => ABI::V9,
    }
}

fn effective_network_mode(mode: NetworkMode, security_mode: SecurityMode) -> NetworkMode {
    if security_mode.is_strict() || mode == NetworkMode::DenyAll {
        mode
    } else {
        NetworkMode::AllowAll
    }
}

fn handled_fs_access(abi: ABI) -> BitFlags<AccessFs> {
    // ResolveUnix is a filesystem capability even when TCP networking is
    // unrestricted. Keep it handled so AllowAll cannot implicitly expose
    // capability brokers such as /var/run/docker.sock. Only per-run private
    // roots receive ResolveUnix through ephemeral_write_access().
    AccessFs::from_all(abi)
}

/// A ready-to-apply Landlock ruleset. Built in the single-threaded launcher;
/// the wrapped [`RulesetCreated`] holds all preopened path FDs internally.
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
    security_mode: SecurityMode,
) -> Result<CompiledLandlock, CoreError> {
    // 1. Lints.
    lint_allow_exec_for_priv_escalation(profile, options)?;
    let forbidden_reads = build_forbidden_reads(profile, security_mode)?;
    lint_forbidden_reads_against_grants(profile, &forbidden_reads, security_mode)?;

    let abi = highest_abi(probe);
    let effective_network = effective_network_mode(profile.network_mode, security_mode);
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled_fs_access(abi))?;
    // Signals are a process-isolation capability, not a network capability,
    // so keep them scoped even when the user explicitly requests AllowAll
    // networking. Abstract Unix sockets, on the other hand, are deliberately
    // left ambient only in AllowAll mode. Descendants remain in the same
    // Landlock domain and can signal/connect to one another.
    let ruleset = if probe.abi.supports_scopes() {
        let ruleset = ruleset.scope(Scope::Signal)?;
        if effective_network == NetworkMode::AllowAll {
            ruleset
        } else {
            ruleset.scope(Scope::AbstractUnixSocket)?
        }
    } else {
        ruleset
    };
    let ruleset =
        if probe.abi.supports_net_port_filter() && effective_network != NetworkMode::AllowAll {
            ruleset.handle_access(AccessNet::ConnectTcp | AccessNet::BindTcp)?
        } else {
            ruleset
        };

    // `no_new_privs(false)` here because the single-threaded launcher issues
    // the prctl explicitly immediately before installing the compiled rules.
    let mut created = ruleset.create()?.no_new_privs(false);

    // Every rule is opened atomically without following user-controlled
    // symlinks. Root-owned distro symlinks are resolved only after verifying
    // every lexical and canonical ancestor.
    let baseline_reads: Vec<PathBuf> = READ_ALLOWLIST_ANCHORS
        .iter()
        .chain(PROC_READ_ALLOWLIST_ANCHORS)
        .map(PathBuf::from)
        .collect();
    let mut carved_entries = 0_usize;
    for path in &baseline_reads {
        let sandbox_path = if path.is_dir() {
            SandboxPath::dir(path.clone())
        } else {
            SandboxPath::file(path.clone())
        };
        created = add_read_rule(
            created,
            &sandbox_path,
            &forbidden_reads,
            abi,
            &mut carved_entries,
            UntrustedSymlinkBehavior::Reject,
        )?;
    }
    for sp in &profile.allow_read {
        created = add_read_rule(
            created,
            sp,
            &forbidden_reads,
            abi,
            &mut carved_entries,
            UntrustedSymlinkBehavior::Reject,
        )?;
    }

    for sp in &profile.allow_write {
        let access = if profile
            .ephemeral_write_exec
            .iter()
            .any(|root| sp.path.starts_with(root))
        {
            ephemeral_write_access(abi)
        } else {
            write_access(abi)
        };
        // Standard mode has already replaced existing symlink grants with
        // canonical snapshots. Reject here so missing paths are created via
        // the descriptor-relative no-symlink walk and a parallel build cannot
        // insert a late symlink between profile resolution and compilation.
        created = add_write_rule(created, sp, access, abi, UntrustedSymlinkBehavior::Reject)?;
        // Mutable caches and outputs must be readable to be useful, but they
        // remain non-executable. The forbidden-read lint rejects overlaps.
        created = add_read_rule(
            created,
            sp,
            &forbidden_reads,
            abi,
            &mut carved_entries,
            UntrustedSymlinkBehavior::Reject,
        )?;
    }
    for path in BASELINE_WRITE_PATHS {
        created = add_write_rule(
            created,
            &SandboxPath::file(PathBuf::from(path)),
            write_access(abi),
            abi,
            UntrustedSymlinkBehavior::Reject,
        )?;
    }

    // Exec allowlist (read+exec); covers shared libraries too. Standard mode
    // supplies canonical snapshots, while strict mode skips unsafe optional
    // built-in alternatives and rejects user/runtime aliases.
    for (index, sp) in profile.allow_exec.iter().enumerate() {
        // Built-in profiles list alternatives for multiple distributions and
        // tool managers. If an optional alias exists under a mutable parent,
        // omitting its rule is fail-closed and lets unrelated commands use
        // the profile. User/runtime grants remain strict because silently
        // ignoring an explicitly requested capability would be misleading.
        let symlink_behavior = if security_mode.is_strict() && index < profile.first_user_allow_exec
        {
            UntrustedSymlinkBehavior::Skip
        } else {
            UntrustedSymlinkBehavior::Reject
        };
        created = add_path_rules(
            created,
            std::slice::from_ref(&sp.path),
            exec_access(abi),
            abi,
            symlink_behavior,
        )?;
    }

    // Net rules — only on v4+. Loopback (proxy) or :443 fallback.
    if probe.abi.supports_net_port_filter() {
        match effective_network {
            NetworkMode::Proxy => {
                let port = proxy_port.ok_or_else(|| {
                    CoreError::Backend("proxy network mode has no live proxy port".to_owned())
                })?;
                created = created.add_rule(NetPort::new(port, AccessNet::ConnectTcp))?;
            }
            NetworkMode::DirectHttps443 => {
                created = created.add_rule(NetPort::new(443, AccessNet::ConnectTcp))?;
            }
            NetworkMode::DenyAll | NetworkMode::AllowAll => {}
        }
    }

    Ok(CompiledLandlock { ruleset: created })
}

/// Add a read subtree while preserving holes for built-in `denyRead` paths.
/// Landlock cannot subtract a child rule from a parent grant, so a subtree
/// containing a denied descendant is represented as ReadDir-only ancestors
/// plus data-read rules for each safe sibling inode.
fn add_read_rule(
    created: RulesetCreated,
    path: &SandboxPath,
    forbidden: &BTreeSet<PathBuf>,
    abi: ABI,
    visited: &mut usize,
    symlink_behavior: UntrustedSymlinkBehavior,
) -> Result<RulesetCreated, CoreError> {
    use crate::config::PathKind;

    let comparison_path = if symlink_behavior == UntrustedSymlinkBehavior::Follow {
        canonicalize_if_present(&path.path)?
    } else {
        path.path.clone()
    };
    if forbidden
        .iter()
        .any(|denied| path_is_under(&comparison_path, denied))
    {
        return Ok(created);
    }
    let has_denied_descendant = forbidden
        .iter()
        .any(|denied| denied != &comparison_path && path_is_under(denied, &comparison_path));
    if !has_denied_descendant {
        return add_path_rules(
            created,
            std::slice::from_ref(&path.path),
            read_access(abi),
            abi,
            symlink_behavior,
        );
    }
    if !matches!(path.kind, PathKind::Subpath) {
        return Err(CoreError::ProfileLint(format!(
            "literal read grant '{}' contains a denied descendant",
            path.path.display()
        )));
    }
    let Some(fd) = open_existing_safely_with(&path.path, symlink_behavior)? else {
        return Ok(created);
    };
    add_carved_read_directory(created, fd, &comparison_path, forbidden, abi, visited)
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode compares the opened referent with protected paths before launch"
)]
fn canonicalize_if_present(path: &Path) -> Result<PathBuf, CoreError> {
    match std::fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(error) => Err(CoreError::Io(error)),
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "the policy compiler runs synchronously in the pre-runtime Linux launcher"
)]
fn add_carved_read_directory(
    mut created: RulesetCreated,
    directory: OwnedFd,
    logical_path: &Path,
    forbidden: &BTreeSet<PathBuf>,
    abi: ABI,
    visited: &mut usize,
) -> Result<RulesetCreated, CoreError> {
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&proc_path).map_err(CoreError::Io)? {
        let entry = entry.map_err(CoreError::Io)?;
        *visited = visited.saturating_add(1);
        if *visited > MAX_CARVED_READ_ENTRIES {
            return Err(CoreError::ProfileLint(format!(
                "read policy under '{}' exceeds {MAX_CARVED_READ_ENTRIES} entries",
                logical_path.display()
            )));
        }
        entries.push(entry.file_name());
    }

    // Preserve directory traversal/listing without granting ReadFile to all
    // descendants. A duplicate keeps the original FD available for openat2.
    created = created.add_rule(PathBeneath::new(
        duplicate_fd(directory.as_raw_fd())?,
        read_directory_access(abi),
    ))?;

    for name in entries {
        let child_path = logical_path.join(&name);
        if forbidden
            .iter()
            .any(|denied| path_is_under(&child_path, denied))
        {
            continue;
        }
        let nested_hole = forbidden
            .iter()
            .any(|denied| denied != &child_path && path_is_under(denied, &child_path));
        let name = CString::new(name.as_bytes()).map_err(|_| {
            CoreError::ProfileLint(format!(
                "sandbox path contains NUL below '{}'",
                logical_path.display()
            ))
        })?;
        let child = match openat2_component(directory.as_raw_fd(), &name, nested_hole) {
            Ok(child) => child,
            // Symlinks receive no grant of their own. If their target is an
            // already-authorized safe inode, normal resolution still works;
            // otherwise access remains denied.
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(CoreError::Io(error)),
        };
        if nested_hole {
            created =
                add_carved_read_directory(created, child, &child_path, forbidden, abi, visited)?;
        } else {
            let compatible = access_for_fd(&child, read_access(abi), abi)?;
            created = created.add_rule(PathBeneath::new(child, compatible))?;
        }
    }
    Ok(created)
}

fn duplicate_fd(fd: libc::c_int) -> Result<OwnedFd, CoreError> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated < 0 {
        return Err(CoreError::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn add_path_rules(
    mut created: RulesetCreated,
    paths: &[PathBuf],
    access: BitFlags<AccessFs>,
    abi: ABI,
    symlink_behavior: UntrustedSymlinkBehavior,
) -> Result<RulesetCreated, CoreError> {
    for path in paths {
        if let Some(fd) = open_existing_safely_with(path, symlink_behavior)? {
            let compatible = access_for_fd(&fd, access, abi)?;
            created = created.add_rule(PathBeneath::new(fd, compatible))?;
        }
    }
    Ok(created)
}

fn add_write_rule(
    mut created: RulesetCreated,
    path: &SandboxPath,
    access: BitFlags<AccessFs>,
    abi: ABI,
    symlink_behavior: UntrustedSymlinkBehavior,
) -> Result<RulesetCreated, CoreError> {
    use crate::config::PathKind;
    let fd = match path.kind {
        PathKind::Subpath => Some(open_or_create_directory(&path.path, symlink_behavior)?),
        PathKind::Literal => open_existing_safely_with(&path.path, symlink_behavior)?,
        PathKind::Regex => {
            return Err(CoreError::ProfileLint(format!(
                "regex write grants are not safely enforceable on Linux: '{}'",
                path.path.display()
            )));
        }
    };
    if let Some(fd) = fd {
        let compatible = access_for_fd(&fd, access, abi)?;
        created = created.add_rule(PathBeneath::new(fd, compatible))?;
    } else {
        tracing::debug!(
            path = %path.path.display(),
            "literal write target does not exist; refusing to broaden its parent"
        );
    }
    Ok(created)
}

/// Landlock rejects directory-only rights (for example `ReadDir`, `MakeReg`,
/// or `RemoveFile`) when a rule targets a regular file or device node. Keep
/// the requested subtree rights for directories, but narrow literal file
/// rules to the ABI's file-compatible access set.
fn access_for_fd(
    fd: &OwnedFd,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<BitFlags<AccessFs>, CoreError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(CoreError::Io(std::io::Error::last_os_error()));
    }
    if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
        Ok(access)
    } else {
        Ok(access & AccessFs::from_file(abi))
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "the policy compiler runs synchronously in the pre-runtime Linux launcher"
)]
fn open_existing_safely_with(
    path: &Path,
    symlink_behavior: UntrustedSymlinkBehavior,
) -> Result<Option<OwnedFd>, CoreError> {
    match open_no_symlinks(path, false) {
        Ok(fd) => Ok(Some(fd)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            // `RESOLVE_NO_SYMLINKS` reports ELOOP as soon as it encounters an
            // intermediate system link (for example `/lib -> /usr/lib`),
            // even when the final cross-distribution fallback path does not
            // exist. A missing target receives no Landlock rule and is safe
            // to skip; existing targets still have both chains verified.
            let canonical = match std::fs::canonicalize(path) {
                Ok(canonical) => canonical,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(CoreError::Io(error)),
            };
            if symlink_behavior == UntrustedSymlinkBehavior::Follow {
                return open_no_symlinks(&canonical, false)
                    .map(Some)
                    .map_err(CoreError::Io);
            }
            if let Err(reason) = root_owned_chain(path) {
                return handle_untrusted_symlink(path, &reason, symlink_behavior);
            }
            if let Err(reason) = root_owned_chain(&canonical) {
                let reason = format!("canonical target is not immutable: {reason}");
                return handle_untrusted_symlink(path, &reason, symlink_behavior);
            }
            open_no_symlinks(&canonical, false)
                .map(Some)
                .map_err(CoreError::Io)
        }
        Err(error) => Err(CoreError::Io(error)),
    }
}

fn handle_untrusted_symlink(
    path: &Path,
    reason: &str,
    behavior: UntrustedSymlinkBehavior,
) -> Result<Option<OwnedFd>, CoreError> {
    match behavior {
        UntrustedSymlinkBehavior::Follow => unreachable!("follow is handled before validation"),
        UntrustedSymlinkBehavior::Reject => Err(CoreError::ProfileLint(format!(
            "allowlist path '{}' traverses an untrusted symlink: {reason}",
            path.display()
        ))),
        UntrustedSymlinkBehavior::Skip => {
            tracing::warn!(
                path = %path.display(),
                reason,
                "skipping unsafe optional built-in executable"
            );
            Ok(None)
        }
    }
}

/// Atomically walk and create a writable directory using directory FDs. No
/// component may be a symlink, so a concurrent rename cannot redirect the
/// grant outside the requested path.
fn open_or_create_directory(
    path: &Path,
    symlink_behavior: UntrustedSymlinkBehavior,
) -> Result<OwnedFd, CoreError> {
    if symlink_behavior == UntrustedSymlinkBehavior::Follow {
        let resolved = resolve_for_creation(path)?;
        return open_or_create_directory_no_symlinks(&resolved);
    }
    open_or_create_directory_no_symlinks(path)
}

fn open_or_create_directory_no_symlinks(path: &Path) -> Result<OwnedFd, CoreError> {
    if !path.is_absolute() {
        return Err(CoreError::ProfileLint(format!(
            "sandbox path must be absolute: '{}'",
            path.display()
        )));
    }
    let mut current = open_root().map_err(CoreError::Io)?;
    for component in path.components() {
        use std::path::Component;
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => {
                return Err(CoreError::ProfileLint(format!(
                    "sandbox path contains traversal: '{}'",
                    path.display()
                )));
            }
        };
        let name = CString::new(name.as_bytes()).map_err(|_| {
            CoreError::ProfileLint(format!("sandbox path contains NUL: '{}'", path.display()))
        })?;
        let next = match openat2_component(current.as_raw_fd(), &name, true) {
            Ok(fd) => fd,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let rc = unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) };
                if rc != 0 {
                    let mkdir_error = std::io::Error::last_os_error();
                    if mkdir_error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(CoreError::Io(mkdir_error));
                    }
                }
                openat2_component(current.as_raw_fd(), &name, true).map_err(CoreError::Io)?
            }
            Err(error) => return Err(CoreError::Io(error)),
        };
        current = next;
    }
    Ok(current)
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode snapshots trusted pre-existing symlinks before launching the child"
)]
fn resolve_for_creation(path: &Path) -> Result<PathBuf, CoreError> {
    let mut existing = path;
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(existing) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = existing.file_name().ok_or_else(|| {
                    CoreError::ProfileLint(format!(
                        "sandbox path has no existing ancestor: '{}'",
                        path.display()
                    ))
                })?;
                missing.push(name.to_os_string());
                existing = existing.parent().ok_or_else(|| {
                    CoreError::ProfileLint(format!(
                        "sandbox path has no parent: '{}'",
                        path.display()
                    ))
                })?;
            }
            Err(error) => return Err(CoreError::Io(error)),
        }
    }
}

fn open_no_symlinks(path: &Path, directory: bool) -> std::io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is not absolute",
        ));
    }
    if path == Path::new("/") {
        return open_root();
    }
    let relative = path.strip_prefix("/").expect("absolute path has root");
    let relative = CString::new(relative.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let root = open_root()?;
    openat2_component(root.as_raw_fd(), &relative, directory)
}

fn open_root() -> std::io::Result<OwnedFd> {
    let root = c"/";
    let fd = unsafe { libc::open(root.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn openat2_component(
    directory_fd: libc::c_int,
    path: &CString,
    directory: bool,
) -> std::io::Result<OwnedFd> {
    let mut flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    if directory {
        flags |= libc::O_DIRECTORY as u64;
    }
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags;
    how.mode = 0;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory_fd,
            path.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        ) as libc::c_int
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "the policy compiler runs synchronously in the pre-runtime Linux launcher"
)]
fn root_owned_chain(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        use std::path::Component;
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => current.push(name),
            _ => {
                return Err(format!(
                    "'{}' contains a non-normal path component",
                    path.display()
                ));
            }
        }
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|error| format!("cannot inspect '{}': {error}", current.display()))?;
        // A symlink has no mutable payload: replacing it requires write
        // access to its parent directory. We verify every non-symlink
        // lexical ancestor here and separately verify the complete
        // canonical target chain in `open_existing_safely`. Requiring the
        // link inode itself to be root-owned rejects immutable system links
        // on distributions that preserve a non-root package-builder UID,
        // without adding any security boundary.
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.uid() != 0 {
            return Err(format!(
                "'{}' is owned by UID {}, not root",
                current.display(),
                metadata.uid()
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(format!(
                "'{}' is group/world writable (mode {:o})",
                current.display(),
                metadata.mode() & 0o7777
            ));
        }
    }
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode snapshots an existing denied symlink referent before launch"
)]
fn build_forbidden_reads(
    profile: &SandboxProfile,
    security_mode: SecurityMode,
) -> Result<BTreeSet<PathBuf>, CoreError> {
    let mut set = BTreeSet::new();
    let mut inspected = 0_usize;
    for sp in &profile.deny_read {
        match open_no_symlinks(&sp.path, false) {
            Ok(fd) if security_mode.is_strict() => {
                reject_aliased_forbidden_tree(&fd, &sp.path, &mut inspected)?;
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                if security_mode.is_strict() {
                    return Err(CoreError::ProfileLint(format!(
                        "denyRead path '{}' traverses a symlink; refusing a policy whose \
                         canonical target could receive a read grant",
                        sp.path.display()
                    )));
                }
                match std::fs::canonicalize(&sp.path) {
                    Ok(resolved) => {
                        set.insert(resolved);
                    }
                    Err(resolve_error) if resolve_error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(resolve_error) => return Err(CoreError::Io(resolve_error)),
                }
            }
            Err(error) => return Err(CoreError::Io(error)),
        }
        set.insert(sp.path.clone());
    }
    Ok(set)
}

/// Landlock authorizes filesystem objects, not pathnames. If a denied regular
/// file has another hard link, granting the alias would also authorize the
/// denied name. Recursively verify denied directories and fail closed instead
/// of pretending that path carving can distinguish names for one inode.
#[allow(
    clippy::disallowed_methods,
    reason = "the policy compiler runs synchronously in the pre-runtime Linux launcher"
)]
fn reject_aliased_forbidden_tree(
    fd: &OwnedFd,
    logical_path: &Path,
    inspected: &mut usize,
) -> Result<(), CoreError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(CoreError::Io(std::io::Error::last_os_error()));
    }
    let file_type = stat.st_mode & libc::S_IFMT;
    if file_type == libc::S_IFREG {
        if stat.st_nlink > 1 {
            return Err(CoreError::ProfileLint(format!(
                "denyRead file '{}' has {} hard links; Landlock cannot deny one pathname while an \
                 alias grants the same inode",
                logical_path.display(),
                stat.st_nlink,
            )));
        }
        return Ok(());
    }
    if file_type != libc::S_IFDIR {
        return Ok(());
    }

    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    for entry in std::fs::read_dir(proc_path).map_err(CoreError::Io)? {
        let entry = entry.map_err(CoreError::Io)?;
        *inspected = inspected.saturating_add(1);
        if *inspected > MAX_CARVED_READ_ENTRIES {
            return Err(CoreError::ProfileLint(format!(
                "denyRead policy under '{}' exceeds {MAX_CARVED_READ_ENTRIES} entries",
                logical_path.display()
            )));
        }
        let name = entry.file_name();
        let child_path = logical_path.join(&name);
        let name = CString::new(name.as_bytes()).map_err(|_| {
            CoreError::ProfileLint(format!(
                "sandbox path contains NUL below '{}'",
                logical_path.display()
            ))
        })?;
        let child = match openat2_component(fd.as_raw_fd(), &name, false) {
            Ok(child) => child,
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(CoreError::ProfileLint(format!(
                    "denyRead path '{}' traverses a symlink; refusing a policy whose canonical \
                     target could receive a read grant",
                    child_path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(CoreError::Io(error)),
        };
        reject_aliased_forbidden_tree(&child, &child_path, inspected)?;
    }
    Ok(())
}

/// Reject any **user-supplied** `allow_write` / `allow_exec` / `allow_read`
/// entry that overlaps a `denyRead` path. Mutable paths receive explicit
/// data-read rights and executable paths receive data-read plus Execute, so
/// without this lint a user who writes
///   profiles.node.allowWrite: ["~/"]
/// would silently broaden read access onto every denyRead path under `~/`.
///
/// The lint only inspects entries appended *after* the curated defaults
/// (indices `>= first_user_*`). Built-in defaults intentionally overlap
/// denyRead in places such as `$PWD/.env`; those built-in read roots are
/// compiled as carved descriptor rules instead of a broad parent grant.
#[allow(
    clippy::disallowed_methods,
    reason = "standard mode compares pre-existing grant referents with protected paths before \
              launch"
)]
fn lint_forbidden_reads_against_grants(
    profile: &SandboxProfile,
    forbidden: &BTreeSet<PathBuf>,
    security_mode: SecurityMode,
) -> Result<(), CoreError> {
    let user_slices: [(&str, &[SandboxPath]); 3] = [
        (
            "allowWrite",
            &profile.allow_write[profile.first_user_allow_write..],
        ),
        (
            "allowExec",
            &profile.allow_exec[profile.first_user_allow_exec..],
        ),
        (
            "allowRead",
            &profile.allow_read[profile.first_user_allow_read..],
        ),
    ];
    for (field, paths) in user_slices {
        for sp in paths {
            let resolved = if security_mode.is_strict() {
                None
            } else {
                std::fs::canonicalize(&sp.path).ok()
            };
            for f in forbidden {
                let overlaps = path_is_under(f, &sp.path)
                    || path_is_under(&sp.path, f)
                    || resolved
                        .as_ref()
                        .is_some_and(|path| path_is_under(f, path) || path_is_under(path, f));
                if overlaps {
                    return Err(CoreError::ProfileLint(format!(
                        "denyRead path '{}' overlaps user-supplied {} entry '{}'. Landlock grants \
                         on allowWrite and allowExec include data-read, so this would silently \
                         expose the denied path. Remove or relocate the {} entry, or remove the \
                         denyRead entry.",
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

fn lint_allow_exec_for_priv_escalation(
    profile: &SandboxProfile,
    options: BackendOptions,
) -> Result<(), CoreError> {
    let _ = options;

    for sp in &profile.allow_exec {
        if !is_subpath(sp) {
            continue;
        }
        for binary in PRIVILEGE_ESCALATION_BINARIES {
            let bin_path = Path::new(binary);
            if path_is_under(bin_path, &sp.path) {
                return Err(CoreError::ProfileLint(format!(
                    "allowExec entry '{}' (directory) covers privilege-escalation binary '{}'. \
                     This would defeat the threat model. Replace it with explicit per-binary \
                     entries.",
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
    fn data_read_grants_never_include_execute() {
        let access = read_access(ABI::V9);
        assert!(access.contains(AccessFs::ReadFile));
        assert!(access.contains(AccessFs::ReadDir));
        assert!(!access.contains(AccessFs::Execute));
    }

    #[test]
    fn persistent_write_grants_exclude_execute_ioctl_and_unix_resolution() {
        for abi in [ABI::V1, ABI::V4, ABI::V5, ABI::V9] {
            let access = write_access(abi);
            assert!(!access.contains(AccessFs::Execute));
            assert!(!access.contains(AccessFs::IoctlDev));
            assert!(!access.contains(AccessFs::ResolveUnix));
        }
        assert!(ephemeral_write_access(ABI::V9).contains(AccessFs::ResolveUnix));
        assert!(!ephemeral_write_access(ABI::V9).contains(AccessFs::IoctlDev));
    }

    #[test]
    fn allow_all_keeps_unix_socket_resolution_mediated() {
        assert!(handled_fs_access(ABI::V9).contains(AccessFs::ResolveUnix));
    }

    #[test]
    fn literal_file_rules_drop_directory_only_rights() {
        let temp = tempfile::tempdir().unwrap();
        let file = tempfile::NamedTempFile::new_in(temp.path()).unwrap();

        let directory = open_no_symlinks(temp.path(), true).unwrap();
        let file = open_no_symlinks(file.path(), false).unwrap();
        let requested = read_access(ABI::V9) | write_access(ABI::V9);

        assert_eq!(
            access_for_fd(&directory, requested, ABI::V9).unwrap(),
            requested
        );
        let file_access = access_for_fd(&file, requested, ABI::V9).unwrap();
        assert_eq!(file_access, requested & AccessFs::from_file(ABI::V9));
        assert!(file_access.contains(AccessFs::ReadFile));
        assert!(file_access.contains(AccessFs::WriteFile));
        assert!(!file_access.contains(AccessFs::ReadDir));
        assert!(!file_access.contains(AccessFs::MakeReg));
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the Linux-only policy test is synchronous"
    )]
    fn immutable_system_symlinks_are_trusted() {
        for path in [
            Path::new("/bin/sh"),
            Path::new("/lib64/ld-linux-x86-64.so.2"),
            Path::new("/lib/ld-linux-x86-64.so.2"),
            Path::new("/lib/ld-linux-aarch64.so.1"),
        ] {
            if path.exists() {
                root_owned_chain(path).unwrap();
                let canonical = std::fs::canonicalize(path).unwrap();
                root_owned_chain(&canonical).unwrap();
            }
        }
    }

    #[test]
    fn missing_target_through_symlink_is_skipped_without_a_rule() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), temp.path().join("redirect")).unwrap();

        let missing = temp.path().join("redirect/missing");
        assert!(
            open_existing_safely_with(&missing, UntrustedSymlinkBehavior::Reject)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn existing_target_through_untrusted_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = tempfile::NamedTempFile::new_in(outside.path()).unwrap();
        symlink(target.path(), temp.path().join("redirect")).unwrap();

        let redirect = temp.path().join("redirect");
        assert!(open_existing_safely_with(&redirect, UntrustedSymlinkBehavior::Reject).is_err());
        assert!(
            open_existing_safely_with(&redirect, UntrustedSymlinkBehavior::Skip)
                .unwrap()
                .is_none()
        );
        assert!(
            open_existing_safely_with(&redirect, UntrustedSymlinkBehavior::Follow)
                .unwrap()
                .is_some(),
            "standard mode should authorize the opened referent"
        );
    }

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
    fn test_should_not_bypass_priv_escalation_lint_with_allow_degraded() {
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
                ..BackendOptions::default()
            },
        );
        assert!(res.is_err());
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
        let forbidden = build_forbidden_reads(&profile, SecurityMode::Standard).unwrap();
        let lint =
            lint_forbidden_reads_against_grants(&profile, &forbidden, SecurityMode::Standard);
        assert!(lint.is_ok(), "baseline anchor overlap must not lint");
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
        let forbidden = build_forbidden_reads(&profile, SecurityMode::Standard).unwrap();
        let err = lint_forbidden_reads_against_grants(&profile, &forbidden, SecurityMode::Standard)
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
        let forbidden = build_forbidden_reads(&profile, SecurityMode::Standard).unwrap();
        let err = lint_forbidden_reads_against_grants(&profile, &forbidden, SecurityMode::Standard)
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
        let forbidden = build_forbidden_reads(&profile, SecurityMode::Standard).unwrap();
        let err = lint_forbidden_reads_against_grants(&profile, &forbidden, SecurityMode::Standard)
            .unwrap_err();
        assert!(format!("{err}").contains("allowExec"));
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "synchronous filesystem setup is isolated to this Linux policy unit test"
    )]
    fn standard_symlink_grants_cannot_bypass_a_forbidden_referent() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let protected = home.path().join("protected");
        std::fs::create_dir(&protected).unwrap();
        let alias = home.path().join("ordinary-alias");
        symlink(&protected, &alias).unwrap();

        for field in ["allowRead", "allowWrite", "allowExec"] {
            let mut profile =
                SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), home.path());
            profile.deny_read = vec![SandboxPath::dir(protected.clone())];
            let grant = SandboxPath::dir(alias.clone());
            match field {
                "allowRead" => profile.allow_read.push(grant),
                "allowWrite" => profile.allow_write.push(grant),
                "allowExec" => profile.allow_exec.push(grant),
                _ => unreachable!(),
            }

            let forbidden = build_forbidden_reads(&profile, SecurityMode::Standard).unwrap();
            let error =
                lint_forbidden_reads_against_grants(&profile, &forbidden, SecurityMode::Standard)
                    .unwrap_err();
            assert!(format!("{error}").contains(field));
        }
    }

    #[test]
    fn test_should_reject_user_grants_nested_beneath_forbidden_read() {
        for field in ["allowRead", "allowWrite", "allowExec"] {
            let mut profile = SandboxProfile::for_ecosystem(
                Ecosystem::Rust,
                &PathBuf::from("/home/test"),
                &PathBuf::from("/home/test/pwd"),
            );
            profile.deny_read.clear();
            profile
                .deny_read
                .push(SandboxPath::dir(PathBuf::from("/home/test/.ssh")));
            let grant = SandboxPath::file(PathBuf::from("/home/test/.ssh/id_rsa"));
            match field {
                "allowRead" => profile.allow_read.push(grant),
                "allowWrite" => profile.allow_write.push(grant),
                "allowExec" => profile.allow_exec.push(grant),
                _ => unreachable!(),
            }

            let forbidden = build_forbidden_reads(&profile, SecurityMode::Standard).unwrap();
            let error =
                lint_forbidden_reads_against_grants(&profile, &forbidden, SecurityMode::Standard)
                    .unwrap_err();
            assert!(format!("{error}").contains(field));
        }
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "synchronous filesystem setup is isolated to this Linux policy unit test"
    )]
    fn forbidden_read_symlink_fails_closed() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let target = project.path().join("config.env");
        std::fs::write(&target, "secret").unwrap();
        let denied = project.path().join(".env");
        symlink(&target, &denied).unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, project.path(), project.path());
        profile.deny_read = vec![SandboxPath::file(denied)];

        let error = build_forbidden_reads(&profile, SecurityMode::Strict).unwrap_err();
        assert!(format!("{error}").contains("traverses a symlink"));

        let standard = build_forbidden_reads(&profile, SecurityMode::Standard).unwrap();
        assert!(standard.contains(&target));
        assert!(standard.contains(&project.path().join(".env")));
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "synchronous filesystem setup is isolated to this Linux policy unit test"
    )]
    fn forbidden_read_hard_link_fails_closed() {
        let project = tempfile::tempdir().unwrap();
        let denied = project.path().join(".env");
        let alias = project.path().join("config.env");
        std::fs::write(&denied, "secret").unwrap();
        std::fs::hard_link(&denied, &alias).unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, project.path(), project.path());
        profile.deny_read = vec![SandboxPath::file(denied)];

        let error = build_forbidden_reads(&profile, SecurityMode::Strict).unwrap_err();
        assert!(format!("{error}").contains("hard links"));
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "synchronous filesystem setup is isolated to this Linux policy unit test"
    )]
    fn forbidden_directory_checks_descendant_hard_links() {
        let project = tempfile::tempdir().unwrap();
        let denied_directory = project.path().join("credentials");
        std::fs::create_dir(&denied_directory).unwrap();
        let denied = denied_directory.join("token");
        std::fs::write(&denied, "secret").unwrap();
        std::fs::hard_link(&denied, project.path().join("token-alias")).unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, project.path(), project.path());
        profile.deny_read = vec![SandboxPath::dir(denied_directory)];

        let error = build_forbidden_reads(&profile, SecurityMode::Strict).unwrap_err();
        assert!(format!("{error}").contains("hard links"));
    }

    #[test]
    fn test_should_reject_forbidden_read_overlap_in_standard_mode() {
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
        let forbidden = build_forbidden_reads(&profile, SecurityMode::Standard).unwrap();
        let res = lint_forbidden_reads_against_grants(&profile, &forbidden, SecurityMode::Standard);
        assert!(
            res.is_err(),
            "standard symlink support must not bypass denyRead"
        );
    }

    #[test]
    fn test_open_or_create_directory_refuses_symlink_ancestor() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), temp.path().join("redirect")).unwrap();
        let target = temp.path().join("redirect/cache");
        assert!(open_or_create_directory(&target, UntrustedSymlinkBehavior::Reject).is_err());
        assert!(!outside.path().join("cache").exists());
    }
}
