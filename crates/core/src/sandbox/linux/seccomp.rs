//! Compile per-process seccomp-bpf filters.
//!
//! The filters are the defense-in-depth layer behind Landlock: they block
//! syscalls Landlock doesn't cover (ptrace, raw sockets, user-namespace
//! creation) and reject Internet datagram/raw sockets for restricted modes.
//!
//! We emit **two** [`BpfProgram`]s rather than one: a "kill" filter for
//! hostile syscalls (`ptrace`, `bpf`, `kexec_*`, `init_module`, …) that map
//! to `SCMP_ACT_KILL_PROCESS`, and an "errno" filter for the softer set
//! (`unshare`, `mount`, `chroot`, …) that returns `-EPERM`. The
//! single-threaded launcher applies both before target exec.

use std::{collections::BTreeMap, convert::TryInto};

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

use crate::{
    error::CoreError,
    profile::{NetworkMode, SandboxProfile},
    sandbox::{BackendOptions, linux::probe::ProbeResult},
};

/// Syscalls killed outright when invoked from inside the sandbox.
/// These signal an attempt to break out or attack the process model.
pub const KILL_LIST: &[&str] = &[
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "process_madvise",
    "kcmp",
    "pidfd_getfd",
    "keyctl",
    "add_key",
    "request_key",
    "userfaultfd",
    "bpf",
    "perf_event_open",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
];

/// Syscalls returned with `-EPERM`. Less hostile than KILL; lets the program
/// fall back gracefully (e.g., libc tries multiple paths).
pub const ERRNO_LIST: &[&str] = &[
    "unshare", // user-namespace creation — would let attacker reset Landlock
    "setns",
    "mount",
    "umount2",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "open_tree",
    "move_mount",
    "mount_setattr",
    "swapon",
    "swapoff",
    "pivot_root",
    "chroot",
    "reboot",
    "settimeofday",
    "clock_settime",
    "clock_adjtime",
    "syslog",
    "acct",
    "vhangup",
    "ioperm",
    "iopl",
    "open_by_handle_at",
    "pidfd_open",
    "pidfd_send_signal",
    // io_uring operations do not traverse the ordinary syscall entry points
    // filtered below. Disabling the ring prevents async socket creation from
    // bypassing the restricted-mode socket(2) rules.
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];

/// Two compiled BPF programs ready for installation by the launcher.
#[derive(Debug)]
pub struct CompiledSeccomp {
    pub kill: BpfProgram,
    pub errno: BpfProgram,
}

/// Build the seccomp programs from the resolved profile and probe state.
pub fn compile(
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
    probe: &ProbeResult,
    _options: BackendOptions,
) -> Result<CompiledSeccomp, CoreError> {
    let target_arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| CoreError::Backend(format!("seccomp arch: {e}")))?;

    // KILL filter — match everything in KILL_LIST unconditionally.
    let mut kill_rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for name in KILL_LIST {
        if let Some(nr) = syscall_number(name) {
            kill_rules.entry(nr).or_default();
        }
    }

    let kill: BpfProgram = SeccompFilter::new(
        kill_rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        target_arch,
    )
    .map_err(|e| CoreError::Backend(format!("seccomp kill filter: {e}")))?
    .try_into()
    .map_err(|e| CoreError::Backend(format!("seccomp kill compile: {e}")))?;

    // ERRNO filter — match ERRNO_LIST and capability-specific socket rules.
    let mut errno_rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for name in ERRNO_LIST {
        if let Some(nr) = syscall_number(name) {
            errno_rules.entry(nr).or_default();
        }
    }
    add_network_socket_rules(&mut errno_rules, profile.network_mode)?;

    // A pre-v4 `connect()` address filter is intentionally impossible here:
    // seccomp cannot inspect `copy_from_user`-backed sockaddrs, and matching
    // on the family alone either over-blocks (kills loopback) or under-blocks
    // (matches nothing). On pre-v4 kernels we rely on Landlock's path filter
    // plus an explicit insecure compatibility warning; strict proxy mode
    // refuses to run.
    let _ = (proxy_port, probe); // reserved for capability-specific filters

    let errno: BpfProgram = SeccompFilter::new(
        errno_rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch,
    )
    .map_err(|e| CoreError::Backend(format!("seccomp errno filter: {e}")))?
    .try_into()
    .map_err(|e| CoreError::Backend(format!("seccomp errno compile: {e}")))?;

    Ok(CompiledSeccomp { kill, errno })
}

fn add_network_socket_rules(
    rules: &mut BTreeMap<i64, Vec<SeccompRule>>,
    mode: NetworkMode,
) -> Result<(), CoreError> {
    let Some(socket) = syscall_number("socket") else {
        return Ok(());
    };
    match mode {
        // An empty rule vector means an unconditional syscall match to
        // seccompiler. That is exactly deny-all behavior here.
        NetworkMode::DenyAll => {
            rules.insert(socket, Vec::new());
        }
        // Do not insert the syscall at all: inserting an empty vector would
        // accidentally turn AllowAll into deny-all.
        NetworkMode::AllowAll => {}
        NetworkMode::Proxy | NetworkMode::DirectHttps443 => {
            rules.insert(socket, network_socket_rules(mode)?);
        }
    }
    Ok(())
}

fn network_socket_rules(mode: NetworkMode) -> Result<Vec<SeccompRule>, CoreError> {
    let internet_families = [libc::AF_INET as u64, libc::AF_INET6 as u64];
    let mut rules = Vec::new();
    for family in internet_families {
        if mode != NetworkMode::AllowAll {
            // The low four bits are the socket type; SOCK_CLOEXEC and
            // SOCK_NONBLOCK may be ORed into the argument.
            for socket_type in [
                libc::SOCK_DGRAM,
                libc::SOCK_RAW,
                libc::SOCK_RDM,
                libc::SOCK_SEQPACKET,
            ] {
                rules.push(socket_rule(family, Some(socket_type as u64))?);
            }
        }
    }
    if mode != NetworkMode::AllowAll {
        rules.push(socket_rule(libc::AF_PACKET as u64, None)?);
    }
    Ok(rules)
}

fn socket_rule(family: u64, socket_type: Option<u64>) -> Result<SeccompRule, CoreError> {
    let mut conditions = vec![
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, family)
            .map_err(|error| CoreError::Backend(format!("seccomp socket family rule: {error}")))?,
    ];
    if let Some(socket_type) = socket_type {
        conditions.push(
            SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(0x0f),
                socket_type,
            )
            .map_err(|error| CoreError::Backend(format!("seccomp socket type rule: {error}")))?,
        );
    }
    SeccompRule::new(conditions)
        .map_err(|error| CoreError::Backend(format!("seccomp socket rule: {error}")))
}

/// Lookup a syscall number by name on the current target architecture.
///
/// Uses the libc constants when available; falls back to `None` for the
/// handful of names that libc does not expose. The seccomp filter silently
/// skips unsupported names (they're not present on this arch).
fn syscall_number(name: &str) -> Option<i64> {
    let n: libc::c_long = match name {
        "ptrace" => libc::SYS_ptrace,
        "process_vm_readv" => libc::SYS_process_vm_readv,
        "process_vm_writev" => libc::SYS_process_vm_writev,
        "process_madvise" => libc::SYS_process_madvise,
        "kcmp" => libc::SYS_kcmp,
        "pidfd_getfd" => libc::SYS_pidfd_getfd,
        "keyctl" => libc::SYS_keyctl,
        "add_key" => libc::SYS_add_key,
        "request_key" => libc::SYS_request_key,
        "userfaultfd" => libc::SYS_userfaultfd,
        "bpf" => libc::SYS_bpf,
        "perf_event_open" => libc::SYS_perf_event_open,
        "kexec_load" => libc::SYS_kexec_load,
        #[cfg(target_arch = "x86_64")]
        "kexec_file_load" => libc::SYS_kexec_file_load,
        // libc-rs doesn't expose SYS_kexec_file_load on aarch64-musl
        // (still missing as of 0.2.186). The syscall number is stable
        // kernel ABI — arch/arm64/include/uapi/asm/unistd.h #294 — so
        // hardcode it to keep aarch64-musl builds blocking the syscall
        // identically to aarch64-glibc.
        #[cfg(target_arch = "aarch64")]
        "kexec_file_load" => 294,
        "init_module" => libc::SYS_init_module,
        "finit_module" => libc::SYS_finit_module,
        "delete_module" => libc::SYS_delete_module,
        "unshare" => libc::SYS_unshare,
        "setns" => libc::SYS_setns,
        "mount" => libc::SYS_mount,
        "umount2" => libc::SYS_umount2,
        "fsopen" => libc::SYS_fsopen,
        "fsconfig" => libc::SYS_fsconfig,
        "fsmount" => libc::SYS_fsmount,
        "fspick" => libc::SYS_fspick,
        "open_tree" => libc::SYS_open_tree,
        "move_mount" => libc::SYS_move_mount,
        "mount_setattr" => libc::SYS_mount_setattr,
        "swapon" => libc::SYS_swapon,
        "swapoff" => libc::SYS_swapoff,
        "pivot_root" => libc::SYS_pivot_root,
        "chroot" => libc::SYS_chroot,
        "reboot" => libc::SYS_reboot,
        "settimeofday" => libc::SYS_settimeofday,
        "clock_settime" => libc::SYS_clock_settime,
        "clock_adjtime" => libc::SYS_clock_adjtime,
        "syslog" => libc::SYS_syslog,
        "acct" => libc::SYS_acct,
        #[cfg(target_arch = "x86_64")]
        "vhangup" => libc::SYS_vhangup,
        #[cfg(target_arch = "x86_64")]
        "ioperm" => libc::SYS_ioperm,
        #[cfg(target_arch = "x86_64")]
        "iopl" => libc::SYS_iopl,
        "open_by_handle_at" => libc::SYS_open_by_handle_at,
        "pidfd_open" => libc::SYS_pidfd_open,
        "pidfd_send_signal" => libc::SYS_pidfd_send_signal,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        "socket" => libc::SYS_socket,
        _ => return None,
    };
    Some(n as i64)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        detect::Ecosystem,
        sandbox::linux::probe::{LandlockAbi, ProbeResult},
    };

    fn probe(abi: LandlockAbi) -> ProbeResult {
        ProbeResult {
            kernel: "Linux 6.8.0".to_owned(),
            abi,
        }
    }

    #[test]
    fn test_should_compile_kill_and_errno_filters() {
        let profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/home/test/pwd"),
        );
        let compiled = compile(
            &profile,
            Some(8080),
            &probe(LandlockAbi::V4),
            BackendOptions::default(),
        )
        .expect("seccomp compile");
        assert!(!compiled.kill.is_empty(), "kill filter empty");
        assert!(!compiled.errno.is_empty(), "errno filter empty");
    }

    #[test]
    fn test_should_resolve_known_syscalls() {
        assert!(syscall_number("ptrace").is_some());
        assert!(syscall_number("unshare").is_some());
        assert!(syscall_number("io_uring_setup").is_some());
        assert!(syscall_number("does_not_exist").is_none());
    }

    #[test]
    fn socket_rule_map_preserves_allow_all_and_makes_deny_all_unconditional() {
        let socket = syscall_number("socket").unwrap();

        let mut rules = BTreeMap::new();
        add_network_socket_rules(&mut rules, NetworkMode::AllowAll).unwrap();
        assert!(!rules.contains_key(&socket));

        add_network_socket_rules(&mut rules, NetworkMode::DenyAll).unwrap();
        assert!(rules.get(&socket).is_some_and(Vec::is_empty));
    }

    #[test]
    fn proxy_mode_blocks_datagram_raw_and_packet_sockets() {
        assert_eq!(network_socket_rules(NetworkMode::Proxy).unwrap().len(), 9);
        assert!(
            network_socket_rules(NetworkMode::AllowAll)
                .unwrap()
                .is_empty()
        );
    }
}
