//! Compile per-process seccomp-bpf filters.
//!
//! The filters are the defense-in-depth layer behind Landlock: they block
//! syscalls Landlock doesn't cover (ptrace, raw sockets, user-namespace
//! creation) and, on pre-v4 kernels, narrow `connect()` semantics best-effort.
//!
//! We emit **two** [`BpfProgram`]s rather than one: a "kill" filter for
//! hostile syscalls (`ptrace`, `bpf`, `kexec_*`, `init_module`, …) that map
//! to `SCMP_ACT_KILL_PROCESS`, and an "errno" filter for the softer set
//! (`unshare`, `mount`, `chroot`, …) that returns `-EPERM`. The pre_exec
//! closure applies both with TSYNC. This keeps the §10 / D-tier promise
//! that the KILL list actually kills.

use std::{collections::BTreeMap, convert::TryInto};

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

use crate::{
    error::CoreError,
    profile::SandboxProfile,
    sandbox::{BackendOptions, linux::probe::ProbeResult},
};

/// Syscalls killed outright when invoked from inside the sandbox.
/// These signal an attempt to break out or attack the process model.
pub const KILL_LIST: &[&str] = &[
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
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
];

/// Two compiled BPF programs ready for `apply_filter_all_threads`. The
/// pre_exec closure applies `kill` first, then `errno`.
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

    // ERRNO filter — match everything in ERRNO_LIST; optionally append a
    // best-effort `connect()` arg-filter row when we're on a pre-v4 kernel
    // and the proxy is the only intended TCP destination.
    let mut errno_rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for name in ERRNO_LIST {
        if let Some(nr) = syscall_number(name) {
            errno_rules.entry(nr).or_default();
        }
    }

    // The pre-v4 `connect()` arg filter is intentionally NOT wired here:
    // seccomp cannot inspect `copy_from_user`-backed sockaddrs, and matching
    // on the family alone either over-blocks (kills loopback) or under-blocks
    // (matches nothing). On pre-v4 kernels we rely on Landlock's path filter
    // plus the orchestrator's proxy bind to funnel TCP egress; `--allow-degraded`
    // surfaces the missing capability to the user.
    let _ = (profile, proxy_port, probe); // suppress unused-arg lint without changing signatures

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
        "kcmp" => libc::SYS_kcmp,
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
        assert!(syscall_number("does_not_exist").is_none());
    }
}
