//! Deterministic policy rendering for `--dry-run` and `sbe inspect`.
//!
//! The output is YAML so it both reads cleanly and round-trips through
//! `serde_yaml::from_str` in tests.

use std::fmt::Write;

use crate::{
    profile::SandboxProfile,
    sandbox::{BackendOptions, linux::probe::ProbeResult},
};

/// Render the live policy view for the given profile + proxy state.
pub fn render(
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
    probe: &ProbeResult,
    options: BackendOptions,
) -> String {
    let mut out = String::with_capacity(2048);

    let _ = writeln!(out, "# sbe linux backend inspection");
    let _ = writeln!(out, "backend: landlock+seccomp");
    let _ = writeln!(out, "kernel: \"{}\"", probe.kernel);
    let _ = writeln!(out, "landlockAbi: {}", probe.abi.as_str());
    let _ = writeln!(out, "allowDegraded: {}", options.allow_degraded);
    let _ = writeln!(out, "profile: {}", profile.name);

    // Resolved features
    let features = probe.features();
    let _ = writeln!(out, "features:");
    let _ = writeln!(out, "  fsWrite: {}", features.fs_write);
    let _ = writeln!(out, "  fsRead: {}", features.fs_read);
    let _ = writeln!(out, "  execAllowlist: {}", features.exec_allowlist);
    let _ = writeln!(out, "  netPortFilter: {}", features.net_port_filter);
    let _ = writeln!(out, "  auditStream: {}", features.audit_stream);

    let _ = writeln!(out, "landlock:");
    let _ = writeln!(out, "  handled:");
    let _ = writeln!(out, "    fs:");
    let _ = writeln!(out, "      - execute");
    let _ = writeln!(out, "      - readFile");
    let _ = writeln!(out, "      - readDir");
    let _ = writeln!(out, "      - writeFile");
    let _ = writeln!(out, "      - removeDir");
    let _ = writeln!(out, "      - removeFile");
    let _ = writeln!(out, "      - makeChar");
    let _ = writeln!(out, "      - makeDir");
    let _ = writeln!(out, "      - makeReg");
    let _ = writeln!(out, "      - makeSock");
    let _ = writeln!(out, "      - makeFifo");
    let _ = writeln!(out, "      - makeBlock");
    let _ = writeln!(out, "      - makeSym");
    if probe.abi.supports_truncate() {
        let _ = writeln!(out, "      - truncate");
    }
    if probe.abi.supports_ioctl_dev() {
        let _ = writeln!(out, "      - ioctlDev");
    }
    if features.net_port_filter {
        let _ = writeln!(out, "    net:");
        let _ = writeln!(out, "      - connectTcp");
    }

    let _ = writeln!(out, "  pathBeneath:");
    for sp in &profile.allow_write {
        let _ = writeln!(
            out,
            "    - path: \"{}\"\n      access: writeAllowlist",
            sp.path.display()
        );
    }
    for sp in &profile.allow_exec {
        let _ = writeln!(
            out,
            "    - path: \"{}\"\n      access: execAllowlist",
            sp.path.display()
        );
    }
    // The curated read allowlist is materialized by the landlock builder at
    // run time; we list its anchors here for transparency.
    let _ = writeln!(out, "  readAllowlistAnchors:");
    for anchor in super::landlock::READ_ALLOWLIST_ANCHORS {
        let _ = writeln!(out, "    - \"{anchor}\"");
    }

    let _ = writeln!(out, "  forbiddenReads:");
    for sp in &profile.deny_read {
        let _ = writeln!(out, "    - \"{}\"", sp.path.display());
    }

    if features.net_port_filter && !profile.allow_all_network {
        let _ = writeln!(out, "  netConnectTcp:");
        if let Some(port) = proxy_port {
            let _ = writeln!(out, "    - {port}");
        } else if !profile.enable_proxy {
            let _ = writeln!(out, "    - 443");
        }
    }

    let _ = writeln!(out, "seccomp:");
    let _ = writeln!(out, "  filters:");
    let _ = writeln!(out, "    - name: kill");
    let _ = writeln!(out, "      defaultAction: allow");
    let _ = writeln!(out, "      onMatch: kill-process");
    let _ = writeln!(out, "      syscalls:");
    for syscall in super::seccomp::KILL_LIST {
        let _ = writeln!(out, "        - {syscall}");
    }
    let _ = writeln!(out, "    - name: errno");
    let _ = writeln!(out, "      defaultAction: allow");
    let _ = writeln!(out, "      onMatch: errno(EPERM)");
    let _ = writeln!(out, "      syscalls:");
    for syscall in super::seccomp::ERRNO_LIST {
        let _ = writeln!(out, "        - {syscall}");
    }
    if !features.net_port_filter && !profile.allow_all_network && proxy_port.is_some() {
        let _ = writeln!(
            out,
            "  netFallback: seccomp connect()-arg filtering is intentionally not enforced — \
             relies on Landlock path filter and proxy loopback bind"
        );
    }

    let _ = writeln!(out, "proxy:");
    if let Some(port) = proxy_port {
        let _ = writeln!(out, "  port: {port}");
        let _ = writeln!(out, "  env:");
        let _ = writeln!(out, "    HTTP_PROXY: http://127.0.0.1:{port}");
        let _ = writeln!(out, "    HTTPS_PROXY: http://127.0.0.1:{port}");
    } else {
        let _ = writeln!(out, "  port: null");
    }

    let _ = writeln!(out, "ignoredFields:");
    if !profile.deny_exec.is_empty() {
        let _ = writeln!(
            out,
            "  - denyExec  # Landlock is allowlist-only; ignored on Linux"
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{detect::Ecosystem, sandbox::linux::probe::LandlockAbi};

    fn probe(abi: LandlockAbi) -> ProbeResult {
        ProbeResult {
            kernel: "Linux 6.8.0-test".to_owned(),
            abi,
        }
    }

    #[test]
    fn test_should_render_baseline_yaml() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/home/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        let out = render(
            &profile,
            Some(12345),
            &probe(LandlockAbi::V4),
            BackendOptions::default(),
        );

        assert!(out.starts_with("# sbe linux backend inspection"));
        assert!(out.contains("backend: landlock+seccomp"));
        assert!(out.contains("landlockAbi: v4"));
        assert!(out.contains("netConnectTcp:"));
        assert!(out.contains("- 12345"));
        assert!(out.contains("forbiddenReads:"));
    }

    #[test]
    fn test_should_omit_net_section_below_v4() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/home/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        let out = render(
            &profile,
            Some(12345),
            &probe(LandlockAbi::V3),
            BackendOptions::default(),
        );

        assert!(!out.contains("netConnectTcp:"));
        assert!(out.contains("connectArgFilter: loopback-only"));
    }

    #[test]
    fn test_should_be_yaml_round_trippable() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/home/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        let out = render(
            &profile,
            Some(8000),
            &probe(LandlockAbi::V4),
            BackendOptions::default(),
        );

        let value: serde_yaml::Value = serde_yaml::from_str(&out).expect("policy YAML parses");
        assert_eq!(value["backend"].as_str(), Some("landlock+seccomp"));
        assert_eq!(value["landlockAbi"].as_str(), Some("v4"));
    }
}
