//! Deterministic policy rendering for `--dry-run` and `sbe inspect`.
//!
//! The output is YAML so it both reads cleanly and round-trips through
//! `serde_yaml::from_str` in tests.

use std::fmt::Write;

use crate::{
    profile::{NetworkMode, SandboxProfile},
    sandbox::{BackendOptions, SecurityMode, linux::probe::ProbeResult},
};

/// Render the live policy view for the given profile + proxy state.
pub fn render(
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
    probe: &ProbeResult,
    options: BackendOptions,
    security_mode: SecurityMode,
) -> String {
    let mut out = String::with_capacity(2048);

    let _ = writeln!(out, "# sbe linux backend inspection");
    let _ = writeln!(out, "backend: landlock+seccomp");
    let _ = writeln!(out, "kernel: {}", yaml_string(&probe.kernel));
    let _ = writeln!(out, "landlockAbi: {}", probe.abi.as_str());
    let _ = writeln!(
        out,
        "securityMode: {}",
        if security_mode.is_strict() {
            "strict"
        } else {
            "standard"
        }
    );
    let _ = writeln!(out, "legacyAllowDegraded: {}", options.allow_degraded);
    let _ = writeln!(
        out,
        "allowInsecureNetwork: {}",
        options.allow_insecure_network
    );
    let _ = writeln!(out, "profile: {}", yaml_string(&profile.name));
    let _ = writeln!(out, "networkMode: {}", profile.network_mode.as_str());
    let _ = writeln!(
        out,
        "strictDomainEgressRequested: {}",
        profile.network_mode == NetworkMode::Proxy
    );
    let _ = writeln!(out, "strictDomainEgressEnforced: false");
    let effective_network =
        if security_mode.is_strict() || profile.network_mode == NetworkMode::DenyAll {
            profile.network_mode
        } else {
            NetworkMode::AllowAll
        };

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
    if probe.abi.supports_unix_path_filter() && effective_network != NetworkMode::AllowAll {
        let _ = writeln!(out, "      - resolveUnix");
    }
    if features.net_port_filter && effective_network != NetworkMode::AllowAll {
        let _ = writeln!(out, "    net:");
        let _ = writeln!(out, "      - connectTcp");
        let _ = writeln!(out, "      - bindTcp");
    }
    if probe.abi.supports_scopes() {
        let _ = writeln!(out, "  scoped:");
        let _ = writeln!(out, "    - signal");
        if effective_network != NetworkMode::AllowAll {
            let _ = writeln!(out, "    - abstractUnixSocket");
        }
    } else {
        let _ = writeln!(out, "  scoped: []");
    }

    let _ = writeln!(out, "  pathBeneath:");
    for sp in &profile.allow_write {
        let _ = writeln!(
            out,
            "    - path: {}\n      access: writeAllowlist",
            yaml_string(&sp.path.to_string_lossy())
        );
    }
    for sp in &profile.allow_exec {
        let _ = writeln!(
            out,
            "    - path: {}\n      access: execAllowlist",
            yaml_string(&sp.path.to_string_lossy())
        );
    }
    // The curated read allowlist is materialized by the landlock builder at
    // run time; we list its anchors here for transparency.
    let _ = writeln!(out, "  readAllowlistAnchors:");
    for anchor in super::landlock::READ_ALLOWLIST_ANCHORS
        .iter()
        .chain(super::landlock::PROC_READ_ALLOWLIST_ANCHORS)
    {
        let _ = writeln!(out, "    - {}", yaml_string(anchor));
    }

    let _ = writeln!(out, "  forbiddenReads:");
    for sp in &profile.deny_read {
        let _ = writeln!(out, "    - {}", yaml_string(&sp.path.to_string_lossy()));
    }

    if features.net_port_filter && effective_network != NetworkMode::AllowAll {
        let _ = writeln!(out, "  netConnectTcp:");
        match effective_network {
            NetworkMode::Proxy => {
                if let Some(port) = proxy_port {
                    let _ = writeln!(out, "    - {port}");
                }
            }
            NetworkMode::DirectHttps443 => {
                let _ = writeln!(out, "    - 443");
            }
            NetworkMode::DenyAll | NetworkMode::AllowAll => {}
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
    if effective_network != NetworkMode::AllowAll {
        match effective_network {
            NetworkMode::DenyAll => {
                let _ = writeln!(out, "        - socket(all families)");
            }
            NetworkMode::Proxy => {
                let _ = writeln!(out, "        - socket(AF_PACKET)");
                let _ = writeln!(out, "        - socket(AF_INET|AF_INET6, datagram|raw)");
            }
            NetworkMode::DirectHttps443 => {
                let _ = writeln!(out, "        - socket(AF_PACKET)");
                let _ = writeln!(out, "        - socket(AF_INET|AF_INET6, raw)");
                let _ = writeln!(out, "  dnsCompatibility: UDP datagrams permitted");
            }
            NetworkMode::AllowAll => {}
        }
    }
    if !features.net_port_filter
        && matches!(
            effective_network,
            NetworkMode::Proxy | NetworkMode::DirectHttps443
        )
    {
        let _ = writeln!(
            out,
            "  netFallback: unavailable — strict execution refuses unless explicitly opted into \
             --allow-insecure-linux-network"
        );
    }

    let _ = writeln!(out, "proxy:");
    if let Some(port) = proxy_port {
        let _ = writeln!(out, "  port: {port}");
        let _ = writeln!(out, "  env:");
        let _ = writeln!(out, "    HTTP_PROXY: <authenticated-url-redacted>");
        let _ = writeln!(out, "    HTTPS_PROXY: <authenticated-url-redacted>");
    } else {
        let _ = writeln!(out, "  port: null");
    }

    out
}

fn yaml_string(value: &str) -> String {
    // JSON quoted strings are valid YAML scalars and provide deterministic
    // escaping for quotes, newlines, and terminal control characters.
    serde_json::to_string(value).expect("string serialization cannot fail")
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

    const fn strict_mode() -> SecurityMode {
        SecurityMode::Strict
    }

    fn strict_options() -> BackendOptions {
        BackendOptions::default()
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
            strict_options(),
            strict_mode(),
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
            strict_options(),
            strict_mode(),
        );

        assert!(!out.contains("netConnectTcp:"));
        assert!(out.contains("netFallback:"));
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
            strict_options(),
            strict_mode(),
        );

        let value: serde_yaml::Value = serde_yaml::from_str(&out).expect("policy YAML parses");
        assert_eq!(value["backend"].as_str(), Some("landlock+seccomp"));
        assert_eq!(value["landlockAbi"].as_str(), Some("v4"));
    }

    #[test]
    fn allow_all_renders_network_rights_as_unhandled() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/home/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        profile.allow_all_network = true;
        profile.recompute_network_mode();

        let out = render(
            &profile,
            None,
            &probe(LandlockAbi::V9),
            strict_options(),
            strict_mode(),
        );
        let value: serde_yaml::Value = serde_yaml::from_str(&out).expect("policy YAML parses");
        let handled = &value["landlock"]["handled"];
        let fs = handled["fs"].as_sequence().expect("filesystem rights");

        assert!(handled["net"].is_null());
        assert!(!fs.iter().any(|right| right.as_str() == Some("resolveUnix")));
        let scoped = value["landlock"]["scoped"]
            .as_sequence()
            .expect("signal scope remains active");
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].as_str(), Some("signal"));
    }

    #[test]
    fn restricted_network_renders_process_and_unix_socket_scopes() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/home/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);

        let out = render(
            &profile,
            Some(12345),
            &probe(LandlockAbi::V9),
            strict_options(),
            strict_mode(),
        );
        let value: serde_yaml::Value = serde_yaml::from_str(&out).expect("policy YAML parses");
        let scoped = value["landlock"]["scoped"]
            .as_sequence()
            .expect("Landlock scopes");

        assert!(scoped.iter().any(|scope| scope.as_str() == Some("signal")));
        assert!(
            scoped
                .iter()
                .any(|scope| scope.as_str() == Some("abstractUnixSocket"))
        );
        let read_anchors = value["landlock"]["readAllowlistAnchors"]
            .as_sequence()
            .expect("read anchors");
        assert!(
            !read_anchors
                .iter()
                .any(|anchor| anchor.as_str() == Some("/proc/self"))
        );
    }

    #[test]
    fn pre_v6_does_not_claim_unavailable_scopes() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/home/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        let out = render(
            &profile,
            Some(12345),
            &probe(LandlockAbi::V5),
            BackendOptions::default(),
            SecurityMode::Standard,
        );
        let value: serde_yaml::Value = serde_yaml::from_str(&out).expect("policy YAML parses");

        assert!(
            value["landlock"]["scoped"]
                .as_sequence()
                .is_some_and(Vec::is_empty)
        );
    }

    #[test]
    fn deny_all_below_v4_does_not_render_insecure_fallback() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/home/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        profile.allow_domains.clear();
        profile.recompute_network_mode();

        let out = render(
            &profile,
            None,
            &probe(LandlockAbi::V3),
            BackendOptions::default(),
            SecurityMode::Standard,
        );

        assert!(!out.contains("netFallback:"));
        assert!(out.contains("socket(all families)"));
    }
}
