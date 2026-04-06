use std::{fmt::Write, path::Path};

use crate::profile::SandboxProfile;

/// Generate a Seatbelt Profile Language (SBPL) policy string from a `SandboxProfile`.
///
/// The profile follows a deny-by-default philosophy:
/// - All writes denied except explicit allowlist
/// - All reads allowed except explicit denylist (secrets)
/// - All network denied except proxy/localhost
/// - All risky process-exec denied
pub fn generate(profile: &SandboxProfile, proxy_port: Option<u16>) -> String {
    let mut sb = String::with_capacity(4096);

    writeln!(sb, "(version 1)").ok();
    writeln!(sb).ok();
    writeln!(sb, ";; sbe sandbox profile: {}", profile.name).ok();
    writeln!(sb, ";; Policy: deny by default, allow explicit exceptions").ok();
    writeln!(sb, "(deny default)").ok();
    writeln!(sb).ok();

    // Process control
    section_process(&mut sb, profile);

    // File system
    section_file_read(&mut sb, profile);
    section_file_write(&mut sb, profile);

    // Network
    section_network(&mut sb, profile, proxy_port);

    // Miscellaneous required permissions
    section_misc(&mut sb);

    sb
}

fn section_process(sb: &mut String, profile: &SandboxProfile) {
    writeln!(sb, ";; Process control").ok();
    writeln!(sb, "(allow process-fork)").ok();
    writeln!(sb, "(allow process-exec").ok();

    for path in &profile.allow_exec {
        write_path_filter(sb, path, "    ");
    }

    writeln!(sb, ")").ok();

    // Deny risky binaries (deny rules override allow in SBPL when placed after)
    if !profile.deny_exec.is_empty() {
        writeln!(sb, "(deny process-exec").ok();
        for path in &profile.deny_exec {
            writeln!(sb, "    (literal \"{}\")", path.display()).ok();
        }
        writeln!(sb, ")").ok();
    }

    writeln!(sb).ok();
}

fn section_file_read(sb: &mut String, profile: &SandboxProfile) {
    writeln!(sb, ";; File reads: allow most, deny secrets").ok();
    writeln!(sb, "(allow file-read*)").ok();

    if !profile.deny_read.is_empty() {
        writeln!(sb, "(deny file-read*").ok();
        for path in &profile.deny_read {
            write_path_filter(sb, path, "    ");
        }
        writeln!(sb, ")").ok();
    }

    writeln!(sb).ok();
}

fn section_file_write(sb: &mut String, profile: &SandboxProfile) {
    writeln!(sb, ";; File writes: deny all, allow specific paths").ok();
    writeln!(sb, "(deny file-write*)").ok();

    if !profile.allow_write.is_empty() {
        writeln!(sb, "(allow file-write*").ok();
        for path in &profile.allow_write {
            write_path_filter(sb, path, "    ");
        }
        // Always allow temp directories for build tools
        writeln!(sb, "    (subpath \"/private/tmp\")").ok();
        writeln!(sb, "    (subpath \"/private/var/folders\")").ok();
        writeln!(sb, ")").ok();
    }

    writeln!(sb).ok();
}

fn section_network(sb: &mut String, profile: &SandboxProfile, proxy_port: Option<u16>) {
    writeln!(sb, ";; Network").ok();

    if profile.allow_all_network {
        writeln!(sb, "(allow network*)").ok();
    } else if let Some(port) = proxy_port {
        // Proxy mode: only allow connections to the local proxy + DNS
        writeln!(sb, "(deny network*)").ok();
        writeln!(sb, "(allow network-outbound").ok();
        writeln!(sb, "    (remote tcp \"localhost:{port}\")").ok();
        writeln!(sb, "    (remote ip \"localhost:*\")").ok();
        writeln!(sb, "    (literal \"/private/var/run/mDNSResponder\")").ok();
        writeln!(sb, ")").ok();
        writeln!(sb, "(allow network-inbound (local ip \"localhost:*\"))").ok();
    } else if !profile.allow_domains.is_empty() && profile.enable_proxy {
        // Proxy mode requested but no port yet — allow localhost broadly
        writeln!(sb, "(deny network*)").ok();
        writeln!(sb, "(allow network-outbound").ok();
        writeln!(sb, "    (remote ip \"localhost:*\")").ok();
        writeln!(sb, "    (literal \"/private/var/run/mDNSResponder\")").ok();
        writeln!(sb, ")").ok();
        writeln!(sb, "(allow network-inbound (local ip \"localhost:*\"))").ok();
    } else {
        // No proxy mode: allow HTTPS only (port 443)
        writeln!(sb, "(deny network*)").ok();
        writeln!(sb, "(allow network-outbound").ok();
        writeln!(sb, "    (remote tcp \"*:443\")").ok();
        writeln!(sb, "    (remote ip \"localhost:*\")").ok();
        writeln!(sb, "    (literal \"/private/var/run/mDNSResponder\")").ok();
        writeln!(sb, ")").ok();
        writeln!(sb, "(allow network-inbound (local ip \"localhost:*\"))").ok();
    }

    writeln!(sb).ok();
}

fn section_misc(sb: &mut String) {
    writeln!(sb, ";; Miscellaneous required permissions").ok();
    writeln!(sb, "(allow sysctl-read)").ok();
    writeln!(sb, "(allow mach-lookup)").ok();
    writeln!(sb, "(allow ipc-posix-shm-read*)").ok();
    writeln!(sb, "(allow ipc-posix-shm-write-data)").ok();
    writeln!(sb, "(allow signal (target self))").ok();
    writeln!(sb, "(allow process-info-pidinfo)").ok();
    writeln!(sb, "(allow process-info-setcontrol)").ok();
    writeln!(sb, "(allow process-info-dirtycontrol)").ok();
}

/// Write a path filter expression. Uses `subpath` for directories and `literal` for files.
fn write_path_filter(sb: &mut String, path: &Path, indent: &str) {
    // Use subpath for directories (the common case for sandbox paths)
    writeln!(sb, "{indent}(subpath \"{path}\")", path = path.display()).ok();
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::detect::Ecosystem;

    #[test]
    fn test_should_generate_valid_sbpl_for_node() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        let sbpl = generate(&profile, None);

        assert!(sbpl.contains("(version 1)"));
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("(allow process-fork)"));
        assert!(sbpl.contains("(allow file-read*)"));
        assert!(sbpl.contains("(deny file-write*)"));
        assert!(sbpl.contains("(deny file-read*"));
        assert!(sbpl.contains("/Users/test/.ssh"));
        assert!(sbpl.contains("/Users/test/project"));
        assert!(sbpl.contains("osascript"));
    }

    #[test]
    fn test_should_generate_proxy_network_rules() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        let sbpl = generate(&profile, Some(12345));

        assert!(sbpl.contains("(remote tcp \"localhost:12345\")"));
        assert!(sbpl.contains("mDNSResponder"));
    }

    #[test]
    fn test_should_generate_allow_all_network() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        profile.allow_all_network = true;
        let sbpl = generate(&profile, None);

        assert!(sbpl.contains("(allow network*)"));
        assert!(!sbpl.contains("(deny network*)"));
    }

    #[test]
    fn test_should_include_temp_dirs_in_write_allow() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Python, &home, &pwd);
        let sbpl = generate(&profile, None);

        assert!(sbpl.contains("/private/tmp"));
        assert!(sbpl.contains("/private/var/folders"));
    }

    #[test]
    fn test_should_generate_no_proxy_mode() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        profile.enable_proxy = false;
        let sbpl = generate(&profile, None);

        // No proxy mode: should allow port 443 directly and localhost for local services
        assert!(sbpl.contains("(remote tcp \"*:443\")"));
        assert!(sbpl.contains("(remote ip \"localhost:*\")"));
        // Should NOT have a specific proxy port
        assert!(!sbpl.contains("(remote tcp \"localhost:"));
    }

    #[test]
    fn test_should_deny_network_when_no_domains_and_no_allow_all() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        profile.allow_domains.clear();
        profile.enable_proxy = false;
        let sbpl = generate(&profile, None);

        // Should still allow port 443 as fallback
        assert!(sbpl.contains("(deny network*)"));
        assert!(sbpl.contains("(remote tcp \"*:443\")"));
    }

    #[test]
    fn test_should_generate_for_all_ecosystems() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");

        for eco in Ecosystem::ALL {
            let profile = SandboxProfile::for_ecosystem(eco, &home, &pwd);
            let sbpl = generate(&profile, None);
            assert!(sbpl.contains("(version 1)"), "missing version for {eco}");
            assert!(
                sbpl.contains("(deny default)"),
                "missing deny default for {eco}"
            );
        }
    }
}
