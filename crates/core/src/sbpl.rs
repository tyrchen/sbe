use std::fmt::Write;

use crate::{config::SandboxPath, profile::SandboxProfile};

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

    section_process(&mut sb, profile);
    section_file_read(&mut sb, profile);
    section_file_write(&mut sb, profile);
    section_network(&mut sb, profile, proxy_port);
    section_misc(&mut sb);

    sb
}

fn section_process(sb: &mut String, profile: &SandboxProfile) {
    writeln!(sb, ";; Process control").ok();
    writeln!(sb, "(allow process-fork)").ok();
    writeln!(sb, "(allow process-exec").ok();

    for sp in &profile.allow_exec {
        write_sandbox_path(sb, sp, "    ");
    }

    writeln!(sb, ")").ok();

    if !profile.deny_exec.is_empty() {
        writeln!(sb, "(deny process-exec").ok();
        for sp in &profile.deny_exec {
            write_sandbox_path(sb, sp, "    ");
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
        for sp in &profile.deny_read {
            write_sandbox_path(sb, sp, "    ");
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
        for sp in &profile.allow_write {
            write_sandbox_path(sb, sp, "    ");
        }
        // Always allow temp directories for build tools
        writeln!(sb, "    (subpath \"/private/tmp\")").ok();
        writeln!(sb, "    (subpath \"/private/var/folders\")").ok();
        // /dev/null and /dev/zero — used by Stdio::null() in build scripts
        writeln!(sb, "    (literal \"/dev/null\")").ok();
        writeln!(sb, "    (literal \"/dev/zero\")").ok();
        writeln!(sb, ")").ok();
    }

    writeln!(sb).ok();
}

fn section_network(sb: &mut String, profile: &SandboxProfile, proxy_port: Option<u16>) {
    writeln!(sb, ";; Network").ok();

    if profile.allow_all_network {
        writeln!(sb, "(allow network*)").ok();
    } else if let Some(port) = proxy_port {
        writeln!(sb, "(deny network*)").ok();
        writeln!(sb, "(allow network-outbound").ok();
        writeln!(sb, "    (remote tcp \"localhost:{port}\")").ok();
        writeln!(sb, "    (remote ip \"localhost:*\")").ok();
        writeln!(sb, "    (literal \"/private/var/run/mDNSResponder\")").ok();
        writeln!(sb, ")").ok();
        writeln!(sb, "(allow network-inbound (local ip \"localhost:*\"))").ok();
    } else if !profile.allow_domains.is_empty() && profile.enable_proxy {
        writeln!(sb, "(deny network*)").ok();
        writeln!(sb, "(allow network-outbound").ok();
        writeln!(sb, "    (remote ip \"localhost:*\")").ok();
        writeln!(sb, "    (literal \"/private/var/run/mDNSResponder\")").ok();
        writeln!(sb, ")").ok();
        writeln!(sb, "(allow network-inbound (local ip \"localhost:*\"))").ok();
    } else {
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
    writeln!(sb, "(allow mach-lookup").ok();
    writeln!(sb, "    (global-name \"com.apple.system.logger\")").ok();
    writeln!(
        sb,
        "    (global-name \"com.apple.system.notification_center\")"
    )
    .ok();
    writeln!(
        sb,
        "    (global-name \"com.apple.CoreServices.coreservicesd\")"
    )
    .ok();
    writeln!(sb, "    (global-name \"com.apple.SecurityServer\")").ok();
    writeln!(
        sb,
        "    (global-name \"com.apple.distributed_notifications@Mu\")"
    )
    .ok();
    writeln!(
        sb,
        "    (global-name-regex #\"^com\\.apple\\.cfprefsd\\.\")"
    )
    .ok();
    writeln!(sb, "    (global-name-regex #\"^com\\.apple\\.lsd\\.\")").ok();
    writeln!(sb, ")").ok();
    writeln!(sb, "(allow ipc-posix-shm-read*)").ok();
    writeln!(sb, "(allow ipc-posix-shm-write-data)").ok();
    writeln!(sb, "(allow signal (target self))").ok();
}

/// Write an SBPL path filter from a `SandboxPath`.
///
/// `is_dir == true` → `(subpath ...)` (matches directory and all contents)
/// `is_dir == false` → `(literal ...)` (exact file match only)
fn write_sandbox_path(sb: &mut String, sp: &SandboxPath, indent: &str) {
    let kind = if sp.is_dir { "subpath" } else { "literal" };
    writeln!(sb, "{indent}({kind} \"{}\")", sp.path.display()).ok();
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
        // Directories use subpath
        assert!(sbpl.contains("(subpath \"/Users/test/.ssh\")"));
        // Project dir uses subpath
        assert!(sbpl.contains("(subpath \"/Users/test/project\")"));
        // Files use literal
        assert!(sbpl.contains("(literal \"/usr/bin/osascript\")"));
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

        assert!(sbpl.contains("(remote tcp \"*:443\")"));
        assert!(sbpl.contains("(remote ip \"localhost:*\")"));
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

    #[test]
    fn test_should_use_literal_for_files_and_subpath_for_dirs() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        let sbpl = generate(&profile, None);

        // Individual binaries should be literal
        assert!(sbpl.contains("(literal \"/bin/sh\")"));
        assert!(sbpl.contains("(literal \"/usr/bin/cc\")"));
        // Directories should be subpath
        assert!(sbpl.contains("(subpath \"/Users/test/.cargo/bin\")"));
        assert!(sbpl.contains("(subpath \"/Users/test/.rustup/toolchains\")"));
    }

    #[test]
    fn test_should_scope_mach_lookup() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        let sbpl = generate(&profile, None);

        // Should have scoped mach-lookup, not blanket allow
        assert!(sbpl.contains("(allow mach-lookup"));
        assert!(sbpl.contains("global-name"));
        assert!(!sbpl.contains("(allow mach-lookup)"));
    }
}
