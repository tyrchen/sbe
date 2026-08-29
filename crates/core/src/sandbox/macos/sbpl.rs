use std::{
    collections::BTreeSet,
    fmt::Write,
    path::{Path, PathBuf},
};

use crate::{
    config::{PathKind, SandboxPath},
    error::CoreError,
    profile::{NetworkMode, SandboxProfile},
    sandbox::SecurityMode,
};

/// Generate a Seatbelt Profile Language (SBPL) policy string from a `SandboxProfile`.
///
/// The profile follows a deny-by-default philosophy:
/// - All writes denied except explicit allowlist
/// - All reads allowed except explicit denylist (secrets)
/// - All network denied except proxy/localhost
/// - All risky process-exec denied
pub fn generate(
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
    security_mode: SecurityMode,
) -> Result<String, CoreError> {
    let mut sb = String::with_capacity(4096);

    if profile.name.chars().any(char::is_control) {
        return Err(CoreError::ProfileLint(
            "profile name contains control characters".to_owned(),
        ));
    }

    writeln!(sb, "(version 1)").ok();
    writeln!(sb).ok();
    writeln!(sb, ";; sbe sandbox profile: {}", profile.name).ok();
    writeln!(sb, ";; Policy: deny by default, allow explicit exceptions").ok();
    writeln!(sb, "(deny default)").ok();
    writeln!(sb).ok();

    section_process(&mut sb, profile)?;
    section_file_read(&mut sb, profile)?;
    section_file_write(&mut sb, profile)?;
    section_network(&mut sb, profile, proxy_port, security_mode)?;
    section_misc(&mut sb);

    Ok(sb)
}

fn section_process(sb: &mut String, profile: &SandboxProfile) -> Result<(), CoreError> {
    writeln!(sb, ";; Process control").ok();
    writeln!(sb, "(allow process-fork)").ok();
    writeln!(sb, "(allow process-exec").ok();

    for sp in &profile.allow_exec {
        write_sandbox_path(sb, sp, "    ")?;
    }

    writeln!(sb, ")").ok();

    if !profile.deny_exec.is_empty() {
        writeln!(sb, "(deny process-exec").ok();
        for sp in &profile.deny_exec {
            write_sandbox_path(sb, sp, "    ")?;
        }
        writeln!(sb, ")").ok();
    }

    writeln!(sb).ok();
    Ok(())
}

fn section_file_read(sb: &mut String, profile: &SandboxProfile) -> Result<(), CoreError> {
    writeln!(sb, ";; File reads: allow most, deny secrets").ok();
    writeln!(sb, "(allow file-read*)").ok();

    // Shared temporary roots belong to every same-user process. Deny them
    // while carving back only this invocation's private root. `require-not`
    // keeps the broad allow-read model compatible without allowing one SBE
    // invocation to inspect another invocation's temporary files.
    for shared in ["/private/tmp", "/private/var/tmp", "/private/var/folders"] {
        let exceptions: BTreeSet<&Path> = profile
            .allow_read
            .iter()
            .chain(&profile.allow_write)
            .chain(&profile.allow_exec)
            .map(|sandbox_path| sandbox_path.path.as_path())
            .chain(profile.ephemeral_write_exec.iter().map(PathBuf::as_path))
            .filter(|path| path.starts_with(shared))
            .collect();
        let mut ancestor_literals = BTreeSet::new();
        for exception in &exceptions {
            let mut ancestor = exception.parent();
            while let Some(path) = ancestor {
                if !path.starts_with(shared) {
                    break;
                }
                ancestor_literals.insert(path.to_path_buf());
                if path == Path::new(shared) {
                    break;
                }
                ancestor = path.parent();
            }
        }
        writeln!(sb, "(deny file-read*").ok();
        writeln!(sb, "    (require-all").ok();
        writeln!(sb, "        (subpath \"{shared}\")").ok();
        // Path canonicalization needs metadata access to each ancestor. A
        // literal exception permits traversal of that inode without opening
        // any sibling child as data.
        for ancestor in ancestor_literals {
            let ancestor = validated_sbpl_path(&ancestor)?;
            writeln!(sb, "        (require-not (literal \"{ancestor}\"))").ok();
        }
        for exception in exceptions {
            let exception = validated_sbpl_path(exception)?;
            writeln!(sb, "        (require-not (subpath \"{exception}\"))").ok();
        }
        writeln!(sb, "    )").ok();
        writeln!(sb, ")").ok();
    }

    if !profile.deny_read.is_empty() {
        writeln!(sb, "(deny file-read*").ok();
        for sp in &profile.deny_read {
            write_sandbox_path(sb, sp, "    ")?;
            if let Some(resolved) = resolved_deny_read_path(sp)? {
                write_sandbox_path(sb, &resolved, "    ")?;
            }
        }
        writeln!(sb, ")").ok();
    }

    writeln!(sb).ok();
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "SBPL is synchronous and must canonicalize denyRead aliases before launch"
)]
fn resolved_deny_read_path(path: &SandboxPath) -> Result<Option<SandboxPath>, CoreError> {
    let resolved = match std::fs::canonicalize(&path.path) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CoreError::ProfileLint(format!(
                "cannot resolve denyRead path '{}': {error}",
                path.path.display()
            )));
        }
    };
    Ok((resolved != path.path).then_some(SandboxPath {
        path: resolved,
        kind: path.kind,
    }))
}

fn section_file_write(sb: &mut String, profile: &SandboxProfile) -> Result<(), CoreError> {
    writeln!(sb, ";; File writes: deny all, allow specific paths").ok();
    writeln!(sb, "(deny file-write*)").ok();

    if !profile.allow_write.is_empty() {
        writeln!(sb, "(allow file-write*").ok();
        for sp in &profile.allow_write {
            write_sandbox_path(sb, sp, "    ")?;
        }
        // /dev/null and /dev/zero — used by Stdio::null() in build scripts
        writeln!(sb, "    (literal \"/dev/null\")").ok();
        writeln!(sb, "    (literal \"/dev/zero\")").ok();
        writeln!(sb, ")").ok();
    }

    writeln!(sb).ok();
    Ok(())
}

fn section_network(
    sb: &mut String,
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
    security_mode: SecurityMode,
) -> Result<(), CoreError> {
    writeln!(sb, ";; Network").ok();

    match profile.network_mode {
        NetworkMode::AllowAll => {
            writeln!(sb, "(allow network*)").ok();
        }
        NetworkMode::DenyAll => {
            writeln!(sb, "(deny network*)").ok();
        }
        NetworkMode::Proxy => {
            let port = proxy_port.ok_or_else(|| {
                CoreError::Backend("proxy network mode has no live proxy port".to_owned())
            })?;
            writeln!(sb, "(deny network*)").ok();
            writeln!(sb, "(allow network-outbound").ok();
            writeln!(sb, "    (remote tcp \"localhost:{port}\")").ok();
            if !security_mode.is_strict() {
                writeln!(sb, "    (remote ip \"localhost:*\")").ok();
            }
            writeln!(sb, ")").ok();
            if !security_mode.is_strict() {
                writeln!(sb, "(allow network-inbound (local ip \"localhost:*\"))").ok();
            }
        }
        NetworkMode::DirectHttps443 => {
            writeln!(sb, "(deny network*)").ok();
            writeln!(sb, "(allow network-outbound").ok();
            writeln!(sb, "    (remote tcp \"*:443\")").ok();
            if !security_mode.is_strict() {
                writeln!(sb, "    (remote ip \"localhost:*\")").ok();
            }
            writeln!(sb, "    (literal \"/private/var/run/mDNSResponder\")").ok();
            writeln!(sb, ")").ok();
            if !security_mode.is_strict() {
                writeln!(sb, "(allow network-inbound (local ip \"localhost:*\"))").ok();
            }
        }
    }

    if !security_mode.is_strict() {
        // Standard mode intentionally trusts ordinary same-user local build
        // services. Keep IP traffic constrained by the mode-specific rules
        // above while allowing pathname Unix-domain clients and servers.
        writeln!(
            sb,
            "(allow network-bind network-inbound (local unix-socket))"
        )
        .ok();
        writeln!(sb, "(allow network-outbound (remote unix-socket))").ok();
    }

    writeln!(sb).ok();
    Ok(())
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
    writeln!(sb, "(allow signal (target self))").ok();
}

/// Write an SBPL path filter from a `SandboxPath`.
///
/// - `Subpath` → `(subpath "/path")` (matches directory and all contents)
/// - `Literal` → `(literal "/path")` (exact file match only)
/// - `Regex`   → `(regex #"pattern")` (regex match against absolute path)
fn write_sandbox_path(sb: &mut String, sp: &SandboxPath, indent: &str) -> Result<(), CoreError> {
    let encoded = validated_sbpl_path(&sp.path)?;
    match sp.kind {
        PathKind::Subpath => {
            writeln!(sb, "{indent}(subpath \"{encoded}\")").ok();
        }
        PathKind::Literal => {
            writeln!(sb, "{indent}(literal \"{encoded}\")").ok();
        }
        PathKind::Regex => {
            writeln!(sb, "{indent}(regex #\"{encoded}\")").ok();
        }
    }
    Ok(())
}

fn validated_sbpl_path(path: &Path) -> Result<String, CoreError> {
    let raw = path.to_str().ok_or_else(|| {
        CoreError::ProfileLint(format!(
            "macOS SBPL does not support non-UTF-8 path: {:?}",
            path
        ))
    })?;
    if raw.contains('\0') || raw.chars().any(char::is_control) {
        return Err(CoreError::ProfileLint(format!(
            "SBPL path contains a control character: {:?}",
            path
        )));
    }
    Ok(encode_sbpl_string(raw))
}

fn encode_sbpl_string(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => encoded.push_str("\\\\"),
            '"' => encoded.push_str("\\\""),
            _ => encoded.push(ch),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};

    use super::*;
    use crate::detect::Ecosystem;

    const fn strict_options() -> SecurityMode {
        SecurityMode::Strict
    }

    #[test]
    fn test_should_generate_valid_sbpl_for_node() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        let sbpl = generate(&profile, Some(12345), strict_options()).unwrap();

        assert!(sbpl.contains("(version 1)"));
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("(allow process-fork)"));
        assert!(sbpl.contains("(allow file-read*)"));
        assert!(sbpl.contains("(deny file-write*)"));
        assert!(sbpl.contains("(deny file-read*"));
        // Directories use subpath
        assert!(sbpl.contains("(subpath \"/Users/test/.ssh\")"));
        // Only expected build outputs, not the project root, are writable.
        assert!(sbpl.contains("(subpath \"/Users/test/project/node_modules\")"));
        assert!(!sbpl.contains("(subpath \"/Users/test/project\")"));
        // Files use literal
        assert!(sbpl.contains("(literal \"/usr/bin/osascript\")"));
    }

    #[test]
    fn test_should_generate_proxy_network_rules() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        let sbpl = generate(&profile, Some(12345), strict_options()).unwrap();

        assert!(sbpl.contains("(remote tcp \"localhost:12345\")"));
        assert!(!sbpl.contains("remote ip \"localhost:*\""));
    }

    #[test]
    fn standard_proxy_mode_allows_local_build_services() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        let sbpl = generate(&profile, Some(12345), SecurityMode::Standard).unwrap();

        assert!(sbpl.contains("(remote tcp \"localhost:12345\")"));
        assert!(sbpl.contains("(remote ip \"localhost:*\")"));
        assert!(sbpl.contains("(allow network-inbound (local ip \"localhost:*\"))"));
        assert!(sbpl.contains("(allow network-bind network-inbound (local unix-socket))"));
        assert!(sbpl.contains("(allow network-outbound (remote unix-socket))"));
    }

    #[test]
    fn strict_proxy_mode_does_not_allow_ambient_unix_sockets() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        let sbpl = generate(&profile, Some(12345), SecurityMode::Strict).unwrap();

        assert!(!sbpl.contains("(local unix-socket)"));
        assert!(!sbpl.contains("(remote unix-socket)"));
    }

    #[test]
    fn test_should_generate_allow_all_network() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        profile.allow_all_network = true;
        profile.recompute_network_mode();
        let sbpl = generate(&profile, None, strict_options()).unwrap();

        assert!(sbpl.contains("(allow network*)"));
        assert!(!sbpl.contains("(deny network*)"));
    }

    #[test]
    fn test_should_only_include_private_temp_in_write_allow() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Python, &home, &pwd);
        profile
            .allow_write
            .push(SandboxPath::dir(PathBuf::from("/private/tmp/sbe-private")));
        profile
            .ephemeral_write_exec
            .push(PathBuf::from("/private/tmp/sbe-private"));
        let sbpl = generate(&profile, Some(12345), strict_options()).unwrap();

        assert!(sbpl.contains("/private/tmp/sbe-private"));
        assert_eq!(sbpl.matches("(subpath \"/private/tmp\")").count(), 1);
        assert_eq!(sbpl.matches("(subpath \"/private/var/tmp\")").count(), 1);
        assert!(sbpl.contains("(require-not (literal \"/private/tmp\"))"));
        assert!(sbpl.contains("(require-not (subpath \"/private/tmp/sbe-private\"))"));
    }

    #[test]
    fn test_should_generate_no_proxy_mode() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        profile.enable_proxy = false;
        profile.recompute_network_mode();
        let sbpl = generate(&profile, None, strict_options()).unwrap();

        assert!(sbpl.contains("(remote tcp \"*:443\")"));
        assert!(!sbpl.contains("(remote ip \"localhost:*\")"));
        assert!(!sbpl.contains("(remote tcp \"localhost:"));
    }

    #[test]
    fn test_should_deny_network_when_no_domains_and_no_allow_all() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        profile.allow_domains.clear();
        profile.recompute_network_mode();
        let sbpl = generate(&profile, None, strict_options()).unwrap();

        assert!(sbpl.contains("(deny network*)"));
        assert!(!sbpl.contains("(remote tcp \"*:443\")"));
    }

    #[test]
    fn test_should_generate_for_all_ecosystems() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");

        for eco in Ecosystem::ALL {
            let profile = SandboxProfile::for_ecosystem(eco, &home, &pwd);
            let sbpl = generate(&profile, Some(12345), strict_options()).unwrap();
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
        let sbpl = generate(&profile, Some(12345), strict_options()).unwrap();

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
        let sbpl = generate(&profile, Some(12345), strict_options()).unwrap();

        // Should have scoped mach-lookup, not blanket allow
        assert!(sbpl.contains("(allow mach-lookup"));
        assert!(sbpl.contains("global-name"));
        assert!(!sbpl.contains("(allow mach-lookup)"));
        assert!(!sbpl.contains("com.apple.SecurityServer"));
        assert!(!sbpl.contains("ipc-posix-shm"));
    }

    #[test]
    fn test_should_escape_sbpl_path_syntax() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        profile
            .allow_write
            .push(SandboxPath::file(PathBuf::from("/tmp/a\"b\\c")));
        let sbpl = generate(&profile, Some(12345), strict_options()).unwrap();
        assert!(sbpl.contains("(literal \"/tmp/a\\\"b\\\\c\")"));
    }

    #[test]
    fn test_should_reject_control_characters_in_paths() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        profile
            .allow_write
            .push(SandboxPath::file(PathBuf::from("/tmp/a\nb")));
        assert!(generate(&profile, Some(12345), strict_options()).is_err());
    }

    #[test]
    fn test_should_reject_non_utf8_paths() {
        let path = PathBuf::from(OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0xff]));
        assert!(validated_sbpl_path(&path).is_err());
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "synchronous filesystem setup is isolated to this SBPL regression test"
    )]
    fn deny_read_includes_resolved_symlink_target() {
        let directory = tempfile::tempdir().unwrap();
        let protected = directory.path().join("dotfiles/ssh");
        std::fs::create_dir_all(&protected).unwrap();
        let canonical_protected = std::fs::canonicalize(&protected).unwrap();
        let alias = directory.path().join(".ssh");
        std::os::unix::fs::symlink(&protected, &alias).unwrap();

        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, directory.path(), directory.path());
        profile.deny_read = vec![SandboxPath::dir(alias.clone())];
        let sbpl = generate(&profile, Some(12345), strict_options()).unwrap();

        assert!(sbpl.contains(&format!("(subpath \"{}\")", alias.display())));
        assert!(sbpl.contains(&format!("(subpath \"{}\")", canonical_protected.display())));
    }
}
