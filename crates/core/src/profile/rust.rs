use std::{
    env,
    path::{Path, PathBuf},
};

use super::{DomainPattern, SandboxProfile, common_allow_exec, common_deny_exec, common_deny_read};

/// Default sandbox profile for the Rust ecosystem.
pub fn rust_profile(home: &Path, pwd: &Path) -> SandboxProfile {
    let mut allow_exec = common_allow_exec();
    allow_exec.extend([
        home.join(".cargo/bin"),
        home.join(".rustup/toolchains"),
        PathBuf::from("/usr/bin/xcrun"),
        PathBuf::from("/usr/bin/xcodebuild"),
    ]);

    let mut allow_write = vec![
        pwd.to_path_buf(),
        home.join(".cargo/registry"),
        home.join(".cargo/git"),
        home.join(".cargo/bin"),
        home.join(".rustup"),
    ];

    // Respect CARGO_TARGET_DIR if set, otherwise try to read from cargo config.
    // The target dir must be both writable (compilation output) and executable
    // (build scripts, proc macros are compiled there and then executed by cargo).
    if let Some(target_dir) = resolve_cargo_target_dir(home, pwd) {
        allow_write.push(target_dir.clone());
        allow_exec.push(target_dir);
    } else {
        // Default target dir — also needs exec for build scripts / proc macros
        allow_exec.push(pwd.join("target"));
    }

    SandboxProfile {
        name: "rust".to_owned(),
        allow_write,
        deny_read: common_deny_read(home),
        allow_domains: vec![
            DomainPattern::from("crates.io"),
            DomainPattern::from("static.crates.io"),
            DomainPattern::from("index.crates.io"),
            DomainPattern::from("static.rust-lang.org"),
            DomainPattern::from("github.com"),
            DomainPattern::from("objects.githubusercontent.com"),
        ],
        deny_exec: common_deny_exec(),
        allow_exec,
        enable_proxy: true,
        allow_all_network: false,
        env: Default::default(),
    }
}

/// Resolve the cargo target directory from environment or cargo config.
///
/// Checks in order:
/// 1. `CARGO_TARGET_DIR` env var
/// 2. `CARGO_BUILD_TARGET_DIR` env var
/// 3. `.cargo/config.toml` in the project or home directory
fn resolve_cargo_target_dir(home: &Path, pwd: &Path) -> Option<PathBuf> {
    // Check environment variables first
    if let Ok(dir) = env::var("CARGO_TARGET_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Ok(dir) = env::var("CARGO_BUILD_TARGET_DIR") {
        return Some(PathBuf::from(dir));
    }

    // Check project-level .cargo/config.toml
    if let Some(dir) = read_target_dir_from_cargo_config(&pwd.join(".cargo/config.toml")) {
        return Some(dir);
    }

    // Check user-level ~/.cargo/config.toml
    if let Some(dir) = read_target_dir_from_cargo_config(&home.join(".cargo/config.toml")) {
        return Some(dir);
    }

    None
}

/// Parse `[build] target-dir` from a cargo config.toml file.
///
/// Uses synchronous I/O because this runs during profile construction
/// which happens before the async runtime is needed. The file is small
/// (cargo config) so blocking is acceptable.
#[allow(clippy::disallowed_methods)]
fn read_target_dir_from_cargo_config(path: &Path) -> Option<PathBuf> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut in_build_section = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_build_section = trimmed == "[build]";
            continue;
        }
        if in_build_section && let Some(value) = trimmed.strip_prefix("target-dir") {
            let value = value.trim().strip_prefix('=')?.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            return Some(PathBuf::from(value));
        }
    }
    None
}
