use std::path::{Path, PathBuf};

use super::{DomainPattern, SandboxProfile, common_allow_exec, common_deny_exec, common_deny_read};

/// Default sandbox profile for the Rust ecosystem.
pub fn rust_profile(home: &Path, pwd: &Path) -> SandboxProfile {
    let mut allow_exec = common_allow_exec();
    allow_exec.extend([
        home.join(".cargo/bin"),
        home.join(".rustup/toolchains"),
        PathBuf::from("/usr/bin/xcrun"),
        PathBuf::from("/usr/bin/xcodebuild"),
        PathBuf::from("/usr/bin/install_name_tool"),
    ]);

    SandboxProfile {
        name: "rust".to_owned(),
        allow_write: vec![
            pwd.to_path_buf(),
            home.join(".cargo/registry"),
            home.join(".cargo/git"),
            home.join(".cargo/bin"),
            home.join(".rustup"),
        ],
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
