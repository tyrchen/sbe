use std::path::{Path, PathBuf};

use super::{DomainPattern, SandboxProfile, common_allow_exec, common_deny_exec, common_deny_read};

/// Default sandbox profile for the Elixir ecosystem.
pub fn elixir_profile(home: &Path, pwd: &Path) -> SandboxProfile {
    let mut allow_exec = common_allow_exec();
    allow_exec.extend([
        PathBuf::from("/usr/local/bin/elixir"),
        PathBuf::from("/usr/local/bin/mix"),
        PathBuf::from("/usr/local/bin/erl"),
        PathBuf::from("/opt/homebrew/bin/elixir"),
        PathBuf::from("/opt/homebrew/bin/mix"),
        PathBuf::from("/opt/homebrew/bin/erl"),
        home.join(".asdf"),
        home.join(".kiex"),
    ]);

    SandboxProfile {
        name: "elixir".to_owned(),
        allow_write: vec![
            pwd.to_path_buf(),
            home.join(".hex"),
            home.join(".mix"),
            home.join(".cache/rebar3"),
        ],
        deny_read: common_deny_read(home),
        allow_domains: vec![
            DomainPattern::from("hex.pm"),
            DomainPattern::from("repo.hex.pm"),
            DomainPattern::from("builds.hex.pm"),
            DomainPattern::from("github.com"),
            DomainPattern::from("objects.githubusercontent.com"),
        ],
        deny_exec: common_deny_exec(),
        allow_exec,
        enable_proxy: true,
        allow_all_network: false,
        allow_fetch: vec![],
        env: Default::default(),
    }
}
