use std::path::{Path, PathBuf};

use super::{DomainPattern, SandboxProfile, common_allow_exec, common_deny_exec, common_deny_read};

/// Default sandbox profile for the Node.js ecosystem.
pub fn node_profile(home: &Path, pwd: &Path) -> SandboxProfile {
    let mut allow_exec = common_allow_exec();
    allow_exec.extend([
        PathBuf::from("/usr/local/bin/node"),
        PathBuf::from("/opt/homebrew/bin/node"),
        home.join(".nvm/versions"),
        home.join(".volta"),
        PathBuf::from("/usr/bin/xcodebuild"),
        PathBuf::from("/usr/bin/xcrun"),
    ]);

    SandboxProfile {
        name: "node".to_owned(),
        allow_write: vec![
            pwd.to_path_buf(),
            home.join(".npm"),
            home.join(".cache/yarn"),
            home.join(".local/share/pnpm"),
            home.join(".bun"),
            home.join(".cache/bun"),
        ],
        deny_read: common_deny_read(home),
        allow_domains: vec![
            DomainPattern::from("registry.npmjs.org"),
            DomainPattern::from("registry.yarnpkg.com"),
            DomainPattern::from("registry.npmmirror.com"),
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
