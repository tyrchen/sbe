use std::path::{Path, PathBuf};

use super::{DomainPattern, SandboxProfile, common_allow_exec, common_deny_exec, common_deny_read};

/// Default sandbox profile for the Python ecosystem.
pub fn python_profile(home: &Path, pwd: &Path) -> SandboxProfile {
    let mut allow_exec = common_allow_exec();
    allow_exec.extend([
        PathBuf::from("/usr/bin/python3"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/opt/homebrew/bin"),
        home.join(".pyenv"),
        home.join(".local/bin"),
    ]);

    SandboxProfile {
        name: "python".to_owned(),
        allow_write: vec![
            pwd.to_path_buf(),
            home.join(".cache/pip"),
            home.join(".cache/uv"),
            home.join(".local/lib"),
            home.join(".local/bin"),
            pwd.join(".venv"),
            pwd.join("venv"),
        ],
        deny_read: common_deny_read(home),
        allow_domains: vec![
            DomainPattern::from("pypi.org"),
            DomainPattern::from("files.pythonhosted.org"),
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
