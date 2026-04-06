mod elixir;
mod java;
mod node;
mod python;
mod rust;

use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

pub use self::{
    elixir::elixir_profile, java::java_profile, node::node_profile, python::python_profile,
    rust::rust_profile,
};
use crate::detect::Ecosystem;

/// A pattern for matching domain names.
///
/// Supports exact match (`"registry.npmjs.org"`) and wildcard prefix
/// (`"*.npmjs.org"` matches any subdomain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DomainPattern(pub String);

impl DomainPattern {
    /// Check whether a given hostname matches this pattern.
    pub fn matches(&self, host: &str) -> bool {
        let pattern = &self.0;
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Wildcard: host must end with .suffix or be exactly suffix
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else {
            host == pattern
        }
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for DomainPattern {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// The resolved set of sandbox permissions for a single execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxProfile {
    /// Human-readable name (e.g., "node", "rust", "custom:my-app").
    pub name: String,

    /// Paths allowed for writing (expanded, absolute).
    #[serde(default)]
    pub allow_write: Vec<PathBuf>,

    /// Paths denied for reading (expanded, absolute).
    #[serde(default)]
    pub deny_read: Vec<PathBuf>,

    /// Domains allowed for outbound HTTPS.
    #[serde(default)]
    pub allow_domains: Vec<DomainPattern>,

    /// Binary paths denied for execution.
    #[serde(default)]
    pub deny_exec: Vec<PathBuf>,

    /// Binary paths explicitly allowed for execution.
    #[serde(default)]
    pub allow_exec: Vec<PathBuf>,

    /// Whether to enable the domain-filtering proxy.
    #[serde(default = "default_true")]
    pub enable_proxy: bool,

    /// Whether to allow all network (disables proxy, allows all outbound).
    #[serde(default)]
    pub allow_all_network: bool,

    /// Additional environment variables to inject.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

impl SandboxProfile {
    /// Get the default profile for a given ecosystem.
    pub fn for_ecosystem(ecosystem: Ecosystem, home: &Path, pwd: &Path) -> Self {
        match ecosystem {
            Ecosystem::Node => node_profile(home, pwd),
            Ecosystem::Rust => rust_profile(home, pwd),
            Ecosystem::Python => python_profile(home, pwd),
            Ecosystem::Elixir => elixir_profile(home, pwd),
            Ecosystem::Java => java_profile(home, pwd),
        }
    }

    /// Merge CLI overrides into this profile.
    ///
    /// Additive fields (allow_write, deny_read, etc.) are appended.
    /// Boolean flags and env vars are overwritten.
    pub fn merge_overrides(&mut self, overrides: &ProfileOverrides) {
        self.allow_write
            .extend(overrides.allow_write.iter().cloned());
        self.deny_read.extend(overrides.deny_read.iter().cloned());
        self.allow_domains
            .extend(overrides.allow_domains.iter().cloned());
        self.deny_exec.extend(overrides.deny_exec.iter().cloned());
        self.allow_exec.extend(overrides.allow_exec.iter().cloned());

        // Remove denied domains
        if !overrides.deny_domains.is_empty() {
            self.allow_domains
                .retain(|d| !overrides.deny_domains.iter().any(|denied| denied.0 == d.0));
        }

        if overrides.allow_all_network {
            self.allow_all_network = true;
            self.enable_proxy = false;
        }
        if overrides.no_proxy {
            self.enable_proxy = false;
        }

        for (k, v) in &overrides.env {
            self.env.insert(k.clone(), v.clone());
        }
    }
}

/// Overrides from CLI flags that get merged into the resolved profile.
#[derive(Debug, Default, Clone)]
pub struct ProfileOverrides {
    pub allow_write: Vec<PathBuf>,
    pub deny_read: Vec<PathBuf>,
    pub allow_domains: Vec<DomainPattern>,
    pub deny_domains: Vec<DomainPattern>,
    pub allow_exec: Vec<PathBuf>,
    pub deny_exec: Vec<PathBuf>,
    pub allow_all_network: bool,
    pub no_proxy: bool,
    pub env: HashMap<String, String>,
}

/// Common sensitive paths that should be denied for reading across all ecosystems.
pub fn common_deny_read(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".ssh"),
        home.join(".gnupg"),
        home.join(".aws"),
        home.join(".azure"),
        home.join(".config/gcloud"),
        home.join("Library/Keychains"),
        home.join(".docker/config.json"),
        home.join(".netrc"),
        home.join("Library/Application Support/Google/Chrome"),
        home.join("Library/Application Support/Firefox"),
        home.join("Library/Application Support/Microsoft Edge"),
        home.join("Library/Application Support/BraveSoftware/Brave-Browser"),
        home.join("Library/Safari"),
    ]
}

/// Common binaries that should be denied execution across all ecosystems.
pub fn common_deny_exec() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/bin/osascript"),
        PathBuf::from("/usr/bin/security"),
        PathBuf::from("/usr/sbin/screencapture"),
        PathBuf::from("/usr/bin/open"),
        PathBuf::from("/usr/bin/pbcopy"),
        PathBuf::from("/usr/bin/pbpaste"),
    ]
}

/// Common shell/utility binaries needed by most build tools.
pub fn common_allow_exec() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/bin/sh"),
        PathBuf::from("/bin/bash"),
        PathBuf::from("/bin/zsh"),
        PathBuf::from("/usr/bin/env"),
        PathBuf::from("/usr/bin/tar"),
        PathBuf::from("/usr/bin/gzip"),
        PathBuf::from("/usr/bin/make"),
        PathBuf::from("/usr/bin/cc"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_match_exact_domain() {
        let p = DomainPattern::from("registry.npmjs.org");
        assert!(p.matches("registry.npmjs.org"));
        assert!(!p.matches("evil.com"));
        assert!(!p.matches("sub.registry.npmjs.org"));
    }

    #[test]
    fn test_should_match_wildcard_domain() {
        let p = DomainPattern::from("*.npmjs.org");
        assert!(p.matches("registry.npmjs.org"));
        assert!(p.matches("npmjs.org"));
        assert!(p.matches("deep.sub.npmjs.org"));
        assert!(!p.matches("evil.com"));
    }

    #[test]
    fn test_should_merge_overrides() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        let original_write_count = profile.allow_write.len();

        let overrides = ProfileOverrides {
            allow_write: vec![PathBuf::from("/extra/path")],
            deny_domains: vec![DomainPattern::from("registry.npmmirror.com")],
            ..Default::default()
        };
        profile.merge_overrides(&overrides);

        assert_eq!(profile.allow_write.len(), original_write_count + 1);
        assert!(
            !profile
                .allow_domains
                .iter()
                .any(|d| d.0 == "registry.npmmirror.com")
        );
    }
}
