use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::{SandboxPath, expand_path},
    detect::Ecosystem,
};

/// Embedded default profiles YAML, compiled into the binary.
const DEFAULTS_YAML: &str = include_str!("defaults.yaml");

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
    pub allow_write: Vec<SandboxPath>,

    /// Paths denied for reading (expanded, absolute).
    #[serde(default)]
    pub deny_read: Vec<SandboxPath>,

    /// Domains allowed for outbound HTTPS.
    #[serde(default)]
    pub allow_domains: Vec<DomainPattern>,

    /// Binary paths denied for execution.
    #[serde(default)]
    pub deny_exec: Vec<SandboxPath>,

    /// Binary paths explicitly allowed for execution.
    #[serde(default)]
    pub allow_exec: Vec<SandboxPath>,

    /// Whether to enable the domain-filtering proxy.
    #[serde(default = "default_true")]
    pub enable_proxy: bool,

    /// Whether to allow all network (disables proxy, allows all outbound).
    #[serde(default)]
    pub allow_all_network: bool,

    /// Domains that build scripts are allowed to fetch from.
    ///
    /// When non-empty, `curl` and `wget` are added to `allow_exec` and these
    /// domains are merged into the proxy allowlist.
    #[serde(default)]
    pub allow_fetch: Vec<DomainPattern>,

    /// Additional environment variables to inject.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

impl SandboxProfile {
    /// Build the default profile for an ecosystem from the embedded YAML defaults.
    pub fn for_ecosystem(ecosystem: Ecosystem, home: &Path, pwd: &Path) -> Self {
        let defaults: DefaultsFile =
            serde_yaml::from_str(DEFAULTS_YAML).expect("embedded defaults.yaml is invalid");

        let common = &defaults.common;
        let profile_name = ecosystem.to_string();
        let eco_cfg = defaults
            .profiles
            .get(&profile_name)
            .unwrap_or_else(|| panic!("missing profile '{profile_name}' in defaults.yaml"));

        // Build allow_exec: common + ecosystem-specific
        let mut allow_exec: Vec<SandboxPath> = common
            .allow_exec
            .iter()
            .chain(eco_cfg.allow_exec.iter())
            .map(|p| expand_path(p, home, pwd))
            .collect();

        // Build deny_exec: from common (also resolve symlinks for deny rules)
        let mut deny_exec: Vec<SandboxPath> = common
            .deny_exec
            .iter()
            .map(|p| expand_path(p, home, pwd))
            .collect();
        resolve_symlinks(&mut deny_exec);

        // Build deny_read: from common
        let deny_read: Vec<SandboxPath> = common
            .deny_read
            .iter()
            .map(|p| expand_path(p, home, pwd))
            .collect();

        // Build allow_write: from ecosystem
        let mut allow_write: Vec<SandboxPath> = eco_cfg
            .allow_write
            .iter()
            .map(|p| expand_path(p, home, pwd))
            .collect();

        // Build allow_domains: from ecosystem
        let allow_domains: Vec<DomainPattern> = eco_cfg
            .allow_domains
            .iter()
            .map(|d| DomainPattern(d.clone()))
            .collect();

        // Node-specific: monorepos hoist node_modules and lock files to the
        // workspace root. Only allow writes to specific paths npm needs —
        // NOT the entire git root, which would let a malicious postinstall
        // script modify source files in sibling packages or CI configs.
        if ecosystem == Ecosystem::Node
            && let Some(git_root) = find_git_root(pwd)
            && git_root != pwd
        {
            allow_exec.push(SandboxPath::dir(git_root.join("node_modules")));
            allow_write.push(SandboxPath::dir(git_root.join("node_modules")));
            allow_write.push(SandboxPath::file(git_root.join("package-lock.json")));
            allow_write.push(SandboxPath::file(git_root.join("yarn.lock")));
            allow_write.push(SandboxPath::file(git_root.join("pnpm-lock.yaml")));
            allow_write.push(SandboxPath::dir(git_root.join(".yarn")));
            allow_write.push(SandboxPath::file(git_root.join(".pnp.cjs")));
            allow_write.push(SandboxPath::file(git_root.join(".pnp.loader.mjs")));
        }

        // Rust-specific: resolve cargo target dir for write + exec
        if ecosystem == Ecosystem::Rust {
            if let Some(target_dir) = resolve_cargo_target_dir(home, pwd) {
                allow_write.push(SandboxPath::dir(target_dir.clone()));
                allow_exec.push(SandboxPath::dir(target_dir));
            } else {
                allow_exec.push(SandboxPath::dir(pwd.join("target")));
            }
        }

        // Java-specific: allow JAVA_HOME
        if ecosystem == Ecosystem::Java
            && let Ok(java_home) = std::env::var("JAVA_HOME")
        {
            allow_exec.push(SandboxPath::dir(PathBuf::from(java_home)));
        }

        // Resolve symlinks: SBPL checks the real path after kernel symlink
        // resolution, so /opt/homebrew/bin/zig (symlink) won't match unless
        // we also allow the resolved /opt/homebrew/Cellar/.../zig path.
        resolve_symlinks(&mut allow_exec);

        SandboxProfile {
            name: profile_name,
            allow_write,
            deny_read,
            allow_domains,
            deny_exec,
            allow_exec,
            enable_proxy: true,
            allow_all_network: false,
            allow_fetch: vec![],
            env: Default::default(),
        }
    }

    /// Merge CLI overrides into this profile.
    pub fn merge_overrides(&mut self, overrides: &ProfileOverrides) {
        self.allow_write
            .extend(overrides.allow_write.iter().cloned());
        self.deny_read.extend(overrides.deny_read.iter().cloned());
        self.allow_domains
            .extend(overrides.allow_domains.iter().cloned());
        self.deny_exec.extend(overrides.deny_exec.iter().cloned());
        self.allow_exec.extend(overrides.allow_exec.iter().cloned());

        if !overrides.deny_domains.is_empty() {
            self.allow_domains
                .retain(|d| !overrides.deny_domains.iter().any(|denied| denied.0 == d.0));
        }

        self.allow_fetch
            .extend(overrides.allow_fetch.iter().cloned());

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

    /// Finalize the profile: apply allow_fetch effects to allow_exec and allow_domains.
    ///
    /// Must be called after all merging is complete, before SBPL generation.
    pub fn finalize(&mut self) {
        if !self.allow_fetch.is_empty() {
            let curl = SandboxPath::file(PathBuf::from("/usr/bin/curl"));
            let wget = SandboxPath::file(PathBuf::from("/usr/bin/wget"));
            if !self.allow_exec.iter().any(|p| p.path == curl.path) {
                self.allow_exec.push(curl);
            }
            if !self.allow_exec.iter().any(|p| p.path == wget.path) {
                self.allow_exec.push(wget);
            }

            for domain in &self.allow_fetch {
                if !self.allow_domains.iter().any(|d| d.0 == domain.0) {
                    self.allow_domains.push(domain.clone());
                }
            }
        }
    }
}

/// For each path in the list, if it's a symlink, also add the resolved real path.
///
/// macOS sandbox-exec resolves symlinks before checking SBPL rules, so
/// `/opt/homebrew/bin/zig` (a symlink to `/opt/homebrew/Cellar/zig/.../zig`)
/// requires the Cellar path to be in the allow list too.
///
/// For Homebrew Cellar paths, we add the package root directory (e.g.,
/// `/opt/homebrew/Cellar/zig/0.15.2/`) rather than just the binary, because
/// tools like zig spawn sub-tools from their lib/ directory.
#[allow(clippy::disallowed_methods)]
fn resolve_symlinks(paths: &mut Vec<SandboxPath>) {
    let additional: Vec<SandboxPath> = paths
        .iter()
        .filter_map(|sp| {
            let resolved = std::fs::canonicalize(&sp.path).ok()?;
            if resolved == sp.path {
                return None;
            }
            // For Homebrew Cellar paths, allow the entire package directory.
            // Structure: /opt/homebrew/Cellar/<pkg>/<version>/bin/<binary>
            // We want:   /opt/homebrew/Cellar/<pkg>/<version>/
            let resolved_str = resolved.to_string_lossy();
            if let Some(cellar_idx) = resolved_str.find("/Cellar/") {
                let after_cellar = &resolved_str[cellar_idx + 8..];
                let parts: Vec<&str> = after_cellar.splitn(3, '/').collect();
                if parts.len() >= 2 {
                    let pkg_root = format!(
                        "{}/Cellar/{}/{}",
                        &resolved_str[..cellar_idx],
                        parts[0],
                        parts[1]
                    );
                    return Some(SandboxPath::dir(PathBuf::from(pkg_root)));
                }
            }
            // Preserve the original is_dir flag for non-Cellar symlinks
            Some(SandboxPath {
                path: resolved,
                is_dir: sp.is_dir,
            })
        })
        .filter(|resolved| !paths.iter().any(|p| p.path == resolved.path))
        .collect();
    paths.extend(additional);
}

/// Find the git root by walking up from `start`.
fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut dir = start;
    loop {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

/// Overrides from CLI flags that get merged into the resolved profile.
#[derive(Debug, Default, Clone)]
pub struct ProfileOverrides {
    pub allow_write: Vec<SandboxPath>,
    pub deny_read: Vec<SandboxPath>,
    pub allow_domains: Vec<DomainPattern>,
    pub deny_domains: Vec<DomainPattern>,
    pub allow_exec: Vec<SandboxPath>,
    pub deny_exec: Vec<SandboxPath>,
    pub allow_fetch: Vec<DomainPattern>,
    pub allow_all_network: bool,
    pub no_proxy: bool,
    pub env: HashMap<String, String>,
}

// --- Embedded YAML deserialization types ---

#[derive(Debug, Deserialize)]
struct DefaultsFile {
    common: CommonDefaults,
    profiles: HashMap<String, EcosystemDefaults>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommonDefaults {
    #[serde(default)]
    deny_read: Vec<String>,
    #[serde(default)]
    deny_exec: Vec<String>,
    #[serde(default)]
    allow_exec: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcosystemDefaults {
    #[serde(default)]
    allow_write: Vec<String>,
    #[serde(default)]
    allow_domains: Vec<String>,
    #[serde(default)]
    allow_exec: Vec<String>,
}

// --- Rust-specific cargo target dir resolution ---

/// Resolve the cargo target directory from environment or cargo config.
fn resolve_cargo_target_dir(home: &Path, pwd: &Path) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Ok(dir) = std::env::var("CARGO_BUILD_TARGET_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Some(dir) = read_target_dir_from_cargo_config(&pwd.join(".cargo/config.toml")) {
        return Some(dir);
    }
    if let Some(dir) = read_target_dir_from_cargo_config(&home.join(".cargo/config.toml")) {
        return Some(dir);
    }
    None
}

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
    fn test_should_load_all_ecosystems_from_yaml() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");

        for eco in Ecosystem::ALL {
            let profile = SandboxProfile::for_ecosystem(eco, &home, &pwd);
            assert_eq!(profile.name, eco.to_string());
            assert!(!profile.allow_write.is_empty(), "no allow_write for {eco}");
            assert!(!profile.deny_read.is_empty(), "no deny_read for {eco}");
            assert!(
                !profile.allow_domains.is_empty(),
                "no allow_domains for {eco}"
            );
            assert!(!profile.deny_exec.is_empty(), "no deny_exec for {eco}");
            assert!(!profile.allow_exec.is_empty(), "no allow_exec for {eco}");
        }
    }

    /// Helper: check if a path list contains a given path (ignoring is_dir).
    fn has(paths: &[SandboxPath], path: &str) -> bool {
        paths.iter().any(|sp| sp.has_path(Path::new(path)))
    }

    #[test]
    fn test_should_expand_paths_in_defaults() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);

        assert!(has(&profile.deny_read, "/Users/test/.ssh"));
        assert!(has(&profile.allow_write, "/Users/test/project"));
        assert!(has(&profile.allow_write, "/Users/test/.npm"));
    }

    #[test]
    fn test_should_include_common_exec_in_all_profiles() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");

        for eco in Ecosystem::ALL {
            let profile = SandboxProfile::for_ecosystem(eco, &home, &pwd);
            assert!(
                has(&profile.allow_exec, "/bin/sh"),
                "missing /bin/sh for {eco}"
            );
            assert!(
                has(&profile.allow_exec, "/usr/bin/cc"),
                "missing /usr/bin/cc for {eco}"
            );
            assert!(
                has(&profile.deny_exec, "/usr/bin/osascript"),
                "missing osascript deny for {eco}"
            );
        }
    }

    #[test]
    fn test_should_merge_overrides() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        let original_write_count = profile.allow_write.len();

        let overrides = ProfileOverrides {
            allow_write: vec![SandboxPath::dir(PathBuf::from("/extra/path"))],
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

    #[test]
    fn test_should_finalize_allow_fetch() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);

        assert!(!has(&profile.allow_exec, "/usr/bin/curl"));

        let overrides = ProfileOverrides {
            allow_fetch: vec![DomainPattern::from("example.com")],
            ..Default::default()
        };
        profile.merge_overrides(&overrides);
        profile.finalize();

        assert!(has(&profile.allow_exec, "/usr/bin/curl"));
        assert!(has(&profile.allow_exec, "/usr/bin/wget"));
        assert!(profile.allow_domains.iter().any(|d| d.0 == "example.com"));
    }

    #[test]
    fn test_should_not_add_curl_without_allow_fetch() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);
        profile.finalize();
        assert!(!has(&profile.allow_exec, "/usr/bin/curl"));
    }

    #[test]
    fn test_should_not_duplicate_domains_on_finalize() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        let original_domain_count = profile.allow_domains.len();

        let overrides = ProfileOverrides {
            allow_fetch: vec![DomainPattern::from("github.com")],
            ..Default::default()
        };
        profile.merge_overrides(&overrides);
        profile.finalize();

        assert_eq!(profile.allow_domains.len(), original_domain_count);
        assert!(has(&profile.allow_exec, "/usr/bin/curl"));
    }
}
