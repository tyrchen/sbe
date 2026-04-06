use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::CoreError,
    profile::{DomainPattern, SandboxProfile},
};

/// Top-level configuration file structure (`.sbe.yaml` or `~/.config/sbe/config.yaml`).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SbeConfig {
    /// Profile overrides keyed by profile name.
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

/// A single profile configuration block from the YAML file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileConfig {
    /// Base profile to extend from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,

    #[serde(default)]
    pub allow_write: Vec<String>,

    #[serde(default)]
    pub deny_read: Vec<String>,

    #[serde(default)]
    pub allow_domains: Vec<String>,

    #[serde(default)]
    pub deny_exec: Vec<String>,

    #[serde(default)]
    pub allow_exec: Vec<String>,

    /// Domains that build scripts are allowed to fetch from.
    ///
    /// When non-empty, enables curl/wget execution and adds these domains
    /// to the proxy allowlist. This is the intended way to allow build-time
    /// downloads for specific crates (e.g., utoipa-swagger-ui, protobuf-src).
    #[serde(default)]
    pub allow_fetch: Vec<String>,

    /// Whether to allow all network access (disables proxy and SBPL network restrictions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_all_network: Option<bool>,

    /// Whether to enable the domain-filtering proxy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_proxy: Option<bool>,

    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl SbeConfig {
    /// Load config from a YAML file. Returns `Ok(None)` if the file does not exist.
    pub async fn load(path: &Path) -> Result<Option<Self>, CoreError> {
        match tokio::fs::read_to_string(path).await {
            Ok(contents) => {
                let config: Self =
                    serde_yaml::from_str(&contents).map_err(|e| CoreError::ConfigLoad {
                        path: path.to_path_buf(),
                        source: Box::new(e),
                    })?;
                Ok(Some(config))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CoreError::ConfigLoad {
                path: path.to_path_buf(),
                source: Box::new(e),
            }),
        }
    }

    /// Find the project config by walking up from `start` to the filesystem root,
    /// stopping at a git repository boundary. Checks both `.sbe.yaml` and `.sbe.yml`.
    pub fn find_project_config(start: &Path) -> Option<PathBuf> {
        let mut dir = start;
        loop {
            for name in [".sbe.yaml", ".sbe.yml"] {
                let candidate = dir.join(name);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
            // Stop at git root
            if dir.join(".git").exists() {
                return None;
            }
            dir = dir.parent()?;
        }
    }

    /// The global config path: `~/.config/sbe/config.yaml`.
    pub fn global_config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("sbe/config.yaml"))
    }
}

impl ProfileConfig {
    /// Apply this config's overrides onto a `SandboxProfile`.
    ///
    /// Paths are expanded relative to `home` (for `~`) and `pwd` (for `./`).
    pub fn apply_to(&self, profile: &mut SandboxProfile, home: &Path, pwd: &Path) {
        for p in &self.allow_write {
            profile.allow_write.push(expand_path(p, home, pwd));
        }
        for p in &self.deny_read {
            profile.deny_read.push(expand_path(p, home, pwd));
        }
        for d in &self.allow_domains {
            profile.allow_domains.push(DomainPattern(d.clone()));
        }
        for p in &self.deny_exec {
            profile.deny_exec.push(expand_path(p, home, pwd));
        }
        for p in &self.allow_exec {
            profile.allow_exec.push(expand_path(p, home, pwd));
        }
        for d in &self.allow_fetch {
            profile.allow_fetch.push(DomainPattern(d.clone()));
        }
        if let Some(allow_all) = self.allow_all_network {
            profile.allow_all_network = allow_all;
            if allow_all {
                profile.enable_proxy = false;
            }
        }
        if let Some(enable_proxy) = self.enable_proxy {
            profile.enable_proxy = enable_proxy;
        }
        for (k, v) in &self.env {
            profile.env.insert(k.clone(), v.clone());
        }
    }
}

/// Expand `~` to home and `./` to pwd in a path string.
pub fn expand_path(raw: &str, home: &Path, pwd: &Path) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        home.join(rest)
    } else if raw == "~" {
        home.to_path_buf()
    } else if let Some(rest) = raw.strip_prefix("./") {
        pwd.join(rest)
    } else if raw == "." {
        pwd.to_path_buf()
    } else if raw.starts_with('/') {
        PathBuf::from(raw)
    } else {
        // Relative path — resolve against pwd
        pwd.join(raw)
    }
}

/// Load and merge configuration from all sources.
///
/// Resolution order (last wins):
/// 1. Built-in ecosystem defaults
/// 2. Global config (`~/.config/sbe/config.yaml`)
/// 3. Project config (`.sbe.yaml` found by walking up from pwd)
/// 4. Explicit config file (`--config` flag)
///
/// Returns the merged configs in order. The caller applies them to the profile.
pub async fn load_configs(
    pwd: &Path,
    explicit_config: Option<&Path>,
) -> Result<Vec<SbeConfig>, CoreError> {
    let mut configs = Vec::new();

    // Global config
    if let Some(global_path) = SbeConfig::global_config_path()
        && let Some(cfg) = SbeConfig::load(&global_path).await?
    {
        configs.push(cfg);
    }

    // Project config
    if let Some(project_path) = SbeConfig::find_project_config(pwd)
        && let Some(cfg) = SbeConfig::load(&project_path).await?
    {
        configs.push(cfg);
    }

    // Explicit config
    if let Some(explicit) = explicit_config
        && let Some(cfg) = SbeConfig::load(explicit).await?
    {
        configs.push(cfg);
    }

    Ok(configs)
}

/// Resolve the final `SandboxProfile` by merging configs into the ecosystem default.
pub fn resolve_profile(base: &mut SandboxProfile, configs: &[SbeConfig], home: &Path, pwd: &Path) {
    let profile_name = base.name.clone();

    for config in configs {
        // Apply matching profile config
        if let Some(pc) = config.profiles.get(&profile_name) {
            // Handle extends
            if let Some(base_name) = &pc.extends
                && let Some(base_pc) = config.profiles.get(base_name)
            {
                base_pc.apply_to(base, home, pwd);
            }
            pc.apply_to(base, home, pwd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_expand_home_path() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        assert_eq!(
            expand_path("~/.ssh", &home, &pwd),
            PathBuf::from("/Users/test/.ssh")
        );
    }

    #[test]
    fn test_should_expand_relative_path() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        assert_eq!(
            expand_path("./node_modules", &home, &pwd),
            PathBuf::from("/Users/test/project/node_modules")
        );
    }

    #[test]
    fn test_should_keep_absolute_path() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        assert_eq!(
            expand_path("/usr/bin/osascript", &home, &pwd),
            PathBuf::from("/usr/bin/osascript")
        );
    }

    #[test]
    fn test_should_parse_config_yaml() {
        let yaml = r#"
profiles:
  node:
    allowWrite:
      - "./node_modules"
      - "~/.npm"
    denyRead:
      - "~/.ssh"
    allowDomains:
      - "registry.npmjs.org"
    env:
      NODE_ENV: production
  my-app:
    extends: node
    allowDomains:
      - "api.mycompany.com"
"#;
        let config: SbeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.profiles.len(), 2);
        assert_eq!(config.profiles["node"].allow_write.len(), 2);
        assert_eq!(config.profiles["my-app"].extends.as_deref(), Some("node"));
    }

    #[test]
    fn test_should_apply_profile_config() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let pc = ProfileConfig {
            allow_write: vec!["./extra".to_owned()],
            allow_domains: vec!["extra.com".to_owned()],
            ..Default::default()
        };
        let mut profile =
            SandboxProfile::for_ecosystem(crate::detect::Ecosystem::Node, &home, &pwd);
        let original_write = profile.allow_write.len();
        let original_domains = profile.allow_domains.len();

        pc.apply_to(&mut profile, &home, &pwd);

        assert_eq!(profile.allow_write.len(), original_write + 1);
        assert_eq!(profile.allow_domains.len(), original_domains + 1);
    }
}
