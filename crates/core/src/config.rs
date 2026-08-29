use std::{
    collections::{HashMap, HashSet},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::CoreError,
    profile::{DomainPattern, GrantKind, GrantOrigin, GrantRecord, SandboxProfile},
};

/// Top-level configuration file structure (`.sbe.yaml` or `~/.config/sbe/config.yaml`).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SbeConfig {
    /// Profile overrides keyed by profile name.
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

/// A single profile configuration block from the YAML file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileConfig {
    /// Base profile to extend from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,

    #[serde(default)]
    pub allow_write: Vec<String>,

    #[serde(default)]
    pub deny_read: Vec<String>,

    /// Linux read-allowlist extensions. macOS ignores this field.
    #[serde(default)]
    pub allow_read: Vec<String>,

    #[serde(default)]
    pub allow_domains: Vec<String>,

    /// Remove domains from grants established by lower-precedence sources.
    #[serde(default)]
    pub deny_domains: Vec<String>,

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

    /// Opt-in to proceed under a degraded kernel (Linux only). See
    /// `cross-platform-backend-design.md` §13 D1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_degraded: Option<bool>,

    #[serde(default)]
    pub env: HashMap<String, String>,
}

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_PROFILES: usize = 128;
const MAX_LIST_ITEMS: usize = 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_ENV_VALUE_BYTES: usize = 8192;
const MAX_ENV_VARS: usize = 128;

const RESERVED_ENV: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "TMPDIR",
    "TMP",
    "TEMP",
    "XDG_RUNTIME_DIR",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET_DIR",
    "CARGO_BUILD_BUILD_DIR",
    "PIP_CACHE_DIR",
    "UV_CACHE_DIR",
    "MIX_BUILD_ROOT",
    "MIX_DEPS_PATH",
    "REBAR_CACHE_DIR",
    "GRADLE_USER_HOME",
    "COURSIER_CACHE",
    "SBT_OPTS",
    "JAVA_TOOL_OPTIONS",
    "SBE_PROXY_TOKEN",
];

/// Trust provenance of a loaded configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ConfigOrigin {
    Global,
    Project,
    Explicit,
}

/// A configuration plus the provenance needed to enforce monotonic project
/// policy and explain the final profile.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: SbeConfig,
    pub origin: ConfigOrigin,
    pub path: PathBuf,
    pub trusted: bool,
}

impl SbeConfig {
    /// Load config from a YAML file. Returns `Ok(None)` if the file does not exist.
    pub async fn load(path: &Path) -> Result<Option<Self>, CoreError> {
        let owned_path = path.to_path_buf();
        let contents = tokio::task::spawn_blocking(move || read_config_bytes(&owned_path))
            .await
            .map_err(|error| {
                CoreError::Backend(format!("configuration reader failed: {error}"))
            })??;
        let Some(contents) = contents else {
            return Ok(None);
        };
        let contents = String::from_utf8(contents).map_err(|error| CoreError::ConfigLoad {
            path: path.to_path_buf(),
            source: Box::new(error),
        })?;
        let config: Self =
            serde_yaml::from_str(&contents).map_err(|error| CoreError::ConfigLoad {
                path: path.to_path_buf(),
                source: Box::new(error),
            })?;
        config.validate(path)?;
        Ok(Some(config))
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

    fn validate(&self, path: &Path) -> Result<(), CoreError> {
        if self.profiles.len() > MAX_PROFILES {
            return Err(config_policy(path, "too many profiles"));
        }
        for (name, profile) in &self.profiles {
            if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                return Err(config_policy(
                    path,
                    format!("invalid profile name '{name}'"),
                ));
            }
            profile.validate(path)?;
        }
        Ok(())
    }
}

#[allow(clippy::disallowed_types)] // Unix flags require std OpenOptions in spawn_blocking.
fn read_config_bytes(path: &Path) -> Result<Option<Vec<u8>>, CoreError> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(CoreError::ConfigLoad {
                path: path.to_path_buf(),
                source: Box::new(source),
            });
        }
    };
    let metadata = file.metadata().map_err(|source| CoreError::ConfigLoad {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    if !metadata.is_file() {
        return Err(config_policy(path, "configuration is not a regular file"));
    }
    if metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(config_policy(
            path,
            format!(
                "file is {} bytes; maximum is {MAX_CONFIG_BYTES}",
                metadata.len()
            ),
        ));
    }
    let mut contents = Vec::new();
    file.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut contents)
        .map_err(|source| CoreError::ConfigLoad {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
    if contents.len() > MAX_CONFIG_BYTES {
        return Err(config_policy(path, "configuration grew beyond 1 MiB"));
    }
    Ok(Some(contents))
}

impl ProfileConfig {
    /// Apply this config's overrides onto a `SandboxProfile`.
    ///
    /// Paths are expanded relative to `home` (for `~`) and `pwd` (for `./`).
    pub fn apply_to(
        &self,
        profile: &mut SandboxProfile,
        home: &Path,
        pwd: &Path,
        origin: &GrantOrigin,
    ) -> Result<(), CoreError> {
        if !self.allow_domains.is_empty()
            || !self.deny_domains.is_empty()
            || !self.allow_fetch.is_empty()
            || self.allow_all_network.is_some()
            || self.enable_proxy.is_some()
        {
            profile.network_origin = origin.clone();
        }
        for p in &self.allow_write {
            let path = expand_path(p, home, pwd);
            record_path(profile, GrantKind::AllowWrite, &path, origin);
            profile.allow_write.push(path);
        }
        for p in &self.deny_read {
            let path = expand_path(p, home, pwd);
            record_path(profile, GrantKind::DenyRead, &path, origin);
            profile.deny_read.push(path);
        }
        for p in &self.allow_read {
            let path = expand_path(p, home, pwd);
            record_path(profile, GrantKind::AllowRead, &path, origin);
            profile.allow_read.push(path);
        }
        for d in &self.allow_domains {
            let domain = DomainPattern::new(d).map_err(CoreError::ProfileLint)?;
            profile.grant_origins.push(GrantRecord {
                kind: GrantKind::AllowDomain,
                value: domain.0.clone(),
                origin: origin.clone(),
            });
            profile.allow_domains.push(domain);
        }
        for p in &self.deny_exec {
            profile.add_deny_exec(expand_path(p, home, pwd), origin.clone());
        }
        for p in &self.allow_exec {
            profile.add_allow_exec(expand_path(p, home, pwd), origin.clone());
        }
        for d in &self.allow_fetch {
            let domain = DomainPattern::new(d).map_err(CoreError::ProfileLint)?;
            profile.grant_origins.push(GrantRecord {
                kind: GrantKind::AllowFetch,
                value: domain.0.clone(),
                origin: origin.clone(),
            });
            profile.allow_fetch.push(domain);
        }
        let denied_domains = self
            .deny_domains
            .iter()
            .map(|domain| DomainPattern::new(domain).map_err(CoreError::ProfileLint))
            .collect::<Result<Vec<_>, _>>()?;
        profile.remove_denied_domains(&denied_domains);
        if let Some(allow_all) = self.allow_all_network {
            profile.allow_all_network = allow_all;
        }
        if let Some(enable_proxy) = self.enable_proxy {
            profile.enable_proxy = enable_proxy;
        }
        if let Some(allow_degraded) = self.allow_degraded {
            profile.allow_degraded = allow_degraded;
        }
        for (k, v) in &self.env {
            profile.env.insert(k.clone(), v.clone());
            profile.grant_origins.push(GrantRecord {
                kind: GrantKind::Environment,
                value: k.clone(),
                origin: origin.clone(),
            });
        }
        profile.recompute_network_mode();
        Ok(())
    }

    fn validate(&self, path: &Path) -> Result<(), CoreError> {
        if self.allow_degraded == Some(true) {
            return Err(config_policy(
                path,
                "allowDegraded in configuration is no longer accepted; use the \
                 capability-specific CLI options --strict and --allow-insecure-linux-network for \
                 one trusted invocation",
            ));
        }
        let lists = [
            ("allowWrite", &self.allow_write),
            ("denyRead", &self.deny_read),
            ("allowRead", &self.allow_read),
            ("allowDomains", &self.allow_domains),
            ("denyDomains", &self.deny_domains),
            ("denyExec", &self.deny_exec),
            ("allowExec", &self.allow_exec),
            ("allowFetch", &self.allow_fetch),
        ];
        for (name, values) in lists {
            if values.len() > MAX_LIST_ITEMS {
                return Err(config_policy(path, format!("{name} has too many entries")));
            }
            for value in values {
                if value.is_empty()
                    || value.len() > MAX_PATH_BYTES
                    || value.contains('\0')
                    || value.chars().any(char::is_control)
                {
                    return Err(config_policy(path, format!("invalid value in {name}")));
                }
            }
        }
        for (name, values) in [
            ("allowWrite", &self.allow_write),
            ("denyRead", &self.deny_read),
            ("allowRead", &self.allow_read),
            ("denyExec", &self.deny_exec),
            ("allowExec", &self.allow_exec),
        ] {
            for value in values {
                let without_directory_marker = value.strip_suffix('/').unwrap_or(value);
                if Path::new(without_directory_marker)
                    .components()
                    .any(|component| component == Component::ParentDir)
                {
                    return Err(config_policy(
                        path,
                        format!("{name} path must not contain '..'"),
                    ));
                }
            }
        }
        for domain in self
            .allow_domains
            .iter()
            .chain(&self.deny_domains)
            .chain(&self.allow_fetch)
        {
            DomainPattern::new(domain).map_err(|reason| config_policy(path, reason))?;
        }
        if self.env.len() > MAX_ENV_VARS {
            return Err(config_policy(path, "too many environment variables"));
        }
        for (name, value) in &self.env {
            if !is_valid_env_name(name) || RESERVED_ENV.contains(&name.as_str()) {
                return Err(config_policy(
                    path,
                    format!("invalid or reserved environment variable '{name}'"),
                ));
            }
            if value.len() > MAX_ENV_VALUE_BYTES || value.contains('\0') {
                return Err(config_policy(
                    path,
                    format!("invalid value for environment variable '{name}'"),
                ));
            }
        }
        Ok(())
    }

    fn validate_untrusted_project(&self, path: &Path) -> Result<(), CoreError> {
        let expands_authority = self.extends.is_some()
            || !self.allow_write.is_empty()
            || !self.allow_read.is_empty()
            || !self.allow_domains.is_empty()
            || !self.allow_exec.is_empty()
            || !self.allow_fetch.is_empty()
            || !self.env.is_empty()
            || self.allow_all_network == Some(true)
            || self.enable_proxy == Some(false)
            || self.allow_degraded == Some(true);
        if expands_authority {
            return Err(config_policy(
                path,
                "project configuration may only add denyRead/denyExec or explicitly disable \
                 allowAllNetwork/allowDegraded; pass --trust-project-config to authorize expansion",
            ));
        }
        Ok(())
    }
}

fn record_path(
    profile: &mut SandboxProfile,
    kind: GrantKind,
    path: &SandboxPath,
    origin: &GrantOrigin,
) {
    profile.grant_origins.push(GrantRecord {
        kind,
        value: path.path.to_string_lossy().into_owned(),
        origin: origin.clone(),
    });
}

fn is_valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn config_policy(path: &Path, reason: impl Into<String>) -> CoreError {
    CoreError::ConfigPolicy {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

/// How a `SandboxPath` should be matched in SBPL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PathKind {
    /// Match the directory and everything under it (SBPL `subpath`).
    Subpath,
    /// Exact file match (SBPL `literal`).
    Literal,
    /// Regex match against the absolute path (SBPL `regex`).
    /// Used for prefix patterns like `<target>XXXXXX` temp dirs.
    Regex,
}

/// A path with an explicit kind for SBPL generation.
///
/// Convention: in YAML configs, paths ending with `/` are directories
/// (generate SBPL `subpath`), paths without trailing `/` are files
/// (generate SBPL `literal`). Regex paths are only constructed
/// programmatically (not from YAML).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPath {
    pub path: PathBuf,
    pub kind: PathKind,
}

impl SandboxPath {
    pub fn dir(path: PathBuf) -> Self {
        Self {
            path,
            kind: PathKind::Subpath,
        }
    }

    pub fn file(path: PathBuf) -> Self {
        Self {
            path,
            kind: PathKind::Literal,
        }
    }

    /// Create a regex match. The path must be a valid regex pattern.
    pub fn regex(pattern: PathBuf) -> Self {
        Self {
            path: pattern,
            kind: PathKind::Regex,
        }
    }

    /// Check if this sandbox path matches a given filesystem path.
    pub fn has_path(&self, path: &Path) -> bool {
        self.path == path
    }
}

impl std::fmt::Display for SandboxPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.path.display().fmt(f)
    }
}

/// Expand path placeholders and detect directory vs file from trailing `/`.
///
/// - `~/.ssh/` → directory (subpath)
/// - `~/.npmrc` → file (literal)
/// - `$PWD/` → directory
pub fn expand_path(raw: &str, home: &Path, pwd: &Path) -> SandboxPath {
    let kind = if raw.ends_with('/') {
        PathKind::Subpath
    } else {
        PathKind::Literal
    };
    let raw = raw.strip_suffix('/').unwrap_or(raw);

    let path = if raw == "$PWD" {
        pwd.to_path_buf()
    } else if let Some(rest) = raw.strip_prefix("$PWD/") {
        pwd.join(rest)
    } else if raw == "$HOME" {
        home.to_path_buf()
    } else if let Some(rest) = raw.strip_prefix("$HOME/") {
        home.join(rest)
    } else if let Some(rest) = raw.strip_prefix("~/") {
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
        pwd.join(raw)
    };

    SandboxPath { path, kind }
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
    trust_project_config: bool,
) -> Result<Vec<LoadedConfig>, CoreError> {
    let mut configs = Vec::new();
    let explicit_path = explicit_config.map(|path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            pwd.join(path)
        }
    });

    // Global config
    if let Some(global_path) = SbeConfig::global_config_path()
        && let Some(cfg) = SbeConfig::load(&global_path).await?
    {
        configs.push(LoadedConfig {
            config: cfg,
            origin: ConfigOrigin::Global,
            path: global_path,
            trusted: true,
        });
    }

    // Project config
    if let Some(project_path) = SbeConfig::find_project_config(pwd) {
        let selected_explicitly = if let Some(explicit) = &explicit_path {
            same_configuration_file(&project_path, explicit).await
        } else {
            false
        };
        if !selected_explicitly && let Some(cfg) = SbeConfig::load(&project_path).await? {
            configs.push(LoadedConfig {
                config: cfg,
                origin: ConfigOrigin::Project,
                path: project_path,
                trusted: trust_project_config,
            });
        }
    }

    // Explicit config
    if let Some(explicit) = explicit_path
        && let Some(cfg) = SbeConfig::load(&explicit).await?
    {
        configs.push(LoadedConfig {
            config: cfg,
            origin: ConfigOrigin::Explicit,
            path: explicit,
            trusted: true,
        });
    }

    Ok(configs)
}

/// Compare file identities instead of spellings so relative paths and hard
/// links cannot make one policy file appear as both an untrusted project
/// source and a trusted explicit source. Any metadata error falls through to
/// normal loading, which reports the appropriate path-specific error.
async fn same_configuration_file(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    let (left_metadata, right_metadata) =
        tokio::join!(tokio::fs::metadata(left), tokio::fs::metadata(right));
    matches!(
        (left_metadata, right_metadata),
        (Ok(left), Ok(right)) if left.dev() == right.dev() && left.ino() == right.ino()
    )
}

/// Resolve the final `SandboxProfile` by merging configs into the ecosystem default.
pub fn resolve_profile(
    base: &mut SandboxProfile,
    configs: &[LoadedConfig],
    home: &Path,
    pwd: &Path,
) -> Result<(), CoreError> {
    let profile_name = base.name.clone();

    for loaded in configs {
        let config = &loaded.config;
        // Apply matching profile config
        if let Some(pc) = config.profiles.get(&profile_name) {
            if loaded.origin == ConfigOrigin::Project && !loaded.trusted {
                pc.validate_untrusted_project(&loaded.path)?;
            }
            let grant_origin = match &loaded.origin {
                ConfigOrigin::Global => GrantOrigin::Global(loaded.path.clone()),
                ConfigOrigin::Project => GrantOrigin::Project(loaded.path.clone()),
                ConfigOrigin::Explicit => GrantOrigin::Explicit(loaded.path.clone()),
            };
            apply_profile_recursive(
                &profile_name,
                config,
                base,
                home,
                pwd,
                &grant_origin,
                &mut HashSet::new(),
            )?;
        }
    }
    base.recompute_network_mode();
    Ok(())
}

fn apply_profile_recursive(
    name: &str,
    config: &SbeConfig,
    profile: &mut SandboxProfile,
    home: &Path,
    pwd: &Path,
    origin: &GrantOrigin,
    visiting: &mut HashSet<String>,
) -> Result<(), CoreError> {
    if !visiting.insert(name.to_owned()) {
        return Err(CoreError::ProfileLint(format!(
            "cyclic profile extends involving '{name}'"
        )));
    }
    let pc = config
        .profiles
        .get(name)
        .ok_or_else(|| CoreError::UnknownBaseProfile {
            child: profile.name.clone(),
            base: name.to_owned(),
        })?;
    if let Some(parent) = &pc.extends {
        if !config.profiles.contains_key(parent) {
            return Err(CoreError::UnknownBaseProfile {
                child: name.to_owned(),
                base: parent.clone(),
            });
        }
        apply_profile_recursive(parent, config, profile, home, pwd, origin, visiting)?;
    }
    pc.apply_to(profile, home, pwd, origin)?;
    visiting.remove(name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_expand_home_path() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let sp = expand_path("~/.ssh/", &home, &pwd);
        assert_eq!(sp.path, PathBuf::from("/Users/test/.ssh"));
        assert_eq!(sp.kind, PathKind::Subpath);
    }

    #[test]
    fn test_should_expand_relative_path() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let sp = expand_path("./node_modules/", &home, &pwd);
        assert_eq!(sp.path, PathBuf::from("/Users/test/project/node_modules"));
        assert_eq!(sp.kind, PathKind::Subpath);
    }

    #[test]
    fn test_should_keep_absolute_path_as_file() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let sp = expand_path("/usr/bin/osascript", &home, &pwd);
        assert_eq!(sp.path, PathBuf::from("/usr/bin/osascript"));
        assert_eq!(sp.kind, PathKind::Literal);
    }

    #[test]
    fn test_should_detect_dir_from_trailing_slash() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");

        let dir = expand_path("~/.cargo/bin/", &home, &pwd);
        assert_eq!(dir.kind, PathKind::Subpath);

        let file = expand_path("~/.cargo/credentials.toml", &home, &pwd);
        assert_eq!(file.kind, PathKind::Literal);

        let pwd_dir = expand_path("$PWD/", &home, &pwd);
        assert_eq!(pwd_dir.kind, PathKind::Subpath);
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

        pc.apply_to(
            &mut profile,
            &home,
            &pwd,
            &GrantOrigin::Explicit(PathBuf::from("test.yaml")),
        )
        .unwrap();

        assert_eq!(profile.allow_write.len(), original_write + 1);
        assert_eq!(profile.allow_domains.len(), original_domains + 1);
    }

    #[test]
    fn profile_config_denials_cover_wildcards_and_same_layer_fetches() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let pc = ProfileConfig {
            allow_domains: vec!["*.example.com".to_owned()],
            deny_domains: vec!["bad.example.com".to_owned()],
            allow_fetch: vec!["bad.example.com".to_owned()],
            ..Default::default()
        };
        let mut profile =
            SandboxProfile::for_ecosystem(crate::detect::Ecosystem::Node, &home, &pwd);

        pc.apply_to(
            &mut profile,
            &home,
            &pwd,
            &GrantOrigin::Explicit(PathBuf::from("test.yaml")),
        )
        .unwrap();
        profile.finalize();

        assert!(profile.allow_fetch.is_empty());
        assert!(
            !profile
                .allow_domains
                .iter()
                .any(|domain| domain.matches("bad.example.com"))
        );
    }

    #[test]
    fn test_should_reject_unknown_config_fields() {
        let yaml = "profiles:\n  node:\n    allowNetwrok: true\n";
        assert!(serde_yaml::from_str::<SbeConfig>(yaml).is_err());
    }

    #[tokio::test]
    async fn test_should_refuse_symlinked_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.yaml");
        tokio::fs::write(&target, "profiles: {}\n").await.unwrap();
        let link = directory.path().join(".sbe.yaml");
        std::os::unix::fs::symlink(target, &link).unwrap();
        assert!(SbeConfig::load(&link).await.is_err());
    }

    #[tokio::test]
    async fn test_should_reject_oversized_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.yaml");
        tokio::fs::write(&path, vec![b' '; MAX_CONFIG_BYTES + 1])
            .await
            .unwrap();
        assert!(SbeConfig::load(&path).await.is_err());
    }

    #[tokio::test]
    async fn explicit_project_config_is_loaded_once_as_trusted() {
        let project = tempfile::tempdir().unwrap();
        let path = project.path().join(".sbe.yaml");
        tokio::fs::write(
            &path,
            "profiles:\n  rust:\n    allowWrite:\n      - '$PWD/generated/'\n",
        )
        .await
        .unwrap();

        let configs = load_configs(project.path(), Some(Path::new(".sbe.yaml")), false)
            .await
            .unwrap();
        let selected: Vec<_> = configs
            .iter()
            .filter(|config| config.path == path)
            .collect();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].origin, ConfigOrigin::Explicit);
        assert!(selected[0].trusted);
    }

    #[tokio::test]
    async fn configuration_identity_recognizes_hard_links() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original.yaml");
        let alias = directory.path().join("alias.yaml");
        tokio::fs::write(&original, "profiles: {}\n").await.unwrap();
        tokio::fs::hard_link(&original, &alias).await.unwrap();

        assert!(same_configuration_file(&original, &alias).await);
    }

    #[test]
    fn test_should_reject_reserved_environment_variable() {
        let yaml = r#"
profiles:
  rust:
    env:
      HTTPS_PROXY: http://attacker.invalid
"#;
        let config: SbeConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate(Path::new("config.yaml")).is_err());
    }

    #[test]
    fn test_should_reject_parent_traversal_in_policy_paths() {
        let yaml = r#"
profiles:
  rust:
    denyRead:
      - "$PWD/output/../.ssh/"
"#;
        let config: SbeConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate(Path::new("config.yaml")).is_err());
    }

    #[test]
    fn test_should_reject_untrusted_project_expansion() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/work/project");
        let mut config = SbeConfig::default();
        config.profiles.insert(
            "node".to_owned(),
            ProfileConfig {
                allow_all_network: Some(true),
                allow_write: vec!["$HOME/".to_owned()],
                ..ProfileConfig::default()
            },
        );
        let loaded = LoadedConfig {
            config,
            origin: ConfigOrigin::Project,
            path: pwd.join(".sbe.yaml"),
            trusted: false,
        };
        let mut profile =
            SandboxProfile::for_ecosystem(crate::detect::Ecosystem::Node, &home, &pwd);
        assert!(resolve_profile(&mut profile, &[loaded], &home, &pwd).is_err());
    }

    #[test]
    fn test_should_allow_untrusted_project_restrictions() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/work/project");
        let mut config = SbeConfig::default();
        config.profiles.insert(
            "node".to_owned(),
            ProfileConfig {
                deny_exec: vec!["/usr/bin/git".to_owned()],
                deny_domains: vec!["registry.npmjs.org".to_owned()],
                allow_all_network: Some(false),
                ..ProfileConfig::default()
            },
        );
        let loaded = LoadedConfig {
            config,
            origin: ConfigOrigin::Project,
            path: pwd.join(".sbe.yaml"),
            trusted: false,
        };
        let mut profile =
            SandboxProfile::for_ecosystem(crate::detect::Ecosystem::Node, &home, &pwd);
        resolve_profile(&mut profile, &[loaded], &home, &pwd).unwrap();
        assert!(
            profile
                .deny_exec
                .iter()
                .any(|path| path.path == Path::new("/usr/bin/git"))
        );
        assert!(
            !profile
                .allow_exec
                .iter()
                .any(|path| path.path == Path::new("/usr/bin/git"))
        );
        assert!(
            !profile
                .allow_domains
                .iter()
                .any(|domain| domain.0 == "registry.npmjs.org")
        );
    }

    #[test]
    fn test_should_reject_cyclic_extends() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/work/project");
        let mut config = SbeConfig::default();
        config.profiles.insert(
            "node".to_owned(),
            ProfileConfig {
                extends: Some("base".to_owned()),
                ..ProfileConfig::default()
            },
        );
        config.profiles.insert(
            "base".to_owned(),
            ProfileConfig {
                extends: Some("node".to_owned()),
                ..ProfileConfig::default()
            },
        );
        let loaded = LoadedConfig {
            config,
            origin: ConfigOrigin::Explicit,
            path: pwd.join("policy.yaml"),
            trusted: true,
        };
        let mut profile =
            SandboxProfile::for_ecosystem(crate::detect::Ecosystem::Node, &home, &pwd);
        assert!(resolve_profile(&mut profile, &[loaded], &home, &pwd).is_err());
    }
}
