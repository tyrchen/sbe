use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    config::{SandboxPath, expand_path},
    detect::Ecosystem,
};

/// Embedded default profiles YAML, compiled into the binary.
///
/// Selection is `cfg(target_os = ...)` so each binary ships exactly the
/// defaults that match its sandbox backend. Both files deserialize through
/// the same [`DefaultsFile`] schema (verified in tests).
#[cfg(target_os = "macos")]
const DEFAULTS_YAML: &str = include_str!("defaults-macos.yaml");

#[cfg(target_os = "linux")]
const DEFAULTS_YAML: &str = include_str!("defaults-linux.yaml");

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const DEFAULTS_YAML: &str = include_str!("defaults-macos.yaml");

/// A pattern for matching domain names.
///
/// Supports exact match (`"registry.npmjs.org"`) and wildcard prefix
/// (`"*.npmjs.org"` matches any subdomain).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainPattern(pub String);

impl DomainPattern {
    /// Parse and canonicalize an exact or `*.` wildcard DNS pattern.
    pub fn new(raw: &str) -> Result<Self, String> {
        let raw = raw.trim().trim_end_matches('.');
        let (wildcard, name) = match raw.strip_prefix("*.") {
            Some(name) => (true, name),
            None => (false, raw),
        };
        if name.is_empty() || name.len() > 253 || name.contains(['/', ':', '\0']) {
            return Err(format!("invalid domain pattern '{raw}'"));
        }

        let ascii = idna::domain_to_ascii(name)
            .map_err(|_| format!("invalid IDNA domain pattern '{raw}'"))?
            .to_ascii_lowercase();
        if IpAddr::from_str(&ascii).is_ok() {
            return Err(format!("IP literals are not domain patterns: '{raw}'"));
        }
        for label in ascii.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(format!("invalid DNS label in domain pattern '{raw}'"));
            }
        }

        Ok(Self(if wildcard {
            format!("*.{ascii}")
        } else {
            ascii
        }))
    }

    /// Check whether a given hostname matches this pattern.
    pub fn matches(&self, host: &str) -> bool {
        let pattern = &self.0;
        if let Some(suffix) = pattern.strip_prefix("*.") {
            host == suffix || host.ends_with(&format!(".{suffix}"))
        } else {
            host == pattern
        }
    }

    /// Return whether two allow/deny patterns authorize at least one common
    /// hostname. Since the proxy has no separate denylist, an overlapping
    /// allow pattern must be removed in full for a denial to remain effective.
    pub fn overlaps(&self, other: &Self) -> bool {
        let self_root = self.0.strip_prefix("*.").unwrap_or(&self.0);
        let other_root = other.0.strip_prefix("*.").unwrap_or(&other.0);
        self.matches(other_root) || other.matches(self_root)
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for DomainPattern {
    fn from(s: &str) -> Self {
        Self::new(s).expect("invalid built-in domain pattern")
    }
}

impl Serialize for DomainPattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DomainPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(&raw).map_err(de::Error::custom)
    }
}

/// Final, validated network behavior after all configuration is merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkMode {
    /// No outbound or inbound network access.
    DenyAll,
    /// HTTPS is mediated by SBE's domain-filtering CONNECT proxy.
    Proxy,
    /// Compatibility mode: direct outbound TCP is limited to port 443 only.
    DirectHttps443,
    /// Network sandboxing is disabled by an explicit trusted choice.
    AllowAll,
}

/// Provenance retained for every permission-bearing profile entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GrantOrigin {
    BuiltIn,
    Global(PathBuf),
    Project(PathBuf),
    Explicit(PathBuf),
    Cli,
    ParentEnvironment,
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GrantKind {
    AllowWrite,
    DenyRead,
    AllowRead,
    AllowDomain,
    DenyExec,
    AllowExec,
    AllowFetch,
    Environment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRecord {
    pub kind: GrantKind,
    pub value: String,
    pub origin: GrantOrigin,
}

impl NetworkMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DenyAll => "denyAll",
            Self::Proxy => "proxy",
            Self::DirectHttps443 => "directHttps443Compatibility",
            Self::AllowAll => "allowAll",
        }
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
    ///
    /// On macOS this is a subtractive `(deny file-read* …)` rule. On Linux
    /// Landlock cannot subtract from an allowed subtree, so the backend
    /// instead treats this list as a *sealed forbidden-list*: paths here are
    /// guaranteed never to be silently added to [`Self::allow_read`], and
    /// any user config that would overlap is rejected.
    #[serde(default)]
    pub deny_read: Vec<SandboxPath>,

    /// Read-allowlist extensions on Linux (no-op on macOS).
    ///
    /// macOS uses an "allow all reads then subtract" model, so this field
    /// goes unused there. On Linux the backend merges these into the
    /// curated read-anchors and runs the [`Self::deny_read`] forbidden-list
    /// lint against the merged set.
    #[serde(default)]
    pub allow_read: Vec<SandboxPath>,

    /// Domains allowed for outbound HTTPS.
    #[serde(default)]
    pub allow_domains: Vec<DomainPattern>,

    /// Binary paths denied for execution.
    #[serde(default)]
    pub deny_exec: Vec<SandboxPath>,

    /// Binary paths explicitly allowed for execution.
    #[serde(default)]
    pub allow_exec: Vec<SandboxPath>,

    /// Requested proxy setting retained while configuration is merged.
    #[serde(skip)]
    pub enable_proxy: bool,

    /// Requested allow-all setting retained while configuration is merged.
    #[serde(skip)]
    pub allow_all_network: bool,

    /// Validated effective network policy. Backends must switch exhaustively
    /// on this field and must not infer a fallback from the legacy booleans.
    pub network_mode: NetworkMode,

    /// Highest-precedence source that selected or materially narrowed the
    /// effective network policy.
    pub network_origin: GrantOrigin,

    /// Domains that build scripts are allowed to fetch from.
    ///
    /// When non-empty, `curl` and `wget` are added to `allow_exec` and these
    /// domains are merged into the proxy allowlist.
    #[serde(default)]
    pub allow_fetch: Vec<DomainPattern>,

    /// Additional environment variables to inject.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Legacy compatibility bit. It maps only to the explicit insecure Linux
    /// network mode and never bypasses filesystem or policy lints.
    #[serde(default)]
    pub allow_degraded: bool,

    /// Per-field boundary marker: indices `< first_user_*` were populated
    /// from the curated per-OS defaults; indices `>=` came from user
    /// `.sbe.yaml` or CLI overrides. The Linux backend's `denyRead`
    /// forbidden-list seal lint only inspects user additions so that
    /// intentional default overlaps (e.g. `$PWD/` covers `$PWD/.env`)
    /// don't trip on every project.
    #[serde(skip)]
    pub first_user_allow_write: usize,
    #[serde(skip)]
    pub first_user_allow_exec: usize,
    #[serde(skip)]
    pub first_user_allow_read: usize,

    /// Per-run roots that may be both writable and executable because they
    /// are mode-0700 and deleted when the invocation completes.
    #[serde(skip)]
    pub ephemeral_write_exec: Vec<PathBuf>,

    /// Audit trail used by `inspect` and policy lints.
    pub grant_origins: Vec<GrantRecord>,
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
        #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
        let mut allow_exec: Vec<SandboxPath> = common
            .allow_exec
            .iter()
            .chain(eco_cfg.allow_exec.iter())
            .map(|p| expand_path(p, home, pwd))
            .collect();

        // Build deny_exec: from common (also resolve symlinks for deny rules
        // on macOS, whose kernel evaluates the resolved executable path).
        #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
        let mut deny_exec: Vec<SandboxPath> = common
            .deny_exec
            .iter()
            .map(|p| expand_path(p, home, pwd))
            .collect();
        #[cfg(target_os = "macos")]
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
            .map(|d| DomainPattern::new(d).expect("invalid built-in domain pattern"))
            .collect();

        // Node-specific: monorepos hoist node_modules and lock files to the
        // workspace root. Only allow writes to specific paths npm needs —
        // NOT the entire git root, which would let a malicious postinstall
        // script modify source files in sibling packages or CI configs.
        if ecosystem == Ecosystem::Node
            && let Some(git_root) = find_git_root(pwd)
            && git_root != pwd
        {
            allow_write.push(SandboxPath::dir(git_root.join("node_modules")));
            allow_write.push(SandboxPath::file(git_root.join("package-lock.json")));
            allow_write.push(SandboxPath::file(git_root.join("yarn.lock")));
            allow_write.push(SandboxPath::file(git_root.join("pnpm-lock.yaml")));
            allow_write.push(SandboxPath::dir(git_root.join(".yarn")));
            allow_write.push(SandboxPath::file(git_root.join(".pnp.cjs")));
            allow_write.push(SandboxPath::file(git_root.join(".pnp.loader.mjs")));
        }

        // Build output locations are selected by SBE-owned environment
        // variables and limited to dedicated profile outputs or the private
        // per-invocation tree. Project-controlled Cargo config and ambient
        // JAVA_HOME therefore cannot create implicit grants here.

        // Resolve symlinks: SBPL on macOS checks the real path after kernel
        // symlink resolution, so /opt/homebrew/bin/zig (a symlink to
        // /opt/homebrew/Cellar/.../zig) won't match unless we also allow the
        // resolved Cellar path. Landlock on Linux dereferences via the
        // preopened FD; symlink resolution there is a non-issue.
        #[cfg(target_os = "macos")]
        resolve_symlinks(&mut allow_exec);

        // Linux read-allowlist additions from defaults (macOS ignores).
        let allow_read: Vec<SandboxPath> = common
            .allow_read
            .iter()
            .chain(eco_cfg.allow_read.iter())
            .map(|p| expand_path(p, home, pwd))
            .collect();

        // After this point everything appended to allow_* is treated as
        // user-supplied. Snapshot the lengths now so the seal lint can
        // identify user additions later.
        let first_user_allow_write = allow_write.len();
        let first_user_allow_exec = allow_exec.len();
        let first_user_allow_read = allow_read.len();

        let enable_proxy = eco_cfg.enable_proxy.unwrap_or(true);
        let network_mode = if enable_proxy {
            if allow_domains.is_empty() {
                NetworkMode::DenyAll
            } else {
                NetworkMode::Proxy
            }
        } else {
            NetworkMode::DirectHttps443
        };

        let mut grant_origins = Vec::new();
        record_paths(
            &mut grant_origins,
            GrantKind::AllowWrite,
            &allow_write,
            GrantOrigin::BuiltIn,
        );
        record_paths(
            &mut grant_origins,
            GrantKind::DenyRead,
            &deny_read,
            GrantOrigin::BuiltIn,
        );
        record_paths(
            &mut grant_origins,
            GrantKind::AllowRead,
            &allow_read,
            GrantOrigin::BuiltIn,
        );
        record_paths(
            &mut grant_origins,
            GrantKind::DenyExec,
            &deny_exec,
            GrantOrigin::BuiltIn,
        );
        record_paths(
            &mut grant_origins,
            GrantKind::AllowExec,
            &allow_exec,
            GrantOrigin::BuiltIn,
        );
        for domain in &allow_domains {
            grant_origins.push(GrantRecord {
                kind: GrantKind::AllowDomain,
                value: domain.0.clone(),
                origin: GrantOrigin::BuiltIn,
            });
        }

        SandboxProfile {
            name: profile_name,
            allow_write,
            deny_read,
            allow_read,
            allow_domains,
            deny_exec,
            allow_exec,
            enable_proxy,
            allow_all_network: false,
            network_mode,
            network_origin: GrantOrigin::BuiltIn,
            allow_fetch: vec![],
            env: Default::default(),
            allow_degraded: false,
            first_user_allow_write,
            first_user_allow_exec,
            first_user_allow_read,
            ephemeral_write_exec: Vec::new(),
            grant_origins,
        }
    }

    /// Merge CLI overrides into this profile.
    pub fn merge_overrides(&mut self, overrides: &ProfileOverrides) {
        if !overrides.allow_domains.is_empty()
            || !overrides.deny_domains.is_empty()
            || !overrides.allow_fetch.is_empty()
            || overrides.allow_all_network
            || overrides.no_proxy
        {
            self.network_origin = GrantOrigin::Cli;
        }
        record_paths(
            &mut self.grant_origins,
            GrantKind::AllowWrite,
            &overrides.allow_write,
            GrantOrigin::Cli,
        );
        record_paths(
            &mut self.grant_origins,
            GrantKind::DenyRead,
            &overrides.deny_read,
            GrantOrigin::Cli,
        );
        record_paths(
            &mut self.grant_origins,
            GrantKind::AllowRead,
            &overrides.allow_read,
            GrantOrigin::Cli,
        );
        for domain in &overrides.allow_domains {
            self.grant_origins.push(GrantRecord {
                kind: GrantKind::AllowDomain,
                value: domain.0.clone(),
                origin: GrantOrigin::Cli,
            });
        }
        for domain in &overrides.allow_fetch {
            self.grant_origins.push(GrantRecord {
                kind: GrantKind::AllowFetch,
                value: domain.0.clone(),
                origin: GrantOrigin::Cli,
            });
        }
        self.allow_write
            .extend(overrides.allow_write.iter().cloned());
        self.deny_read.extend(overrides.deny_read.iter().cloned());
        self.allow_read.extend(overrides.allow_read.iter().cloned());
        self.allow_domains
            .extend(overrides.allow_domains.iter().cloned());
        for path in &overrides.deny_exec {
            self.add_deny_exec(path.clone(), GrantOrigin::Cli);
        }
        for path in &overrides.allow_exec {
            self.add_allow_exec(path.clone(), GrantOrigin::Cli);
        }

        self.allow_fetch
            .extend(overrides.allow_fetch.iter().cloned());
        self.remove_denied_domains(&overrides.deny_domains);

        if overrides.allow_all_network {
            self.allow_all_network = true;
        }
        if overrides.no_proxy {
            self.enable_proxy = false;
        }
        if overrides.allow_degraded {
            self.allow_degraded = true;
        }

        for (k, v) in &overrides.env {
            self.env.insert(k.clone(), v.clone());
            self.grant_origins.push(GrantRecord {
                kind: GrantKind::Environment,
                value: k.clone(),
                origin: GrantOrigin::Cli,
            });
        }
    }

    /// Apply a higher-precedence domain denial to every network grant that
    /// has been accumulated so far. Pattern intersection matters: retaining
    /// `*.example.com` would otherwise defeat a denial for `bad.example.com`.
    pub(crate) fn remove_denied_domains(&mut self, denied: &[DomainPattern]) {
        if denied.is_empty() {
            return;
        }
        self.allow_domains
            .retain(|allowed| !denied.iter().any(|pattern| pattern.overlaps(allowed)));
        self.allow_fetch
            .retain(|allowed| !denied.iter().any(|pattern| pattern.overlaps(allowed)));
        self.grant_origins.retain(|record| {
            if !matches!(record.kind, GrantKind::AllowDomain | GrantKind::AllowFetch) {
                return true;
            }
            DomainPattern::new(&record.value)
                .is_ok_and(|allowed| !denied.iter().any(|pattern| pattern.overlaps(&allowed)))
        });
    }

    /// Finalize the profile: apply allow_fetch effects to allow_exec and allow_domains.
    ///
    /// Must be called after all merging is complete, before SBPL generation.
    pub fn finalize(&mut self) {
        if !self.allow_fetch.is_empty() {
            let curl = SandboxPath::file(PathBuf::from("/usr/bin/curl"));
            let wget = SandboxPath::file(PathBuf::from("/usr/bin/wget"));
            let fetch_origin = self
                .grant_origins
                .iter()
                .rev()
                .find(|record| record.kind == GrantKind::AllowFetch)
                .map(|record| record.origin.clone())
                .unwrap_or(GrantOrigin::Runtime);
            if !self.allow_exec.iter().any(|p| p.path == curl.path) {
                self.grant_origins.push(GrantRecord {
                    kind: GrantKind::AllowExec,
                    value: curl.path.to_string_lossy().into_owned(),
                    origin: fetch_origin.clone(),
                });
                self.allow_exec.push(curl);
            }
            if !self.allow_exec.iter().any(|p| p.path == wget.path) {
                self.grant_origins.push(GrantRecord {
                    kind: GrantKind::AllowExec,
                    value: wget.path.to_string_lossy().into_owned(),
                    origin: fetch_origin,
                });
                self.allow_exec.push(wget);
            }

            for domain in &self.allow_fetch {
                if !self.allow_domains.iter().any(|d| d.0 == domain.0) {
                    self.allow_domains.push(domain.clone());
                    let origin = self
                        .grant_origins
                        .iter()
                        .rev()
                        .find(|record| {
                            record.kind == GrantKind::AllowFetch && record.value == domain.0
                        })
                        .map(|record| record.origin.clone())
                        .unwrap_or(GrantOrigin::Runtime);
                    self.grant_origins.push(GrantRecord {
                        kind: GrantKind::AllowDomain,
                        value: domain.0.clone(),
                        origin,
                    });
                }
            }
        }

        self.recompute_network_mode();
    }

    /// Recompute the effective mode without carrying stateful side effects
    /// across configuration precedence boundaries.
    pub fn recompute_network_mode(&mut self) {
        self.network_mode = if self.allow_all_network {
            NetworkMode::AllowAll
        } else if self.enable_proxy {
            if self.allow_domains.is_empty() {
                NetworkMode::DenyAll
            } else {
                NetworkMode::Proxy
            }
        } else {
            NetworkMode::DirectHttps443
        };
    }

    /// Reject persistent write/execute overlap. Mutable executable content is
    /// a persistence boundary, not merely a filesystem convenience.
    pub fn validate_security_invariants(&self) -> Result<(), crate::error::CoreError> {
        for write in &self.allow_write {
            for execute in &self.allow_exec {
                if paths_overlap(&write.path, &execute.path)
                    && !self
                        .ephemeral_write_exec
                        .iter()
                        .any(|root| write.path.starts_with(root) && execute.path.starts_with(root))
                {
                    return Err(crate::error::CoreError::ProfileLint(format!(
                        "persistent path is both writable ('{}') and executable ('{}'); use a \
                         private per-run output or split the grants",
                        write.path.display(),
                        execute.path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    /// Apply an execute denial at the current precedence level. Landlock has
    /// no subtractive rule, so an overlapping allow entry is removed in full;
    /// this can be stricter than the requested path but never weaker.
    pub(crate) fn add_deny_exec(&mut self, path: SandboxPath, origin: GrantOrigin) {
        let old_boundary = self.first_user_allow_exec;
        let mut built_in_remaining = 0_usize;
        let mut removed = Vec::new();
        self.allow_exec = self
            .allow_exec
            .drain(..)
            .enumerate()
            .filter_map(|(index, allowed)| {
                if paths_overlap(&allowed.path, &path.path) {
                    removed.push(allowed.path.to_string_lossy().into_owned());
                    None
                } else {
                    if index < old_boundary {
                        built_in_remaining += 1;
                    }
                    Some(allowed)
                }
            })
            .collect();
        self.first_user_allow_exec = built_in_remaining;
        self.grant_origins.retain(|record| {
            record.kind != GrantKind::AllowExec || !removed.contains(&record.value)
        });
        self.grant_origins.push(GrantRecord {
            kind: GrantKind::DenyExec,
            value: path.path.to_string_lossy().into_owned(),
            origin,
        });
        self.deny_exec.push(path);
    }

    /// Apply an execute grant at the current precedence level, removing an
    /// earlier overlapping denial so trusted later sources can re-authorize.
    pub(crate) fn add_allow_exec(&mut self, path: SandboxPath, origin: GrantOrigin) {
        let mut removed = Vec::new();
        self.deny_exec.retain(|denied| {
            let overlaps = paths_overlap(&denied.path, &path.path);
            if overlaps {
                removed.push(denied.path.to_string_lossy().into_owned());
            }
            !overlaps
        });
        self.grant_origins.retain(|record| {
            record.kind != GrantKind::DenyExec || !removed.contains(&record.value)
        });
        self.grant_origins.push(GrantRecord {
            kind: GrantKind::AllowExec,
            value: path.path.to_string_lossy().into_owned(),
            origin,
        });
        self.allow_exec.push(path);
    }
}

fn record_paths(
    records: &mut Vec<GrantRecord>,
    kind: GrantKind,
    paths: &[SandboxPath],
    origin: GrantOrigin,
) {
    records.extend(paths.iter().map(|path| GrantRecord {
        kind,
        value: path.path.to_string_lossy().into_owned(),
        origin: origin.clone(),
    }));
}

#[allow(clippy::disallowed_methods)] // Synchronous invariant used by both backends before spawn.
fn paths_overlap(left: &Path, right: &Path) -> bool {
    if left == right || left.starts_with(right) || right.starts_with(left) {
        return true;
    }
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => {
            left == right || left.starts_with(&right) || right.starts_with(&left)
        }
        _ => false,
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
#[cfg(target_os = "macos")]
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
            // Preserve the original kind for non-Cellar symlinks
            Some(SandboxPath {
                path: resolved,
                kind: sp.kind,
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
    pub allow_read: Vec<SandboxPath>,
    pub allow_domains: Vec<DomainPattern>,
    pub deny_domains: Vec<DomainPattern>,
    pub allow_exec: Vec<SandboxPath>,
    pub deny_exec: Vec<SandboxPath>,
    pub allow_fetch: Vec<DomainPattern>,
    pub allow_all_network: bool,
    pub no_proxy: bool,
    pub allow_degraded: bool,
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
    allow_read: Vec<String>,
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
    allow_read: Vec<String>,
    #[serde(default)]
    allow_domains: Vec<String>,
    #[serde(default)]
    allow_exec: Vec<String>,
    /// Whether to start the domain-filtering proxy. Some ecosystems whose
    /// HTTP stack does not respect `HTTP_PROXY` env (notably JVM tools like
    /// Maven and Gradle) cannot benefit from the proxy and need the kernel
    /// to open port 443 directly. Set this to `false` in those profiles —
    /// kernel TCP filter still enforces "egress on port 443 only", but
    /// domain filtering is delegated to the proxy when set to true.
    /// Defaults to `true`.
    #[serde(default)]
    enable_proxy: Option<bool>,
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
    fn test_should_canonicalize_and_validate_domains() {
        assert_eq!(
            DomainPattern::new("BÜCHER.Example.").unwrap().0,
            "xn--bcher-kva.example"
        );
        assert!(DomainPattern::new("127.0.0.1").is_err());
        assert!(DomainPattern::new("bad..example").is_err());
        assert!(DomainPattern::new("evil.com:443").is_err());
    }

    #[test]
    fn test_should_reject_persistent_write_execute_overlap() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/work/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        profile
            .allow_write
            .push(SandboxPath::dir(home.join("mutable-tool")));
        profile
            .allow_exec
            .push(SandboxPath::dir(home.join("mutable-tool/bin")));
        assert!(profile.validate_security_invariants().is_err());
    }

    #[test]
    fn test_should_allow_ephemeral_write_execute_overlap() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/work/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        let root = PathBuf::from("/tmp/sbe-test-private");
        profile.allow_write.push(SandboxPath::dir(root.clone()));
        profile.allow_exec.push(SandboxPath::dir(root.clone()));
        profile.ephemeral_write_exec.push(root);
        assert!(profile.validate_security_invariants().is_ok());
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
            assert!(!profile.allow_exec.is_empty(), "no allow_exec for {eco}");
            // Linux defaults need no subtractive entries because execution is
            // allowlist-only; macOS keeps explicit defense-in-depth denials.
            #[cfg(target_os = "macos")]
            assert!(!profile.deny_exec.is_empty(), "no deny_exec for {eco}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn python_profile_allows_github_setup_python_toolchains() {
        let profile = SandboxProfile::for_ecosystem(
            Ecosystem::Python,
            &PathBuf::from("/home/test"),
            &PathBuf::from("/work/project"),
        );

        assert!(has(&profile.allow_exec, "/opt/hostedtoolcache/Python"));
    }

    #[test]
    fn default_profiles_satisfy_persistent_write_xor_execute() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");

        for ecosystem in Ecosystem::ALL {
            let profile = SandboxProfile::for_ecosystem(ecosystem, &home, &pwd);
            profile
                .validate_security_invariants()
                .unwrap_or_else(|error| panic!("invalid default {ecosystem} profile: {error}"));
        }
    }

    #[tokio::test]
    async fn project_cargo_target_dir_never_creates_a_write_grant() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let cargo = project.path().join(".cargo");
        let sensitive = home.path().join("sensitive");
        tokio::fs::create_dir(&cargo).await.unwrap();
        tokio::fs::write(
            cargo.join("config.toml"),
            format!("[build]\ntarget-dir = {:?}\n", sensitive),
        )
        .await
        .unwrap();

        let profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        assert!(
            profile
                .allow_write
                .iter()
                .all(|grant| !paths_overlap(&grant.path, &sensitive)),
            "project-controlled Cargo target-dir created write authority"
        );
    }

    #[test]
    fn network_mode_precedence_recomputes_without_stale_fallbacks() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &pwd);

        assert_eq!(profile.network_mode, NetworkMode::Proxy);
        profile.allow_all_network = true;
        profile.network_origin = GrantOrigin::Global(PathBuf::from("global.yaml"));
        profile.recompute_network_mode();
        assert_eq!(profile.network_mode, NetworkMode::AllowAll);

        profile.allow_all_network = false;
        profile.enable_proxy = false;
        profile.recompute_network_mode();
        assert_eq!(profile.network_mode, NetworkMode::DirectHttps443);

        profile.enable_proxy = true;
        profile.allow_domains.clear();
        profile.recompute_network_mode();
        assert_eq!(profile.network_mode, NetworkMode::DenyAll);

        profile
            .allow_domains
            .push(DomainPattern::from("example.com"));
        profile.network_origin = GrantOrigin::Cli;
        profile.recompute_network_mode();
        assert_eq!(profile.network_mode, NetworkMode::Proxy);
        assert_eq!(profile.network_origin, GrantOrigin::Cli);
    }

    #[test]
    fn later_execute_sources_revoke_and_can_explicitly_reauthorize() {
        let home = PathBuf::from("/home/test");
        let pwd = PathBuf::from("/work/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        let git = SandboxPath::file(PathBuf::from("/usr/bin/git"));
        assert!(profile.allow_exec.iter().any(|path| path.path == git.path));

        profile.add_deny_exec(git.clone(), GrantOrigin::Project(pwd.join(".sbe.yaml")));
        assert!(!profile.allow_exec.iter().any(|path| path.path == git.path));
        assert!(profile.deny_exec.iter().any(|path| path.path == git.path));

        profile.add_allow_exec(git.clone(), GrantOrigin::Cli);
        assert!(profile.allow_exec.iter().any(|path| path.path == git.path));
        assert!(!profile.deny_exec.iter().any(|path| path.path == git.path));
        assert!(profile.grant_origins.iter().any(|record| {
            record.kind == GrantKind::AllowExec
                && record.value == "/usr/bin/git"
                && record.origin == GrantOrigin::Cli
        }));
    }

    /// Both YAML defaults files must deserialize through [`DefaultsFile`]
    /// (regression guard for the macOS/Linux schema split).
    #[test]
    fn test_should_parse_both_defaults_files() {
        let macos: DefaultsFile =
            serde_yaml::from_str(include_str!("defaults-macos.yaml")).expect("macOS defaults");
        let linux: DefaultsFile =
            serde_yaml::from_str(include_str!("defaults-linux.yaml")).expect("Linux defaults");
        for name in ["node", "rust", "python", "elixir", "java"] {
            assert!(macos.profiles.contains_key(name), "macos missing {name}");
            assert!(linux.profiles.contains_key(name), "linux missing {name}");
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
        assert!(has(
            &profile.allow_write,
            "/Users/test/project/node_modules"
        ));
        assert!(!has(&profile.allow_write, "/Users/test/project"));
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
            // osascript deny only exists in the macOS defaults.
            #[cfg(target_os = "macos")]
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
    fn domain_denials_remove_fetch_grants_before_finalize() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        let overrides = ProfileOverrides {
            allow_fetch: vec![DomainPattern::from("downloads.example.com")],
            deny_domains: vec![DomainPattern::from("downloads.example.com")],
            ..Default::default()
        };

        profile.merge_overrides(&overrides);
        profile.finalize();

        assert!(profile.allow_fetch.is_empty());
        assert!(
            !profile
                .allow_domains
                .iter()
                .any(|domain| domain.matches("downloads.example.com"))
        );
    }

    #[test]
    fn domain_denials_remove_intersecting_exact_and_wildcard_grants() {
        let home = PathBuf::from("/Users/test");
        let pwd = PathBuf::from("/Users/test/project");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, &home, &pwd);
        profile.allow_domains = vec![
            DomainPattern::from("*.example.com"),
            DomainPattern::from("api.other.test"),
        ];

        profile.remove_denied_domains(&[DomainPattern::from("bad.example.com")]);
        assert_eq!(
            profile.allow_domains,
            vec![DomainPattern::from("api.other.test")]
        );

        profile.allow_domains = vec![DomainPattern::from("api.example.com")];
        profile.remove_denied_domains(&[DomainPattern::from("*.example.com")]);
        assert!(profile.allow_domains.is_empty());
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

    #[cfg(unix)]
    #[tokio::test]
    async fn test_should_reject_write_execute_overlap_through_symlink_alias() {
        let directory = tempfile::tempdir().unwrap();
        let mutable = directory.path().join("mutable");
        tokio::fs::create_dir(&mutable).await.unwrap();
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&mutable, &alias).unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, directory.path(), directory.path());
        profile.allow_write = vec![SandboxPath::dir(mutable)];
        profile.allow_exec = vec![SandboxPath::dir(alias)];
        assert!(profile.validate_security_invariants().is_err());
    }
}
