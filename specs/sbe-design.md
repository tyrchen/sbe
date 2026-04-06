# sbe — Architecture and Technical Design

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        sbe CLI                              │
│                                                             │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────────┐  │
│  │ Profile  │  │  SBPL     │  │  Proxy   │  │  Audit    │  │
│  │ Resolver │  │ Generator │  │  Server  │  │  Logger   │  │
│  └────┬─────┘  └─────┬─────┘  └────┬─────┘  └─────┬─────┘  │
│       │              │             │               │        │
│       v              v             v               v        │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                 Sandbox Executor                     │    │
│  │  1. Resolve profile + config + CLI flags             │    │
│  │  2. Start proxy (if network allowed)                 │    │
│  │  3. Generate SBPL tempfile                           │    │
│  │  4. Spawn: sandbox-exec -f <sbpl> <command>          │    │
│  │  5. Stream audit events (optional)                   │    │
│  │  6. Wait for exit, cleanup, return exit code         │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘

Inside the sandbox:
┌─────────────────────────────────────────────────────────────┐
│  sandbox-exec (kernel Seatbelt enforcement)                 │
│                                                             │
│  ┌─────────────────────┐     ┌──────────────────────┐       │
│  │  npm install         │────>│  HTTP_PROXY=127.0.0.1│       │
│  │  (or cargo/pip/etc.) │     │  :${PROXY_PORT}      │       │
│  └──────────┬──────────┘     └──────────┬───────────┘       │
│             │                           │                   │
│  SBPL enforces:                         │                   │
│  - file-write* denied except allowlist  │                   │
│  - file-read* denied for secrets        │                   │
│  - network-outbound only to proxy       │                   │
│  - process-exec denied for risky bins   │                   │
└─────────────────────────────┬───────────────────────────────┘
                              │ (only localhost:PROXY_PORT)
                              v
┌─────────────────────────────────────────────────────────────┐
│  sbe Proxy (runs OUTSIDE sandbox)                           │
│                                                             │
│  - HTTP CONNECT proxy for HTTPS                             │
│  - Domain allowlist enforcement                             │
│  - Logs blocked/allowed connections                         │
│  - Terminates when sandboxed process exits                  │
└─────────────────────────────────────────────────────────────┘
```

## Crate Architecture

```
sbe/
├── crates/
│   ├── core/              # sbe-core: profile system, config, SBPL generation
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── profile/
│   │   │   │   ├── mod.rs          # Profile trait + resolution logic
│   │   │   │   ├── node.rs         # Node.js ecosystem defaults
│   │   │   │   ├── rust.rs         # Rust ecosystem defaults
│   │   │   │   ├── python.rs       # Python ecosystem defaults
│   │   │   │   ├── elixir.rs       # Elixir ecosystem defaults
│   │   │   │   ├── java.rs         # Java ecosystem defaults
│   │   │   │   └── custom.rs       # User-defined profile from config
│   │   │   ├── config.rs           # YAML config loading + merging
│   │   │   ├── sbpl.rs             # SBPL profile generator
│   │   │   ├── detect.rs           # Ecosystem auto-detection
│   │   │   └── error.rs            # Error types
│   │   └── Cargo.toml
│   │
│   └── proxy/             # sbe-proxy: domain-filtering HTTP CONNECT proxy
│       ├── src/
│       │   ├── lib.rs
│       │   ├── server.rs           # Async TCP listener + CONNECT handler
│       │   ├── allowlist.rs        # Domain matching logic
│       │   └── error.rs
│       └── Cargo.toml
│
├── apps/
│   └── cli/               # sbe CLI binary
│       ├── src/
│       │   ├── main.rs
│       │   ├── cli.rs              # clap argument definitions
│       │   ├── executor.rs         # Orchestrates sandbox lifecycle
│       │   └── audit.rs            # sandboxd log streaming
│       └── Cargo.toml
```

## Component Design

### 1. Profile System (`sbe-core::profile`)

A **Profile** is the resolved set of sandbox permissions for a single execution:

```rust
#[derive(Debug, Clone)]
pub struct SandboxProfile {
    /// Human-readable name (e.g., "node", "rust", "custom:my-app")
    pub name: String,

    /// Paths allowed for writing (expanded, absolute)
    pub allow_write: Vec<PathBuf>,

    /// Paths denied for reading (expanded, absolute)
    pub deny_read: Vec<PathBuf>,

    /// Domains allowed for outbound HTTPS
    pub allow_domains: Vec<DomainPattern>,

    /// Binary paths denied for execution
    pub deny_exec: Vec<PathBuf>,

    /// Binary paths explicitly allowed for execution
    pub allow_exec: Vec<PathBuf>,

    /// Whether to enable the domain-filtering proxy
    pub enable_proxy: bool,

    /// Whether to allow all network (disables proxy, allows all outbound)
    pub allow_all_network: bool,

    /// Additional environment variables to inject
    pub env: HashMap<String, String>,
}
```

**DomainPattern** supports exact match and wildcard prefix:
- `"registry.npmjs.org"` — exact match
- `"*.npmjs.org"` — matches any subdomain of npmjs.org

Each ecosystem module provides a `fn default_profile(home: &Path, pwd: &Path) -> SandboxProfile` that returns sensible defaults. The profile resolver merges: builtin -> global config -> project config -> CLI flags.

### 2. Ecosystem Auto-Detection (`sbe-core::detect`)

```rust
pub enum Ecosystem {
    Node,
    Rust,
    Python,
    Elixir,
    Java,
}

/// Detect ecosystem from command name and working directory.
/// Returns None if unrecognized (user must specify --profile).
pub fn detect(command: &str, pwd: &Path) -> Option<Ecosystem>;
```

Detection logic:
1. Parse the first argument of the command (basename of executable)
2. Match against known command names per ecosystem
3. If no match, scan `pwd` for marker files (`package.json`, `Cargo.toml`, etc.)
4. If multiple markers found, prefer the command-based detection

### 3. SBPL Generator (`sbe-core::sbpl`)

Converts a `SandboxProfile` into a valid SBPL string. Key design decisions:

**Template structure:**
```scheme
(version 1)

;; Base: deny everything
(deny default)

;; Process control
(allow process-fork)
(allow process-exec ...) ;; from allow_exec + toolchain paths
(deny process-exec ...)  ;; from deny_exec

;; File reads: allow most, deny secrets
(allow file-read*)
(deny file-read* ...) ;; from deny_read (secrets)

;; File writes: deny all, then allow specific paths
(deny file-write*)
(allow file-write* ...) ;; from allow_write

;; Network: only localhost proxy
(deny network-outbound)
(allow network-outbound
    (remote ip "localhost:*")
    (literal "/private/var/run/mDNSResponder")
)

;; Misc required permissions
(allow sysctl-read)
(allow mach-lookup)
(allow ipc-posix-shm-read*)
(allow signal (target self))
```

**Path expansion rules:**
- `~` is expanded to the actual home directory
- Relative paths are resolved against `$PWD`
- All paths are canonicalized to handle symlinks
- SBPL uses `(subpath ...)` for directories, `(literal ...)` for files

**Network mode selection:**
- If `allow_all_network: true` → `(allow network*)` — no proxy, no restrictions
- If `allow_domains` is non-empty → proxy mode (only localhost allowed in SBPL)
- If `allow_domains` is empty and not `allow_all_network` → full network deny

### 4. Domain-Filtering Proxy (`sbe-proxy`)

A minimal async HTTP CONNECT proxy:

```
Client (inside sandbox) ──CONNECT registry.npmjs.org:443──> sbe-proxy
  sbe-proxy checks domain against allowlist:
    ✓ allowed → establish TCP tunnel, return 200
    ✗ denied  → return 403, log violation
```

**Implementation details:**
- Built on `tokio` + raw TCP (no heavy HTTP framework needed)
- Binds to `127.0.0.1:0` (OS-assigned ephemeral port)
- Port communicated to sandbox executor, injected as env var
- Handles HTTP CONNECT method for HTTPS tunneling
- For plain HTTP requests: inspect Host header, allow/deny, then proxy
- Graceful shutdown: proxy watches for sandboxed process exit, then terminates
- All proxy decisions logged to audit system

**Why not just SBPL network rules?**
- SBPL only supports IP:port filtering, not domain names
- CDN-backed registries (npm, PyPI) use dynamic IP pools
- Hardcoding IPs would break constantly and require maintenance
- The proxy approach is the standard solution (used by Anthropic's sandbox-runtime, fence, etc.)

### 5. Sandbox Executor (`apps/cli::executor`)

Orchestration sequence:

```
1. Parse CLI args
2. Detect ecosystem (or use --profile)
3. Load and merge config (builtin + global + project + CLI)
4. Resolve final SandboxProfile
5. If proxy needed:
   a. Spawn proxy server in background tokio task
   b. Wait for proxy to bind and report its port
6. Generate SBPL from profile (inject proxy port)
7. Write SBPL to temp file
8. Build sandbox command:
   sandbox-exec -f /tmp/sbe-XXXX.sb <command> [args...]
9. Inject env vars (HTTP_PROXY, HTTPS_PROXY, NO_PROXY, plus profile.env)
10. Spawn sandboxed process, forward stdin/stdout/stderr
11. If --audit: spawn audit log watcher in parallel
12. Wait for sandboxed process to exit
13. Cleanup: remove temp SBPL file, stop proxy
14. Print audit summary if --audit
15. Exit with sandboxed process's exit code
```

### 6. Audit Logger (`apps/cli::audit`)

Monitors macOS unified log for sandbox violations:

```rust
// Spawns: log stream --style ndjson --predicate 'process == "sandboxd"'
// Parses JSON events, filters by our sandbox PID
// Formats and writes to stderr or --audit-log file
```

**Event format:**
```
[sbe:audit] DENIED file-write /Library/Caches/com.apple.act.mond (pid=12345)
[sbe:audit] DENIED network-outbound 142.11.206.73:8000 (pid=12345)
[sbe:audit] DENIED process-exec /usr/bin/osascript (pid=12345)
```

### 7. CLI Interface (`apps/cli::cli`)

```
sbe — Run commands in a macOS sandbox

USAGE:
    sbe run [OPTIONS] -- <COMMAND>...
    sbe inspect [OPTIONS] -- <COMMAND>...
    sbe profiles

SUBCOMMANDS:
    run         Execute a command inside the sandbox
    inspect     Print resolved config and generated SBPL without executing
    profiles    List available profiles and their defaults

RUN OPTIONS:
    -p, --profile <NAME>           Use a specific profile (overrides auto-detect)
    -n, --allow-domain <DOMAIN>    Add domain to network allowlist (repeatable)
    -N, --deny-domain <DOMAIN>     Remove domain from network allowlist (repeatable)
    -w, --allow-write <PATH>       Add writable path (repeatable)
    -r, --deny-read <PATH>         Add read-denied path (repeatable)
    -e, --allow-exec <PATH>        Allow execution of binary (repeatable)
    -E, --deny-exec <PATH>         Deny execution of binary (repeatable)
    --allow-all-network            Disable network sandboxing entirely
    --no-proxy                     Disable proxy (use SBPL-only network rules)
    --audit                        Stream sandbox violations to stderr
    --audit-log <PATH>             Write violations to file
    --dry-run                      Print SBPL to stdout, do not execute
    -c, --config <PATH>            Use specific config file
    -v, --verbose                  Verbose output
```

## Per-Ecosystem Default Profiles

### Node.js

```yaml
allow_write:
  - "$PWD"
  - "~/.npm"
  - "~/.cache/yarn"
  - "~/.local/share/pnpm"
  - "~/.bun"
  - "~/.cache/bun"
deny_read:
  - "~/.ssh"
  - "~/.gnupg"
  - "~/.aws"
  - "~/.azure"
  - "~/.config/gcloud"
  - "~/Library/Keychains"
  - "~/.docker/config.json"
  - "~/.netrc"
allow_domains:
  - "registry.npmjs.org"
  - "registry.yarnpkg.com"
  - "registry.npmmirror.com"
allow_exec:
  - "/usr/local/bin/node"
  - "/opt/homebrew/bin/node"
  - "$HOME/.nvm/versions/**"
  - "$HOME/.volta/**"
  - "/bin/sh"
  - "/bin/bash"
  - "/bin/zsh"
  - "/usr/bin/env"
  - "/usr/bin/tar"
  - "/usr/bin/gzip"
  - "/usr/bin/xcodebuild"  # native modules
  - "/usr/bin/make"
  - "/usr/bin/cc"
deny_exec:
  - "/usr/bin/osascript"
  - "/usr/bin/security"
  - "/usr/sbin/screencapture"
  - "/usr/bin/open"
```

### Rust

```yaml
allow_write:
  - "$PWD"
  - "~/.cargo/registry"
  - "~/.cargo/git"
  - "~/.cargo/bin"        # cargo install
  - "~/.rustup"
allow_domains:
  - "crates.io"
  - "static.crates.io"
  - "index.crates.io"
  - "static.rust-lang.org"
  - "github.com"
  - "objects.githubusercontent.com"
allow_exec:
  - "~/.cargo/bin/**"
  - "~/.rustup/toolchains/**"
  - "/bin/sh"
  - "/bin/bash"
  - "/usr/bin/env"
  - "/usr/bin/make"
  - "/usr/bin/cc"
  - "/usr/bin/xcrun"
  - "/usr/bin/xcodebuild"
  - "/usr/bin/install_name_tool"
  - "/usr/bin/tar"
```

### Python

```yaml
allow_write:
  - "$PWD"
  - "~/.cache/pip"
  - "~/.cache/uv"
  - "~/.local/lib/python*"
  - "~/.local/bin"
  - "$PWD/.venv"
  - "$PWD/venv"
allow_domains:
  - "pypi.org"
  - "files.pythonhosted.org"
allow_exec:
  - "/usr/bin/python3"
  - "/usr/local/bin/python*"
  - "/opt/homebrew/bin/python*"
  - "$HOME/.pyenv/**"
  - "$HOME/.local/bin/**"
  - "/bin/sh"
  - "/bin/bash"
  - "/usr/bin/env"
  - "/usr/bin/make"
  - "/usr/bin/cc"
```

### Elixir

```yaml
allow_write:
  - "$PWD"
  - "~/.hex"
  - "~/.mix"
  - "~/.cache/rebar3"
allow_domains:
  - "hex.pm"
  - "repo.hex.pm"
  - "builds.hex.pm"
  - "github.com"
  - "objects.githubusercontent.com"
allow_exec:
  - "/usr/local/bin/elixir"
  - "/usr/local/bin/mix"
  - "/usr/local/bin/erl"
  - "/opt/homebrew/bin/elixir"
  - "/opt/homebrew/bin/mix"
  - "/opt/homebrew/bin/erl"
  - "$HOME/.asdf/**"
  - "$HOME/.kiex/**"
  - "/bin/sh"
  - "/bin/bash"
  - "/usr/bin/env"
  - "/usr/bin/make"
  - "/usr/bin/cc"
```

### Java

```yaml
allow_write:
  - "$PWD"
  - "~/.m2/repository"
  - "~/.gradle/caches"
  - "~/.gradle/wrapper"
  - "$PWD/.gradle"
  - "$PWD/build"
  - "$PWD/target"
allow_domains:
  - "repo1.maven.org"
  - "repo.maven.apache.org"
  - "plugins.gradle.org"
  - "services.gradle.org"
  - "downloads.gradle-dn.com"
  - "jcenter.bintray.com"
  - "github.com"
  - "objects.githubusercontent.com"
allow_exec:
  - "/usr/bin/java"
  - "/usr/libexec/java_home"
  - "$JAVA_HOME/**"
  - "$HOME/.sdkman/**"
  - "/opt/homebrew/opt/openjdk/**"
  - "/bin/sh"
  - "/bin/bash"
  - "/usr/bin/env"
  - "/usr/bin/make"
```

## Security Considerations

### Threat Model

sbe defends against **malicious code executed during dependency installation or build**, specifically:

| Attack Vector | Mitigation |
|---------------|------------|
| Network C2 (non-standard ports) | SBPL denies all outbound; proxy only allows registry domains on 443 |
| Secret exfiltration via network | Proxy blocks non-allowlisted domains; SBPL blocks reads to credential dirs |
| File write to system dirs | SBPL denies file-write except explicit allowlist |
| Persistent malware (LaunchAgents, crontab) | Write deny to `~/Library/LaunchAgents`, `/Library/Caches`, etc. |
| osascript / AppleScript abuse | SBPL denies process-exec for osascript |
| curl/wget download of 2nd-stage payload | Proxy blocks non-registry domains; SBPL can deny curl exec |
| Reading SSH keys / cloud creds | SBPL denies file-read for sensitive paths |
| Clipboard exfiltration | SBPL denies pbcopy/pbpaste execution |

### What sbe Does NOT Protect Against

- Malicious code in allowed dependencies that runs at application runtime (sbe is for install/build time)
- Attacks that only need access to the project directory (e.g., modifying source files)
- Exfiltration through allowed registry domains (covert channel via package uploads)
- Kernel exploits that escape Seatbelt (extremely unlikely, nation-state level)

### Sandbox Escape Hardening

- SBPL temp file is written with mode 0400 (read-only) and deleted immediately after sandbox-exec reads it
- Proxy binds to 127.0.0.1 only — not accessible from network
- Proxy validates CONNECT target against allowlist before establishing any connection
- sbe itself runs outside the sandbox — it cannot be tampered with by sandboxed code
- The proxy rejects non-CONNECT HTTP methods to prevent SSRF through the proxy

## Performance Considerations

- **Sandbox setup**: ~5ms (write SBPL, spawn sandbox-exec)
- **Proxy startup**: ~10ms (bind TCP listener)
- **Proxy overhead per request**: < 1ms (TCP splice, no TLS termination)
- **SBPL enforcement overhead**: negligible (kernel-level, no context switches per operation — only on denied operations)
- **Total overhead**: < 50ms startup, unmeasurable steady-state for allowed operations
