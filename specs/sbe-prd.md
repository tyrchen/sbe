# sbe — Sandbox Exec CLI: Product Requirements

## Problem Statement

Modern software development relies heavily on open-source package ecosystems (npm, cargo, pip, hex, maven/gradle). These ecosystems execute arbitrary code during dependency installation and build steps — `postinstall` scripts in npm, `build.rs` in Rust, `setup.py` in Python, `mix compile` hooks in Elixir, and Gradle/Maven plugins in Java. Supply chain attacks (e.g., the 2026-03 Axios NPM attack) exploit this trust to:

1. **Exfiltrate secrets** — read `~/.ssh`, `~/.aws`, `.env`, cloud credentials, browser cookies
2. **Establish C2 channels** — connect to attacker-controlled servers on non-standard ports
3. **Persist malware** — write to `/Library/Caches`, LaunchAgents, crontabs, shell profiles
4. **Abuse system tools** — invoke `osascript`, `curl`, `wget`, PowerShell for lateral movement

macOS provides `sandbox-exec` (Seatbelt/TrustedBSD MAC framework) — a kernel-level mandatory access control mechanism that cannot be escaped from userspace. However, it is difficult to use directly: SBPL syntax is arcane, per-ecosystem needs differ, and it lacks domain-level network filtering.

## Product Vision

**sbe** is a single Rust CLI binary that wraps any command in a macOS sandbox with sensible defaults per language ecosystem. Zero-config for common workflows, fully customizable for advanced use.

```
sbe run -- npm install
sbe run -- cargo build
sbe run -- pip install -r requirements.txt
sbe run -- mix deps.get && mix compile
sbe run -- ./gradlew build
```

## Target Users

- Software engineers using macOS as their primary development machine
- DevOps/Platform engineers hardening CI/CD on macOS runners
- Security-conscious teams wanting defense-in-depth against supply chain attacks

## Core Requirements

### R1: Language Ecosystem Auto-Detection

sbe MUST auto-detect the language ecosystem from:
1. Explicit `--profile <name>` flag (highest priority)
2. The command being executed (e.g., `npm` -> node, `cargo` -> rust)
3. Files in the current working directory (e.g., `package.json` -> node, `Cargo.toml` -> rust)

Supported ecosystems with their package managers and build tools:

| Ecosystem | Detected Commands | Detected Files | Package Managers / Build Tools |
|-----------|-------------------|----------------|-------------------------------|
| Node.js   | `node`, `npm`, `npx`, `yarn`, `pnpm`, `bun` | `package.json` | npm, yarn, pnpm, bun |
| Rust      | `cargo`, `rustc`, `rustup` | `Cargo.toml` | cargo |
| Python    | `python`, `python3`, `pip`, `pip3`, `uv`, `poetry`, `pdm`, `rye` | `pyproject.toml`, `setup.py`, `requirements.txt`, `Pipfile` | pip, uv, poetry, pdm, rye |
| Elixir    | `mix`, `elixir`, `iex` | `mix.exs` | mix (hex) |
| Java      | `java`, `javac`, `mvn`, `gradle`, `gradlew` | `pom.xml`, `build.gradle`, `build.gradle.kts` | maven, gradle |

### R2: Filesystem Sandboxing (Kernel-Level)

For each ecosystem, sbe MUST enforce via SBPL:

**Default deny all writes.** Then allow writes ONLY to:
- Current working directory and its subtree (`$PWD`)
- Language-specific cache/data directories (see per-ecosystem defaults below)
- System temp directories (`/private/tmp`, `/private/var/folders`)

**Default allow all reads** (required for toolchain discovery), EXCEPT deny reads to:
- `~/.ssh` (SSH keys)
- `~/.gnupg` (GPG keys)
- `~/.aws`, `~/.azure`, `~/.config/gcloud` (cloud credentials)
- `~/Library/Keychains` (macOS Keychain)
- `~/.docker/config.json` (Docker auth)
- `~/.netrc` (HTTP credentials)
- Browser profile directories (`~/Library/Application Support/Google/Chrome`, etc.)
- Any paths specified in `--deny-read`

Users can override with `--allow-read` and `--deny-read`.

### R3: Network Sandboxing (Kernel + Proxy)

**Layer 1 — Kernel (SBPL):**
- Deny all outbound network by default
- Allow only `localhost:*` and the sbe proxy port
- Allow DNS resolution (mDNSResponder socket)

**Layer 2 — Domain-Filtering Proxy:**
- sbe spawns a local HTTP CONNECT proxy on an ephemeral port
- Configures `HTTP_PROXY` / `HTTPS_PROXY` env vars inside the sandbox
- Proxy enforces a domain allowlist per ecosystem
- Non-allowlisted domains are rejected with a clear error logged

Default domain allowlists per ecosystem:

| Ecosystem | Allowed Domains |
|-----------|----------------|
| Node.js   | `registry.npmjs.org`, `registry.yarnpkg.com`, `registry.npmmirror.com` |
| Rust      | `crates.io`, `static.crates.io`, `index.crates.io`, `static.rust-lang.org` |
| Python    | `pypi.org`, `files.pythonhosted.org` |
| Elixir    | `hex.pm`, `repo.hex.pm`, `builds.hex.pm` |
| Java      | `repo1.maven.org`, `repo.maven.apache.org`, `plugins.gradle.org`, `services.gradle.org`, `downloads.gradle-dn.com` |
| Common    | `github.com`, `objects.githubusercontent.com` (for git dependencies) |

Users can extend with `--allow-domain` or restrict with `--deny-domain`.

### R4: Process Execution Control

**Deny execution of high-risk system binaries by default:**
- `/usr/bin/osascript` (AppleScript — used by macOS malware for stealth execution)
- `/usr/bin/security` (Keychain access)
- `/usr/sbin/screencapture` (screen recording)
- `/usr/bin/open` (launch arbitrary apps)
- `/usr/bin/pbcopy`, `/usr/bin/pbpaste` (clipboard access)

Users can override with `--allow-exec <path>` or add more blocks with `--deny-exec <path>`.

### R5: Configuration File

sbe MUST support a YAML configuration file for persistent, per-project or global settings.

**Resolution order (last wins):**
1. Built-in defaults
2. Global config: `~/.config/sbe/config.yaml`
3. Project config: `.sbe.yaml` in `$PWD` (or parent directories, up to git root)
4. CLI flags

**Config schema:**

```yaml
# .sbe.yaml
profiles:
  node:
    allow_write:
      - "./node_modules"
      - "~/.npm"
      - "~/.cache/yarn"
      - "~/.local/share/pnpm"
    deny_read:
      - "~/.ssh"
      - "~/.aws"
    allow_domains:
      - "registry.npmjs.org"
      - "registry.yarnpkg.com"
    deny_exec:
      - "/usr/bin/osascript"
    allow_exec: []
    env:
      NODE_ENV: "production"

  rust:
    allow_write:
      - "./target"
      - "~/.cargo/registry"
      - "~/.cargo/git"
      - "~/.rustup"
    allow_domains:
      - "crates.io"
      - "static.crates.io"
      - "index.crates.io"
      - "static.rust-lang.org"

  # Custom profiles
  my-app:
    extends: node
    allow_domains:
      - "api.mycompany.com"
    allow_write:
      - "./dist"
```

### R6: Audit Logging

sbe MUST provide visibility into sandbox enforcement:

- `--audit` flag: stream real-time sandbox violation events from `sandboxd` to stderr
- `--audit-log <path>`: write violations to a file
- Each violation event includes: timestamp, PID, operation attempted, path/address, verdict (denied)
- Summary at command exit: count of violations by category (file-write, network, process-exec)

### R7: Dry Run and Inspect

- `--dry-run`: print the generated SBPL profile to stdout without executing
- `--inspect`: print the resolved configuration (merged from all sources) as YAML

### R8: Exit Code Passthrough

sbe MUST propagate the wrapped command's exit code. sbe's own errors use exit codes 125-127 (matching `env` and `docker run` conventions):
- 125: sbe internal error
- 126: sandbox setup failed
- 127: command not found

## Non-Requirements (Explicit Exclusions)

- **Linux support**: Out of scope for v1. macOS sandbox-exec only. Linux (bubblewrap/landlock) is a future goal.
- **GUI**: CLI only.
- **Package manager replacement**: sbe wraps existing tools, does not replace them.
- **Static analysis of dependencies**: sbe is a runtime sandbox, not a SAST/SCA tool.
- **Windows support**: Not planned (Windows lacks equivalent unprivileged sandboxing).

## Success Metrics

1. Zero additional commands to learn for basic usage — just prefix with `sbe run --`
2. < 50ms overhead on sandbox setup (excluding proxy startup)
3. Blocks 100% of the Axios attack chain (network C2, file write to /Library/Caches, osascript execution)
4. No false-positive blocks on standard `npm install` / `cargo build` / `pip install` / `mix deps.get` / `gradle build` for top-100 packages
