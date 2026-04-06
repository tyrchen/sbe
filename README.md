# sbe — Sandbox Exec

Run any command in a macOS sandbox with sensible defaults per language ecosystem. Defend your development machine against supply chain attacks at the OS kernel level.

```
sbe run -- npm install
sbe run -- cargo build
sbe run -- pip install -r requirements.txt
sbe run -- mix deps.get
sbe run -- ./gradlew build
```

## Why

Package managers execute arbitrary code during install and build: npm `postinstall` scripts, Rust `build.rs`, Python `setup.py`, Elixir mix compile hooks, Gradle plugins. A single compromised dependency can read your SSH keys, exfiltrate cloud credentials, install persistent malware, or establish C2 channels — all silently, in the background.

sbe wraps your existing tools in a macOS `sandbox-exec` (Seatbelt/TrustedBSD) kernel-level sandbox. No code changes, no new package manager. Just prefix your command with `sbe run --`.

## What It Blocks

| Attack Vector | How sbe Stops It |
|---|---|
| Read `~/.ssh`, `~/.aws`, cloud creds | SBPL denies file-read to sensitive paths |
| Write to `/Library/Caches`, LaunchAgents | SBPL denies file-write outside project + cache dirs |
| Network C2 on non-standard ports | Proxy allows only registry domains on 443; SBPL blocks all direct outbound |
| `osascript` / AppleScript abuse | SBPL denies process-exec for risky binaries |
| `curl`/`wget` 2nd-stage download | Proxy rejects non-allowlisted domains with 403 |
| Clipboard / screen exfiltration | SBPL denies `pbcopy`, `pbpaste`, `screencapture` |

## Install

```bash
cargo install --path apps/cli
```

Or from the workspace root:

```bash
make install
```

Requires macOS (uses `sandbox-exec` which is macOS-only).

## Quick Start

```bash
# Auto-detects ecosystem from command name or project files
sbe run -- npm install
sbe run -- cargo build

# Specify ecosystem explicitly
sbe run -p python -- pip install flask

# See what SBPL profile would be generated (does not execute)
sbe run --dry-run -- npm install

# Print resolved config + SBPL
sbe inspect -- cargo build

# List all default profiles
sbe profiles

# Disable network sandboxing for debugging
sbe run --allow-all-network -- npm install

# Add a custom allowed domain
sbe run -n "api.mycompany.com" -- npm install

# Allow an extra binary
sbe run -e /usr/bin/curl -- npm install

# Stream sandbox violations in real-time
sbe run --audit -- npm install
```

## Supported Ecosystems

| Ecosystem | Auto-detected commands | Auto-detected files | Default allowed domains |
|---|---|---|---|
| **Node.js** | `node`, `npm`, `npx`, `yarn`, `pnpm`, `bun` | `package.json` | `registry.npmjs.org`, `registry.yarnpkg.com`, `github.com` |
| **Rust** | `cargo`, `rustc`, `rustup` | `Cargo.toml` | `crates.io`, `static.crates.io`, `index.crates.io`, `github.com` |
| **Python** | `python`, `pip`, `uv`, `poetry`, `pdm`, `rye` | `pyproject.toml`, `setup.py`, `requirements.txt` | `pypi.org`, `files.pythonhosted.org`, `github.com` |
| **Elixir** | `mix`, `elixir`, `iex` | `mix.exs` | `hex.pm`, `repo.hex.pm`, `github.com` |
| **Java** | `java`, `javac`, `mvn`, `gradle`, `gradlew` | `pom.xml`, `build.gradle` | `repo1.maven.org`, `plugins.gradle.org`, `github.com` |

## Configuration

Create a `.sbe.yaml` in your project root (or `~/.config/sbe/config.yaml` for global defaults):

```yaml
profiles:
  node:
    allowWrite:
      - "./dist"
    allowDomains:
      - "api.mycompany.com"
    env:
      NODE_ENV: production

  # Custom profile extending an existing one
  my-app:
    extends: node
    allowDomains:
      - "internal-registry.mycompany.com"
    enableProxy: true
    allowAllNetwork: false
```

**Config resolution order** (last wins):
1. Built-in ecosystem defaults
2. Global config: `~/.config/sbe/config.yaml`
3. Project config: `.sbe.yaml` (walks up to git root)
4. CLI flags

## Architecture

```
                          sbe CLI
                            |
              +-------------+-------------+
              |             |             |
         Profile       SBPL Gen      Proxy Server
         Resolver      (sbe-core)    (sbe-proxy)
         (sbe-core)         |             |
              |             v             |
              +-----> sandbox-exec <------+
                      (macOS kernel)
                            |
                      +-----------+
                      | Your Cmd  |----> HTTP_PROXY=127.0.0.1:PORT
                      | (npm,     |        |
                      |  cargo,..)| All outbound forced through proxy
                      +-----------+

 Inside sandbox (kernel-enforced):          Outside sandbox:
 - file-write denied except allowlist       - sbe-proxy on localhost
 - file-read denied for secrets             - Domain allowlist filtering
 - network only to localhost proxy          - Audit log collection
 - risky binaries blocked                   - SBPL tempfile management
```

**Two-layer network defense:**
1. **Kernel layer (SBPL):** blocks all outbound except `localhost:PROXY_PORT` + DNS
2. **Application layer (proxy):** HTTP CONNECT proxy checks domain against allowlist before tunneling

This combination solves SBPL's limitation of IP-only filtering — CDN-backed registries use dynamic IPs, so domain-level filtering requires the proxy.

### Crate Structure

```
sbe/
├── crates/
│   ├── core/           # sbe-core: profiles, config, SBPL generation, detection
│   │   └── src/
│   │       ├── profile/    # Per-ecosystem defaults (node, rust, python, elixir, java)
│   │       ├── config.rs   # YAML config loading + merging
│   │       ├── sbpl.rs     # SBPL profile generator
│   │       ├── detect.rs   # Ecosystem auto-detection
│   │       └── error.rs
│   └── proxy/          # sbe-proxy: domain-filtering HTTP CONNECT proxy
│       └── src/
│           ├── server.rs     # Async TCP listener + CONNECT handler
│           ├── allowlist.rs  # Domain matching (exact + wildcard)
│           └── error.rs
├── apps/
│   └── cli/            # sbe binary
│       └── src/
│           ├── main.rs       # Entry point + tracing setup
│           ├── cli.rs        # clap argument definitions
│           ├── executor.rs   # Sandbox lifecycle orchestration
│           └── audit.rs      # sandboxd log streaming
└── specs/              # Design documents (PRD, design, impl plan)
```

## CLI Reference

```
sbe run [OPTIONS] -- <COMMAND>...

Options:
  -p, --profile <NAME>           Use a specific profile (overrides auto-detect)
  -n, --allow-domain <DOMAIN>    Add domain to network allowlist (repeatable)
  -N, --deny-domain <DOMAIN>     Remove domain from allowlist (repeatable)
  -w, --allow-write <PATH>       Add writable path (repeatable)
  -r, --deny-read <PATH>         Add read-denied path (repeatable)
  -e, --allow-exec <PATH>        Allow execution of binary (repeatable)
  -E, --deny-exec <PATH>         Deny execution of binary (repeatable)
      --allow-all-network        Disable network sandboxing entirely
      --no-proxy                 Disable proxy (SBPL port-443-only mode)
      --audit                    Stream sandbox violations to stderr
      --audit-log <PATH>         Write violations to file
      --dry-run                  Print SBPL to stdout, do not execute
  -c, --config <PATH>            Use specific config file
  -v, --verbose                  Verbose output
```

**Exit codes:** sbe passes through the child process exit code. sbe's own errors use 125 (internal error) and 126 (sandbox setup failed).

## Development

```bash
# Build
make build

# Run tests (requires cargo-nextest)
make test

# Or with standard cargo
cargo test

# Format + lint + test
make check

# Install locally
make install
```

### Requirements

- macOS (uses `sandbox-exec`)
- Rust 2024 edition (stable)
- `cargo-nextest` for `make test` (optional — `cargo test` works too)

## How It Works

1. **Detect ecosystem** from command name (`npm` -> Node) or project files (`Cargo.toml` -> Rust)
2. **Load profile** — built-in defaults merged with global/project `.sbe.yaml` and CLI flags
3. **Start proxy** — bind HTTP CONNECT proxy on `127.0.0.1:0`, get ephemeral port
4. **Generate SBPL** — deny-by-default policy with explicit exceptions for the ecosystem
5. **Write tempfile** — SBPL to `/tmp/sbe-XXXX.sb` with mode 0400
6. **Execute** — `sandbox-exec -f /tmp/sbe-XXXX.sb <command>` with `HTTP_PROXY` env injected
7. **Monitor** — optionally stream sandboxd violations via `log stream`
8. **Cleanup** — stop proxy, remove tempfile, propagate exit code

## License

This project is distributed under the terms of MIT.

See [LICENSE](LICENSE.md) for details.

Copyright 2025 Tyr Chen
