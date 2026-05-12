# sbe — Sandbox Exec

Run any command in a kernel-enforced sandbox with sensible defaults per language
ecosystem. Defend your development machine and CI runners against supply chain
attacks. Supports **macOS** (Seatbelt / SBPL) and **Linux** (Landlock LSM +
seccomp-bpf).

```
sbe run -- npm install
sbe run -- cargo build
sbe run -- pip install -r requirements.txt
sbe run -- mix deps.get
sbe run -- ./gradlew build
```

## Why

Package managers execute arbitrary code during install and build: npm
`postinstall` scripts, Rust `build.rs`, Python `setup.py`, Elixir mix compile
hooks, Gradle plugins. A single compromised dependency can read your SSH keys,
exfiltrate cloud credentials, install persistent malware, or establish C2
channels — all silently, in the background.

sbe wraps your existing tools in a self-applied kernel sandbox: macOS
`sandbox-exec` or Linux Landlock + seccomp. No code changes, no new package
manager. Just prefix your command with `sbe run --`.

## What It Blocks

| Attack Vector | macOS (Seatbelt / SBPL) | Linux (Landlock + seccomp) |
|---|---|---|
| Read `~/.ssh`, `~/.aws`, cloud creds | SBPL `file-read*` denylist | `denyRead` forbidden-list (see Caveats) |
| Write to `/Library/Caches`, LaunchAgents | SBPL `file-write*` allowlist | Landlock write allowlist |
| Network C2 on non-standard ports | SBPL pins egress to proxy / `:443` | Landlock `NET_CONNECT_TCP` (≥6.7) or `:443` |
| Second-stage download via `curl`/`wget` | Proxy 403s non-allowlisted domains | Same proxy, identical behaviour |
| `osascript` / AppleScript abuse | SBPL `process-exec` denylist | n/a (Linux) |
| `sudo`, `pkexec`, privilege escalation | n/a (macOS) | Lint refuses `allowExec` subpaths covering `sudo`/`pkexec`/etc. |
| Clipboard / screen exfiltration | SBPL denies `pbcopy`/`screencapture` | Allowlist omits them |
| Module load / kernel attack surface | n/a | seccomp blocks `bpf`, `init_module`, `kexec_*`, `ptrace`, … |

## Install

```bash
cargo install --path apps/cli
```

Or:

```bash
make install
```

Supported targets:
- **macOS** — any release with `/usr/bin/sandbox-exec` (all SIP-compliant builds).
- **Linux** — kernel **≥5.13** for basic enforcement, **≥6.7** for full
  per-port TCP filtering (Landlock ABI v4). On 5.13–6.6 a `--allow-degraded`
  fallback is available; without that flag, sbe refuses to start rather than
  silently downgrading.

### CI (GitHub Actions)

The bundled composite action installs a prebuilt static binary and adds it to
`PATH`:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: tyrchen/sbe@sbexec-v0.2.0   # or @master with `version: latest`
        with:
          version: latest
      - run: sbe --version
      - run: sbe run -- cargo build
```

Inputs:

| Input | Default | Description |
|---|---|---|
| `version` | `latest` | Release to install. Accepts `latest`, a semver (`0.2.2`), or a full tag (`sbexec-v0.2.2`). |
| `github-token` | `${{ github.token }}` | Token used for releases API + asset download. |

Outputs: `version` (resolved tag) and `bin-path` (absolute path to the installed binary).

Linux runners get full enforcement on `ubuntu-latest` / `ubuntu-24.04` (kernel
6.x with Landlock ABI v4). On macOS runners the binary uses `sandbox-exec` as
before.

## Quick Start

```bash
# Auto-detects ecosystem from command name or project files
sbe run -- npm install
sbe run -- cargo build

# Specify ecosystem explicitly
sbe run -p python -- pip install flask

# See what policy would be installed (does not execute)
sbe run --dry-run -- npm install

# Print resolved config + generated policy
sbe inspect -- cargo build

# List all default profiles
sbe profiles

# Disable network sandboxing for debugging
sbe run --allow-all-network -- npm install

# Add a custom allowed domain
sbe run -n "api.mycompany.com" -- npm install

# Allow build-time downloads (enables curl/wget + adds domains to proxy)
sbe run -f "download.example.com" -- cargo build

# Allow an extra binary
sbe run -e /usr/bin/curl -- npm install

# Stream sandbox violations in real-time
sbe run --audit -- npm install

# Linux: proceed under a kernel without ABI v4 net filter (best-effort)
sbe run --allow-degraded -- cargo build
```

## Architecture

```
                          sbe CLI
                            │
              ┌─────────────┴─────────────┐
              │                           │
       Profile/Config             SandboxBackend          (cfg-selected at
       Resolver                   trait                    compile time)
       (sbe-core)                       │
                            ┌───────────┴───────────┐
                            │                       │
                  ┌─────────▼────────┐   ┌──────────▼────────┐
                  │  MacosSandbox    │   │  LinuxSandbox     │
                  │  (sandbox-exec)  │   │  (Landlock +      │
                  │                  │   │   seccomp +       │
                  │  - SBPL gen      │   │   pre_exec)       │
                  │  - tempfile      │   │  - Ruleset build  │
                  │  - spawn -f      │   │  - BPF compile    │
                  └─────────┬────────┘   └──────────┬────────┘
                            │                       │
                            └───────────┬───────────┘
                                        │
                                        ▼
                                  ┌──────────┐
                                  │  user    │     HTTP_PROXY → sbe-proxy
                                  │  command │ ──────────────────────────►
                                  └──────────┘     (same path both platforms)
```

**Two-layer network defense:**
1. **Kernel layer:** SBPL or Landlock pins outbound traffic to `localhost:PROXY_PORT` (or `:443`).
2. **Application layer (proxy):** an HTTP CONNECT proxy checks the requested domain against the per-ecosystem allowlist before tunneling.

This combination defeats CDN-backed registries: SBPL and Landlock can't filter
by hostname, but the proxy does — and the kernel forces every TCP egress
through it.

## Linux Backend Caveats

These differences from the macOS path are surface-level — the same `sbe run`
UX still works. Documented here so you know what you're getting:

- **`denyRead` is allowlist-omission, not subtractive deny.** Landlock has no
  way to subtract from a granted subtree. sbe ships a curated read-allowlist
  on Linux (`/etc`, `/lib`, `/usr`, `/proc`, `/sys`, `/tmp`, `$HOME` XDG dirs)
  that intentionally excludes `~/.ssh`, `~/.aws`, etc. Anything you list in
  `denyRead` becomes a *sealed forbidden-list*: future config changes that try
  to grant read on a forbidden path are rejected at backend-time.
- **`denyExec` is a no-op.** Landlock is allowlist-only; `denyExec` entries
  in a Linux profile emit a warning and are otherwise ignored. The defaults
  ship a per-binary `allowExec` enumeration that omits `sudo`, `su`, `pkexec`,
  `doas`, `chsh`, `chfn`, `newgrp`, `sg`, `passwd`, `gpasswd`, `mount`,
  `umount`. A `.sbe.yaml` that grants `allowExec: ["/usr/bin/"]` is rejected
  at startup (use `--allow-degraded` to override after considering the
  threat model).
- **`PR_SET_NO_NEW_PRIVS` is mandatory.** Linux requires it for unprivileged
  seccomp; sbe sets it before applying any filter. The flag persists across
  `execve` and disables `setuid` bits across the descendant tree. Consequence:
  `sudo` / `su` / `pkexec` cannot escalate — this is desired. The handful of
  tools that depend on setuid binaries (e.g., legacy `ping`) will fail; the
  vast majority of build scripts are unaffected.
- **UDP is unfiltered.** Landlock filters only TCP. DNS over UDP, NTP, QUIC
  egress are not subject to per-port enforcement. The seccomp baseline blocks
  `AF_PACKET` raw sockets but not `SOCK_DGRAM` on `AF_INET`. The HTTP CONNECT
  proxy is TCP-only by design.
- **DBus-resolved DNS may fail.** Tools that resolve via systemd-resolved's
  DBus path (some Python/Node DNS libraries through `nss-systemd`) will hit
  `EACCES` on `/run/dbus/system_bus_socket`. The fallback through glibc's
  `getaddrinfo` over UDP (`/etc/resolv.conf`) works. Workaround for affected
  tools: use `--allow-fetch` or add the DBus socket to a custom profile.
- **Kernel <6.7 needs `--allow-degraded`.** Without Landlock ABI v4, sbe
  cannot pin TCP egress to a specific port. With the flag, a best-effort
  seccomp `connect()` arg filter is used and a warning is printed. We refuse
  to silently downgrade.

## Supported Ecosystems

| Ecosystem | Auto-detected commands | Auto-detected files |
|---|---|---|
| **Node.js** | `node`, `npm`, `npx`, `yarn`, `pnpm`, `bun` | `package.json` |
| **Rust** | `cargo`, `rustc`, `rustup` | `Cargo.toml` |
| **Python** | `python`, `python3`, `pip`, `pip3`, `uv`, `poetry`, `pdm`, `rye` | `pyproject.toml`, `setup.py`, `requirements.txt`, `Pipfile` |
| **Elixir** | `mix`, `elixir`, `iex` | `mix.exs` |
| **Java** | `java`, `javac`, `mvn`, `mvnw`, `gradle`, `gradlew`, `sbt`, `scala`, `scalac`, `kotlinc` | `pom.xml`, `build.gradle`, `build.gradle.kts`, `build.sbt` |

`sbe profiles` prints the full per-OS defaults.

## Configuration

Create a `.sbe.yaml` (or `.sbe.yml`) in your project root, or
`~/.config/sbe/config.yaml` for global defaults:

```yaml
profiles:
  node:
    allowWrite:
      - "./dist"
    allowDomains:
      - "api.mycompany.com"
    allowFetch:
      - "download.example.com"  # enables curl/wget + adds to proxy allowlist
    env:
      NODE_ENV: production

  # Custom profile extending an existing one
  my-app:
    extends: node
    allowDomains:
      - "internal-registry.mycompany.com"
    enableProxy: true
    allowAllNetwork: false
    allowDegraded: false        # Linux only; default false
```

**Config resolution order** (last wins):
1. Built-in ecosystem defaults (per-OS YAML embedded at compile time)
2. Global config: `~/.config/sbe/config.yaml`
3. Project config: `.sbe.yaml` or `.sbe.yml` (walks up to git root)
4. CLI flags

### Crate Structure

```
sbe/
├── crates/
│   ├── core/                       # sbe-core: profile + backends
│   │   └── src/
│   │       ├── profile/            # Per-ecosystem defaults (per-OS YAML)
│   │       │   ├── defaults-macos.yaml
│   │       │   └── defaults-linux.yaml
│   │       ├── sandbox/            # SandboxBackend trait + impls
│   │       │   ├── mod.rs          # Trait + cfg-selected Sandbox re-export
│   │       │   ├── macos/          # sandbox-exec backend
│   │       │   │   ├── mod.rs
│   │       │   │   ├── sbpl.rs
│   │       │   │   └── exec.rs
│   │       │   └── linux/          # Landlock + seccomp backend
│   │       │       ├── mod.rs
│   │       │       ├── probe.rs    # Kernel/ABI probe
│   │       │       ├── policy.rs   # YAML render for --dry-run
│   │       │       ├── landlock.rs # Ruleset builder
│   │       │       ├── seccomp.rs  # BpfProgram builder
│   │       │       └── exec.rs     # pre_exec wiring
│   │       ├── config.rs
│   │       ├── detect.rs
│   │       └── error.rs
│   └── proxy/                      # sbe-proxy: domain-filtering CONNECT proxy
├── apps/
│   └── cli/                        # sbe binary
└── specs/                          # Design documents
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
  -E, --deny-exec <PATH>         Deny execution of binary (repeatable; macOS only)
  -f, --allow-fetch <DOMAIN>     Allow build-time downloads (enables curl/wget + adds to proxy)
      --allow-all-network        Disable network sandboxing entirely
      --no-proxy                 Disable proxy (kernel port-443 mode)
      --allow-degraded           Proceed under a degraded kernel (Linux <ABI v4)
      --audit                    Stream sandbox violations to stderr
      --audit-log <PATH>         Write violations to file
      --dry-run                  Print policy to stdout, do not execute
  -c, --config <PATH>            Use specific config file
  -v, --verbose                  Verbose output
```

```
sbe inspect [OPTIONS] -- <COMMAND>...

  Print resolved config + generated policy without executing.
  macOS: SBPL Scheme document.
  Linux: YAML policy showing Landlock ruleset + seccomp action table.
```

```
sbe profiles

  List all built-in ecosystem profiles and their defaults.
```

**Exit codes:** sbe passes through the child process exit code. sbe's own
errors use 125 (internal error) and 126 (sandbox setup failed).

## How It Works

1. **Detect ecosystem** from command name (`npm` → Node) or project files (`Cargo.toml` → Rust).
2. **Load profile** — built-in per-OS defaults merged with global/project `.sbe.yaml` and CLI flags.
3. **Probe backend** — `sandbox-exec` on macOS, Landlock ABI level on Linux. Refuse on missing capability unless `--allow-degraded`.
4. **Start proxy** — bind HTTP CONNECT proxy on `127.0.0.1:0`, get ephemeral port.
5. **Compile policy** — SBPL string + tempfile on macOS; Landlock `Ruleset` + `BpfProgram` in-memory on Linux.
6. **Execute** —
    - macOS: `sandbox-exec -f /tmp/sbe-XXXX.sb <command>` with `HTTP_PROXY` env injected.
    - Linux: `Command::pre_exec` issues `prctl(PR_SET_NO_NEW_PRIVS) → landlock_restrict_self → seccomp(TSYNC)`, then `execve`. No tempfile on disk.
7. **Monitor** — optionally stream violations (macOS `sandboxd`; Linux `/dev/kmsg` audit).
8. **Cleanup** — stop proxy, propagate exit code.

## Development

```bash
make build
make test          # uses cargo-nextest under sbe
make fmt
make lint
make check         # fmt + lint + test
make install
```

### Requirements

- Rust 2024 edition (stable)
- macOS, or Linux ≥5.13 (≥6.7 for full network parity)
- `cargo-nextest` for `make test` (optional)

## License

This project is distributed under the terms of MIT.

See [LICENSE](LICENSE.md) for details.

Copyright 2025-2026 Tyr Chen
