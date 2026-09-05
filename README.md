# SBE — Sandbox Exec

SBE runs package managers, compilers, build scripts, and other development
tools inside a kernel-enforced sandbox. It uses Seatbelt/SBPL on macOS and
Landlock plus seccomp on Linux.

```bash
# Practical protection for everyday development
sbe run -- cargo build

# Fail-closed protection for a high-assurance, offline build
sbe run --strict -- cargo build --offline
```

SBE is designed for code that may be malicious: repositories, dependencies,
install hooks, compiler plugins, and build scripts. It protects host
credentials and limits filesystem, process, environment, and network access.
The operating-system kernel and the installed SBE executable remain trusted.

Current release: [`0.4.3`](https://github.com/tyrchen/sbe/releases/tag/sbexec-v0.4.3)

## Install

Install the `sbexec` crate, which provides the `sbe` command:

```bash
cargo install sbexec --version 0.4.3 --locked
sbe --version
```

To install the current checkout for development:

```bash
cargo install --path apps/cli --locked --force
```

Source builds require the current Rust stable toolchain and one of:

- macOS with `/usr/bin/sandbox-exec`; or
- Linux 5.13 or newer. Landlock ABI v4 or newer is required for TCP
  destination-port enforcement.

SBE does not pin an exact Rust patch release; CI builds with `stable`.

## Quick start

Put `sbe run --` before the command you want to isolate. SBE detects the
ecosystem from the command and project files:

```bash
sbe run -- npm install
sbe run -- cargo build
sbe run -- uv build
sbe run -- mix compile
sbe run -- mvn package
```

Common operations:

```bash
# Preview the resolved policy without running the command
sbe inspect -- cargo build

# Select a profile explicitly
sbe run --profile python -- uv build

# Add or remove an HTTPS proxy destination
sbe run --allow-domain api.example.com -- npm install
sbe run --deny-domain github.com -- npm install

# Permit curl/wget execution and its download destination
sbe run --allow-fetch downloads.example.com -- cargo build

# Grant an additional filesystem capability
sbe run --allow-read ../shared --allow-write ./generated -- cargo build

# List the built-in profiles and defaults
sbe profiles
```

The `--` separator is required. Options before it belong to SBE; everything
after it is passed unchanged to the target command. SBE returns the target's
exit status. SBE's own errors use status 125, and sandbox setup or target exec
failures use 126.

## Choose a security mode

Version 0.4.3 uses `standard` mode by default and provides the original 0.4
fail-closed boundary through `--strict`.

| | Standard (default) | Strict (`--strict`) |
|---|---|---|
| Best for | Everyday builds and installs | Offline or explicitly provisioned high-assurance builds |
| Workspace | Readable and writable | Source writes limited to recognized outputs |
| Build outputs and caches | May be both writable and executable | Persistent write/execute overlap is rejected |
| Environment | Ordinary build settings inherited; sensitive variables removed | Small positive allowlist |
| Local services | Allowed where the platform supports them | Narrow or denied |
| Missing enforcement | Reported; compatible work may continue | Fails before launching the target |

Standard mode keeps the core host protections active while allowing normal
incremental builds, compiler wrappers, local developer services, mutable
outputs, and package caches. Because the whole workspace is readable in this
mode, do not keep real credentials in repository files such as `.env`. Put
them outside the workspace or use strict mode.

The standard profiles also include common child build tools—downloaders,
scripting runtimes, OpenSSL, `protoc`, native code generators, and platform
toolchain launchers—using explicit per-platform paths. This covers helpers
launched by npm scripts, uv or pip builds, Cargo build scripts, Maven/Gradle,
and native extension builds. For Go, SBE derives the matching
`GOROOT/pkg/tool/` directory from the resolved standard `go` launcher so its
compiler subprocesses work without granting a broad package-manager directory.
These compatibility grants are standard-only;
strict mode keeps its smaller executable allowlist.

Standard mode also removes language-runtime launcher variables such as
`JAVA_TOOL_OPTIONS`, `NODE_OPTIONS`, and `PYTHONPATH` from the inherited
environment. Pass a reviewed value with `--keep-env` when a build genuinely
needs one; SBE-controlled variables remain reserved.

Strict mode is intentionally less convenient. It is most useful with a warm,
reviewed dependency cache and a command that does not need the network:

```bash
sbe run --strict -- cargo build --offline
```

Persistent files produced by untrusted code remain untrusted in both modes.
SBE does not certify generated binaries, scripts, libraries, or dependencies
for later execution outside the sandbox.

## GitHub Actions

The setup action installs the published `0.4.3` binary, verifies its SHA-256
checksum and GitHub build-provenance attestation, and adds it to `PATH`.
The action now defaults to the current release, so a normal workflow needs no
extra version configuration:

```yaml
name: build

on: [push, pull_request]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Install SBE
        uses: tyrchen/sbe@sbexec-v0.4.3
      - run: sbe --version
      - run: sbe run -- cargo build
```

For high-assurance workflows, pin the action code to the immutable commit SHA
for `sbexec-v0.4.3` from the release page. The installed archive is always
checked against both its release checksum and GitHub build provenance.

The optional `version` input accepts `0.4.3`, `v0.4.3`, `sbexec-v0.4.3`, or
`latest`; it defaults to `0.4.3`. Use it only to override the default or when
you deliberately want automatic upgrades to the latest stable GitHub release.
The optional `github-token` defaults to `github.token`. The action exposes the
resolved release tag as `version` and the installed executable as `bin-path`.

Release binaries are available for:

- `x86_64-unknown-linux-musl`;
- `aarch64-unknown-linux-musl`; and
- `aarch64-apple-darwin`.

Releases before 0.4.0 are rejected by the action because they do not contain
the required checksum and provenance artifacts.

## Supported ecosystems

SBE detects these built-in profiles:

| Ecosystem | Commands | Project files |
|---|---|---|
| Node.js | `node`, `npm`, `npx`, `corepack`, `yarn`, `pnpm`, `bun` | `package.json` |
| Rust | `cargo`, `rustc`, `rustup` | `Cargo.toml` |
| Python | `python`, `pip`, `uv`, `uvx`, `poetry`, `pdm`, `rye` | `pyproject.toml`, requirements files |
| Elixir | `mix`, `elixir`, `iex` | `mix.exs` |
| Java/Scala | `java`, `javac`, `mvn`, `gradle`, `sbt`, `scala` | Maven, Gradle, and sbt descriptors |

Standard mode makes the workspace, conventional package caches, and expected
dependency/build directories usable for normal install-then-run workflows.
Strict mode separates writable dependency installation from dependency
execution:

- Rust keeps final `cargo build` artifacts in `target` while putting executable
  intermediate build artifacts in private per-run storage. Commands such as
  `cargo test`, `cargo run`, and `cargo nextest` use a private target directory.
- Node installation keeps dependency directories writable but non-executable.
  Run installed tools in a separate invocation such as `sbe run -- npm test`.
- Python installation keeps `.venv` or `venv` writable but non-executable. Run
  the installed environment in a separate invocation such as
  `sbe run -- uv run pytest`.
- Hex 2.5.x creates unpredictable temporary directories in the project root.
  Strict mode therefore requires fetching Elixir dependencies first, followed
  by a separate `sbe run --strict -- mix compile` invocation.

SBE rejects package-manager options that relocate the project outside the
working tree. Change to the intended project directory before running SBE.
Cargo `--manifest-path` is supported only inside the selected workspace.

## Grant only what the command needs

### Environment

Standard mode inherits normal build configuration such as `RUSTFLAGS`,
`CFLAGS`, and feature switches while removing high-confidence credentials,
token-file locators, agent sockets, dynamic-loader controls, and SBE-reserved
variables. Strict mode starts from a much smaller allowlist.

Restore or set individual values explicitly:

```bash
sbe run --keep-env MY_REQUIRED_TOKEN -- cargo build
sbe run --env BUILD_MODE=release -- cargo build
```

`sbe inspect` shows effective variable names and their origins but always
redacts values. Proxy, temporary-directory, and SBE-controlled build-output
variables are reserved and cannot be replaced.

### Filesystem and executables

Use repeatable grants when a command needs a path outside its profile:

```bash
sbe run \
  --allow-read ../shared-sources \
  --allow-write ./generated \
  --allow-exec /opt/toolchain/bin/compiler \
  -- cargo build
```

Built-in secret denials still win over `--allow-read`. On Linux, broad
privilege-bearing executable directories are rejected. Shared temporary roots
are not granted broadly; each run receives private storage through `TMPDIR`,
`TMP`, `TEMP`, and `XDG_RUNTIME_DIR`.

SBE follows ordinary source and cache symlinks in standard mode after resolving
and validating their targets. Protected paths and magic links remain rejected.
Strict mode retains no-follow path resolution except for immutable system
aliases and also checks hard-link aliases to enforce persistent W^X.

Stdin, stdout, and stderr are deliberate capabilities. For example,
`sbe run -- tool < secret.txt` explicitly gives the file contents to `tool`,
even though other inherited file descriptors are closed before target exec.

### Network

Profiles include the normal HTTPS destinations for their package ecosystem.
Use `--allow-domain` to add a proxy destination and `--deny-domain` to remove
one. `--allow-fetch` additionally permits supported downloader executables.

Two compatibility options deliberately weaken network isolation:

- `--no-proxy` allows direct TCP on destination port 443 and is not
  domain-filtered. On Linux it also permits the datagram sockets libc needs for
  DNS resolution.
- `--allow-all-network` removes network confinement.

The local CONNECT proxy is authenticated with a per-run random token, permits
port 443 by default, validates DNS results, rejects IP literals and special-use
addresses, and enforces bounded requests, connections, and timeouts. If the
proxy exits unexpectedly, SBE terminates the sandboxed command.

#### Important Linux limitation

Landlock ABI v4 can restrict a destination **port**, not a destination IP
address. Standard mode on Linux therefore cannot force hostile TCP traffic
through the domain-filtering proxy. Proxy-aware tools still use the proxy, but
network isolation is reported as best-effort and local developer traffic is
allowed.

Strict proxy mode on Linux refuses to run unless you explicitly pass
`--allow-insecure-linux-network`, which acknowledges the destination-port-only
limitation. For hostile CI, prefer strict offline builds or combine SBE with a
network namespace or trusted egress firewall.

On macOS, external traffic remains proxy-mediated. Standard mode also permits
localhost developer services; strict mode narrows the policy to the requested
proxy endpoint.

## Configuration

Policy sources are merged in this order:

1. built-in platform and ecosystem defaults;
2. `~/.config/sbe/config.yaml`;
3. an auto-discovered project `.sbe.yaml` or `.sbe.yml`;
4. a file selected with `--config`; and
5. CLI options.

An auto-discovered project file is untrusted by default. In standard mode it
may add the project's ordinary registry or download domains with
`allowDomains` and `allowFetch`, or tighten policy with `denyRead`, `denyExec`,
and `denyDomains`. A private registry therefore works without a trust flag:

```yaml
# .sbe.yaml
profiles:
  rust:
    allowDomains:
      - "cargo-index.int.example.com"
```

It cannot grant filesystem, execution, environment, proxy, or degraded-mode
authority. Strict mode keeps the restrictive-only behavior. Inspect before
trusting a repository-controlled expansion that needs broader authority:

```bash
sbe inspect --trust-project-config -- npm install
sbe run --trust-project-config -- npm install
```

Global configuration, an explicitly selected file, and CLI options are treated
as trusted user choices.

Configuration rejects unknown fields, unsafe paths, malformed domains and
environment names, oversized input, missing bases, and cyclic `extends`
chains. `sbe inspect` shows the origin of every permission-bearing entry.

## Security boundary

Both platforms enforce these core properties:

- deny-by-default filesystem writes and executable paths;
- protected host credential paths;
- removal of sensitive ambient environment variables and file descriptors;
- private per-run temporary storage;
- untrusted project configuration cannot expand authority without consent;
- an authenticated, destination-restricted HTTPS proxy; and
- capability reporting that does not claim unavailable enforcement.

The backend details differ:

| Capability | macOS | Linux |
|---|---|---|
| Filesystem | SBPL rules | Descriptor-backed Landlock rules |
| Processes and syscalls | SBPL process/Mach-service rules | Landlock scopes plus seccomp |
| Host credential reads | Explicit SBPL denials, including canonical targets | Read rules with protected descendants carved out |
| Domain-filtered HTTPS | Enforced for external traffic through the proxy | Best-effort in standard mode; unavailable fail-closed in strict mode |
| Same-user signals and Unix sockets | Narrow in strict mode | Signals on ABI v6+; pathname sockets on ABI v9+ |
| Persistent W^X | Allowed and marked tainted in standard; rejected in strict | Same |

Linux exposes only curated public procfs files such as `/proc/cpuinfo`, not
`/proc/self`. Pathname Unix-socket mediation requires Landlock ABI v9. On ABI
v9+, capability brokers such as `docker.sock` stay outside the standard
boundary; older kernels report that enforcement as unavailable.

## Limitations

- Linux does not yet have a strict domain-egress backend. Standard networking
  is best-effort, and strict domain mode fails closed unless its insecure
  compatibility option is acknowledged.
- macOS uses an allow-most/read-deny model for compatibility. Curated secret
  paths, Keychain service access, shared temporary roots, environment, and
  inherited descriptors are protected, but this is not a complete home-folder
  read allowlist.
- Correlated kernel violation streaming is currently unavailable. Ordinary
  denials still appear as `EACCES`, `EPERM`, or target failure.
- SBE does not defend against kernel vulnerabilities, a compromised SBE
  binary, CPU or memory exhaustion, timing/cache side channels, or capabilities
  explicitly passed through standard input/output/error.

Run `sbe inspect -- <command>` on the target machine to see the exact policy
and capabilities supported by its operating system and kernel.

## CLI reference

Run `sbe run --help` and `sbe inspect --help` for the complete reference.
Frequently used security options are:

| Option | Purpose |
|---|---|
| `--strict` | Require the fail-closed 0.4 boundary |
| `--profile NAME` | Override ecosystem detection |
| `--allow-domain DOMAIN` | Add an HTTPS proxy destination |
| `--deny-domain DOMAIN` | Remove an HTTPS proxy destination |
| `--allow-fetch DOMAIN` | Permit a downloader and its destination |
| `--allow-read PATH` | Add a readable path; secret denials still win |
| `--deny-read PATH` | Add a protected read path |
| `--allow-write PATH` | Add a writable path |
| `--allow-exec PATH` | Add an executable path |
| `--deny-exec PATH` | Remove an executable path |
| `--keep-env NAME` | Preserve one parent variable |
| `--env NAME=VALUE` | Set one child variable |
| `--trust-project-config` | Allow broader filesystem, execution, or environment grants from project config |
| `--no-proxy` | Use direct TCP 443 compatibility mode |
| `--allow-all-network` | Remove network confinement |
| `--allow-insecure-linux-network` | Acknowledge strict Linux port-only networking |
| `--dry-run` | Render the policy without running the target |

## Further reading

- [Architecture](docs/arch.md)
- [Security hardening design and threat model](specs/security-hardening-design.md)
- [0.4.3 usable-security design](specs/usable-security-design.md)
- [Changelog](CHANGELOG.md)

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
cargo deny check advisories bans licenses sources
cargo machete
```

The release workflow uses the Rust `stable` channel, full-SHA-pinned actions,
least-privilege job permissions, draft-first publication, SHA-256 checksums,
SPDX SBOMs, and GitHub build-provenance attestations.

## License

MIT. See [LICENSE.md](LICENSE.md).

Copyright 2025–2026 Tyr Chen
