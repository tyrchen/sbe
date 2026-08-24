# sbe — Sandbox Exec

Run package managers and build tools with a kernel-enforced filesystem,
process, and network policy. SBE supports macOS Seatbelt/SBPL and Linux
Landlock plus seccomp.

```bash
# macOS: strict domain-filtered proxy mode
sbe run -- cargo build

# Linux: the current kernel can only enforce the proxy destination port.
# This explicit compatibility option acknowledges that limitation.
sbe run --allow-insecure-linux-network -- cargo build
```

SBE is designed for repositories, dependencies, build scripts, compiler
plugins, and install hooks that may be malicious. The kernel and the installed
SBE executable remain trusted.

## Security boundary

SBE 0.4 fails closed when a requested guarantee cannot be enforced.

| Capability | macOS | Linux |
|---|---|---|
| Filesystem writes | SBPL allowlist | Landlock allowlist |
| Secret-path reads | SBPL deny rules | Descriptor-based read rules with denied descendants carved out |
| Executable paths | SBPL allow/deny rules | Landlock allowlist; broad privilege-bearing directories are rejected |
| Ambient environment | Cleared, then rebuilt from a small positive allowlist | Same |
| Ambient file descriptors | `CLOEXEC` before target exec | `close_range(CLOEXEC)` with bounded fallback |
| Domain-filtered HTTPS | Enforced through the exact authenticated proxy port | Not currently enforceable; strict mode refuses to run |
| Restricted TCP/UDP | SBPL network policy | Landlock TCP plus seccomp Internet datagram/raw-socket rules |
| Same-user signals and Unix sockets | SBPL signal/network rules | Landlock ABI v6 signal and abstract-socket scopes; ABI v9 pathname-socket mediation |
| Persistent W^X | Validated before launch | Validated before launch, including existing symlink aliases |
| Private temporary storage | Per-run root; other shared temp roots denied | Per-run root; other temp paths omitted from Landlock grants |
| Violation audit stream | Reported unavailable unless a correlatable source exists | Reported unavailable until kernel-domain correlation is verifiable |

Important Linux distinction: Landlock ABI v4 can authorize a destination
**port**, not a destination IP address. A malicious process that knows the
proxy's random port can connect to a different host listening on that port.
SBE therefore does not call this domain confinement. A proxy profile either:

- refuses by default; or
- runs only after `--allow-insecure-linux-network`, with a warning explaining
  the bypass.

Linux intentionally exposes only curated public procfs nodes such as
`/proc/cpuinfo`; it does not grant `/proc/self`. A rule opened for the launcher's
`/proc/self` inode would not follow spawned descendants to their different proc
inodes and would create a false guarantee. On kernels before Landlock ABI v6,
same-user signal and abstract Unix-socket isolation is unavailable; pathname
Unix-socket mediation requires ABI v9.

`--allow-all-network` remains an explicit request to remove network isolation.
`--no-proxy` selects direct-TCP-443 compatibility mode and is never described
as domain-filtered. On Linux it also permits Internet datagram sockets so libc
can resolve DNS; use proxy mode when UDP egress must remain blocked.

See the [security hardening design](specs/security-hardening-design.md) for the
threat model, findings, and adversarial verification plan.

## Install

```bash
cargo install sbexec --locked
```

For development from this repository:

```bash
cargo install --path apps/cli --locked --force
```

Requirements:

- the current Rust stable toolchain for source builds;
- macOS with `/usr/bin/sandbox-exec`; or
- Linux 5.13 or newer for Landlock filesystem enforcement, with Landlock ABI
  v4 or newer required for TCP destination-port enforcement.

No exact Rust patch version is pinned. CI installs `stable`.

### GitHub Actions

Release 0.4.0 and newer publishes SHA-256 checksums, an SPDX SBOM, and GitHub
build-provenance attestations. The composite action verifies both the checksum
and the attestation before installing the binary. The action defaults to the
audited `0.4.0` release; pass `version: latest` only when intentionally opting
into automatic release upgrades.

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@<full-commit-sha>
  - uses: tyrchen/sbe@sbexec-v0.4.0
    with:
      version: '0.4.0'
  - run: sbe --version
  - run: sbe run --allow-insecure-linux-network -- cargo build
```

For high-assurance workflows, replace the SBE release tag in `uses:` with the
full commit SHA belonging to that tag. Supported release targets are
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and
`aarch64-apple-darwin`.

The action accepts `0.4.0`, `v0.4.0`, or `sbexec-v0.4.0` and reports the
resolved `sbexec-v0.4.0` tag through its `version` output. Releases older than
0.4.0 are rejected because they do not provide the required checksum and
provenance artifacts.

## Quick start

```bash
# Detect the ecosystem from the command or project files
sbe run -- npm install
sbe run -- cargo build

# Linux proxy compatibility (required for current networked defaults)
sbe run --allow-insecure-linux-network -- npm install

# Explicit profile
sbe run --profile python -- uv build

# Add or remove domains
sbe run --allow-domain api.example.com -- npm install
sbe run --deny-domain github.com -- npm install

# Permit a build-time downloader and its destination
sbe run --allow-fetch downloads.example.com -- cargo build

# Inspect the effective policy without executing the command
sbe inspect -- cargo build

# List built-in profiles
sbe profiles
```

### Environment grants

The child does not inherit the complete parent environment. SBE keeps only a
small CLI baseline such as `PATH`, `HOME`, locale, terminal, and selected tool
home variables. Credential variables and agent sockets are absent unless the
user grants them explicitly:

```bash
sbe run --keep-env MY_REQUIRED_TOKEN -- cargo build
sbe run --env BUILD_MODE=release -- cargo build
```

Proxy, temporary-directory, and SBE-controlled build-output variables are
reserved and cannot be replaced through configuration or CLI flags. `inspect`
prints effective variable names and origins, but all values are redacted.

On current stable Cargo, SBE keeps final Rust artifacts in `$PWD/target` while
placing intermediate artifacts and executable build scripts in the private
per-run tree through `CARGO_BUILD_BUILD_DIR`. This preserves persistent W^X
without discarding the final build output. Commands that execute target
artifacts—including `cargo test`, `cargo run`, and `cargo nextest`—instead use
the private executable `CARGO_TARGET_DIR`.

Node dependency installation keeps `node_modules` writable but non-executable.
Commands that explicitly run already-installed tools, such as `npm test`,
`npm exec`, and `npx`, switch the built-in dependency-tree grant to
read/execute and remove its write grant for that invocation. Modern Yarn PnP
installs pre-create `.pnp.cjs` (and the optional ESM loader when configured)
only when `.yarnrc.yml` or `packageManager` identifies a PnP-capable Yarn;
Classic Yarn and the `node-modules` linker remain lockfile-only.

Persistent outputs and package caches are still attacker-controlled data after
an untrusted build. W^X prevents direct execution during that invocation; it
does not make generated binaries, scripts, dynamic libraries, or interpreted
packages trustworthy. Review or discard them before running them outside SBE.

Stdin, stdout, and stderr are intentional capabilities. For example,
`sbe run -- tool < secret.txt` explicitly gives that file's contents to the
tool even though all other inherited descriptors are closed.

## Configuration trust

Configuration sources are merged in this order:

1. built-in platform/ecosystem policy;
2. `~/.config/sbe/config.yaml`;
3. an auto-discovered project `.sbe.yaml` or `.sbe.yml`;
4. an explicitly named `--config` file; and
5. CLI grants.

An automatically discovered project file is untrusted. By default it may add
`denyRead`, `denyExec`, or `denyDomains`, and may turn off a previously granted
allow-all/degradation setting. It may not add read, write, execute, network,
environment, fetch, or degradation authority.

Review a repository before granting expansion for one invocation:

```bash
sbe inspect --trust-project-config -- npm install
sbe run --trust-project-config -- npm install
```

Global, explicitly named, and CLI policy are trusted user choices. All schemas
reject unknown fields, oversized input, invalid environment names, malformed
IDNA domains, unsafe paths, missing bases, and cyclic `extends` chains.

Example trusted configuration:

```yaml
profiles:
  node:
    allowWrite:
      - "$PWD/dist/"
    allowDomains:
      - "api.example.com"
    denyDomains:
      - "github.com"
    allowFetch:
      - "downloads.example.com"
    env:
      NODE_ENV: production
```

Every permission-bearing resolved entry retains its built-in, global,
project, explicit-file, CLI, parent-environment, or runtime origin.

## Filesystem and process policy

Built-in profiles grant specific outputs and lockfiles rather than the entire
working tree. Source, `.git`, workflow definitions, manifests, and SBE policy
remain non-writable unless explicitly granted. Shared system temporary roots
are not writable; every invocation gets a canonical private root used for
`TMPDIR`, `TMP`, `TEMP`, and `XDG_RUNTIME_DIR`.

Persistent write and execute grants may not overlap. The only default W+X
exception is the private per-run root, which is deleted when the invocation
finishes. Toolchains such as `~/.rustup` are executable/readable but not
writable. Mutable caches are readable/writable but not executable.

On Linux, paths are opened with descriptor-relative `openat2` resolution using
`RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and
`RESOLVE_NO_MAGICLINKS`. Writable directories are created component by
component with directory FDs. Root-owned immutable distribution symlinks are
the only symlink exception. Because Landlock authorizes inodes rather than
pathnames, SBE fails closed if a denied regular file—or a file below a denied
directory—has multiple hard links.

Hex 2.5.x currently extracts packages through an unpredictable `tmp_*`
directory in the project root and exposes no temp-directory setting. Strict
SBE therefore blocks `mix deps.get` rather than granting project-wide write
access. Fetch dependencies before entering SBE, then run
`sbe run -- mix compile`; dependency build code still executes inside the
sandbox.

## Network proxy

The local CONNECT proxy:

- requires a random 256-bit per-run Basic-authentication token;
- accepts only CONNECT over HTTP/1.0 or HTTP/1.1;
- bounds request lines, individual and total headers, header count, concurrent
  connections, resolved addresses, and task lifetime;
- enforces total header, DNS, connect, aggregate bidirectional idle, and
  maximum tunnel timeouts;
- canonicalizes lowercase IDNA names and matches wildcards on label boundaries;
- permits port 443 by default;
- rejects IP literals and any resolution containing loopback, private,
  link-local, unspecified, multicast, documentation, or other selected
  special-use addresses; and
- resolves once and connects only to a validated returned address.

If the proxy exits while the sandboxed command is alive, SBE terminates the
command instead of silently leaving it without the requested mediator.

JVM profiles receive SBE-owned proxy system properties and a private per-run
authentication agent. The agent reads the one-time token from a reserved
environment variable and answers authentication challenges only for SBE's
exact loopback proxy endpoint. The token is deliberately excluded from
`JAVA_TOOL_OPTIONS`, which the JVM prints at startup. Maven and sbt therefore
use the same domain allowlist as the other ecosystems. Gradle daemon IPC may
require additional local-service authority and is not enabled broadly by
default.

## Linux launcher

Linux policy installation does not run complex Rust code in a multithreaded
`pre_exec` closure. The parent serializes a bounded policy into an anonymous
descriptor and starts an internal single-threaded launcher before constructing
any runtime in that process. The launcher:

1. parses and revalidates the policy;
2. safely opens Landlock rule paths;
3. applies `PR_SET_NO_NEW_PRIVS`, Landlock, and seccomp;
4. marks ambient descriptors close-on-exec; and
5. executes the target.

A dedicated status descriptor distinguishes launcher setup failure from the
target itself returning exit code 126.

## Limitations

- Linux has no strict domain-egress backend yet. The explicit port-only mode is
  bypassable and should be combined with a network namespace, firewall, or
  trusted CI egress controls when the repository may be malicious.
- On Linux kernels before Landlock ABI v4, restricted TCP modes refuse unless
  the same insecure compatibility option is supplied; in that case TCP
  confinement is unavailable and SBE says so.
- Path-based Unix-socket mediation depends on newer Landlock ABIs. Local IPC is
  a separate capability from Internet egress.
- macOS retains an allow-most/read-deny model for compatibility. The curated
  secret paths, Keychain service, shared temp roots, environment, and inherited
  descriptors are protected, but this is not a complete home-directory read
  allowlist.
- Correlated kernel violation streaming is currently reported as unavailable.
  Ordinary denials still surface as `EACCES`, `EPERM`, or command failure.
- SBE does not defend against kernel vulnerabilities, a compromised SBE
  binary, CPU/memory exhaustion by the target, timing/cache side channels, or
  explicit capabilities supplied through stdio.

## Supported ecosystems

| Ecosystem | Commands | Project files |
|---|---|---|
| Node.js | `node`, `npm`, `npx`, `yarn`, `pnpm`, `bun` | `package.json` |
| Rust | `cargo`, `rustc`, `rustup` | `Cargo.toml` |
| Python | `python`, `pip`, `uv`, `poetry`, `pdm`, `rye` | `pyproject.toml`, `requirements.txt`, and related files |
| Elixir | `mix`, `elixir`, `iex` | `mix.exs` |
| Java/Scala | `java`, `javac`, `mvn`, `gradle`, `sbt`, `scala` | Maven, Gradle, and sbt descriptors |

## CLI

Run `sbe run --help` and `sbe inspect --help` for the complete current
reference. Security-relevant options include:

```text
--allow-insecure-linux-network  Explicit port-only Linux compatibility
--allow-all-network             Remove network confinement
--no-proxy                      Direct-TCP-443 compatibility
--trust-project-config          Let auto-discovered project policy add grants
--keep-env NAME                 Preserve one parent variable
--env NAME=VALUE                Add one explicit variable
--allow-write PATH              Add a writable path
--deny-read PATH                Add a protected read path
--allow-exec PATH               Add an executable path
--allow-fetch DOMAIN            Add downloader execution and proxy destination
--dry-run                       Render policy without target execution
```

SBE passes through normal target exit codes. Its own errors use 125; sandbox
setup/exec failure uses 126.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
cargo deny check advisories bans licenses sources
cargo machete
```

The release workflow uses the Rust `stable` channel, pinned third-party action
SHAs, least-privilege job permissions, draft-first publication, SHA-256
checksums, SPDX SBOMs, and GitHub artifact attestations.

## License

MIT. See [LICENSE.md](LICENSE.md).

Copyright 2025–2026 Tyr Chen
