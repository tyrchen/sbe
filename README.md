# sbe — Sandbox Exec

Run package managers and build tools with a kernel-enforced filesystem,
process, and network policy. SBE supports macOS Seatbelt/SBPL and Linux
Landlock plus seccomp.

```bash
# Standard mode: practical containment for everyday builds
sbe run -- cargo build

# Strict mode: retain the fail-closed 0.4 security boundary
sbe run --strict -- cargo build
```

SBE is designed for repositories, dependencies, build scripts, compiler
plugins, and install hooks that may be malicious. The kernel and the installed
SBE executable remain trusted.

## Security boundary

SBE 0.4.1 defaults to a practical `standard` mode so ordinary build tools,
compiler wrappers, mutable outputs, and local developer services work without
broad escape flags. `--strict` retains the fail-closed 0.4 boundary for offline
or explicitly provisioned high-assurance builds.

| Capability | macOS | Linux |
|---|---|---|
| Filesystem writes | SBPL allowlist | Landlock allowlist |
| Host credential reads | SBPL deny rules | Descriptor-based read rules with denied descendants carved out |
| Executable paths | SBPL allow/deny rules | Landlock allowlist; broad privilege-bearing directories are rejected |
| Ambient environment | Sensitive/capability variables removed in standard mode; positive allowlist under `--strict` | Same |
| Ambient file descriptors | `CLOEXEC` before target exec | `close_range(CLOEXEC)` with bounded fallback |
| Domain-filtered HTTPS | Enforced through the authenticated proxy; standard mode also permits localhost tooling | Best-effort in standard mode; strict domain mode refuses to run |
| Restricted TCP/UDP | External traffic remains proxy-mediated | Best-effort in standard mode; Landlock/seccomp restrictions under `--strict` |
| Same-user signals and Unix sockets | Local services allowed in standard mode; narrow under `--strict` | Signals scoped on ABI v6+; filesystem sockets limited to private roots on ABI v9+ |
| Persistent W^X | Allowed and tainted in standard mode; validated under `--strict` | Same |
| Private temporary storage | Per-run root; other shared temp roots denied | Per-run root; other temp paths omitted from Landlock grants |
| Violation audit stream | Reported unavailable unless a correlatable source exists | Reported unavailable until kernel-domain correlation is verifiable |

Important Linux distinction: Landlock ABI v4 can authorize a destination
**port**, not a destination IP address. A malicious process that knows the
proxy's random port can connect to a different host listening on that port.
SBE therefore does not describe Linux standard networking as domain-confined.
Standard mode keeps the filesystem, environment, descriptor, privilege, and
proxy protections active and reports the limitation. A strict proxy profile
either:

- refuses by default; or
- runs only after `--allow-insecure-linux-network`, with a warning explaining
  the bypass.

Linux intentionally exposes only curated public procfs nodes such as
`/proc/cpuinfo`; it does not grant `/proc/self`. A rule opened for the launcher's
`/proc/self` inode would not follow spawned descendants to their different proc
inodes and would create a false guarantee. On kernels before Landlock ABI v6,
same-user signal and abstract Unix-socket isolation is unavailable; pathname
Unix-socket mediation requires ABI v9. On ABI v9+, SBE keeps filesystem-backed
capability brokers such as `docker.sock` outside the standard envelope and
permits socket resolution only in its private per-run root. Older kernels
cannot enforce this distinction and report the capability as unavailable.

`--allow-all-network` remains an explicit request to remove network isolation.
`--no-proxy` selects direct-TCP-443 compatibility mode and is never described
as domain-filtered. On Linux it also permits Internet datagram sockets so libc
can resolve DNS. Only strict proxy mode blocks Internet datagram sockets.

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
audited `0.4.1` release; pass `version: latest` only when intentionally opting
into automatic release upgrades.

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@<full-commit-sha>
  - uses: tyrchen/sbe@sbexec-v0.4.1
    with:
      version: '0.4.1'
  - run: sbe --version
  - run: sbe run -- cargo build
```

For high-assurance workflows, replace the SBE release tag in `uses:` with the
full commit SHA belonging to that tag. Supported release targets are
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and
`aarch64-apple-darwin`.

The action accepts `0.4.1`, `v0.4.1`, or `sbexec-v0.4.1` and reports the
resolved `sbexec-v0.4.1` tag through its `version` output. Releases older than
0.4.0 are rejected because they do not provide the required checksum and
provenance artifacts.

## Quick start

```bash
# Detect the ecosystem from the command or project files
sbe run -- npm install
sbe run -- cargo build

# Opt into the high-assurance boundary for an offline build
sbe run --strict -- cargo build --offline

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

Standard mode inherits ordinary build configuration such as `RUSTFLAGS`,
`CFLAGS`, and feature switches, while removing high-confidence credential,
OIDC token-file, agent, dynamic-loader, and SBE-reserved variables. Strict mode
keeps only a small positive baseline. Removed values can be granted explicitly:

```bash
sbe run --keep-env MY_REQUIRED_TOKEN -- cargo build
sbe run --env BUILD_MODE=release -- cargo build
```

Proxy, temporary-directory, and SBE-controlled build-output variables are
reserved and cannot be replaced through configuration or CLI flags. `inspect`
prints effective variable names and origins, but all values are redacted.

Under `--strict`, SBE keeps final Rust artifacts in `$PWD/target` while
placing intermediate artifacts and executable build scripts in the private
per-run tree through `CARGO_BUILD_BUILD_DIR`. This preserves persistent W^X
without discarding the final build output. Commands that execute target
artifacts—including `cargo test`, `cargo run`, and `cargo nextest`—instead use
the private executable `CARGO_TARGET_DIR`.

In strict mode, Node dependency installation keeps `node_modules` writable but
non-executable.
Commands that explicitly run already-installed tools, such as `npm test`,
`npm exec`, `npx`, and corresponding Yarn/pnpm/Bun forms, switch the built-in
dependency-tree grant to read/execute and remove its write grant for that
invocation. Modern Yarn PnP installs pre-create `.pnp.cjs` (and the optional
ESM loader when configured)
only when `.yarnrc.yml` or `packageManager` identifies a PnP-capable Yarn;
Classic Yarn and the `node-modules` linker remain lockfile-only. Mutating Bun
commands receive only their own `bun.lock` output, plus `yarn.lock` when Bun's
`--yarn` compatibility output is requested. SBE walks bounded, no-follow
workspace metadata up to the Git boundary, including workspace roots between
the current directory and repository root, and grants/pre-creates outputs at
exactly one active Node workspace root. `npm --no-package-lock` and
`--package-lock=false` never create an empty lockfile. Package-manager options
that relocate the project
(`--prefix`, `--cwd`, `--dir`, `--directory`, `--project`, and equivalent short
forms) are rejected before policy preparation; change directory before running
SBE instead.

Strict Python installation and synchronization commands similarly keep project
`.venv`/`venv` directories writable but non-executable. Run/test commands,
including `uv run`, `poetry run`, activated entry points, and direct
`.venv/bin/...` paths, switch those built-in grants to read/execute without
write. This mode is for an already-installed environment; synchronize it in a
separate invocation before running tools.

In standard mode the workspace and conventional package caches are writable,
and expected build/dependency roots are executable. This makes install-then-run
workflows, sccache, Gradle daemons, virtual environments, and normal incremental
builds usable in one invocation. Top-level `cargo install` also receives its
selected install root; the installed binary is not made trustworthy by SBE.
An external Cargo target can be selected with an inherited `CARGO_TARGET_DIR`
or a direct `--config build.target-dir='path'` override, or granted explicitly
with matching `--allow-write` and `--allow-exec` paths. Cargo `--config` file
paths are rejected because SBE cannot determine their effective target without
reimplementing Cargo's layered configuration; use `--target-dir` instead.
Without an explicit or inherited override, standard mode selects `$PWD/target`
instead of trying to reproduce Cargo's layered configuration rules.

Persistent outputs and package caches are still attacker-controlled data after
an untrusted build. Strict W^X prevents direct execution during that invocation;
standard mode deliberately allows expected mutable build outputs to execute.
Neither mode makes generated binaries, scripts, dynamic libraries, or
interpreted packages trustworthy. Review or discard them before running them
outside SBE.

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

Standard profiles grant the working tree and conventional tool data so package
managers can evolve without SBE reimplementing their command grammars. Strict
profiles retain exact output/lockfile grants and source immutability. Shared
system temporary roots are not granted broadly; every invocation gets a
canonical private root used for `TMPDIR`, `TMP`, `TEMP`, and
`XDG_RUNTIME_DIR`.

Workspace grants are anchored to the launch directory. Package-manager project
relocation options such as npm `--prefix`, Cargo `-C`, Gradle `--project-dir`,
or Maven `--file` fail early with an actionable error in both modes; change
directory before invoking SBE.

Standard mode does not hide files inside the selected workspace, including
`.env*`; dependencies already run with the repository as input, and trying to
carve individual project files breaks general output creation on Linux. Keep
real credentials outside untrusted workspaces or use `--strict`. Host SSH,
cloud, package-registry, browser, and keychain credential paths remain denied.

Standard mode permits expected persistent write/execute overlap and labels the
result tainted. Strict mode keeps the 0.4 W^X and hard-link checks. Toolchains
such as `~/.rustup` remain non-writable during ordinary builds in both modes.

On Linux, standard grants follow an existing ordinary symlink to its opened
referent and install the Landlock rule from that descriptor. Built-in writable
cache links must resolve within the workspace, a conventional cache namespace,
or another declared writable root; an external referent fails with a copyable
`--allow-write` approval. If the final cache or output directory does not exist,
SBE resolves its nearest existing ancestor and reconstructs the missing suffix
beneath the approved referent, so symlinked cache roots work on a cold build.
Before launch SBE discovers source-tree symlinks
outside generated dependency/output directories, including nested links in an
external source referent, so a link into an ordinary sibling checkout is
readable without granting the sibling's parent. Canonical directory identities
prevent traversal cycles, while entry and depth budgets bound discovery work.
Magic links and protected referents remain rejected.
This validation also applies to built-in readable and executable entries such
as project-local `gradlew` and `mvnw`; a wrapper symlink cannot turn an execute
grant into read access to a protected credential.
Strict mode retains no-follow resolution except for immutable system aliases.
Denied paths include their current canonical target. Strict mode also retains
hard-link alias rejection; standard mode does not recursively scan historical
caches before every launch.

For sbt, standard keeps boot, Ivy, and Coursier dependency caches persistent,
but places the mutable global base in the private per-run directory. This keeps
`~/.sbt` settings and global-plugin locations from becoming a persistence path.
Maven command properties, `MAVEN_ARGS`, project `.mvn/maven.config`,
`MAVEN_OPTS`, and project `.mvn/jvm.config` can select a replacement for the
default writable local repository. SBE follows Maven's source precedence,
resolves relative paths from the project, and rejects ambiguous option forms.

On macOS, secret read denials include both the configured pathname and its
canonical target. A symlinked `~/.ssh`, `.aws`, or similar protected directory
therefore cannot escape the Seatbelt deny rule through pathname resolution.

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

- Linux has no strict domain-egress backend yet. Standard mode permits local
  developer services and cannot force hostile TCP through the proxy. Use
  strict offline mode or combine SBE with a network namespace/firewall in
  hostile CI.
- On Linux kernels before Landlock ABI v4, strict restricted TCP modes refuse
  unless the insecure compatibility option is supplied; in that case TCP
  confinement is unavailable and SBE says so. Standard mode already reports
  network restriction as best-effort.
- Path-based Unix-socket mediation depends on Landlock ABI v9. Where available,
  it remains active even when TCP is unrestricted and grants only SBE's private
  per-run socket root; older kernels cannot mediate filesystem socket paths.
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
--allow-insecure-linux-network  Strict port-only Linux compatibility
--strict                        Require the fail-closed 0.4 boundary
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
