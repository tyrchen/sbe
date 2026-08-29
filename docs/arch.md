# sbe Architecture

> **Status:** Current for SBE 0.4.1. Standard mode is the default; `--strict`
> retains the 0.4 fail-closed boundary. Security requirements and finding IDs are
> defined in the [security hardening design](../specs/security-hardening-design.md).

## 1. Security model

SBE runs package managers, compilers, build scripts, hooks, and plugins as
untrusted code. The operating-system kernel, the installed SBE executable, and
the SBE host process are trusted. Stdin, stdout, and stderr are intentional
capabilities; kernel vulnerabilities, resource exhaustion, and side channels
are outside the boundary.

Both modes retain these cross-platform invariants:

1. the child receives no ambient file descriptors or high-confidence
   credential/capability environment variables;
2. an auto-discovered project configuration cannot expand authority without
   `--trust-project-config`;
3. an empty allowlist never becomes broader network access;
4. the local proxy is authenticated, destination-restricted, and bounded; and
5. capability output does not claim a guarantee the running backend lacks.

Strict mode additionally uses a positive environment allowlist, rejects
persistent W+X, denies ambient local services, keeps source writes narrow, and
fails before launch when a requested high-assurance capability is unavailable.

## 2. Components

```text
apps/cli
  detect command and project
  load and merge trusted/untrusted configuration
  create private per-run storage and effective environment
  start and supervise the proxy when requested
  invoke the platform backend and propagate target status

crates/core
  typed profile, provenance, validation, and W^X lint
  macOS SBPL rendering and sandbox-exec lifecycle
  Linux probe, policy rendering, launcher, Landlock, and seccomp

crates/proxy
  authenticated bounded HTTP CONNECT parser
  IDNA domain allowlist, DNS/address validation, and tunnel lifecycle
```

`SandboxProfile` is the only input to a backend. It contains the final
`NetworkMode`, filesystem and executable grants, protected paths, environment
grants, the effective network origin, and a provenance record for every
permission-bearing entry.

## 3. Policy resolution

Policy sources are applied in this order:

1. built-in platform and ecosystem defaults;
2. global user configuration;
3. auto-discovered project configuration;
4. an explicit `--config` file; and
5. CLI options.

Project configuration is restrictive-only by default. It may add read/execute
denials, remove destinations, or disable previously granted broad modes. It may
not add filesystem, execution, environment, fetch, network, or degradation
authority. Configuration schemas reject unknown fields and enforce file, list,
string, environment, domain, and inheritance limits.

The network booleans used while merging are converted into one exhaustive
effective mode:

| Mode | Meaning |
|---|---|
| `DenyAll` | no Internet socket capability |
| `Proxy` | CONNECT through SBE's authenticated domain-filtering proxy |
| `DirectHttps443` | explicit compatibility mode; TCP destination port only |
| `AllowAll` | trusted request to remove network isolation |

An enabled proxy with no domains resolves to `DenyAll`, never direct port 443.

## 4. Process launch and environment

The child environment is always rebuilt explicitly. Standard mode inherits
ordinary build configuration after removing high-confidence secret, agent,
dynamic-loader, and reserved variables. Strict mode uses the 0.4 positive
allowlist. Explicit `--keep-env`/`--env` grants work in both modes. Inspection
prints environment names and origins with every value redacted.

Every descriptor above stderr is marked close-on-exec. macOS uses a bounded
`fcntl` pass. Linux uses `close_range(CLOSE_RANGE_CLOEXEC)` with a bounded
fallback in its internal launcher.

Each invocation owns a canonical mode-0700 temporary root used for `TMPDIR`,
`TMP`, `TEMP`, and `XDG_RUNTIME_DIR`. Shared temporary roots are not writable;
on macOS they are also denied for reads except for paths explicitly belonging
to the invocation.

In standard mode the workspace is writable and conventional output roots are
writable+executable. Persistent workspace, cache, and install results are
tainted. SBE recognizes only top-level install intent; it does not reproduce a
package manager's lockfile and output grammar. An inherited
`CARGO_TARGET_DIR` receives matching write and execute authority; otherwise
standard Rust mode selects `$PWD/target` without parsing layered Cargo config.
Workspace contents, including `.env*`, are readable in standard mode so Linux
can grant general create/read/write semantics without package-manager-specific
precreation. Strict mode retains project secret-file denials.

Under `--strict`, Cargo's stable `build.build-dir` split keeps final artifacts
in the non-executable `$PWD/target` grant and places intermediate objects, build
scripts, and procedural build tools in the private per-run W+X root. Commands
that execute target artifacts, including cargo-nextest, use a private
`CARGO_TARGET_DIR`. Node install commands keep `node_modules` writable and
non-executable; explicit local-tool execution switches that built-in grant to
read/execute without write. Yarn linker metadata selects only the required
lock/PnP output files. Nested Node projects discover the nearest matching
workspace ancestor, including roots below the Git root, from bounded,
no-follow metadata and add only manager-specific outputs there. Lockfile opt-out
and project-relocation flags are honored before policy preparation. Bun
mutations select `bun.lock` and add `yarn.lock` only for `--yarn`. Python
environment installation and execution apply the same invocation-specific
write-or-execute split to project `.venv` and `venv` roots.
The sandbox never certifies persistent output for later execution outside the
boundary. In strict mode, inode validation rejects a writable regular file
unless every hard-link pathname is accounted for inside writable roots, even
when an unseen alias is not executable. This prevents writable aliases from
modifying source, workflow, toolchain, or other protected content.

## 5. macOS backend

The macOS backend renders a fallible SBPL profile and validates it with
`sandbox-exec` before launching the target. Values are encoded as data: quotes
and backslashes are escaped, and control characters or non-UTF-8 paths are
rejected.

The policy uses:

- allow-most reads with explicit secret and shared-temp denials; secret rules
  cover both configured and canonical paths so symlinks cannot bypass them;
- deny-by-default writes with workspace/tool-data grants in standard mode and
  output-specific grants in strict mode;
- an executable allowlist plus explicit sensitive-binary denials;
- the authenticated proxy plus localhost developer services in standard mode,
  or only the exact proxy port in strict `Proxy` mode; and
- a narrow Mach-service list that excludes `com.apple.SecurityServer`.

The allow-most read model is a compatibility limitation, not a complete home
directory allowlist. CI includes direct keychain and unrelated-localhost denial
probes.

## 6. Linux backend

The async parent serializes a bounded policy into an anonymous descriptor and
spawns the current executable in an internal launcher mode. Its multithreaded
`pre_exec` closure performs only two `fcntl` calls needed to pass the policy
and status descriptors. Before any runtime or worker thread exists, the
launcher:

1. parses and revalidates the bounded payload;
2. safely opens rule paths and compiles Landlock/seccomp;
3. applies `PR_SET_NO_NEW_PRIVS` and both filters;
4. closes ambient descriptors on target exec; and
5. executes the command with a cleared, explicit environment.

A dedicated status descriptor distinguishes setup failure from a target that
itself exits 126.

Linux paths use descriptor-backed resolution and always reject magic links.
Standard mode follows an existing ordinary symlink to its opened referent;
strict mode uses `RESOLVE_NO_SYMLINKS`, with root-owned immutable distribution
aliases as the exception. Landlock
read grants exclude `Execute`; write grants add only data-read rights, while
execute grants are separate. Parent read trees are carved into safe inode
rules when they contain a protected descendant such as `$PWD/.env`.
Only curated public procfs files are readable. `/proc/self` is deliberately
not granted because a descriptor opened by the launcher names only that
process's proc inode; descendants get different inodes after spawning.

On Landlock ABI v6 and newer, every sandbox domain scopes signals, and
restricted network modes also scope abstract Unix sockets. ABI v9 additionally
mediates connections to pathname Unix sockets. `sbe inspect` reports only the
scopes supported and installed on the current kernel.

Landlock ABI v4 can restrict a TCP destination **port**, not an address.
Standard mode therefore permits the TCP needed by local build services and
reports external domain egress as best-effort; proxy-compatible clients still
use the authenticated proxy. Strict proxy mode refuses unless the legacy
`--allow-insecure-linux-network` compatibility acknowledgement is supplied,
ideally together with a network namespace or trusted egress firewall. The
syscall layer also blocks keyring access, cross-process descriptor duplication,
`io_uring`, and old and new mount APIs that could bypass ordinary syscall or
capability paths.

## 7. CONNECT proxy

The proxy listens on an ephemeral IPv4 loopback port and requires a random
256-bit per-run Basic-authentication token. It accepts only HTTP/1.0 or HTTP/1.1
`CONNECT`, canonicalizes lowercase IDNA names, enforces label-boundary
wildcards, and permits port 443 by default.

Request-line, header-line, total-header, header-count, connection, DNS-result,
and task limits are enforced. Header, DNS, connect, aggregate bidirectional
idle, and maximum-tunnel deadlines bound work. IP literals and special-use
resolutions are rejected;
all returned addresses are validated once and connections use only that saved
set. The parent terminates the invocation if its proxy exits unexpectedly.

## 8. Audit and capability reporting

Audit file handling is private, no-follow, regular-file-only, and bounded.
However, neither supported backend currently proves that system denial records
can be correlated to the complete launched process tree. Both therefore report
`audit_stream: false`, and audit flags fail before launch instead of consuming
unrelated system events.

`sbe inspect` reports the live backend feature set, final typed profile,
redacted effective environment, grant provenance, and rendered policy.

## 9. Release trust

Release workflows use least-privilege job permissions and full-SHA pins for
third-party actions. Tags are verified against the workspace version, release
assets are assembled before a draft becomes public, and each supported binary
ships with SHA-256 checksums, an SPDX SBOM, and GitHub build-provenance
attestations. The composite action for 0.4 and newer verifies checksum and
attestation before installation.

## 10. Verification

Unit and integration tests cover profile precedence, untrusted configuration,
environment and descriptor hygiene, W^X, path/symlink handling, proxy parsing
and destination checks, SBPL generation, private audit files, and launcher
capability refusal. GitHub-hosted macOS and Linux jobs additionally execute the
real kernel sandboxes and adversarial cross-process probes.
