# SBE Usable Security Design

- Status: Accepted for 0.4.1
- Delivery: 0.4.1 implements the standard/strict split and immediate
  compatibility changes; narrow persistent approvals remain follow-up work
- Owner: SBE
- Last updated: 2026-08-28
- Supersedes the 0.4 hardening design as the default product contract while
  retaining it as the strict-mode contract:
  [Security Hardening Design](security-hardening-design.md)

## 1. Decision summary

SBE 0.4 fixed real vulnerabilities, but it also made the strongest threat
model the only product mode. That choice turned secondary guarantees into
startup requirements and made SBE understand package-manager internals. The
result is secure only when users can keep it enabled; ordinary failures push
users toward broad escape flags or abandoning SBE entirely.

The next release adopts these decisions:

1. `sbe run -- <command>` uses a usable `standard` mode by default. It reduces
   the blast radius of untrusted build code without promising perfect
   containment.
2. `sbe run --strict -- <command>` provides the fail-closed, high-assurance
   boundary. Strictness is a deliberate user choice, not a hidden requirement
   of every built-in profile.
3. SBE treats the command tree as opaque. It may classify a small number of
   top-level user intents, but it does not reimplement Cargo, npm, Yarn, Bun,
   Poetry, or other package-manager argument and metadata semantics.
4. A symlink is not unsafe by itself. A grant authorizes its resolved target;
   safety depends on the operation, grant origin, resolved location, and
   whether the rule is installed without a race.
5. SBE does not vendor sccache, Cargo, or other tools that it neither patches,
   builds, nor ships. Compatibility is tested through public interfaces.
6. W^X, cache poisoning resistance, exact-output promotion, and strict domain
   egress are separate guarantees. Their absence must not discard the useful
   environment, filesystem, process, and release protections that remain.

This is not a rollback to silent insecurity. `inspect` reports both the
requested mode and the guarantees actually enforced. Standard mode degrades
individual capabilities instead of failing the whole command; strict mode
still fails before launch when one of its promised capabilities is missing.

### 1.1 0.4.1 delivery boundary

0.4.1 delivers the mode split, standard workspace/output behavior,
non-sensitive environment inheritance, referent-aware symlinks, ordinary
sccache compatibility, top-level Cargo install intent, local developer
services, and truthful Linux best-effort networking. It preserves the 0.4
implementation behind `--strict` for regression compatibility.

Narrow durable approvals, per-capability status enums, removal of the remaining
curated standard executable list, and strict-mode startup-cost simplification
are follow-up work. Until then, `inspect` exposes the selected security mode and
the backend's existing feature/policy fields rather than claiming that those
future interfaces already exist.

## 2. Product contract

The primary UX is unchanged and must work without repository-specific SBE
configuration:

```text
sbe run -- cargo build
sbe run -- npm install
sbe run -- uv sync
sbe run -- ./gradlew build
```

Common host-tool arrangements are part of the acceptance matrix, including
tool-manager symlinks, external build directories, compiler wrappers, local
build daemons, and user package caches.

The default promise is:

> If dependency code becomes malicious, SBE substantially limits its access to
> ambient credentials and its ability to persist outside the project and
> expected tool data, while preserving normal build-tool behavior.

The strict promise is:

> If SBE reports that a strict command started, every requested strict
> capability was kernel-enforced; otherwise SBE did not start the command.

SBE is defense in depth. It is not a proof that dependencies, generated
artifacts, the workspace, or persistent package caches are trustworthy.

## 3. Why 0.4 is over-designed

0.4 correctly repaired fail-open networking, ambient environment and
descriptor inheritance, unsafe SBPL encoding, proxy resource exhaustion, and
Linux launch hazards. Those changes directly protect the advertised boundary
at low compatibility cost and remain.

The over-design comes from composing every defense-in-depth idea into the
default launch gate:

- Linux cannot enforce destination-aware domain egress, so an otherwise useful
  filesystem sandbox refuses every normal networked build unless the user
  supplies a flag named `--allow-insecure-linux-network`.
- Persistent W^X is modeled as a universal pre-launch invariant even though
  build directories, virtual environments, `node_modules`, compiler wrappers,
  and installers routinely combine mutation and later execution.
- SBE parses top-level and ecosystem-specific command grammars to decide which
  lockfiles and outputs to pre-create. This logic will always trail the tools it
  is trying to emulate.
- Startup may recursively scan large writable caches for hard links. The cost
  grows with unrelated historical cache content, and the scan still cannot
  establish that the same-user host was uncompromised before SBE started.
- User-managed symlinks are treated as evidence of an attack even when they are
  the normal representation of Homebrew, rustup, mise, asdf, Nix, external
  disks, or monorepo build roots.
- Project configuration is either mostly ignored or entirely trusted for one
  run. There is no durable, narrow approval for the actual authority delta.
- Proposed sccache support adds a Cargo-config parser, a special adapter, a
  private server protocol, supervision, locking, and cache fallback. Repeating
  this pattern for Gradle, Bazel, language servers, test runners, and future
  wrappers would turn SBE into a second process manager for the build
  ecosystem.
- Proposed `cargo install` support reimplements Cargo target discovery,
  installation registries, locking, atomic activation, overwrite ownership,
  and rollback. That is package-manager logic, not sandbox policy.

The issue is not that these attacks are impossible. The issue is that SBE 0.4
does not distinguish:

- a boundary necessary to stop the primary attack;
- a cheap defense-in-depth measure;
- a high-assurance measure with a substantial compatibility cost; and
- an attempt to make hostile output trustworthy after the sandbox ends.

## 4. Threat model by mode

### 4.1 Shared assumptions

Both modes trust the kernel, the installed SBE executable, the user-selected
host toolchain, and the host state that existed before invocation. They do not
defend against a compromised kernel or SBE binary, a malicious same-user
process racing SBE from outside the sandbox, hardware or timing side channels,
or denial of service by CPU and memory exhaustion.

The repository, manifests, dependencies, build scripts, compiler plugins, and
all descendants of the requested command are untrusted. Stdin, stdout, and
stderr are intentional user-granted capabilities.

### 4.2 Standard mode

Standard mode protects:

- high-confidence credential files and secret-bearing environment variables;
- shell startup files, SSH authorization, LaunchAgents, and other persistence
  paths outside the workspace and expected tool data;
- inherited file descriptors and ambient agent sockets;
- setuid escalation and high-risk kernel interfaces where supported;
- direct external network access where the platform can enforce the selected
  policy without breaking ordinary local tooling; and
- the SBE proxy and parent process from unbounded untrusted input.

Standard mode deliberately does not protect:

- integrity of the current workspace;
- confidentiality of files placed inside the selected workspace;
- integrity or confidentiality of declared package caches and build outputs;
- future execution of artifacts written during this or an earlier invocation;
- local development services and build daemons needed by ordinary tooling;
- strict destination-aware egress on Linux; or
- an explicitly selected installation destination such as `~/.cargo/bin` for
  a top-level install command.

Workspace and cache contents are tainted after running untrusted code. Version
control, lockfile verification, cache eviction, review, and CI isolation remain
the appropriate tools for deciding whether to reuse them.

### 4.3 Strict mode

Strict mode additionally requires:

- a read-only source tree unless exact writable outputs are declared;
- non-executable or private dependency caches;
- no persistent write/execute overlap;
- no ambient local services;
- a positive environment allowlist;
- no unapproved project-origin authority expansion; and
- truthful, destination-aware network confinement or no network.

On a Linux backend without destination-aware mediation, `--strict` with domain
egress is unsupported. Strict mode remains useful with a deny-all profile for
an offline build. A future namespace, cgroup, firewall, or seccomp-notify
backend may add strict Linux domain egress without changing this contract.

## 5. Policy modes and capability reporting

The policy model gains an explicit mode:

```rust
pub enum SecurityMode {
    Standard,
    Strict,
}
```

Security features are reported independently rather than collapsed into one
`secure` boolean:

| Capability | Standard | Strict |
| --- | --- | --- |
| Secret file reads | Enforced | Enforced |
| Ambient file descriptors | Closed | Closed |
| Environment | Inherit non-sensitive values | Positive allowlist |
| Workspace writes | Allowed and labeled tainted | Denied except declared outputs |
| Persistent caches | Read/write, non-trusted | Non-executable or private |
| Persistent W^X | Warn and label tainted | Rejected |
| Local IPC | Allowed where normal tooling needs it | Denied unless explicitly granted |
| macOS external egress | Exact proxy policy | Exact proxy policy |
| Linux external egress | Best available, explicitly not strict | Refuse domain mode if unavailable |
| Missing secondary capability | Continue with one concise warning | Refuse before spawn |

`inspect` emits, for each capability, one of `enforced`, `bestEffort`,
`unavailable`, `notRequested`, or `explicitlyAllowed`, plus the origin of the
decision. Human output starts with a short summary; machine output retains the
complete typed policy.

Warnings are deduplicated. A normal run does not print a page of threat-model
text. Persistent platform limitations may be acknowledged in trusted global
configuration, but acknowledgement never changes strict-mode semantics.

## 6. Filesystem policy

### 6.1 Standard authority envelope

Standard mode grants writes to:

- the current workspace;
- the profile's conventional package caches and build data;
- SBE's private per-run temporary directory; and
- an installation root only when the user's top-level command clearly requests
  an install operation.

For npm and npx commands, `--cache` overrides `NPM_CONFIG_CACHE`, then a simple
project `.npmrc` `cache=path`, user `~/.npmrc`, then the default `~/.npm`.
An npm `--userconfig` or explicitly restored user-config locator selects the
user layer. The effective existing user configuration receives an exact read
grant so the child npm, npx, or pnpm process sees the same configuration SBE
used without opening the containing directory.
pnpm's `--store-dir`, configuration environment, project `.npmrc`, and user
`.npmrc` select its store in the same manner. The effective cache/store replaces
the corresponding default writable grant; relative paths are anchored to the
command project. Without an override, `PNPM_HOME/store` precedes the XDG and
conventional defaults. A repository-selected external path requires
`--allow-write`.

For uv and pip commands, `--cache-dir` overrides the corresponding
`UV_CACHE_DIR` or `PIP_CACHE_DIR`. uv then resolves a simple `cache-dir` from
project `uv.toml`, or `[tool.uv]` in `pyproject.toml` when no adjacent
`uv.toml` exists. pip resolves `cache-dir` from its legacy/current user
configuration after environment overrides; each effective existing user
configuration receives an exact read grant. `XDG_CACHE_HOME` and the
conventional cache are the final fallback. The selected cache replaces only
that tool's default grant; a repository-selected uv cache outside the workspace
requires `--allow-write`. Conventional macOS caches live beneath
`~/Library/Caches`; Linux follows XDG conventions.
Poetry follows command `--cache-dir`, `POETRY_CACHE_DIR`, then
`XDG_CACHE_HOME`; its selected `pypoetry` cache replaces the conventional
writable grants, including both historical macOS-compatible locations.

For Gradle commands, the conventional cache grant follows Gradle's effective
user home: `--gradle-user-home`, every accepted `-g` form including `-g/path`,
inherited `GRADLE_USER_HOME`, then `~/.gradle`. Relative selections are anchored
to the command's project. Only runtime subdirectories such as `.tmp`, caches,
wrapper distributions, daemons, and toolchains are writable; the user-home root
and `init.d` remain immutable. The effective user-home root is readable so
Gradle can load root-level properties, initialization scripts, and wrapper
metadata without making those persistence-capable files writable.

For Maven commands, `-D`/`--define maven.repo.local=path` on the actual command
selects the writable local repository, followed in precedence by `MAVEN_ARGS`,
project `.mvn/maven.config`, `MAVEN_OPTS`, project `.mvn/jvm.config`, and the
effective settings `<localRepository>`, then the default `~/.m2/repository`.
Settings selection follows the actual command, `MAVEN_ARGS`, project
`.mvn/maven.config`, then the default user settings. An explicit
`-gs`/`--global-settings` selection is read as the fallback when the effective
user settings do not provide `<localRepository>`. The effective default user
settings and repository roots follow `-Duser.home` from `MAVEN_OPTS`, then
project `.mvn/jvm.config`. Within each source the last property wins. This
matches Maven's CLI merge, where environment arguments precede actual CLI
arguments and CLI user properties override project configuration and JVM system
properties. Relative selections are anchored to the command project; quoted,
expanded, or otherwise ambiguous option values fail with guidance to use a
direct unambiguous command property.
Because `.mvn/maven.config` and `.mvn/jvm.config` are repository-controlled,
their selected repository, settings, or effective home may expand authority
automatically only inside the workspace or conventional `~/.m2/repository`
namespace. An external referent requires a matching explicit writable grant;
command and host-environment sources continue to represent direct user intent.
Explicit user/global settings files and the effective user `.m2` directory are
granted read-only access; only the selected repository receives write access.
A settings path selected by repository-controlled Maven config must stay inside
the workspace or receive explicit `--allow-read` approval. The same read gate
applies when project `.mvn/jvm.config` changes `user.home` and therefore the
effective `.m2` directory. Built-in secret denials remain sealed even against
an explicit read grant.

It denies writes everywhere else. In particular, home-directory persistence,
credentials, shell startup, SSH authorization, user service configuration, and
system locations remain outside the envelope.

The workspace is also readable as one authority root in standard mode. Project
`.env*` files are therefore not a separate confidentiality boundary: carving
them on Linux prevents general `O_RDWR` creation of new package-manager files
and leads back to per-tool precreation. Credentials that must remain secret from
dependencies belong outside an untrusted workspace or require strict mode.
When a Node command starts in a declared monorepo member, bounded no-follow
metadata discovery promotes the matching workspace root to readable input and
grants only its manager-specific lockfile/dependency outputs for write and
execution; it does not make the whole parent workspace writable.
On Linux, missing selected root lockfiles are created with the descriptor-bound
no-follow helper before Landlock, and source-symlink discovery starts once at
the workspace root so linked root dependencies receive safe referent grants.

Recognizing `cargo install` as install intent is acceptable; parsing Cargo
metadata and recreating Cargo's installation transaction is not. The package
manager owns its destination format, locking, overwrite behavior, and rollback.
An explicit `--root` is the selected install root and takes precedence over
`CARGO_INSTALL_ROOT`, a direct `--config install.root='path'`, `CARGO_HOME`, and
the default. An implicit Cargo config install root is rejected before launch
with `--root` guidance rather than granting a repository-selected external
location or reproducing Cargo's layered configuration. Inspection must say
that the selected install root is writable and that the installed result is
untrusted.
Cargo's writable `registry` and `git` dependency caches follow the same
effective `CARGO_HOME`, while its credential files stay denied.

Path grants derived from environment variables use the same final precedence
as the child environment: trusted configuration and explicit CLI environment
values override the parent environment. Policy compilation must not authorize
one Cargo target or install root and then launch Cargo with another.
Tool-native precedence must be preserved: Cargo `--target-dir` wins first,
then `CARGO_TARGET_DIR`, then `CARGO_BUILD_TARGET_DIR`, then a direct
`--config build.target-dir='path'`. Cargo install uses `--root`, then
`CARGO_INSTALL_ROOT`, then a direct `--config install.root='path'`, then
`CARGO_HOME` and the default. Gradle's user-home flags and
`gradle.user.home` system property override `GRADLE_OPTS` and
`JAVA_OPTS`, then `GRADLE_USER_HOME`. Repeated JVM properties use the last
value. An inherited JVM-option value requiring shell expansion is rejected with
guidance to use an explicit, unambiguous user-home mechanism.

Built-in profiles should remain small declarations of roots, domains, reserved
environment names, and optional local IPC needs. They must not contain a second
grammar for every supported package manager.

Project-relocation options do not silently retarget an already resolved policy.
Until configuration discovery and every grant are rooted at the requested
project, both modes reject the option early and tell the user to change
directory before invoking SBE. Cargo `--manifest-path` remains usable when its
resolved manifest stays inside the selected workspace, including release
workflow subcrates, but an external manifest receives the same early guidance.

### 6.2 Strict authority envelope

Strict mode does not infer fine-grained output authority from arbitrary command
arguments. Writable roots come from small built-in strict profiles, trusted
global configuration, explicit CLI grants, or approved project requirements.
Temporary build roots are preferred. If a tool cannot operate without broad
source writes or persistent W+X, strict mode returns an actionable error and
standard mode remains available.

### 6.3 Hard links

Standard mode performs no recursive hard-link scan. Such a scan has unbounded
cost relative to the requested command and assumes it can validate historical
same-user state. Standard mode already treats writable workspace and cache
inodes as untrusted.

Strict mode avoids the problem structurally by using newly created private
roots. For an explicitly granted existing literal file, it may reject
`link_count > 1` with an O(1) metadata check. It must not recursively walk a
large user cache before launch.

## 7. Symlink semantics

### 7.1 Principle

A policy grant names an object through a path. If the path contains a symlink,
the grant applies to the resolved referent, not to the spelling of the path.
The question is therefore not “does this path contain a symlink?” but “is this
referent within the authority the grant source may confer?”

SBE must never reject a path merely because it contains an ordinary symlink.
It always rejects magic links such as `/proc/*/fd/*` as policy inputs.

### 7.2 Rules by operation and origin

| Operation | Built-in or unapproved project path | Trusted global/CLI/approved path |
| --- | --- | --- |
| Read | Follow if the referent does not intersect a protected read denial | Follow; protected reads still require an explicit secret override |
| Write | Follow only when the referent remains inside the mode's writable envelope | The resolved referent is the authority the user explicitly granted |
| Execute | Follow tool-manager and system aliases; validate the referent under an executable/readable root | Authorize the exact resolved referent or resolved subtree |
| Deny | Deny both the lexical path and the current referent when it exists | Same |

Examples:

- `/opt/homebrew/bin/rustup -> ../Cellar/rustup/.../rustup-init` is valid. The
  immutable resolved tool is what executes.
- `~/.cargo/bin/cargo -> rustup` is valid. A user-managed toolchain symlink is
  normal host state, not a project attack.
- `$PWD/target -> /Volumes/build/sbe-target` requires the resolved target to
  be in a trusted writable root. Otherwise SBE prints the exact target and
  offers a one-time or durable narrow approval; it does not tell the user to
  remove the symlink.
- `$PWD/output -> ~/.ssh` is not authorized by the built-in workspace grant.
- `~/.npm -> ~/.config/autostart` is not authorized by the built-in cache
  grant; the user must explicitly grant the resolved target if that unusual
  layout is intentional. A link into `~/.cache` or `~/Library/Caches` remains
  inside the conventional cache envelope.
- A source symlink into an ordinary sibling checkout is readable in standard
  mode, but a symlink into `~/.aws` remains denied.

### 7.3 Resolution and race handling

The trusted parent resolves each existing grant before the child starts and
retains the lexical spelling for audit, but replaces writable/executable
symlink grants with their canonical snapshot. The launcher therefore never
reopens a mutable lexical link after its referent was approved. On Linux it
opens the canonical final object with descriptor-relative kernel resolution,
rejects magic links, validates the opened object's type and boundary, and
installs the Landlock rule from that file descriptor.
Before retaining a canonical built-in read or execute alias, SBE compares its
referent with every protected read denial. This check includes project-local
wrapper entries such as `gradlew` and `mvnw`, because Landlock execute authority
also permits reading the executable inode. A built-in alias never overrides a
protected read denial.
When the final writable object is missing, policy resolution walks to the
nearest existing ancestor, canonicalizes that ancestor, appends the unresolved
suffix, and validates the reconstructed target against the same writable
envelope. The launcher receives only that snapshot. Thus a cold cache such as
`~/.cache -> /mnt/cache` with missing `~/.cache/coursier` works after
`/mnt/cache/` is approved, without reopening the mutable home-directory link.
For the built-in workspace read grant, standard mode discovers symlinks in the
source tree and performs a shallow symlink-entry check inside conventional
generated dependency and output roots, then installs separate read rules for
safe external referents. It does not recurse through ordinary contents beneath
those generated roots. External directory referents are inspected for nested
source links; canonical directory identities break cycles, and fixed
entry/depth budgets bound startup time and memory. Exceeding either budget
fails policy resolution instead of continuing with a partial authority view.
Referents overlapping protected read denials are omitted.

On macOS it resolves and validates the target before rendering its canonical
SBPL grant. Because the untrusted child has not started and cannot write
the protected ancestors after launch, a malicious same-user process racing
that snapshot is part of the pre-compromised-host exclusion, not a reason to
reject every user symlink.

Missing optional built-in alternatives are skipped. A broken or cyclic
explicit grant is an error because its authority is ambiguous. A missing
literal write target is created beneath an already approved, safely opened
parent; its parent may itself resolve through an approved symlink.

### 7.4 Deny paths

A deny path that is missing or contains a broken symlink does not prevent an
unrelated command from starting. SBE installs every denial it can represent,
reports unresolved strict denials as unavailable, and in strict mode fails only
when an overlapping allow could expose that unresolved location.

Landlock's inode semantics must be described honestly: pathname aliases cannot
be distinguished after they reach the same inode. Standard mode does not scan
the filesystem looking for all possible aliases. Strict mode uses isolated
roots rather than claiming that an exhaustive alias proof is practical.

## 8. Environment, descriptors, and process execution

### 8.1 Environment

Standard mode inherits ordinary build configuration such as compiler flags,
feature switches, terminal settings, and tool paths. It removes:

- names matching a maintained high-confidence secret pattern such as tokens,
  passwords, private keys, and cloud credentials;
- known credential variables independent of spelling convention, including
  prefix-encoded forms such as Terraform's `TF_TOKEN_<host>` and concatenated
  platform names such as Azure Pipelines' `SYSTEM_ACCESSTOKEN` and GitLab's
  `CI_JOB_JWT` / `CI_JOB_JWT_V2`, plus OIDC bearer paths such as
  `AWS_WEB_IDENTITY_TOKEN_FILE` and `ARM_OIDC_TOKEN_FILE_PATH`, certificate
  locators such as `ARM_CLIENT_CERTIFICATE_PATH`, and custom credential stores
  such as `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `CLOUDSDK_CONFIG`,
  `AZURE_CONFIG_DIR`, Azure
  client certificates selected by `AZURE_CLIENT_CERTIFICATE_PATH`, and Docker
  client TLS key directories selected by `DOCKER_CERT_PATH`, custom GitHub CLI
  credential directories selected by `GH_CONFIG_DIR`, and GnuPG homes selected
  by `GNUPGHOME`; Cargo credential files beneath the effective `CARGO_HOME` and
  GitHub CLI credentials beneath an inherited `XDG_CONFIG_HOME` receive
  matching path denials rather than withholding those ordinary configuration
  locators; npm user-config files selected by `NPM_CONFIG_USERCONFIG` are
  withheld because they commonly contain registry authentication tokens, as
  are Kerberos ticket-cache/keytab locators `KRB5CCNAME`, `KRB5_KTNAME`, and
  `KRB5_CLIENT_KTNAME`, plus the custom netrc locator `NETRC`;
- Python package configuration locators `PIP_CONFIG_FILE` and
  `UV_CONFIG_FILE`, because those files can contain authenticated indexes;
- agent and credential socket variables;
- dynamic-loader injection variables; and
- SBE-reserved proxy, runtime, and policy variables.

The user may pass a removed value explicitly. `inspect` shows names and origins,
never values. Strict mode retains 0.4's positive allowlist behavior.

This is an intentional difference in guarantee: a denylist cannot prove that
standard mode removed every application-specific secret, so standard mode does
not claim that it did.

### 8.2 Descriptors and privilege

Closing ambient descriptors, using private temporary storage, setting
`no_new_privs`, blocking dangerous kernel interfaces, and using the
single-threaded Linux launcher have low compatibility cost and remain in both
modes.

Execution allowlisting is weak against malicious native code and creates
continuous toolchain breakage. The target standard design therefore blocks
small, reviewed sets of true capability brokers where the OS can enforce that
distinction, and relies on filesystem, secret, network, and `no_new_privs`
boundaries for the primary protection. 0.4.1 keeps the existing curated list
but resolves normal tool-manager aliases and adds black-box compatibility tests;
removing that list safely is follow-up work. Strict mode retains a positive
execute allowlist.

## 9. Network and local IPC

### 9.1 macOS

Standard mode uses the domain proxy for external traffic and permits local IPC
needed by developer tools: loopback TCP and ordinary same-user Unix sockets are
inside the standard trust envelope. Agent and credential socket variables are
still removed, but standard mode does not claim isolation from discoverable
local services. Strict mode permits only SBE-owned proxy/private IPC endpoints
explicitly present in the final policy.

When the external proxy is active, standard mode injects localhost-only
`NO_PROXY`/`no_proxy` and Java `http.nonProxyHosts` values so ordinary clients
actually use the permitted loopback path. Strict mode keeps those bypasses
empty.

### 9.2 Linux

Landlock destination-port filtering is not domain filtering and cannot express
“any dynamic port on loopback, but no remote host.” Standard mode permits the
TCP needed by dynamic loopback tools. Therefore it cannot force hostile Linux
code through the proxy; proxy-compatible package managers still use the
injected proxy settings, but capability output labels external egress
`bestEffort`. SBE keeps the filesystem, environment, descriptor, privilege,
and proxy defenses instead of refusing the entire command.

On Landlock ABI v9 and newer, filesystem-backed Unix-socket resolution remains
mediated independently of TCP policy. Standard mode grants it only beneath the
private per-run root used by cooperating build processes; capability brokers
such as `/var/run/docker.sock` remain outside the envelope. Older kernels
cannot enforce pathname socket mediation and must report it unavailable rather
than imply that unrestricted TCP also authorizes ambient filesystem sockets.

Strict Linux domain egress remains unavailable until a destination-aware
backend exists. This limitation is a capability result, not a command-line
option named “insecure” that every Linux user must routinely paste.

### 9.3 Proxy

Proxy parser bounds, timeouts, destination validation, authentication, and
structured shutdown remain. They protect a trusted component from hostile
input and have negligible ecosystem compatibility cost.

## 10. sccache and other host tools

### 10.1 No vendoring

SBE must not vendor sccache. Vendoring is justified only when SBE patches,
builds, or ships that source, or when a reproducible source snapshot is itself
a released product input. SBE does none of those things.

The temporary local sccache checkout was useful for a one-time source study and
line-level references. That makes it research material, not a product
dependency. Ordinary Rust libraries remain declared dependencies
resolved by Cargo and pinned through `Cargo.lock`; external tool source trees
do not become repository dependencies merely because SBE interoperates with
them.

A vendored tree does not prove runtime compatibility with the user's installed
binary. It creates an update obligation, increases repository and review
surface, can mislead reviewers into treating sccache as part of SBE's audited
TCB, and establishes a pattern that cannot scale to every wrapper and daemon.

Research documents use immutable upstream permalinks. CI exercises a bounded
matrix of released sccache binaries through their public CLI and environment
contract, with versions and downloaded artifacts pinned by checksum in test
metadata. Test fixtures are not linked into or shipped with SBE.

### 10.2 No first-class adapter

Standard mode treats a user-installed compiler wrapper or build daemon as part
of the trusted host toolchain. Symlinked wrapper executables and ordinary local
IPC work under the standard local-tool policy. SBE does not parse Cargo's
layered configuration, replace sccache configuration, own the cache server,
or implement sccache-specific locking and fallback.

This means an ambient helper can perform work outside the sandbox. Standard
mode reports that local helpers are trusted and does not claim otherwise.
Strict mode denies ambient helper IPC unless the user provides a narrow strict
helper policy; it may require disabling the wrapper. This honest boundary is
preferable to quietly implementing a partial clone of each tool's supervisor.

The same rule applies to Gradle daemons, Bazel servers, language-server
helpers, and future compiler wrappers.

## 11. Configuration and approval UX

Configuration is separated into requirements and trusted authority:

- A repository `.sbe.yaml` may select a profile, add restrictions, and request
  additional capabilities.
- Requests already inside the active mode's authority envelope are applied
  automatically.
- Requests that cross the envelope are shown as a concise diff and require a
  trusted CLI/global grant or a stored approval.
- `sbe trust` stores the repository identity, normalized capability delta, and
  config digest. Editing the authority-relevant portion invalidates approval.
- CI never prompts. It can verify a committed policy against separately
  provisioned trusted configuration or an explicit digest.

Approval is per capability, not “trust the entire project config.” Adding one
external build root must not also authorize arbitrary environment variables,
all network access, or future unrelated edits.

Errors name the blocked operation, lexical path, resolved target, source of the
request, and smallest safe remediation. SBE must not recommend a broad network,
home-directory, or executable-tree grant when a narrow one suffices.

## 12. Security-control disposition

| 0.4 or proposed control | New disposition | Reason |
| --- | --- | --- |
| Empty network allowlist and helper failure fail closed | Keep in both modes | Fixes a real fail-open transition |
| Ambient descriptor closure | Keep in both modes | Strong protection, low compatibility cost |
| SBPL encoding and bounded config parsing | Keep in both modes | Untrusted data must not become policy syntax |
| Descriptor-based Linux rule installation | Keep, but follow ordinary symlinks | Prevent races without banning normal layouts |
| Single-threaded Linux launcher | Keep | Avoids unsafe post-fork runtime behavior |
| Proxy parser/resource/destination hardening | Keep | Protects the trusted broker cheaply |
| Release checksums, attestations, least privilege | Keep | Protects SBE's own distribution chain; no runtime UX cost |
| Positive environment allowlist | Strict only | Strong guarantee, significant build compatibility cost |
| Per-binary executable enumeration | Strict only | High maintenance and limited value against native malicious code |
| Exact workspace output and lockfile inference | Remove from standard | Reimplements changing package-manager grammars |
| Recursive hard-link scans | Remove | Unbounded startup cost and mismatched pre-host assumption |
| Persistent W^X rejection | Strict only | Standard outputs and environments routinely transition from write to execute |
| Project config all-or-nothing trust flag | Replace | Narrow durable approvals preserve provenance with less friction |
| Linux strict-domain startup refusal | Strict only | Partial sandboxing remains useful in standard mode |
| Correlated audit as launch requirement | Strict request only | Observability must not disable unrelated enforcement |
| Vendored sccache/Cargo sources | Remove | SBE neither patches nor ships them |
| Sccache managed adapter | Remove | Does not scale across host tools; changes the trust boundary silently |
| Trusted-parent `cargo install` reimplementation | Remove | Attempts to recreate Cargo and bless hostile output |

## 13. Supply-chain attack analysis

Not every possible supply-chain attack requires every 0.4 mechanism.

- Credential theft is primarily reduced by secret-path denial, environment
  filtering, descriptor closure, agent isolation, and network controls.
- Persistence outside the repository is primarily reduced by the write
  envelope and `no_new_privs`, not by scanning package caches for hard links.
- C2 and second-stage download are reduced by macOS egress enforcement and the
  proxy. Linux standard mode cannot honestly close this channel with current
  primitives, but filesystem and credential containment still reduce impact.
- Writes to toolchain and install roots are prevented during an ordinary strict
  invocation. Standard mode accepts that mutable caches, explicit install
  roots, wrappers, and workspace artifacts are part of the user's development
  state and labels them tainted.
- Release supply-chain attacks against SBE itself require checksums,
  attestations, pinned CI actions, and least-privilege publishing; those
  controls remain fully necessary.

The right comparison is not “perfect sandbox versus no attack.” It is “SBE
enabled for routine work versus SBE bypassed because routine work fails.” A
default control is successful only if it both blocks meaningful attacks and
stays enabled.

## 14. Acceptance criteria

### 14.1 Standard usability

The following work on supported macOS and Linux hosts with no project
`.sbe.yaml`, no trust flag, and no broad escape flag:

```text
sbe run -- cargo build
sbe run -- cargo test
sbe run -- cargo install --path apps/cli
sbe run -- npm install
sbe run -- npm test
sbe run -- uv sync
sbe run -- uv run pytest
sbe run -- ./gradlew build
```

The matrix includes Homebrew, rustup, mise/asdf-style symlinks, a source link
into a sibling checkout, a globally configured sccache, concurrent builds, an
approved external target-directory symlink, and warm package caches.

Standard policy compilation never recursively scans unrelated caches or the
workspace for hard links. Read-denial carving may inspect siblings along the
small number of protected paths, but its cost does not grow with unrelated
cache history. A missing optional tool path, broken unrelated deny path,
unavailable audit stream, or unsupported strict network primitive does not
prevent launch.

### 14.2 Standard security

Existing hostile fixtures must still fail to read known host credential files
outside the workspace,
inherit sentinel credential environment variables or descriptors, modify
shell/SSH persistence targets outside the workspace, invoke privilege
escalation successfully, or exhaust/crash the trusted proxy. Tests separately
assert and document the weaker Linux network and workspace/cache integrity
properties.

### 14.3 Strict security

Strict adversarial tests prove the positive environment allowlist, read-only
source policy, private/read-only caches, persistent W^X, no ambient local IPC,
no unapproved project authority, and truthful network capability refusal.
Tests do not claim strict Linux domain egress until a destination-aware backend
exists.

### 14.4 Configuration and diagnostics

An external symlinked output requires at most one narrow approval. A changed
authority delta invalidates only the affected approval. Every denial gives one
copyable narrow remediation, and `inspect` accurately distinguishes enforced
from best-effort behavior without exposing values or secrets.

## 15. Migration from 0.4

1. Introduce `SecurityMode` and capability reporting before removing old
   checks. Initially map 0.4 behavior to `strict` for regression comparison.
2. Make `standard` the default and remove the Linux routine opt-in named
   `--allow-insecure-linux-network`. Preserve the option only for an explicit
   strict port-only compatibility request.
3. Replace recursive hard-link validation and command-specific lockfile/output
   preparation in standard mode with the authority envelope.
4. Change Linux path opening from “reject every non-system symlink” to “open
   the referent, validate its boundary, install the rule from its FD.”
5. Replace `--trust-project-config` with narrow approval records while keeping
   the flag as a one-run compatibility mechanism during migration.
6. Remove the proposed sccache adapter and Cargo-install promotion work from
   the roadmap. Remove vendored tool sources before merge; retain only
   black-box research conclusions and immutable upstream references.
7. Rewrite README claims around the standard/strict distinction. Never call
   Linux standard networking domain-confined.

Implementation should delete superseded complexity rather than leave dormant
command parsers and validators behind. Strict mode keeps only mechanisms that
are part of its explicit contract.

## 16. Non-goals

- Making untrusted build artifacts safe to execute outside SBE.
- Certifying the integrity of a pre-existing user toolchain or package cache.
- Managing the lifecycle of every build daemon and compiler wrapper.
- Reproducing package-manager transaction semantics.
- Identical enforcement mechanisms across macOS and Linux.
- Protecting against a malicious same-user process already running outside
  SBE.
- Trading all useful containment for a single unavailable platform guarantee.
