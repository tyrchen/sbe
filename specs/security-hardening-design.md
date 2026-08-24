# SBE Security Hardening Design

- Status: Implemented for SBE 0.4.0; strict Linux domain egress and correlated
  audit streaming remain explicitly unavailable
- Review baseline: `sbe` 0.3.3 (`4311190`)
- Last updated: 2026-08-23
- Scope: macOS SBPL, Linux Landlock/seccomp, local CONNECT proxy, configuration,
  process launch, audit, and release workflows

## 1. Summary

SBE 0.3.3 has a useful filesystem sandbox and a small attack surface, but it
does not yet provide the isolation guarantees implied by "domain-filtered
network" and "protected secrets" against a malicious build or install script.
The most important confirmed problems are:

1. Linux Landlock filters a destination **port**, not a destination IP. A child
   can read the proxy's ephemeral port from `HTTPS_PROXY` and connect directly
   to an attacker-controlled host listening on that port, bypassing the domain
   allowlist.
2. On macOS, proxy-enabled profiles with an empty domain allowlist fall through
   to the no-proxy policy and allow direct TCP to any host on port 443.
3. The child inherits the complete parent environment and inherited file
   descriptors. Secrets and already-open files or sockets therefore bypass the
   path and network policy.
4. Auto-discovered project configuration and project-controlled Cargo
   configuration can expand authority before the project has been trusted.
5. User-controlled paths are interpolated into SBPL without escaping, and the
   Linux path-opening logic relies on path prefixes and non-atomic symlink
   checks.
6. The proxy has no request-size, connection-count, or timeout limits and does
   not constrain destination address classes or ports.
7. Persistent paths are commonly both writable and executable. On Linux,
   `AccessFs::from_all()` explicitly grants execute permission to every writable
   path. A malicious dependency can poison future builds or toolchains.

These issues require a staged hardening release. Documentation must stop
claiming strict Linux domain confinement until a destination-aware enforcement
backend exists.

## 2. Goals

- Prevent untrusted build code from reading ambient credentials or reusing
  inherited capabilities.
- Make the effective policy fail closed and unambiguous on both platforms.
- Prevent an untrusted repository from silently weakening its own sandbox.
- Make every rendered policy safe for arbitrary supported path bytes.
- Bound the trusted proxy's memory, file-descriptor, task, and connection use.
- Prevent persistent writable content from becoming executable by default.
- Report backend capabilities and degradation accurately.
- Make releases independently verifiable and minimize CI token authority.

## 3. Non-goals

- Defending against kernel vulnerabilities or a compromised SBE binary.
- Eliminating timing, cache, CPU, memory, or other side channels.
- Inspecting TLS application data or authorizing individual HTTP paths.
- Claiming identical kernel mechanisms on macOS and Linux. The required
  security invariants are cross-platform; their implementation may differ.

## 4. Trust model

### 4.1 Protected assets

- Credentials in environment variables, credential files, keychains, agents,
  inherited descriptors, and local services.
- Source, VCS metadata, CI definitions, lockfiles, and toolchain installations.
- Other same-user processes and data, including shared temporary directories.
- The integrity and availability of the parent SBE process and its proxy.
- Release credentials and distributed artifacts.

### 4.2 Adversary

The adversary controls the repository being built, its `.sbe.yaml`, package
metadata, dependency hooks, compiler plugins, build scripts, test commands, and
all input sent from the sandbox to the proxy. The adversary can race filesystem
operations and deliberately exhaust local resources. The operating-system
kernel and the SBE executable are trusted.

An automatically discovered project file is therefore untrusted input, not a
security-policy authority. Global configuration, an explicitly named config,
and CLI flags are trusted user input, subject to validation.

### 4.3 Required invariants

1. **No ambient capabilities:** the child receives only explicitly selected
   environment variables and descriptors.
2. **Deny means deny:** an empty allowlist or failed helper cannot become a
   broader fallback policy.
3. **No self-authorization:** project-controlled input cannot expand read,
   write, execute, network, environment, or degradation permissions without an
   explicit trust decision.
4. **Exact policy encoding:** a path or domain is data and cannot alter the
   generated policy language.
5. **Bounded trusted components:** untrusted traffic cannot cause unbounded
   allocation, tasks, descriptors, or connection lifetime in SBE.
6. **Persistent W^X:** persistent mutable caches and toolchains are not both
   writable and executable in the same invocation unless explicitly approved.
7. **Truthful capability reporting:** SBE refuses a requested strict guarantee
   when the backend cannot enforce it.

## 5. Findings

Severity describes impact under the adversary in section 4, not exploit
complexity in an arbitrary desktop threat model.

The findings have different kinds of evidence:

- **Confirmed implementation defects:** SEC-001 through SEC-004, SEC-006
  through SEC-010, SEC-013, SEC-016, and SEC-020 have a concrete bypass,
  fail-open path, leak, panic, race, or resource-exhaustion path in current
  code.
- **Threat-model/design gaps:** SEC-005, SEC-011, SEC-014, SEC-015, SEC-018,
  and SEC-019 behave substantially as implemented but are too permissive for
  the adversary defined in section 4.
- **Assurance gaps:** SEC-012 and SEC-017 need a safer architecture or a test
  that proves the claimed boundary; the review does not claim a demonstrated
  keychain theft or post-fork deadlock.
- **Maintenance:** SEC-021 does not directly weaken sandbox enforcement.

| ID | Severity | Area | Confirmed finding | Required disposition |
|---|---|---|---|---|
| SEC-001 | Critical | Linux network | Landlock `NetPort` authorizes the proxy's destination port for every IP. Direct TCP to an attacker using that port bypasses the domain proxy. | Do not describe port pinning as domain confinement. Strict mode must use destination-aware mediation or refuse to run. |
| SEC-002 | High | macOS network | `allowDomains: []` prevents proxy startup, then SBPL falls through to direct `*:443`. | Replace boolean fall-through with a closed `NetworkMode`; empty allowlist means `DenyAll`. |
| SEC-003 | High | Process launch | `Command` inherits the complete parent environment. Filesystem deny rules do not protect secrets already present in environment variables. | Clear the environment and rebuild an explicit safe set; redact inspection output. |
| SEC-004 | High | Process launch | Non-`CLOEXEC` descriptors can carry open files and connected sockets across exec, bypassing later path/network restrictions. | Close or mark close-on-exec for every descriptor other than the intended stdio and launcher channels. |
| SEC-005 | High | Config trust | Auto-discovered `.sbe.yaml` may enable all network, disable the proxy, allow degraded mode, or add broad filesystem and executable grants. | Project config may restrict only unless explicitly trusted. |
| SEC-006 | High | Rust profile | `$PWD/.cargo/config.toml` controls `target-dir`, which is added as a curated write+exec path before provenance markers. It can point at `$HOME` or another sensitive tree. | Treat it as project-origin input; restrict it to approved output/cache roots and run every lint. |
| SEC-007 | High | macOS policy | SBPL literal, subpath, and regex values interpolate `Path::display()` without escaping quotes, backslashes, newlines, or control characters. | Introduce a typed, fallible SBPL encoder and reject unsupported paths. |
| SEC-008 | High | Linux paths | Trust is inferred from prefixes including `/tmp`, `/var/tmp`, `/run`, `/opt`, and `/var/cache`; final-component symlink checks and later `PathFd::new()` are racy and follow ancestors. | Resolve by descriptor, atomically reject symlinks/magic links, and verify every trusted ancestor's owner/mode. |
| SEC-009 | High | Proxy | Lines, headers, accepted connections, spawned tasks, connection setup, and tunnel lifetime are unbounded. The sandbox can exhaust the trusted parent. | Add strict parser, concurrency, byte, header, connect, and idle limits. |
| SEC-010 | High | Filesystem/exec | Linux write access uses `AccessFs::from_all`, granting execute to writable trees. Profiles also make mutable caches and toolchains writable+executable. | Use write-only rights and enforce a W^X overlap lint with narrow per-run exceptions. |
| SEC-011 | High | Workspace/temp | Most profiles grant the entire working tree write access and grant shared system temp directories. Build code can persistently modify source, VCS hooks, CI files, or same-user temp data. | Use private per-run temp and output-specific workspace grants; protect source/VCS/CI metadata by default. |
| SEC-012 | High | Linux launch | The Tokio post-fork `pre_exec` closure invokes external Rust libraries and consumes complex objects. A source-token scan cannot establish async-signal safety of dependencies or destructors. | Move policy installation into a single-threaded launcher process or a syscall-only audited shim. |
| SEC-013 | High | Proxy destination | Hostname allowlisting is followed by unconstrained resolver/connect behavior. Allowed names may resolve to loopback/private/link-local addresses; arbitrary CONNECT ports and IP literals are accepted. Malformed bracket syntax can panic a task. | Canonicalize names, restrict ports, resolve once, validate all addresses, reject special ranges by default, and make parsing total. |
| SEC-014 | Medium | macOS network | Proxy mode additionally permits every localhost port and inbound localhost binding, exposing local services beyond the proxy. | Separate proxy access, loopback destinations, and inbound binds into explicit capabilities. |
| SEC-015 | Medium | Linux capability | `CompatLevel::BestEffort` can silently remove unsupported access rights. One `allow_degraded` switch disables three unrelated checks, and ABI support is capped below the crate's current capability. | Use hard requirements for promised rights and capability-specific, trusted degradation flags. |
| SEC-016 | Medium | Audit | macOS watches all `sandboxd` events; Linux parses global `/dev/kmsg` without child-PID correlation. Logs may be misattributed, leaked, or flooded. Log creation does not enforce private mode/no-follow. | Correlate a launched process/domain, secure the output file, sanitize output, bound buffering, and report availability dynamically. |
| SEC-017 | Medium | macOS IPC | The SBPL baseline permits `com.apple.SecurityServer`, while the documented model claims keychain protection. Direct Security.framework behavior is not tested. | Remove the service unless required; add a keychain access denial test and narrow any exception. |
| SEC-018 | Medium | Config/parser | YAML accepts unknown fields and unbounded project-controlled input. Domain matching is case-sensitive and lacks IDNA/trailing-dot normalization. `serde_yaml` is deprecated. | Define limits and strict schemas, validate/canonicalize values, and migrate to a maintained parser after review. |
| SEC-019 | Medium | Release | Workflows use mutable third-party action tags, give `contents: write` globally (including PR builds), and publish unsigned assets without checksums, attestations, or an SBOM. | Pin action SHAs, use least privilege, and publish verifiable provenance and integrity metadata. |
| SEC-020 | Low | Inspection/logging | `sbe inspect` serializes `profile.env` values and policy/log renderers do not consistently escape terminal or YAML control data. | Show environment names with redacted values and use safe structured renderers. |
| SEC-021 | Low | Dependencies | `cargo machete` reports `tempfile` unused by `apps/cli`; `cargo deny` reports known duplicate dependency families. | Remove the unused dependency and monitor/deduplicate where practical. |

`cargo audit` and `cargo deny check advisories bans licenses sources` passed at
the review baseline. Those results do not address the design and policy issues
above.

### 5.1 Code evidence map

- Process environment, proxy startup, and inspection:
  [`apps/cli/src/executor.rs`](../apps/cli/src/executor.rs)
- Configuration precedence and project discovery:
  [`crates/core/src/config.rs`](../crates/core/src/config.rs)
- Cargo target discovery and permission provenance:
  [`crates/core/src/profile/mod.rs`](../crates/core/src/profile/mod.rs)
- Linux rights, ports, path opening, and degradation:
  [`crates/core/src/sandbox/linux/landlock.rs`](../crates/core/src/sandbox/linux/landlock.rs)
- Linux post-fork setup:
  [`crates/core/src/sandbox/linux/exec.rs`](../crates/core/src/sandbox/linux/exec.rs)
- macOS network branches, Mach services, and path rendering:
  [`crates/core/src/sandbox/macos/sbpl.rs`](../crates/core/src/sandbox/macos/sbpl.rs)
- CONNECT parsing and tunnel lifecycle:
  [`crates/proxy/src/server.rs`](../crates/proxy/src/server.rs)
- Global audit streams and log files:
  [`apps/cli/src/audit.rs`](../apps/cli/src/audit.rs)
- Workflow permissions and mutable action references:
  [`build.yml`](../.github/workflows/build.yml),
  [`release-cli.yml`](../.github/workflows/release-cli.yml), and
  [`test-cli.yml`](../.github/workflows/test-cli.yml)

At the review time, crates.io reported `sbexec` 0.3.3, but the repository had no
`sbexec-v0.3.3` tag and GitHub Releases still reported 0.3.2 as latest. The
release design must either publish all promised channels atomically or state
which channels are intentionally independent.

### 5.2 Implementation disposition

SBE 0.4.0 implements the required disposition for SEC-001 through SEC-021.
Where the host primitive cannot support the requested guarantee, the result is
an explicit unavailable capability rather than a weaker success:

| Findings | 0.4.0 disposition |
|---|---|
| SEC-001, SEC-002, SEC-014, SEC-015 | Typed network modes; exact macOS proxy port; Linux strict proxy refusal with an explicit port-only compatibility flag; restricted Internet datagram/raw/packet sockets |
| SEC-003, SEC-004, SEC-020 | Positive environment allowlist, reserved runtime variables, redacted inspection, and ambient descriptor closure |
| SEC-005, SEC-006, SEC-018 | Strict bounded schemas, maintained YAML parser, IDNA types, provenance, and restrictive-by-default project policy; project Cargo target discovery no longer creates grants |
| SEC-007, SEC-008, SEC-012 | Fallible SBPL encoding, descriptor-relative Linux path handling, and a single-threaded internal Linux launcher |
| SEC-009, SEC-013 | Authenticated proxy with parser, concurrency, address-count, timeout, destination-port, and special-address limits |
| SEC-010, SEC-011 | Data-only write/read rights, persistent W^X validation, output-specific workspace grants, and private per-run temp |
| SEC-016, SEC-017 | Secure bounded audit files, truthful unavailable audit capability, minimized Mach services, and macOS keychain/localhost probes |
| SEC-019, SEC-021 | Least-privilege SHA-pinned workflows, Dependabot, checksums, SBOM, attestations, and clean dependency checks |

## 6. Implemented design

### 6.1 Typed effective policy

Interacting booleans are converted into a validated policy after all sources
are merged:

```rust
enum NetworkMode {
    DenyAll,
    Proxy,
    DirectHttps443, // compatibility mode; never called domain-filtered
    AllowAll,
}

struct DomainPattern(String); // validated lowercase IDNA, exact or `*.`
```

The resolver must reject contradictory inputs. In particular:

- `enableProxy=true` plus no allowed destinations becomes `DenyAll`.
- `allowAllNetwork=false` at a higher precedence recomputes the mode; it must
  not retain an earlier `enableProxy=false` side effect.
- A higher-precedence `denyDomains` removes intersecting exact or wildcard
  grants from both `allowDomains` and `allowFetch`, before fetch finalization.
- Proxy startup failure aborts the command.
- A proxy task that exits while the command is alive terminates the command and
  reports an SBE failure.
- `HTTP_PROXY`, `HTTPS_PROXY`, their lowercase variants, and `NO_PROXY` are
  reserved internal keys and cannot be overridden by profile environment.

Inspection prints the final enum and backend capability fields. Linux policy
rendering separately labels requested strict domain egress and the actual
port-only enforcement state.

### 6.2 Policy provenance and untrusted project configuration

Every grant must retain its origin:

```rust
enum ConfigOrigin {
    BuiltIn,
    Global(PathBuf),
    Project(PathBuf),
    Explicit(PathBuf),
    Cli,
    ToolDiscovery(&'static str),
}

struct Grant<T> {
    value: T,
    origin: ConfigOrigin,
}
```

The default project-config policy is monotonic: it may remove domains or
narrow existing permissions, but may not add read/write/exec/network access,
inject environment variables, or enable a degradation. SBE reports every
ignored escalation.

An explicit `--trust-project-config` may authorize expansion for one run. A
future approval store may remember a repository identity plus config digest;
changing the file invalidates approval. Non-interactive CI must never prompt
and must require an explicit flag or explicit config path.

Tool discovery, including Cargo's `target-dir` and `JAVA_HOME`, is not built-in
authority. A discovered Cargo target must be canonicalized and limited to the
workspace's dedicated output directory or an approved cache root. It is then
subject to forbidden-read, privilege-exec, trusted-ancestor, and W^X lints.

All config structs use `deny_unknown_fields`. Loading enforces a small maximum
file size, YAML nesting/alias limits supported by the selected parser, list
length limits, and maximum string lengths. Missing or cyclic `extends` is an
error. Config and CLI paths containing NUL or unsupported encoding are rejected.

### 6.3 Process capability hygiene

Before launch SBE resolves the executable path, then constructs the child
environment from an explicit baseline:

- locale and terminal variables required for normal CLI behavior;
- a minimal, validated `PATH` or an already-resolved executable;
- ecosystem variables explicitly named by the built-in profile;
- SBE-owned proxy variables; and
- trusted `--env NAME=VALUE` / `--keep-env NAME` choices.

The default must not pass variables matching credential-bearing names such as
`*_TOKEN`, `*_SECRET`, `*_PASSWORD`, cloud credentials, SSH/GPG agent sockets,
or package publishing tokens. A positive allowlist is preferred over an
ever-growing denylist. `sbe inspect` prints only variable names and origins;
values are always redacted.

On Unix, close or set `CLOEXEC` on every descriptor greater than 2 except an
explicit launcher channel. Linux should use `close_range(...,
CLOSE_RANGE_CLOEXEC)` when available and a bounded `/proc/self/fd`/rlimit
fallback. macOS should use the corresponding close-on-exec mechanism. Stdio
inheritance remains intentional and must be documented: redirecting a secret
file to stdin explicitly grants it to the command.

Linux must not grant recursive read access to `/proc`: that would let the
child recover filtered credentials from `/proc/$PPID/environ`. Grant the
current process's procfs subtree by descriptor plus an explicit list of public
kernel-information nodes; parent and sibling process directories remain
unreadable.

### 6.4 Safe launcher architecture on Linux

Do not install Landlock and seccomp through a complex `pre_exec` closure in a
multi-threaded Tokio process. Add a small internal launcher executable or mode:

1. The parent validates and serializes a versioned policy to a private pipe or
   sealed descriptor.
2. The parent starts the launcher with only stdio and that descriptor.
3. Before creating threads, the launcher parses the bounded policy, opens paths
   safely, installs `no_new_privs`, Landlock, and seccomp, closes descriptors,
   and calls `execve`.
4. A status pipe distinguishes policy-install failure from target exit.

If a separate helper is rejected, the alternative must be a reviewed
syscall-only shim with raw FDs, no allocator, no locks, no formatting, no
library destructors, and tests that exercise the actual compiled closure. A
source token scan alone is not an acceptance test.

### 6.5 Linux network modes

Landlock `ConnectTcp` plus `NetPort` is named `tcp_destination_port_filter` in
capability output. It is useful for deny-all or fixed-port restriction, but it
must not satisfy `strict_domain_egress`.

Strict proxy confinement requires a primitive that validates the destination
address, such as:

- a network namespace with only an authenticated proxy route;
- cgroup/eBPF or firewall enforcement tied to the child's cgroup/namespace; or
- seccomp user notification with a trusted `connect` broker that safely reads
  and validates the child's `sockaddr`.

Classic seccomp-BPF cannot dereference the user-space `sockaddr` and is not an
acceptable substitute. Until a strict backend is implemented, Linux must do
one of the following:

- fail closed when a profile requests strict domain egress; or
- require an explicit trusted compatibility flag and print that a malicious
  process can bypass the domain allowlist.

UDP, Unix sockets, inherited sockets, and local services are separately
modeled capabilities. Strict mode denies all except what the profile explicitly
needs. Direct-TCP-443 compatibility may retain datagram sockets for libc DNS,
but must disclose that UDP egress is not destination-confined. An explicit
allow-all mode must also stop handling Landlock `ResolveUnix`, so it does not
silently continue blocking ambient Unix-domain sockets.

### 6.6 Linux filesystem policy

Path opening must be descriptor-based and atomic. Prefer `openat2` with
`RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_BENEATH`; otherwise walk
each component with `openat` and `O_NOFOLLOW`. Verify trusted system ancestors
are root-owned and not writable by the invoking user/group. Use the verified FD
directly when creating the Landlock rule. A lexical prefix is never proof of
ownership.

Replace `AccessFs::from_all()` for write grants with only the rights needed to
read/write/create/remove/rename within that path. Do not include `Execute` or
device `IoctlDev` unless the grant explicitly requests them. Narrow baseline
reads from `/dev` and shared temporary trees to named devices and private temp.

The policy compiler rejects persistent overlap between write and execute
grants. Narrow exceptions are permitted only for per-invocation output
directories that are removed or treated as tainted after the command. In
particular:

- `~/.rustup` and other toolchain roots are read+execute, never writable during
  ordinary builds;
- shared package caches are writable but not executable where the ecosystem
  supports separated caches;
- generated binaries use a dedicated per-run output root; and
- `/usr/lib` and other library trees receive read access, not directory-wide
  execute access, unless tests demonstrate a required helper.

Use `CompatLevel::HardRequirement` for every feature behind a user-visible
security promise. Expose individual capabilities and individual opt-ins, for
example `allow_missing_net_isolation`; never let one `allow_degraded` disable
unrelated path lints. Probe and test newer Landlock ABI rights explicitly rather
than clamping all future kernels to an older enum.

### 6.7 Workspace and temporary storage

Create a mode-0700 per-run directory, set `TMPDIR`, `TMP`, and `TEMP`, and grant
only that directory. Do not grant write access to global `/tmp`, `/var/tmp`,
`/private/tmp`, `/private/var/folders`, or `/dev/shm` by default.

Built-in profiles grant the smallest expected project outputs and lockfiles,
not all of `$PWD`. `.git`, `.github/workflows`, SBE config, source files, and
package manifests remain non-writable during install/build by default. A
compatibility option may grant full workspace write, but inspection must label
it as persistent-source mutation authority.

On Linux, missing literal lockfiles are created only when the invoked package
manager subcommand can update that specific lockfile. Mutually exclusive
manager outputs and read-only commands must not acquire empty lockfiles as a
launcher side effect. Denied read paths that traverse symlinks fail policy
compilation, and user grants are rejected whether they contain a denied path or
are nested beneath one.

### 6.8 macOS SBPL generation and IPC

SBPL generation becomes fallible and uses distinct encoders for literal
strings and regular expressions. The encoder must escape SBPL syntax exactly,
reject NUL/control characters and unsupported non-UTF-8 paths, and preserve path
semantics without `Path::display()` lossiness. SBE validates the generated
profile with `sandbox-exec` before launching the untrusted command.

Network generation switches exhaustively on `NetworkMode`; there is no default
fallback branch. Proxy mode permits only its exact loopback port. General
loopback destinations and inbound binds require explicit rules.

Audit every baseline Mach service using executable compatibility tests. Remove
`com.apple.SecurityServer` unless it is strictly required, and add an
integration test proving that a sandboxed process cannot retrieve a test
keychain item. Documentation must not claim keychain isolation until that test
passes on supported macOS versions.

### 6.9 Proxy hardening

The proxy is a trusted parser and capability broker. It must implement:

- a maximum request-line size, total header bytes, header count, and per-header
  size without `read_line`-based unbounded growth;
- a semaphore limiting concurrent connections and in-flight DNS/connect work;
- header read, DNS, connect, handshake, idle, and maximum tunnel timeouts;
- graceful shutdown that tracks and aborts or drains child tasks;
- a total, non-panicking authority parser using standard URI/authority types;
- canonical lowercase IDNA hostnames with trailing-dot handling;
- exact/wildcard matching at label boundaries;
- port 443 by default, with explicit ports per destination rule;
- rejection of IP literals and loopback, private, link-local, unspecified,
  multicast, documentation, and other non-global addresses unless explicitly
  authorized; and
- resolution once per request, validation of every candidate, and connection
  only to a validated resolved address to avoid validation/use divergence.

A random per-run proxy authentication token can prevent unrelated local
processes from casually using the proxy. It is defense in depth and does not
fix SEC-001 by itself because the sandboxed child also knows the token and port.

JVM clients use a private per-run Java agent to install an `Authenticator` for
the exact SBE loopback proxy host and port. The agent reads the token from the
reserved `SBE_PROXY_TOKEN` environment variable and responds only to proxy
authentication challenges for that endpoint. The token must not be embedded in
`JAVA_TOOL_OPTIONS`, because the JVM prints that variable at startup. The agent
JAR is embedded in the CLI, created with exclusive-create semantics and mode
0400 inside the private runtime directory, and never loaded from the project.

### 6.10 Audit correctness

The backend launch result must expose the child PID and, where possible, a
kernel-domain identifier before audit begins. macOS predicates and parsed
events must correlate to the launched sandbox. Linux must filter audit records
to the child process tree/domain, not all `/dev/kmsg` events.

Audit files are opened with mode 0600, no symlink following, and an explicit
append/truncate policy. Terminal control characters and newlines in event data
are escaped. Parsing and queues are bounded, dropped-event counts are reported,
and `audit_stream` is false when the required source is unavailable.

### 6.11 Release hardening

- Set workflow-level permissions to `contents: read`; grant `contents: write`,
  `id-token: write`, or `attestations: write` only to the release job that needs
  them.
- Pin every third-party action to a full commit SHA and use Dependabot/Renovate
  to update pins.
- Build releases from the exact protected tag in a protected environment.
- Publish SHA-256 checksums, an SPDX or CycloneDX SBOM, and GitHub artifact
  attestations for binaries.
- Verify the digest/provenance of any downloaded SBE binary used to dogfood CI.
- Prefer short-lived trusted publishing over long-lived registry tokens when
  the target registry supports it.
- Document reproducibility inputs and work toward reproducible artifacts.

## 7. Verification plan

### 7.1 Mandatory adversarial tests

1. Put sentinel secrets in environment variables and verify they are absent;
   verify `--keep-env` passes only the named variable and inspection redacts it.
2. Give the parent an open secret file and connected socket without `CLOEXEC`;
   verify the child cannot use either descriptor.
3. Verify every combination and precedence order of proxy, allow-all, and empty
   allowlist. Empty allowlist must deny all on both platforms.
4. On Linux, run an attacker listener on the proxy port at a non-loopback
   address. Strict mode must block it; compatibility mode must clearly report
   that it cannot.
5. Use paths containing quotes, backslashes, newlines, regex metacharacters,
   invalid UTF-8, and very long components. Policy generation must either
   encode them exactly or reject before spawn.
6. Race every path component with a symlink and test project
   `target-dir=$HOME`. No grant may escape its approved root.
7. Assert that a file created in every persistent writable cache cannot execute
   in the same sandbox. Assert protected workspace files cannot be modified.
8. Verify two concurrent runs have isolated private temp roots and cannot read
   or write each other's temporary files.
9. Send oversized/slow headers, thousands of connections, malformed IPv6
   authorities, arbitrary ports, IP literals, and allowed domains resolving to
   special-use addresses. Resource use stays within configured bounds and the
   proxy never panics.
10. On macOS, verify the sandbox cannot read a test keychain item and cannot
    connect to an unrelated localhost service in proxy-only mode.
11. Generate unrelated system sandbox/seccomp events and verify SBE neither
    prints nor records them. Verify audit file permissions and symlink refusal.
12. Stress Linux spawning from a busy multithreaded runtime under sanitizers
    and fault injection; every launcher failure must be reported deterministically.

### 7.2 Property and static tests

- Config merge is monotonic for untrusted origins.
- Serialization round-trips never change a grant's meaning.
- No final policy contains an untrusted grant without origin metadata.
- No persistent path is both writable and executable.
- Workflow lint rejects mutable action references and excessive permissions.
- CI runs `cargo audit`, `cargo deny`, and `cargo machete`.
- Hex 2.5.x dependency extraction is staged outside strict mode because it
  creates unpredictable `tmp_*` entries in the project root. CI still runs
  dependency compilation and adversarial Mix project evaluation inside SBE;
  SBE does not silently trade source immutability for `mix deps.get`
  compatibility.

### 7.3 Documentation tests

Every capability statement in README and architecture documentation maps to an
automated test. Platform matrices distinguish `enforced`, `best-effort`,
`unsupported`, and `not requested`; they do not use a single ambiguous checkmark.

## 8. Rollout record

### 8.1 Immediate patch work (completed)

- Correct Linux domain-confinement claims and label port filtering accurately.
- Fix macOS empty-allowlist fail-open and network precedence.
- Redact environment values in inspection output and reserve proxy variables.
- Add safe SBPL encoding/rejection.
- Fix the malformed authority panic; add proxy byte, connection, and timeout
  limits; restrict ports and special-use destinations.
- Make workflow permissions read-only by default and begin action SHA pinning.

### 8.2 Compatibility-affecting hardening (completed)

- Introduce policy provenance and restrictive-by-default project config.
- Clear ambient environment and descriptors.
- Add private temp roots and narrower workspace writes.
- Add descriptor-based Linux path resolution and W^X enforcement.
- Split degradation flags and require advertised Landlock features.
- Secure audit output and report streaming unavailable until reliable process
  correlation exists.

These changes are intentionally compatibility-affecting. SBE provides
actionable errors and explicit one-run compatibility flags, not silent
fallback.

### 8.3 0.4 release boundary (implemented)

- The single-threaded Linux launcher is the default execution path.
- Linux refuses strict domain mode because a destination-aware backend is not
  yet available.
- macOS uses a minimized Mach-service list and CI keychain tests.
- Release workflows publish checksums, SBOMs, and signed provenance for every
  release artifact.

## 9. Acceptance criteria

This design's acceptance checklist is:

- every Critical and High finding has a regression test and a merged fix;
- strict mode passes all mandatory adversarial tests on supported macOS and
  Linux versions;
- an untrusted repository cannot expand its policy without a visible trusted
  opt-in;
- no documented guarantee is implemented only as best effort;
- capability inspection accurately describes the running kernel and policy;
- release artifacts have checksums, SBOMs, and verifiable provenance; and
- the compatibility-mode risks are explicit at invocation time and in docs.

## 10. References

- [Rust `Command` environment behavior](https://doc.rust-lang.org/std/process/struct.Command.html)
- [Rust Unix `pre_exec` safety contract](https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html)
- [Linux Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html)
- [GitHub Actions security hardening](https://docs.github.com/en/code-security/tutorials/secure-your-organization/protect-against-threats)
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services/)
- [Apple Security Server architecture](https://developer.apple.com/library/archive/documentation/Security/Conceptual/Security_Overview/Architecture/Architecture.html)
