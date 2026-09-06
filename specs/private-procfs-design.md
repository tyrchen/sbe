# Private procfs for the Linux sandbox

- Status: Proposed
- Owner: SBE
- Last updated: 2026-09-05
- Scope: Linux launcher, Landlock policy materialization, process lifecycle,
  capability reporting, and verification
- Related:
  [Security Hardening Design](security-hardening-design.md),
  [Usable Security Design](usable-security-design.md), and
  [Architecture](../docs/arch.md)

## 1. Decision summary

SBE's Linux backend currently grants only a curated set of public procfs
nodes. This preserves the environment and descriptor boundary, but it breaks
ordinary runtimes that use `/proc/self/statm` or related process metrics.
Node.js worker pools are a concrete example: Vitest can report every test as
passed and then remain alive because a worker's `process.memoryUsage()` fails
under Landlock.

Adding the host's `/proc` recursively to the default read allowlist is not an
acceptable fix. It would allow sandboxed code to recover filtered credentials
from the SBE parent, inspect same-user processes, and potentially read
capability-bearing procfs links.

The proposed fix is a private procfs capability:

1. The trusted Linux launcher creates a private PID and mount namespace.
2. It mounts a procfs instance whose process view contains only the sandbox
   process tree.
3. It closes launcher policy and status descriptors before target execution.
4. It materializes Landlock rules only after the private procfs is mounted.
5. It allows recursive read access to `/proc` only inside that private mount
   namespace.
6. It installs seccomp, `no_new_privs`, and the remaining policy before
   executing the untrusted target.

The target and its descendants can then use normal procfs APIs without seeing
the host SBE parent or unrelated host processes. This feature does not provide
network isolation and must not change SBE's network capability reporting.

Private procfs is a Linux backend feature, not a project `.sbe.yaml` grant.
Project configuration must never be able to request a host-wide `/proc` read.

## 2. Problem and evidence

### 2.1 Current behavior

The Linux backend opens policy paths in a trusted launcher and applies
Landlock before `exec`. Its baseline procfs list is intentionally narrow:

```text
/proc/cpuinfo
/proc/filesystems
/proc/loadavg
/proc/meminfo
/proc/stat
/proc/sys
/proc/uptime
/proc/version
```

`/proc` and `/proc/self` are excluded because Landlock rules are backed by
opened filesystem objects. A rule opened for the launcher's `/proc/self`
does not authorize the distinct proc inode seen by a later child process.

On Linux with SBE 0.4.3, the following behavior is reproducible:

| Command | Result |
|---|---|
| Vitest without SBE | tests pass and process exits |
| Vitest through SBE with the curated procfs list | tests pass, process can hang during worker teardown |
| Vitest through SBE with `--allow-read /proc` | tests pass and process exits |
| `node -e 'process.memoryUsage()'` through SBE | `EACCES: uv_resident_set_memory` |
| The same command with host `/proc` read access | succeeds |

Adding only `/proc/self/statm` is insufficient. It does not authorize the
different procfs inode of a forked worker, and a literal grant also depends on
when and how the launcher resolves the procfs magic link.

### 2.2 Why recursive host `/proc` is unsafe

SBE removes high-confidence credentials from the target environment, but the
SBE parent and the invoking CI process may still hold the original values.
Recursive host procfs access creates this bypass:

```text
untrusted package hook
  -> /proc/$PPID/environ
  -> filtered CI credentials
  -> stdout, workspace artifact, or an available network path
```

Other procfs data is also sensitive:

- `/proc/<pid>/environ` for visible same-user processes;
- `/proc/<pid>/fd` and its links to open files, pipes, and sockets;
- `/proc/<pid>/cwd`, `/root`, and `/exe` for host layout and capability
  discovery;
- `/proc/<pid>/cmdline`, `maps`, `mountinfo`, and network metadata;
- process identities, local service ports, and orchestration details.

Kernel permission checks, Yama, seccomp, and Landlock may prevent particular
files such as `mem` from being useful. The design must not rely on those
incidental checks to protect the parent environment; `/proc/$PPID/environ` is
the explicit invariant.

The risk remains relevant when outbound network is denied. A malicious hook
can print recovered values to CI logs, write them into an artifact that the
job uploads, or use a local service. Network policy is a separate capability.

## 3. Goals

The implementation MUST:

1. Let ordinary runtimes read the procfs nodes they can read in a normal
   process, including `/proc/self/statm`, for the sandbox process tree.
2. Prevent the sandbox from seeing the host SBE parent and unrelated host
   processes through procfs.
3. Prevent access to host paths through `/proc/<host-pid>/root`, `cwd`, or
   `fd` links.
4. Preserve the existing environment, descriptor, Landlock, and seccomp
   invariants.
5. Keep launcher policy descriptors, proxy credentials, and status channels
   out of the target's visible file-descriptor set.
6. Prevent the untrusted target from creating or joining another namespace,
   remounting procfs, or weakening the established policy.
7. Preserve target exit status and signal behavior for shells, package
   managers, and worker pools.
8. Make capability availability explicit and make failure actionable. A
   namespace setup failure MUST NOT silently fall back to host-wide `/proc`.
9. Keep the existing command UX. A normal command MUST NOT require a
   repository-specific procfs grant.
10. Provide a safe path for kernels or security policies that do not permit
    the required namespace operations.

The implementation SHOULD preserve the target's observable host UID/GID and
normal `/proc` compatibility where possible. Any unavoidable identity change
must be reported and covered by compatibility tests.

## 4. Non-goals

This feature does not:

- enforce domain-aware network egress;
- replace the SBE CONNECT proxy;
- create a full container runtime;
- provide CPU, memory, timing, or other side-channel isolation;
- defend against a compromised kernel, SBE binary, or host user;
- make workspace or dependency output trustworthy after the run;
- allow a project to choose arbitrary namespace flags;
- make `/proc/sys` writable;
- solve all runtime APIs that require host-global process information.

A private PID/mount namespace is a procfs confidentiality mechanism. Network
namespace or firewall work is a separate design and rollout.

## 5. Threat model and security invariants

### 5.1 Trusted components

The kernel, SBE executable, outer SBE process, and the host state before the
invocation are trusted. The repository, dependency hooks, package-manager
scripts, compiler plugins, test workers, and every descendant of the target
are untrusted.

### 5.2 Required invariants

After the target starts:

1. `/proc` is mounted from a procfs instance associated with the private PID
   namespace.
2. The target can see only the private PID namespace's process tree.
3. The outer SBE parent has no visible PID in the target's `/proc`.
4. `/proc/$PPID/environ` cannot return the outer SBE or CI environment.
5. `/proc/<pid>/fd` cannot expose launcher policy, proxy, or host descriptors.
6. The target cannot access a host process by guessing or learning its PID.
7. The target cannot use `mount`, `umount2`, `unshare`, `setns`, `pivot_root`,
   `fsopen`, `fsconfig`, `fsmount`, `open_tree`, or equivalent namespace
   operations to create a broader view.
8. Landlock rules are attached to the private procfs objects, never to the
   host procfs mount by accident.
9. A failed namespace or procfs setup leaves the target unstarted.
10. `sbe inspect` does not claim private procfs unless all of these properties
    were established.

The private procfs may expose the SBE namespace supervisor and sibling worker
processes. That is acceptable only if the supervisor has a minimal sanitized
environment, no policy secrets, and no reusable sensitive descriptors.

## 6. Proposed architecture

### 6.1 Process topology

The current launcher directly applies policy and execs the target. A private
PID namespace requires a supervisor because the first process created in a new
PID namespace becomes PID 1 and has special signal and reaping semantics.

The proposed topology is:

```text
outer SBE parent
  |
  +-- outer launcher (original PID namespace)
        |
        +-- namespace supervisor (private PID namespace, PID 1)
              |
              +-- sandbox target
                    |
                    +-- package-manager children
                    +-- Vitest workers
                    +-- build helpers
```

The namespace supervisor is trusted SBE code. It MUST:

- create or enter the private user, PID, and mount namespaces as configured;
- mount procfs before the target policy is materialized;
- create the target with a clean, explicit environment;
- close all policy and control descriptors not needed by the supervisor;
- forward termination signals to the target process group;
- reap orphaned descendants;
- report the target's actual exit status to the outer launcher; and
- exit when the target tree is complete.

The supervisor MUST NOT retain secrets in its environment. Its environment
should be empty except for values strictly required for setup. The policy
descriptor should be closed before the target is created or otherwise be
unreadable and unreachable from target-visible descriptors.

The implementation may use `clone3`, `clone`, or a small dedicated helper.
The API choice is an implementation detail, but it must not require an
untrusted target to call `unshare` or `setns`.

### 6.2 Namespace setup order

The order is security-sensitive:

1. Parse and bound-check the launcher payload.
2. Resolve the requested capability and probe kernel support.
3. Create the user namespace if required and establish UID/GID mappings.
4. Create a private mount namespace.
5. Make mount propagation private so changes cannot affect the host.
6. Create the private PID namespace and start its supervisor.
7. Mount procfs at `/proc` inside the private mount/PID namespace.
8. Apply restrictive procfs mount flags:
   `MS_NOSUID`, `MS_NODEV`, and `MS_NOEXEC`; use a read-only remount where
   compatible with required runtime behavior.
9. Verify that `/proc/1` is the namespace supervisor and that a known host PID
   is not visible.
10. Resolve and open all Landlock paths from this final mount view.
11. Compile the Landlock ruleset, including recursive read access to the
    private `/proc` only.
12. Install `PR_SET_NO_NEW_PRIVS`, seccomp, and Landlock in the target launch
    path.
13. Close ambient descriptors and execute the target.

The target MUST never run between steps 3 and 12. In particular, it must not
receive a temporary view of the host procfs.

### 6.3 User namespace and identity

An ordinary user cannot generally mount procfs in a new mount namespace without
the necessary capability. The implementation therefore needs two paths:

1. A privileged path for an already-authorized launcher.
2. An unprivileged path using a user namespace, only when the host permits
   it.

The unprivileged path must:

- write `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map` safely;
- write `setgroups` restrictions before `gid_map`;
- avoid leaving unexpected capabilities in the target;
- preserve the caller's effective filesystem permissions;
- avoid exposing a target-visible UID change unless explicitly accepted;
- handle hosts that disable unprivileged user namespaces; and
- distinguish “namespace unavailable” from “namespace setup failed”.

The design must not assume that Ubuntu, GitHub Actions, containers, rootless
CI, and developer workstations expose the same user-namespace policy. Capability
probing is mandatory.

Creating a user namespace solely to mount procfs must not become an escape
hatch. After setup, the target receives no namespace-management capability and
seccomp denies namespace and mount syscalls.

### 6.4 Private procfs policy

Once the private procfs is mounted and verified, the Linux backend may install
one recursive `/proc` read rule. This rule is safe only because its opened
directory belongs to the private procfs mount and private PID namespace.

The implementation MUST:

- open the private `/proc` directory after namespace setup;
- verify the filesystem type and mount identity where available;
- reject a path that resolves to the host procfs;
- avoid accepting a project-supplied `/proc` grant as equivalent;
- keep write and execute rights out of the procfs rule;
- preserve explicit secret-path denials for non-procfs paths; and
- record the grant origin as `RuntimePrivateProcfs`, not CLI or project.

The implementation SHOULD retain the curated procfs list as a compatibility
fallback for commands that do not need recursive procfs. It MUST NOT silently
replace private procfs with host `/proc`.

### 6.5 Target and worker lifecycle

The supervisor is PID 1 in the private PID namespace. It must handle:

- target exit before all grandchildren exit;
- orphaned package-manager and compiler children;
- SIGTERM, SIGINT, SIGHUP, and SIGKILL behavior;
- target process groups and workers that ignore SIGTERM;
- outer launcher cancellation;
- a target that forks rapidly;
- a target that exits with a signal;
- an outer launcher that loses its control channel; and
- supervisor failure.

The supervisor must have bounded shutdown behavior. If the target does not
exit after the normal grace period, the supervisor must terminate the target
process group and reap remaining descendants before reporting completion.

The implementation must not use `/proc` polling as the only child-reaping
mechanism. Use kernel wait operations and explicit process handles where
available; procfs is for runtime compatibility, not lifecycle correctness.

### 6.6 Descriptor and environment hygiene

Before target exec:

- policy, status, proxy control, and namespace setup descriptors are closed or
  marked close-on-exec;
- only intentional stdio and explicitly granted runtime descriptors remain;
- the supervisor environment contains no filtered parent variables;
- proxy credentials are present only where required and are not retained by a
  target-visible supervisor descriptor or file;
- `/proc/1/environ` does not contain parent secrets; and
- `/proc/1/fd` does not expose the policy payload or host file descriptors.

This is required even with a private procfs. A private namespace limits which
processes are visible; it does not make a poorly sanitized supervisor safe.

## 7. Capability model and fallback

### 7.1 Internal capability states

The backend should report a structured procfs capability:

```text
Private      private PID + mount namespace and verified private procfs
Curated      existing public procfs nodes only
Unavailable  curated nodes cannot satisfy a requested strict capability
UnsafeHost   explicit user opt-in to host-wide /proc
```

`UnsafeHost` must never be selected by project configuration or automatically
as a namespace fallback.

`sbe inspect` should report at least:

```yaml
procfs:
  mode: private
  pidNamespace: private
  mountNamespace: private
  hostProcfsVisible: false
```

The output must omit sensitive PIDs and paths that would aid host
reconnaissance.

### 7.2 Default behavior

When private procfs is available, it becomes the default Linux runtime
capability. Node, Rust, Python, Java, and other profiles do not need a
repository-specific setting.

When private procfs is unavailable:

- SBE MUST preserve the curated procfs boundary;
- SBE MUST NOT grant host `/proc`;
- strict mode MUST fail before launch if private procfs is required by the
  requested capability contract;
- standard mode MAY run commands that do not require recursive procfs; and
- recognized runtime probes MAY fail fast with an actionable message instead
  of allowing a post-test hang.

The error should explain that the host cannot provide private procfs and give
the user the explicit unsafe escape hatch, if supported. It must not suggest
that the unsafe escape hatch has the same security guarantee.

### 7.3 Explicit unsafe escape hatch

If host-wide procfs access remains supported for debugging, it should have a
dedicated, visibly unsafe flag rather than being hidden behind a generic
`--allow-read /proc`:

```text
--allow-host-proc
```

The flag must:

- be rejected by an automatically discovered project configuration;
- be rejected in strict mode;
- emit a warning on stderr;
- appear in `sbe inspect` and grant provenance;
- explain that filtered environment values may become readable; and
- never be implied by a namespace setup failure.

Whether to retain this flag is a product decision. Removing it is preferable
for high-assurance deployments.

## 8. Network boundary

Private procfs does not change network behavior. The implementation must not
claim that a private PID or mount namespace forces traffic through SBE's proxy.

Network modes remain separate:

- `DenyAll` blocks network socket creation;
- `Proxy` supplies an authenticated domain-filtering proxy;
- Linux standard mode may still report domain egress as best effort when the
  kernel cannot prevent direct connections;
- strict domain egress requires a destination-aware enforcement mechanism or a
  trusted external network namespace/firewall; and
- a future network namespace may be combined with private procfs but is not
  part of this proposal.

The procfs capability and network capability must be independently reported.

## 9. Security risks and mitigations

| Risk | Mitigation |
|---|---|
| User namespaces disabled | Capability probe, curated fallback, clear error; never host `/proc` fallback |
| Host procfs mounted accidentally | Mount identity/type verification after setup; integration test with host PID |
| Supervisor exposes policy | Minimal environment, descriptor closure, no target-visible policy fd |
| PID 1 mishandles signals | Dedicated lifecycle state machine and signal/reaping tests |
| Target remounts procfs | `no_new_privs`, seccomp denial of mount/namespace APIs, dropped capabilities |
| UID/GID mapping changes tool behavior | Preserve identity where possible; test `id`, file ownership, and package managers |
| Private procfs breaks `/proc/cpuinfo` | Compatibility matrix; retain required read nodes or mount options |
| Namespace setup races policy setup | Namespace and procfs setup complete before Landlock path resolution |
| Outer launcher loses child | Status channel plus explicit supervisor exit protocol and timeout |
| Private procfs mistaken for network isolation | Separate capability fields and truthful warnings |
| Namespace implementation enlarges attack surface | Keep it in a small Linux-only module; avoid generic container features |

## 10. Alternatives considered

### 10.1 Add `/proc` to the default allowlist

Rejected. It fixes Node compatibility but directly violates the environment
and same-user process confidentiality invariant.

### 10.2 Add only `/proc/self/statm`

Rejected as a general solution. Landlock path rules bind opened filesystem
objects, and forked workers have distinct procfs objects. It also does not
cover runtimes that use other process-local procfs files.

### 10.3 Use `hidepid` without a PID namespace

Insufficient. It depends on procfs mount privileges and host UID policy, and
does not robustly define which same-user host processes are visible. A private
PID namespace is the primary isolation boundary; mount options are defense in
depth.

### 10.4 Patch each runtime

A Node/libuv or Tinypool fallback to V8 heap statistics or `getrusage` is a
valuable short-term compatibility fix. It does not solve other runtimes and
does not provide a general procfs contract, so it is complementary rather
than a replacement for private procfs.

### 10.5 Procfs broker

A trusted helper could expose a small API for RSS and CPU information without
mount namespaces. This minimizes kernel namespace complexity but creates a
new IPC protocol, authorization surface, and runtime-specific compatibility
problem. It is a fallback option if user namespaces are unavailable on the
target platforms.

## 11. Implementation plan

### Phase 1: capability probe and test harness

- Add Linux probes for user namespace, PID namespace, mount namespace, procfs
  mounting, and required mount flags.
- Add a namespace test helper that reports only capability booleans.
- Add negative tests proving that a failed probe does not widen procfs access.
- Add a runtime probe for Node's `process.memoryUsage()` to reproduce the
  current availability issue without relying on a long-running test.

### Phase 2: isolated namespace prototype

- Add a Linux-only namespace setup module.
- Implement the private PID/mount namespace topology and supervisor.
- Keep it behind an internal feature or explicit development flag.
- Verify UID/GID behavior, process-tree visibility, procfs mount identity,
  signal forwarding, and exit status in root and unprivileged environments.

### Phase 3: launcher and Landlock integration

- Move policy path opening after private procfs setup.
- Add a runtime private procfs grant.
- Install seccomp and Landlock only in the final target launch path.
- Close policy/control descriptors before target exec.
- Add capability reporting and `inspect` output.
- Ensure project configuration cannot select host procfs.

### Phase 4: default rollout

- Enable private procfs by default when the capability probe succeeds.
- Preserve curated procfs when it is sufficient.
- Fail fast for known runtime requirements when private procfs is unavailable.
- Decide whether to keep the explicit `--allow-host-proc` debugging escape hatch.

### Phase 5: release hardening

- Run the full Linux matrix on GitHub-hosted runners, rootless containers,
  smolvm, and representative developer distributions.
- Document namespace prerequisites and failure modes.
- Review the supervisor and all namespace-related unsafe code separately.
- Add release notes that private procfs does not imply network isolation.

## 12. Verification plan

### 12.1 Positive procfs tests

Inside SBE:

- read `/proc/self/statm`;
- read `/proc/self/status`;
- read `/proc/cpuinfo`, `/proc/meminfo`, and `/proc/uptime`;
- run Node `process.memoryUsage()`;
- run Vitest with fork workers;
- run Vitest with thread workers;
- spawn nested shell and compiler children;
- verify `/proc` exposes the target and its private descendants.

### 12.2 Isolation tests

The test harness must create a sentinel secret in the outer SBE environment and
verify that the sandbox cannot:

- read `/proc/$PPID/environ`;
- find the outer process through `/proc`;
- read host process environments;
- resolve host `/proc/<pid>/root`, `cwd`, or `fd`;
- access the policy descriptor, proxy credential, or status channel through
  `/proc/1/fd`;
- escape through a newly created namespace or remount; or
- cause the outer mount namespace to change.

Tests must use synthetic secrets and never real credentials.

### 12.3 Lifecycle tests

- target exits normally;
- target exits non-zero;
- target is killed by SIGTERM/SIGINT;
- target forks children that outlive the original process;
- workers ignore SIGTERM and require escalation;
- outer SBE cancellation terminates the complete private process tree;
- supervisor failure is reported as sandbox setup failure;
- status channel closes on successful target exec;
- no zombie processes remain in the private namespace or outer launcher.

### 12.4 Capability and fallback tests

- user namespace enabled;
- user namespace disabled;
- mount blocked by policy;
- PID namespace unavailable;
- procfs mount fails;
- root and unprivileged execution;
- nested container/CI runner;
- Linux kernels with and without the relevant Landlock ABI;
- no setup failure ever grants host-wide `/proc`.

### 12.5 Network regression tests

Run the existing network matrix unchanged. Add assertions that:

- `procfs: private` does not imply `network: confined`;
- proxy allowlist behavior remains unchanged;
- `DenyAll` remains enforced;
- standard Linux reports best-effort domain egress where appropriate; and
- private procfs setup does not alter proxy lifecycle or shutdown.

## 13. Acceptance criteria

The feature is ready for default rollout only when all of the following hold:

1. Node/Vitest completes without a procfs-related hang on supported Linux CI.
2. `process.memoryUsage()` succeeds for the target and forked workers.
3. `/proc/$PPID/environ` cannot recover the outer sentinel secret.
4. The target cannot see the outer SBE process or host process tree.
5. The target cannot reach launcher policy or proxy descriptors through procfs.
6. Namespace creation failure is explicit and never falls back to host `/proc`.
7. Target signals, exit codes, and orphan reaping match pre-namespace behavior.
8. `sbe inspect` reports private procfs and network capability independently.
9. Standard and strict modes have documented, tested behavior.
10. No project-level config can request or imply host-wide procfs access.

## 14. Open decisions

Before implementation, the following decisions require review:

1. Whether identity preservation requires a two-entry UID/GID map or whether
   the target may run as namespace root mapped to the invoking user.
2. Whether the supervisor remains in the target-visible process tree or the
   target becomes PID 1 with a separate outer reaper.
3. Whether a read-only procfs remount is compatible with all supported tools.
4. Whether private procfs is required in standard mode or only when a runtime
   probe detects the capability.
5. Whether to retain `--allow-host-proc` for debugging.
6. Whether a Node/libuv/Tinypool fallback should ship before namespace support.
7. Which kernel and container policies are supported for the unprivileged
   namespace path.
