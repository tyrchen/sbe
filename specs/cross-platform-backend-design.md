# Cross-Platform Sandbox Backend — Design

Status: proposed
Target audience: implementers extending sbe to Linux without disturbing the existing macOS path

## 1. Context

sbe today is a macOS-only wrapper around `sandbox-exec` (Seatbelt / SBPL). The
two-layer model — kernel deny-by-default + a userspace HTTP CONNECT proxy that
filters by domain — is platform-neutral in design, but the current code path is
hard-wired to SBPL string generation and `/usr/bin/sandbox-exec`.

The Linux primitive landscape in 2025/2026 makes a near 1:1 port feasible:

- **Landlock LSM** (stable since 5.13) gives unprivileged, process-self-applied
  filesystem allowlist/denylist policy. ABI v4 (6.7+) adds TCP
  bind/connect-by-port filtering — the exact shape sbe needs to pin egress to
  the proxy socket.
- **seccomp-bpf** (universal, ≥3.5) supplies syscall-level defense-in-depth
  (block `ptrace`, `unshare(CLONE_NEWUSER)`, raw sockets, etc.).
- **The existing sbe-proxy** carries over unchanged on both platforms — domain
  filtering happens at L7 regardless of how the kernel pins egress.

Namespaces (bwrap/nsjail) were considered and rejected as the *primary*
backend because Ubuntu 24.04+ default-blocks unprivileged user-namespace
creation via AppArmor. Landlock has no such regression. Landlock is also a
better semantic match for SBPL: both are self-applied, irrevocable, per-process
policies, not container-style isolation.

Windows is **not** a target. No Cygwin/MSYS path. No WSL-specific code (WSL2's
kernel is ≥6.6 on modern releases; users can run sbe inside WSL using the
Linux backend, but no special-casing).

## 2. Goals and Non-Goals

### Goals

- **G1.** Linux runs the same `sbe run -- <cmd>` UX as macOS today, with
  equivalent threat-model coverage on kernels ≥5.13 (filesystem and exec
  policy) and ≥6.7 (full network parity).
- **G2.** The shared core (`SandboxProfile`, config, ecosystem detect, proxy)
  is platform-agnostic. Only policy *materialization* and process spawning are
  platform-specific.
- **G3.** A trait — `SandboxBackend` — is the single seam between the
  orchestrator and platform code. Backends are selected at compile time via
  `cfg(target_os = …)`; no runtime dispatch on the hot path.
- **G4.** Graceful capability degradation: at startup, the backend reports
  what it can enforce given the running kernel. The user sees a clear
  one-line warning if a requested feature isn't available (e.g., Landlock net
  on 6.6).
- **G5.** Linux CI runners (the dominant case) become a first-class target,
  including the build workflow for sbe itself.

### Non-Goals

- Windows or non-Linux Unix support (FreeBSD's Capsicum, OpenBSD's pledge —
  interesting, but out of scope).
- Container-style isolation (mount namespaces, pid namespaces, hostname
  spoofing). sbe is not a container runtime.
- Replacing the proxy with kernel-level domain filtering. Neither SBPL nor
  Landlock filters by hostname; the proxy stays.
- Supporting kernel <5.13 on Linux. We refuse to start on older kernels with
  a clear error rather than offering a degraded mode that lies about safety.

## 3. Capability Parity Matrix

| Profile field | macOS (SBPL) | Linux (Landlock + seccomp) | Notes |
|---|---|---|---|
| `allowWrite` | `(allow file-write* (subpath/literal …))` | Landlock `WRITE_FILE` + `MAKE_*` rules per path | Both recursive on directories |
| `denyRead` | `(deny file-read* …)` after global allow | **Semantic-shift on Linux:** Landlock has no subtractive deny under a broader allow. Backend uses a curated `allowRead` allowlist (see §8) that excludes `$HOME` root; `denyRead` becomes a *sealed forbidden-list* — paths in `denyRead` are guaranteed never to be added to `allowRead`, with a build-time error on conflict. |
| `allowExec` | `(allow process-exec …)` | Landlock `EXECUTE` access on listed paths | Linux allowlist *is* the deny mechanism |
| `denyExec` | `(deny process-exec …)` | n/a — implicit (anything not in `allowExec` cannot exec) | Linux ignores `denyExec`; backend reports it as a no-op when set |
| `allowDomains` | sbe-proxy at L7 | sbe-proxy at L7 | Identical on both |
| `enableProxy = true` | SBPL pins egress to `localhost:<proxy>` | Landlock `NET_CONNECT_TCP` to `<proxy>` only (≥6.7); seccomp `connect()` arg filter to loopback (<6.7) | Functional parity at ≥6.7 |
| `enableProxy = false` (port-443 mode) | SBPL `(remote tcp "*:443")` | Landlock `NET_CONNECT_TCP` to port 443 (≥6.7) | Parity at ≥6.7 |
| `allowAllNetwork` | `(allow network*)` | Skip Landlock `NET_*` rules | Trivial on both |
| `env` injection | `Command::env` | `Command::env` | Shared in orchestrator, not backend |
| `--audit` | Stream `sandboxd` unified log | seccomp `SCMP_ACT_LOG` → dmesg/auditd reader, *deferred* | Linux audit is a follow-up; backend exposes capability flag |

## 4. Architecture (Updated)

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
                  │  - spawn -f      │   │  - filter build   │
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

The orchestrator (`apps/cli/src/executor.rs`) no longer references SBPL or
`sandbox-exec` directly. It owns: config resolution, proxy lifecycle, audit
spawning, and exit-code propagation. Everything platform-specific lives behind
the trait.

## 5. The `SandboxBackend` Trait

```rust
// crates/core/src/sandbox/mod.rs

use std::collections::HashMap;
use std::process::ExitStatus;

use crate::{error::CoreError, profile::SandboxProfile};

/// A platform-specific sandbox backend.
///
/// Implementations turn a resolved [`SandboxProfile`] into kernel-enforced
/// restrictions on a spawned child process. Backends are selected at compile
/// time via `cfg(target_os = "...")`; the orchestrator never holds a
/// `dyn SandboxBackend` — it sees the concrete `Sandbox` type re-exported by
/// this module for the current target.
pub trait SandboxBackend: Send + Sync {
    /// Human-readable backend identifier, e.g. `"sandbox-exec"` or
    /// `"landlock+seccomp"`. Surfaced in `sbe inspect` output and audit logs.
    fn name(&self) -> &'static str;

    /// What this backend can enforce on the current kernel/host. Populated
    /// during construction (`Backend::new()` performs the kernel probe); this
    /// accessor is infallible. macOS reports static features; Linux reports
    /// features derived from the live Landlock ABI level.
    fn info(&self) -> &BackendInfo;

    /// Render the resolved policy for `--dry-run` and `sbe inspect`. Output
    /// must be **deterministic and platform-stable** so tests can assert on
    /// substrings.
    ///
    /// macOS: canonical SBPL Scheme document — same text that
    /// `sandbox-exec -f` consumes.
    /// Linux: a YAML document (`# sbe linux backend inspection`) listing the
    /// Landlock ruleset (`handled` access set + each path-beneath rule with
    /// access flags), the seccomp action table (allow/log/kill per syscall),
    /// the proxy env, and the resolved `BackendFeatures`. YAML so it's
    /// readable AND parseable for round-trip tests.
    fn render_policy(&self, profile: &SandboxProfile, proxy_port: Option<u16>) -> String;

    /// Run the user command under the sandbox and return its exit status.
    ///
    /// The backend owns the full per-invocation lifecycle:
    /// 1. Compile `profile` → platform-specific policy artifact (SBPL
    ///    tempfile / Landlock `Ruleset` with all path FDs preopened + seccomp
    ///    `BpfProgram` bytes). **All allocation and FD opens happen here, in
    ///    the parent.**
    /// 2. Spawn the child with policy applied before `execve` (mac: via
    ///    `sandbox-exec`; linux: via `Command::pre_exec`, see §6 invariants).
    /// 3. Forward stdin/stdout/stderr (inherited).
    /// 4. Wait for exit; clean up artifacts.
    ///
    /// Proxy lifecycle, audit logging, config resolution, and exit-code
    /// mapping live in the orchestrator — not here. `extra_env` is the
    /// orchestrator-merged env (proxy vars + `profile.env`), set on the
    /// child's Command verbatim.
    async fn run(
        &self,
        profile: &SandboxProfile,
        proxy_port: Option<u16>,
        command: &[String],
        extra_env: &HashMap<String, String>,
    ) -> Result<ExitStatus, CoreError>;
}

/// Construction contract: every backend exposes
/// `pub fn new() -> Result<Self, CoreError>` (or `new_with_options` if it
/// takes configuration). Construction performs the kernel/feature probe.
/// If the platform cannot host the backend at all (kernel <5.13 on Linux;
/// `sandbox-exec` missing on macOS), construction fails with a clear
/// `CoreError::BackendUnavailable { reason }` — no degraded silent path.

/// What a backend can enforce on the current kernel/host.
#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub name: &'static str,
    /// Kernel version string for diagnostics; e.g. "Darwin 24.6.0" or "Linux 6.8.0".
    pub kernel: String,
    pub features: BackendFeatures,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BackendFeatures {
    /// FS write allowlist enforceable.
    pub fs_write: bool,
    /// FS read denylist enforceable.
    pub fs_read: bool,
    /// Per-path exec allowlist enforceable.
    pub exec_allowlist: bool,
    /// Outbound TCP can be pinned to specific port(s).
    pub net_port_filter: bool,
    /// `--audit` streaming of violation events supported.
    pub audit_stream: bool,
}
```

### Why native `async fn` and not `#[async_trait]`?

Per project convention, native `async fn` is the default. We don't need
object safety: the trait is satisfied by exactly one concrete type per target,
re-exported as:

```rust
// crates/core/src/sandbox/mod.rs

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosSandbox as Sandbox;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxSandbox as Sandbox;
```

The orchestrator calls `Sandbox::new()` and the concrete type's async methods
directly. Tests that want a mock backend implement the trait with their own
struct — also no `dyn`.

If a future feature needs runtime dispatch (e.g., picking between Landlock and
a fallback bwrap path at runtime on Linux), we'll introduce a small enum
wrapper (`enum LinuxBackend { Landlock(…), Bwrap(…) }`) rather than `dyn`,
keeping the cost out of generated code.

## 6. Lifecycle Model

The two backends have *different* execution models. The trait abstracts them
behind `run`, but it's worth being explicit:

### macOS

```
parent (sbe)                 child (user cmd)
  │
  ├─ build SBPL string from profile
  ├─ write tempfile (mode 0400)
  ├─ Command::new("/usr/bin/sandbox-exec")
  │       .args(["-f", path, cmd, args…])
  │       .spawn()                     ───────►  exec sandbox-exec
  │                                                 │
  │                                                 ├─ reads SBPL, installs seatbelt
  │                                                 └─ execve(cmd, args…)  ─► (sandboxed)
  ├─ wait()
  └─ drop tempfile
```

### Linux

```
parent (sbe)                 child (user cmd)
  │
  ├─ build Ruleset (landlock crate) + BpfProgram (seccompiler)
  ├─ Command::new(cmd)
  │       .args(args…)
  │       .env(...)
  │       .pre_exec(|| {
  │            prctl(PR_SET_NO_NEW_PRIVS, 1);
  │            ruleset.restrict_self()?;        // Landlock, irrevocable
  │            seccompiler::apply_filter(...)?; // seccomp, irrevocable
  │            Ok(())
  │       })
  │       .spawn()                     ───────►  fork()
  │                                                 │
  │                                                 ├─ run pre_exec closure
  │                                                 │     (self-restrict)
  │                                                 └─ execve(cmd, args…)  ─► (sandboxed)
  └─ wait()
```

### Hard invariants for the Linux `pre_exec` closure

Tokio's multi-threaded runtime hosts many threads. When the parent calls
`Command::spawn`, the `pre_exec` closure runs after `fork()` (or `clone()`)
but before `execve()` — in a child process where **only the calling thread
survived**, but where any mutex held by another thread of the parent at fork
time is now permanently locked in the child. glibc's `malloc` uses internal
mutexes; touching the allocator from `pre_exec` can deadlock the child.

Therefore the closure runs under these hard invariants:

1. **No heap allocation.** No `String`, `Vec`, `Box`, `format!`, `println!`,
   `eprintln!`, no `?`-based error conversion that allocates. Errors out of
   syscalls are reported by writing a single static `&[u8]` to fd 2 with
   `write(2)` directly and returning `io::Error::from_raw_os_error`.
2. **No FD opens.** All path FDs that Landlock needs (every path-beneath rule
   target) are `open()`-ed in the **parent**, stored inside the `Ruleset`,
   and moved into the closure by value. The closure performs only the
   `landlock_restrict_self` syscall.
3. **No standard-library calls into the runtime.** No `tokio::*`, no `tracing::*`,
   no logger init. Tracing must be done in the parent before/after spawn.
4. **Only three syscalls run in the closure**, in this order:
   1. `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` — required for unprivileged
      seccomp; also disables setuid bits across `execve` (see §6 gotchas).
   2. `landlock_restrict_self(ruleset_fd, 0)` — irrevocable.
   3. `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &bpf_program)`
      — irrevocable; `TSYNC` per §13 D3.

The seccomp `BpfProgram` bytes are compiled in the parent by `seccompiler`
and passed into the closure as `&'static [u8]` (or moved-in `Vec<u8>` that
the closure only `as_ptr`s — no realloc). Same for any small `&'static str`
diagnostic buffers.

**Enforcement.** The `sandbox/linux/exec.rs` module declares
`#[allow(unsafe_code)] // pre_exec`, scoped to the closure body only.
Project-level `clippy.toml` adds a `disallowed-methods` entry rejecting
`{format,write}!`, `String::from`, `Vec::with_capacity`, `eprintln!`,
`println!`, etc., inside this module. A code-review checklist line names the
invariants.

### Other lifecycle notes

- **No tempfile on Linux.** Policy lives in memory and is applied in the
  forked child via syscalls. Less attack surface; nothing on disk for another
  process to tamper with.
- **`PR_SET_NO_NEW_PRIVS` side effects.** The flag persists across `execve`
  and disables `setuid`/`setgid` bits for the entire descendant tree. Known
  consequences:
  - `sudo`, `su`, `pkexec`, `doas` cannot escalate — this is the *desired*
    outcome for sbe and reinforces the threat model.
  - `ping` (where it's still setuid rather than `cap_net_raw`-blessed) fails.
  - Some Python wrappers that rely on setuid-for-privilege-drop break.
  - The vast majority of package-manager build scripts are unaffected.
  Document in the user-facing README.
- **Signal forwarding.** The Linux child is a direct child of sbe (no
  `sandbox-exec` middle process). Tokio's `Command` handles signal
  forwarding through PID groups in the normal way; sbe relays `SIGINT`/`SIGTERM`
  to the child via the existing parent-side signal handlers. No new code
  needed beyond what `tokio::process` provides.

## 7. Crate / Module Layout

```
crates/core/src/
├── lib.rs
├── config.rs                  (unchanged)
├── detect.rs                  (unchanged)
├── error.rs                   (extend with Linux variants)
├── profile/
│   ├── mod.rs                 (unchanged shape; per-OS YAML selection — see §8)
│   ├── defaults-macos.yaml    (renamed from defaults.yaml)
│   └── defaults-linux.yaml    (new)
└── sandbox/
    ├── mod.rs                 (trait + cfg-selected `Sandbox` re-export)
    ├── macos/
    │   ├── mod.rs             (`MacosSandbox` impl)
    │   ├── sbpl.rs            (moved from crates/core/src/sbpl.rs)
    │   └── exec.rs            (tempfile + sandbox-exec spawn)
    └── linux/
        ├── mod.rs             (`LinuxSandbox` impl)
        ├── landlock.rs        (Ruleset builder from `SandboxProfile`)
        ├── seccomp.rs         (BpfProgram builder)
        ├── probe.rs           (kernel/ABI detection)
        └── exec.rs            (pre_exec wiring)
```

`crates/proxy/` is unchanged. `apps/cli/src/executor.rs` shrinks to ~80 lines
of orchestration (config → proxy → backend.run → cleanup).

The current `crates/core/src/sbpl.rs` becomes `sandbox/macos/sbpl.rs`. Public
exports compress to `pub use sandbox::Sandbox;` from `lib.rs` — callers
outside core never name the platform-specific type.

## 8. Profile Defaults — Per-OS Pivot

`profile/defaults.yaml` currently encodes macOS paths
(`~/Library/Keychains/`, `/opt/homebrew/bin/zig`, `/usr/bin/osascript`). We
split into two embedded YAMLs:

- `defaults-macos.yaml` — existing content
- `defaults-linux.yaml` — Linux-flavored equivalents

`profile/mod.rs` picks the YAML at compile time:

```rust
#[cfg(target_os = "macos")]
const DEFAULTS_YAML: &str = include_str!("defaults-macos.yaml");

#[cfg(target_os = "linux")]
const DEFAULTS_YAML: &str = include_str!("defaults-linux.yaml");
```

### Linux-specific shifts vs. macOS

#### Reads: `denyRead` → `allowRead` (semantic inversion, with translation)

Landlock has **no subtractive operation**: if you grant `FS_READ_FILE` on a
parent path, you cannot then deny a child. macOS's "allow all reads, deny a
specific set of secret paths" model therefore doesn't translate. We use
option B from the principal-engineer review: a curated default *allowlist*
that excludes `$HOME` root and lists everything a build/install tool
realistically needs.

**Linux `common.allowRead` (baseline read-allowlist):**

```yaml
common:
  allowRead:
    # Dynamic linker, NSS, system config
    - "/etc/ld.so.cache"
    - "/etc/ld.so.conf"
    - "/etc/ld.so.conf.d/"
    - "/etc/nsswitch.conf"
    - "/etc/resolv.conf"
    - "/etc/hosts"
    - "/etc/host.conf"
    - "/etc/passwd"
    - "/etc/group"
    - "/etc/localtime"
    - "/etc/os-release"
    - "/etc/alternatives/"
    # TLS roots (cargo, curl, openssl, rustls system-roots, etc.)
    - "/etc/ssl/"
    - "/usr/share/ca-certificates/"
    - "/usr/local/share/ca-certificates/"
    # Time zone data
    - "/usr/share/zoneinfo/"
    # Locale data
    - "/usr/share/locale/"
    - "/usr/lib/locale/"
    # System libraries (needed for read-before-exec on .so loads)
    - "/lib/"
    - "/lib32/"
    - "/lib64/"
    - "/usr/lib/"
    - "/usr/lib32/"
    - "/usr/lib64/"
    - "/usr/local/lib/"
    # Toolchains (read access; exec controlled separately)
    - "/usr/bin/"
    - "/usr/local/bin/"
    - "/bin/"
    - "/sbin/"
    - "/usr/sbin/"
    # /proc and /sys (process introspection, runtime probes)
    - "/proc/"
    - "/sys/"
    # /dev — controlled subset (random, null, urandom, tty)
    - "/dev/null"
    - "/dev/zero"
    - "/dev/random"
    - "/dev/urandom"
    - "/dev/tty"
    - "/dev/stdin"
    - "/dev/stdout"
    - "/dev/stderr"
    # Temp
    - "/tmp/"
    - "/var/tmp/"
    # Project + HOME-scoped tool data (additive, per-ecosystem may add more)
    - "$PWD/"
    - "~/.cache/"          # XDG cache
    - "~/.config/"         # XDG config (specific secret dirs are NOT in this allowlist)
    - "~/.local/share/"
```

Note that **`~/` itself is NOT in the allowlist** — only the specific XDG
subdirectories that build tools touch. `~/.ssh/`, `~/.aws/`, `~/.gnupg/`,
`~/.password-store/`, etc., are simply *never added* to the read-allowlist —
they fail closed by virtue of not being on it.

**`denyRead` becomes a sealed list, not a deny rule.** On Linux, a `denyRead`
entry is a *promise to never silently add this path to the allowlist*, even if
a user config or future default tries to. The backend keeps an in-memory
`forbidden_reads` set; when applying user config that broadens `allowRead`,
any overlap with `forbidden_reads` is rejected with an error pointing the
user at the conflict. This preserves the threat-model intent of `denyRead`
without lying about how Landlock enforces it.

#### Exec: per-binary literals only

`allowExec` defaults on Linux MUST be per-binary `literal` entries, not
directory `subpath` entries. The macOS profile already follows this pattern
(`/bin/sh`, `/usr/bin/cc`, …). On Linux it is **load-bearing**: a subpath
allow on `/usr/bin/` transitively permits `/usr/bin/sudo`, `/usr/bin/pkexec`,
`/usr/bin/su`, `/usr/bin/chsh`, etc., defeating the threat model.

Linux `common.allowExec` (excerpt — full list mirrors macOS shape):

```yaml
common:
  allowExec:
    # Shells
    - "/bin/sh"
    - "/bin/bash"
    - "/usr/bin/env"
    # Core utilities — each one explicit (no /usr/bin subpath)
    - "/bin/cat"
    - "/bin/cp"
    - "/bin/mv"
    - "/bin/rm"
    - "/bin/mkdir"
    - "/bin/ls"
    - "/usr/bin/awk"
    - "/usr/bin/grep"
    - "/usr/bin/sed"
    - "/usr/bin/find"
    - "/usr/bin/xargs"
    # ... (full enumeration in defaults-linux.yaml)
    # Build toolchain
    - "/usr/bin/cc"
    - "/usr/bin/gcc"
    - "/usr/bin/g++"
    - "/usr/bin/clang"
    - "/usr/bin/ld"
    - "/usr/bin/make"
    - "/usr/bin/pkg-config"
    # Dynamic linker (FS_EXECUTE required to start any dynamically-linked binary)
    - "/lib64/ld-linux-x86-64.so.2"
    - "/lib/ld-linux-aarch64.so.1"
    # Shared libraries — these ARE allowed as subpaths because
    # they contain no shell-callable binaries
    - "/lib/"
    - "/lib32/"
    - "/lib64/"
    - "/usr/lib/"
    - "/usr/lib32/"
    - "/usr/lib64/"
    - "/usr/local/lib/"
    # Git (used by cargo, mix deps.get, etc.)
    - "/usr/bin/git"
    - "/usr/local/bin/git"
```

**Conspicuously omitted** (privilege-escalation surface, must never appear in
defaults): `sudo`, `su`, `pkexec`, `doas`, `chsh`, `chfn`, `newgrp`, `sg`,
`mount`, `umount`, `passwd`, `gpasswd`.

**Backend-time lint.** When `LinuxSandbox::new` constructs the policy from a
resolved profile, it scans `allow_exec` for directory-subpath entries that
overlap any known privilege-escalation binary and refuses to build the
ruleset with a clear error. This catches user `.sbe.yaml` mistakes that
would silently re-enable `sudo`. Override: `--allow-degraded` (same flag as
§13 D1) bypasses the lint with a warning.

#### `denyExec` is a no-op on Linux

Landlock is allowlist-only. The backend ignores `deny_exec` entirely and
emits a warning if a config sets it on Linux:

```
warning: denyExec has no effect on Linux (Landlock is allowlist-only).
         The 3 entries you listed are already implicitly denied by virtue
         of not being in allowExec.
```

#### Writes and Rust target dir

`allowWrite` for the rust ecosystem keeps `~/.cargo/registry`, `~/.cargo/git`,
`~/.rustup`. Adds `/tmp/`, `/var/tmp/` (instead of mac's `/private/tmp/`,
`/private/var/folders/`). Drops macOS Cellar/Homebrew paths.

#### `allowDomains` — unchanged

The proxy doesn't care about the host OS.

### Known-limitation caveats (Linux)

These are documented in the README's "What sbe Does NOT Protect Against"
section, not silently swallowed:

- **`denyRead` is allowlist-omission, not subtractive deny.** A future
  config change that broadens `allowRead` could expose a path a user thought
  was denied. The `forbidden_reads` lint above mitigates this for paths
  explicitly named in `denyRead`, but the difference in mechanism is
  user-visible.
- **DBus-mediated DNS may fail.** Tools that resolve via systemd-resolved's
  DBus path (some Python/Node DNS libraries through `nss-systemd`) will hit
  `EACCES` on `/run/dbus/system_bus_socket`. The fallback path through
  glibc's `getaddrinfo` (UDP DNS via `/etc/resolv.conf`) works. Workaround
  for affected tools: use `--allow-fetch` or add the DBus socket to a custom
  profile.
- **UDP is unfiltered by Landlock.** Egress UDP (DNS on :53, NTP, QUIC) is
  not subject to kernel filtering. The seccomp baseline blocks `AF_PACKET`
  raw sockets but not `SOCK_DGRAM` on `AF_INET`. Document.
- **`AF_UNIX` sockets pre-ABI v6** are unrestricted. On 6.12+, Landlock
  scope rules tighten this; we don't depend on it.

### Cross-OS YAML hygiene

Schema additions (`CommonDefaults::allow_read`, `EcosystemDefaults::allow_read`)
are macOS-no-op fields — macOS ignores them. The schema (`CommonDefaults` /
`EcosystemDefaults`) stays the same shape so both YAMLs deserialize through
the same parser, and tests can cross-check both files load with the same
struct.

## 9. Compatibility Tiers (Linux)

`LinuxSandbox::new()` performs a one-shot kernel probe at construction time
(per §5 construction contract) and stores the resulting `BackendInfo` for
the lifetime of the backend instance. The probe outcomes:

| Kernel version | `landlock` ABI | Features enabled |
|---|---|---|
| <5.13 | none | Probe fails. sbe exits with `EXIT_SBE_ERROR` and a clear message: "Landlock LSM required (kernel ≥5.13). Detected: …" |
| 5.13–6.6 | v1–v3 | `fs_write`, `fs_read`, `exec_allowlist` ✓ &nbsp; `net_port_filter` ✗ — falls back to seccomp `connect()` arg filter (allow AF_UNIX + loopback only). Default behavior: **refuse to start** if the profile requires `enableProxy: true` or any network restriction (see §13 D1). Opt-in with `--allow-degraded` (and config equivalent `allowDegraded: true`) to proceed with the coarser kernel filter — sbe prints a one-line warning naming the missing capability. |
| ≥6.7 | v4+ | All features ✓ |

The probe uses `landlock::ABI::current()` from the `landlock` crate
(>=0.4) with `CompatLevel::BestEffort`. No raw syscall handling needed. The
`BestEffort` setting also covers per-rule access flags — `LANDLOCK_ACCESS_FS_TRUNCATE`
(v3) and `LANDLOCK_ACCESS_FS_IOCTL_DEV` (v5) are included in the default
ruleset (see §13 D4); older kernels silently skip them rather than failing
the build (see §13 D4).

Seccomp filters are installed with the `TSYNC` flag (per §13 D3) so any
threads the child may have created between `clone()` and `execve()` — rare,
but possible with some libc/runtime combinations — inherit the filter
atomically.

## 10. Audit Asymmetry

`--audit` is a macOS-first feature today. On Linux:

- **Phase 1 (initial port):** `BackendFeatures::audit_stream = false`. CLI
  prints "audit streaming not yet supported on Linux backend; violations will
  surface as failed syscalls (`EACCES` / `EPERM`) and non-zero exit status"
  and proceeds.
- **Phase 2 (follow-up):** Implement an `Auditor` trait in `apps/cli/src/audit.rs`
  with two impls: `MacosLogStream` (existing) and `LinuxSeccompLog` (reads
  `/dev/kmsg` filtered to current pid, decodes `SCMP_ACT_LOG` syslog lines).
  Both feed the same `SandboxEvent` stream consumer.

`Auditor` is **separate** from `SandboxBackend` — different lifetimes
(audit runs concurrent to the child, not before/around it) and different
extension points (audit-log file, summary, formatters).

## 11. CI / GitHub Action Implications

With Linux supported:

- `tyrchen/sbe` composite action can stop erroring on non-Linux runners. It
  still installs the Linux musl prebuilt by default; macOS support arrives by
  adding a darwin tarball to `release-cli.yml` and extending `action.yml`'s
  arch/os detection.
- `.github/workflows/build.yml` can stay on `ubuntu-latest` and wrap cargo
  commands with `sbe run --` once the Linux backend lands. The proxy
  integration test (`test_should_allow_permitted_domain`) needs the same
  `enableProxy: false` carve-out as today — Landlock+seccomp filters network
  by port, not by hostname, identical to SBPL.

### GitHub-hosted runner kernels (snapshot 2026-05)

| Runner | Kernel | Landlock net (ABI v4, ≥6.7) | bwrap viable? |
|---|---|---|---|
| `ubuntu-latest` → `ubuntu-24.04` | 6.17.0-azure | ✓ | ✗ — AppArmor restricts unprivileged userns |
| `ubuntu-22.04` | 6.8.0-azure (HWE) | ✓ | ✓ |

Implication: the "kernel 5.13–6.6 seccomp `connect()` fallback" tier (§9) is
**not exercised by GitHub-hosted CI**. It exists for self-hosted runners and
end-user dev boxes on older kernels. CI gets the full-fat Landlock+net path.
This also reinforces the recommendation in §13 Q2: don't ship a bwrap
fallback — `ubuntu-24.04`'s AppArmor regression would block it on the
dominant runner anyway, and the kernels where it'd help are shrinking.

## 12. Migration Plan

Five sequential PRs. Each is independently reviewable and leaves the codebase
shippable on macOS at every step.

1. **Refactor in place (no behavior change).** Create `crates/core/src/sandbox/`,
   define the `SandboxBackend` trait, move `sbpl.rs` →
   `sandbox/macos/sbpl.rs`, move executor's sandbox-exec invocation →
   `sandbox/macos/exec.rs`. Implement `MacosSandbox`. Orchestrator goes
   through the trait. macOS test suite stays green; SBPL output bit-identical.
2. **Per-OS profile defaults.** Split `defaults.yaml` into
   `defaults-macos.yaml` (rename) and add `defaults-linux.yaml`. Conditional
   `include_str!`. Add `cfg(target_os = "linux")` to compile-and-test the
   Linux YAML loads cleanly even on macOS host (parser only, not enforcer).
3. **Linux backend skeleton.** `LinuxSandbox` with `probe()` returning kernel
   info and `render_policy()` printing a structured policy view. `run()`
   returns `CoreError::Unimplemented`. Crate compiles on Linux via cargo
   check on a Linux CI matrix entry. Unit tests for ruleset/seccomp builders
   against fixture profiles, no kernel calls.
4. **Linux enforcement.** Implement `landlock.rs` (Ruleset builder with
   all path FDs preopened in the parent — see §6 invariants) and
   `seccomp.rs` (seccompiler BpfProgram builder). Wire `pre_exec` with the
   alloc-free closure body. Implement the `forbidden_reads` sealing logic
   (§8) and the backend-time `allow_exec` lint that rejects subpath rules
   containing privilege-escalation binaries. Land integration tests that
   actually fork+execve under Landlock on a Linux runner — proxy
   integration test must pass with `enableProxy: false`. Verify pinned
   crate versions before merge: `landlock = "~0.4"`, `seccompiler = "~0.4"`,
   `nix` (already in workspace). Drop `caps` — sbe runs unprivileged so there
   are no ambient caps to manage.
5. **Audit + polish.** Phase-2 audit on Linux (seccomp `SCMP_ACT_LOG` →
   `/dev/kmsg` reader). Documentation pass on `README.md` (lift "macOS only"
   disclaimer, document Linux kernel requirement, document `PR_SET_NO_NEW_PRIVS`
   side effects on setuid binaries, document DBus-DNS / UDP / `denyRead`
   caveats from §8). Update `tyrchen/sbe` composite action to install on both
   OS targets if release artifacts exist.

## 13. Decisions

- **D1. Refuse by default when the kernel can't enforce a requested feature.**
  `LinuxSandbox::run` cross-checks the resolved `SandboxProfile` against
  the `BackendFeatures` captured during `LinuxSandbox::new()`. If the profile
  requires `enableProxy: true` (or any `allowDomains`-bearing config) on a
  kernel without Landlock ABI v4, sbe exits with `EXIT_SANDBOX_FAILED` and a
  message naming the missing capability. Opt-out: `--allow-degraded` CLI
  flag and `allowDegraded: true` in profile config — proceeds with the
  seccomp `connect()` arg-filter fallback after printing a single warning
  line. The same flag also bypasses the §8 backend-time lints
  (`allow_exec` subpath that includes a privilege-escalation binary,
  `denyRead` forbidden-list conflict). Rationale: a security tool that
  silently downgrades is a footgun.
- **D2. No bwrap fallback.** Refuse to start on kernel <5.13 with a clear
  message; do not carry a `bubblewrap` code path. The kernels where bwrap
  would help are shrinking; on `ubuntu-24.04` (the dominant CI runner)
  AppArmor's user-namespace restriction breaks bwrap anyway, making it a net
  liability. Users who want a bwrap boundary can run `sbe` inside a
  bwrap-controlled environment — sbe doesn't need to know.
- **D3. Install seccomp filters with `TSYNC`.** All threads in the child
  (rare pre-`execve`, but possible with some libc/runtime combinations)
  inherit the filter atomically. Matches `seccompiler`'s default; we set it
  explicitly so the intent survives crate upgrades.
- **D4. Include Landlock ABI v3+v5 access flags in the default ruleset.**
  `LANDLOCK_ACCESS_FS_TRUNCATE` (v3) and `LANDLOCK_ACCESS_FS_IOCTL_DEV` (v5)
  are added via `CompatLevel::BestEffort` so 5.13–5.18 kernels silently skip
  them rather than failing ruleset construction. No user-visible config
  surface — these are "harden by default" choices baked into the backend.
