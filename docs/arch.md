# sbe Architecture

> **Status:** Reflects the code at `master` (v0.2.0).
> **Audience:** Contributors to sbe, security engineers evaluating the design,
> and users who want to understand what actually happens when they type
> `sbe run -- npm install`.

## 1. Purpose and Threat Model

### 1.1 Problem

Modern package managers execute arbitrary code during install and build:

- npm `preinstall` / `postinstall` hooks
- Rust `build.rs` scripts and procedural macros
- Python `setup.py` / PEP 517 backends
- Elixir `mix compile` hooks, rebar3 plugins
- Gradle plugins, Maven lifecycle hooks, sbt tasks

A single compromised transitive dependency can run code with the full
ambient authority of the user who invoked the build: read `~/.ssh`,
`~/.aws`, macOS Keychain items, browser profiles; write to
`~/Library/LaunchAgents`; establish C2 channels; or install persistent
backdoors under `~/.cargo/bin`, `~/.local/bin`, `/usr/local/bin`.

### 1.2 Goals

1. **Kernel-enforced isolation** of build and install steps, without
   requiring containers, VMs, or a new package manager.
2. **Zero friction.** `sbe run -- <anything>` should Just Work for the
   supported ecosystems (Node, Rust, Python, Elixir, Java).
3. **Defense in depth** against two concrete attack classes:
   - **Secret exfiltration:** reading sensitive files or screenshots.
   - **Unauthorized network egress:** reaching C2, pastebins, or
     non-registry endpoints to fetch second-stage payloads.
4. **Deny-by-default** file writes, with a small, auditable allowlist
   per ecosystem.
5. **Observability** of denials through the macOS audit log.

### 1.3 Non-Goals

- **Sandbox escape hardening beyond what `sandbox-exec` provides.** sbe
  is as strong as Apple's Seatbelt / TrustedBSD MAC framework and no
  stronger. It is not a hypervisor.
- **Cross-platform support.** sbe is macOS-only. Linux would require a
  completely different backend (seccomp-bpf, Landlock, bubblewrap).
- **Protecting against malicious tools that `sbe` itself invokes.** If a
  user adds `curl` to `allow_exec` and points at a malicious mirror, sbe
  cannot help them.
- **A new package manager.** sbe deliberately wraps existing tools; it
  does not vendor, pin, or audit dependencies itself.

### 1.4 Trust Boundaries

```
 ┌─────────────────────────────────────────────────────────────────┐
 │  User login session (TCC, ambient authority, keychain access)   │
 │                                                                 │
 │  ┌───────────────────────────────────────────────────────────┐  │
 │  │  sbe host process (trusted)                               │  │
 │  │  ├─ reads ~/.sbe.yaml, ~/.config/sbe/config.yaml          │  │
 │  │  ├─ reads $CWD for ecosystem detection                    │  │
 │  │  ├─ writes /tmp/sbe-XXXX.sb (0400)                        │  │
 │  │  ├─ forks sbe-proxy on 127.0.0.1:<ephemeral>              │  │
 │  │  └─ forks sandbox-exec                                    │  │
 │  │       │                                                   │  │
 │  │       ▼                                                   │  │
 │  │  ┌─────────────────────────────────────────────────┐      │  │
 │  │  │  Sandboxed process tree (untrusted)             │      │  │
 │  │  │  (npm / cargo / pip / mix / gradle / ...)       │      │  │
 │  │  │  — kernel-enforced SBPL policy                  │      │  │
 │  │  │  — no direct network except 127.0.0.1:<proxy>   │      │  │
 │  │  │  — no reads of denied secret paths              │      │  │
 │  │  └─────────────────────────────────────────────────┘      │  │
 │  └───────────────────────────────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────────┘
```

The **sbe host** and **sbe-proxy** are trusted; they run with the user's
full ambient authority. The **sandboxed tree** is untrusted.

All security properties of sbe reduce to two enforcement points:

1. The SBPL policy written to `/tmp/sbe-XXXX.sb` and loaded by
   `sandbox-exec(1)` into the kernel's TrustedBSD MAC hook table.
2. The in-process domain allowlist checked by `sbe-proxy` on every
   HTTP `CONNECT` request before any upstream bytes flow.

## 2. High-Level Architecture

### 2.1 Component Diagram

```
                              sbe CLI (apps/cli)
                                    │
                ┌───────────────────┼───────────────────┐
                │                   │                   │
                ▼                   ▼                   ▼
        ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
        │ detect        │  │ config +      │  │ sbpl          │
        │ (Ecosystem)   │  │ profile merge │  │ generator     │
        └───────┬───────┘  └───────┬───────┘  └───────┬───────┘
                │                  │                  │
                └─────── sbe-core (crates/core) ──────┘
                                   │
         SandboxProfile + proxy_port                SBPL string
                                   │
                                   ▼
        ┌─────────────────────────────────────────────────────┐
        │ executor::execute (apps/cli/src/executor.rs)        │
        │  1. verify platform                                 │
        │  2. resolve ecosystem                               │
        │  3. build SandboxProfile                            │
        │  4. start ProxyServer (if domains are allowlisted)  │
        │  5. generate SBPL                                   │
        │  6. write /tmp/sbe-XXXX.sb (mode 0400)              │
        │  7. spawn sandbox-exec -f <sbpl> <cmd> ...          │
        │  8. (optional) stream sandboxd log for audit        │
        │  9. propagate exit code, cleanup tempfile + proxy   │
        └─────────────────────────────────────────────────────┘
                                   │
                         ┌─────────┴─────────┐
                         │                   │
                         ▼                   ▼
           ┌───────────────────┐   ┌────────────────────┐
           │ sbe-proxy         │   │ sandbox-exec       │
           │ (crates/proxy)    │◄──│ + child process    │
           │ HTTP CONNECT on   │   │ HTTP_PROXY=        │
           │ 127.0.0.1:<eph>   │   │  http://127.0.0.1: │
           │ domain allowlist  │   │  <eph>             │
           └───────────────────┘   └────────────────────┘
```

### 2.2 Crate Layout

```
sbe/
├── apps/
│   └── cli/               # sbe binary (the only binary)
│       └── src/
│           ├── main.rs       # tokio entrypoint, tracing setup, subcommand dispatch
│           ├── cli.rs        # clap: Cli, Commands, RunArgs, InspectArgs
│           ├── executor.rs   # sandbox lifecycle orchestration
│           └── audit.rs      # `log stream` tailer, violation summary
├── crates/
│   ├── core/              # sbe-core: pure logic, no side effects beyond FS reads
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── detect.rs   # Ecosystem enum, command→eco, markerfile→eco
│   │       ├── config.rs   # YAML loading, merging, path expansion
│   │       ├── profile/
│   │       │   ├── mod.rs      # SandboxProfile, ProfileOverrides, finalize
│   │       │   └── defaults.yaml  # embedded via include_str!
│   │       ├── sbpl.rs     # SBPL string emitter
│   │       └── error.rs
│   └── proxy/             # sbe-proxy: HTTP CONNECT forward proxy
│       └── src/
│           ├── lib.rs
│           ├── server.rs     # bind + accept loop + CONNECT handler
│           ├── allowlist.rs  # exact + wildcard domain matching
│           └── error.rs
├── fixtures/              # integration test fixtures (per-language projects)
└── specs/                 # PRD / design / impl plan
```

**Why this split.** `sbe-core` is pure and deterministic: given
`(ecosystem, home, pwd, configs, cli-args)` it produces a
`SandboxProfile` and an SBPL string. It contains no `tokio::spawn`, no
process execution, and no proxy. It is trivially unit-testable without
a macOS host. The proxy is a separate crate because it is an I/O-bound
async server with its own error surface; isolating it keeps `core`
cheap to compile and test.

## 3. Execution Lifecycle

This is the canonical order of operations for `sbe run -- <cmd>`.
Implementation lives in `apps/cli/src/executor.rs::execute_inner`.

```
┌───────────────────────────────────────────────────────────────────┐
│ 1. verify_platform()                                              │
│     - cfg!(target_os = "macos")                                   │
│     - /usr/bin/sandbox-exec must exist                            │
│                                                                   │
│ 2. Read `pwd` and `home`                                          │
│                                                                   │
│ 3. resolve_ecosystem(command[0], --profile, pwd)                  │
│     - --profile <name> wins                                       │
│     - else detect::detect() looks at argv[0] basename, then       │
│       walks marker files in pwd (Cargo.toml, package.json, ...)   │
│                                                                   │
│ 4. SandboxProfile::for_ecosystem(eco, home, pwd)                  │
│     - loads embedded defaults.yaml                                │
│     - merges common.{denyRead, denyExec, allowExec}               │
│     - merges ecosystem.{allowWrite, allowDomains, allowExec}      │
│     - expands ~ / $PWD / relative paths                           │
│     - applies ecosystem-specific quirks:                          │
│         * Node monorepo: walk up to .git root for hoisted         │
│           node_modules + lockfiles                                │
│         * Rust: resolve CARGO_TARGET_DIR (env or .cargo/config),  │
│           add sibling temp-dir regex                              │
│         * Java: allow JAVA_HOME subtree                           │
│     - resolve_symlinks() canonicalizes allow_exec and deny_exec   │
│       and special-cases Homebrew Cellar package roots             │
│                                                                   │
│ 5. load_configs(pwd, --config)                                    │
│     - ~/.config/sbe/config.yaml                                   │
│     - .sbe.yaml walked up from pwd to git root                    │
│     - --config <path> last (wins)                                 │
│                                                                   │
│ 6. resolve_profile() — applies YAML profile blocks onto profile   │
│     (respecting `extends:` within a file)                         │
│                                                                   │
│ 7. merge_overrides() — CLI flags (-w, -n, -N, -e, -E, -f, ...)    │
│                                                                   │
│ 8. profile.finalize() — if allow_fetch is non-empty, push         │
│    /usr/bin/curl and /usr/bin/wget into allow_exec and fold       │
│    allow_fetch into allow_domains                                 │
│                                                                   │
│ 9. start_proxy_if_needed(profile, shutdown_rx)                    │
│     - skipped when enable_proxy=false OR allow_all_network=true   │
│       OR allow_domains is empty                                   │
│     - otherwise: bind 127.0.0.1:0, get ephemeral port,            │
│       tokio::spawn(server.run())                                  │
│                                                                   │
│10. sbpl::generate(profile, Some(port))                            │
│                                                                   │
│11. if args.dry_run { print profile + SBPL; return SUCCESS; }      │
│                                                                   │
│12. write_sbpl_tempfile() → NamedTempFile                          │
│     - created under OS tempdir with prefix "sbe-"                 │
│     - chmod 0400 so the child cannot rewrite its own policy       │
│     - RAII: file is unlinked on drop                              │
│                                                                   │
│13. AuditLogger (optional) — spawns `log stream --predicate        │
│    'process == "sandboxd"'` and tails for deny lines              │
│                                                                   │
│14. run_sandboxed_command()                                        │
│     /usr/bin/sandbox-exec -f <sbpl_path> <cmd> <args>...          │
│     with env HTTP_PROXY / HTTPS_PROXY (and lowercase twins)       │
│     pointing at http://127.0.0.1:<port>, plus NO_PROXY=localhost  │
│     stdin/stdout/stderr inherited from the parent                 │
│                                                                   │
│15. shutdown_tx.send(true) — proxy select!s on this and exits      │
│    AuditHandle::stop_and_summarize() prints violation counts      │
│                                                                   │
│16. Map ExitStatus → u8:                                           │
│     - normal exit code is passed through                          │
│     - signaled death → 126 (EXIT_SANDBOX_FAILED)                  │
│     - code 71 or 126 + no --audit: print hint about sandbox denial│
│     - sbe's own errors → 125 (EXIT_SBE_ERROR)                     │
└───────────────────────────────────────────────────────────────────┘
```

### 3.1 Concurrency Model

sbe runs on a multi-threaded tokio runtime (`#[tokio::main]`).

- **Proxy server** is `tokio::spawn`ed onto the runtime. Each accepted
  connection is spawned as its own task and owns an `Arc<DomainAllowlist>`.
- **Shutdown** uses a `tokio::sync::watch::<bool>` channel. The
  executor holds the `Sender`; the proxy `select!`s on
  `listener.accept()` vs `shutdown_rx.changed()`. A single `send(true)`
  after the child exits is sufficient to drain all connection tasks
  (bidirectional copies terminate naturally when either socket closes).
- **Audit logger** uses `Arc<AtomicBool>` as its stop signal and kills
  the child `log stream` process on stop.
- **No shared mutable state.** The allowlist is built once, wrapped in
  `Arc`, and never mutated. `SandboxProfile` is owned by the executor
  and never crosses a task boundary.

### 3.2 Error Handling

- Library code (`sbe-core`, `sbe-proxy`) defines `thiserror`-derived
  error enums (`CoreError`, `ProxyError`). No `unwrap` on the hot path.
- Application code (`apps/cli`) uses `anyhow::Result` with
  `.context()` for top-level error surfaces.
- Exit-code contract:
  - `0..=255` → child exit code, passed through
  - `125` → sbe internal error (wraps whatever `anyhow` bubbled up)
  - `126` → sandbox setup failed / child killed by signal
  - `71` or `126` from the child triggers an informational hint telling
    the user to re-run with `--audit`
- The one `panic!` in `sbe-core` is a load-time assertion on the
  embedded `defaults.yaml` — if the shipped YAML is unparsable, that is
  a build-time bug, not a runtime condition.

## 4. Profile Resolution

`SandboxProfile` is the single data structure that drives everything
downstream (SBPL emission, proxy allowlist, env injection).

```rust
pub struct SandboxProfile {
    pub name: String,                  // e.g. "node", "rust", "custom:my-app"
    pub allow_write:  Vec<SandboxPath>,
    pub deny_read:    Vec<SandboxPath>,
    pub allow_domains:Vec<DomainPattern>,
    pub deny_exec:    Vec<SandboxPath>,
    pub allow_exec:   Vec<SandboxPath>,
    pub enable_proxy: bool,            // default true
    pub allow_all_network: bool,       // default false (--allow-all-network)
    pub allow_fetch:  Vec<DomainPattern>,
    pub env:          HashMap<String, String>,
}
```

### 4.1 `SandboxPath` and `PathKind`

`SandboxPath { path: PathBuf, kind: PathKind }` wraps a path with its
intended SBPL match mode:

| `PathKind` | SBPL form            | Used for                                   |
|------------|----------------------|--------------------------------------------|
| `Subpath`  | `(subpath "/a/b")`   | directories (recursive match)              |
| `Literal`  | `(literal "/a/b")`   | exact file paths (e.g. binaries)           |
| `Regex`    | `(regex #"^/a/b.*$")`| cargo target sibling temp dirs             |

**Path convention in YAML and CLI input:** a trailing slash marks a
directory (emits `Subpath`); no trailing slash marks a file (emits
`Literal`). `Regex` paths are produced only programmatically — they are
not a user-facing surface.

Path expansion (`config::expand_path`) supports:

- `~`, `~/...` → `$HOME`
- `$HOME`, `$HOME/...` → `$HOME`
- `$PWD`, `$PWD/...` → working directory
- `./foo` and bare relative → joined onto `$PWD`
- `/abs` → verbatim

### 4.2 Merge Order (last writer wins)

```
  (1) built-in defaults.yaml  ← embedded via include_str!
      │
      ▼
  (2) ~/.config/sbe/config.yaml  ← global, if present
      │
      ▼
  (3) .sbe.yaml / .sbe.yml       ← project, walks up to git root
      │
      ▼
  (4) --config <path>            ← explicit override
      │
      ▼
  (5) CLI flags via ProfileOverrides
      │
      ▼
  (6) profile.finalize()         ← allow_fetch → curl/wget + domain fold-in
```

List-valued fields (`allow_write`, `allow_exec`, `allow_domains`, ...)
are **additive** through layers 1–5; there is no override semantics for
list removal except:

- `--deny-domain <d>` removes a previously allowed domain in
  `merge_overrides` (used for e.g. disabling `registry.npmmirror.com`).
- `allow_all_network: true` clears `enable_proxy`.

Within a YAML file, a profile block may `extends: <other>` to inherit
list contents from another profile block in the same file. This is a
flat one-level mechanism, intentionally simple.

### 4.3 Ecosystem-Specific Quirks

These live in `profile::for_ecosystem` and are the practical result of
running real build systems under the sandbox:

- **Node monorepos.** If `pwd` is inside a git repo whose root is an
  ancestor, also allow `<git_root>/node_modules` (write + exec) and
  lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) and
  `.yarn/`, `.pnp.{cjs,loader.mjs}`. The git root itself is **not**
  granted write access — that would let a malicious postinstall modify
  sibling packages or CI configs.
- **Rust target dir.** Resolved in order:
  `$CARGO_TARGET_DIR` → `$CARGO_BUILD_TARGET_DIR` →
  `pwd/.cargo/config.toml` `[build] target-dir = "..."` →
  `~/.cargo/config.toml` [build].target-dir → fallback `pwd/target`.
  For custom target dirs, a regex is also added to allow the
  atomic-rename siblings cargo creates
  (`^<target-dir>[A-Za-z0-9]*$`).
- **Java.** If `JAVA_HOME` is set in the parent env, the entire subtree
  is added to `allow_exec`.
- **Symlink resolution.** macOS `sandbox-exec` checks the real path
  after kernel symlink resolution, so a shim at
  `/opt/homebrew/bin/zig` (a symlink into
  `/opt/homebrew/Cellar/zig/0.15.2/bin/zig`) will not match unless the
  Cellar path is also in the allow list. `resolve_symlinks` canonicalizes
  every entry and, for Homebrew `/Cellar/<pkg>/<ver>/` paths, grants the
  entire package root subtree (because tools like `zig` spawn sub-tools
  from their own `lib/`). This is applied to both `allow_exec` and
  `deny_exec`.

### 4.4 `allow_fetch`: Opt-in Build-Time Downloads

Some crates legitimately need to download during `build.rs`
(`utoipa-swagger-ui`, `protobuf-src`, etc.). `allow_fetch` is the clean
way to say "yes, but only from these domains":

1. User adds `allowFetch: [download.example.com]` (YAML) or
   `-f download.example.com` (CLI).
2. `profile.finalize()` pushes `/usr/bin/curl` and `/usr/bin/wget` into
   `allow_exec` (if not already present).
3. `allow_fetch` domains are merged into `allow_domains`, so the proxy
   will tunnel CONNECTs to them.

Without `allow_fetch`, `curl`/`wget` are **not** in the allow list and
will be denied by the kernel — a strong default that prevents a
compromised build script from using them as a second-stage downloader.

## 5. SBPL Generation

`sbe_core::sbpl::generate(&profile, proxy_port)` emits a Scheme-like
Seatbelt Profile Language (SBPL) document. SBPL is the format consumed
by `sandbox-exec(1)` and implemented by Apple's Sandbox kext.

### 5.1 Policy Shape

```
(version 1)

;; sbe sandbox profile: <name>
;; Policy: deny by default, allow explicit exceptions
(deny default)

;; Process control
(allow process-fork)
(allow process-exec
    (literal "/bin/sh")
    (subpath "/Users/<user>/.cargo/bin")
    ...)
(deny process-exec
    (literal "/usr/bin/osascript")
    (literal "/usr/bin/pbcopy")
    ...)

;; File reads: allow most, deny secrets
(allow file-read*)
(deny file-read*
    (subpath "/Users/<user>/.ssh")
    (subpath "/Users/<user>/.aws")
    (literal "/Users/<user>/.cargo/credentials.toml")
    ...)

;; File writes: deny all, allow specific paths
(deny file-write*)
(allow file-write*
    (subpath "/Users/<user>/project")
    (subpath "/Users/<user>/.cargo/registry")
    ...
    (subpath "/private/tmp")
    (subpath "/private/var/folders")
    (literal "/dev/null")
    (literal "/dev/zero"))

;; Network
(deny network*)
(allow network-outbound
    (remote tcp "localhost:<proxy_port>")
    (remote ip "localhost:*")
    (literal "/private/var/run/mDNSResponder"))
(allow network-inbound (local ip "localhost:*"))

;; Miscellaneous required permissions
(allow sysctl-read)
(allow mach-lookup
    (global-name "com.apple.system.logger")
    (global-name "com.apple.system.notification_center")
    (global-name "com.apple.CoreServices.coreservicesd")
    (global-name "com.apple.SecurityServer")
    (global-name "com.apple.distributed_notifications@Mu")
    (global-name-regex #"^com\.apple\.cfprefsd\.")
    (global-name-regex #"^com\.apple\.lsd\."))
(allow ipc-posix-shm-read*)
(allow ipc-posix-shm-write-data)
(allow signal (target self))
```

### 5.2 Design Rationale

- **`(deny default)` first.** Every operation is denied unless an
  explicit rule allows it. This is the inverse of macOS's native
  default-allow posture.
- **Asymmetric reads vs. writes.** `file-read*` is **allow-by-default**
  with a small denylist for secrets. This is a pragmatic trade-off:
  build tools read an enormous amount of data (`/usr/include`,
  `/System`, `.git/objects`, shared libraries), and enumerating every
  read is infeasible. Writes, by contrast, are **deny-by-default** with
  a small allowlist — writes are what attacks use to persist.
- **Four network modes** (`sbpl::section_network`):
  1. `allow_all_network` → `(allow network*)` (explicit escape hatch).
  2. Proxy enabled with port → deny all, allow only
     `localhost:<port>`, localhost, and `mDNSResponder` (for DNS lookups
     via `getaddrinfo` on platforms where it talks to mDNS).
  3. Proxy would be enabled but has no port yet → same as (2) minus the
     port (used only on the dry-run inspect path before a proxy is
     started).
  4. No proxy — `--no-proxy` → deny all, allow `*:443` outbound. This
     is a weaker fallback that lets TLS through on IP alone.
- **`(allow network-inbound (local ip "localhost:*"))`.** Many tools
  (Bazel, Gradle, dev servers) bind loopback sockets for worker IPC;
  without this rule they fail to start.
- **Temp-dir writes are always allowed.** `/private/tmp` and
  `/private/var/folders` are added to the write allowlist unconditionally
  when any writes are allowed, because nearly every toolchain writes
  there (`mktemp`, `NamedTempFile`, `/var/folders/..`).
- **`/dev/null` and `/dev/zero`** are allow-listed as literals because
  Rust's `Stdio::null()` opens them for write, and several build
  scripts use `/dev/null` as a throwaway sink.
- **`mach-lookup` is scoped, not blanket.** A naive
  `(allow mach-lookup)` would let the sandboxed process talk to any
  Mach service, defeating much of the isolation. sbe lists only the
  services needed for tracing, notifications, core-services, and
  securityd/cfprefs.

### 5.3 Tempfile Handling

SBPL is written to a `NamedTempFile` (via the `tempfile` crate)
prefixed with `sbe-`. Key properties:

- **Unique per invocation.** Multiple `sbe` processes do not race.
- **Mode `0400`.** The sandboxed child cannot modify its own policy.
  Even if it could find the path (via `/proc`-equivalents), the kernel
  will deny the write because the temp dir is outside the write
  allowlist in the policy the child is running under — but the
  belt-and-suspenders `chmod` means even the host process and unrelated
  processes owned by the user can't accidentally clobber it.
- **RAII cleanup.** On `NamedTempFile` drop, the file is unlinked
  regardless of whether the child succeeded, failed, or crashed.

## 6. Proxy Subsystem (`sbe-proxy`)

### 6.1 Why a Proxy at All

SBPL's `network-outbound` clause can only filter by IP/port, not by
DNS name. Modern package registries (`crates.io`, `pypi.org`,
`registry.npmjs.org`) are fronted by CDNs (Fastly, Cloudflare) whose
IP ranges overlap with large swaths of the commercial internet.
Allowlisting `fastly.net` IPs at the kernel level effectively allows
most of the web.

sbe's solution is a **two-layer defense**:

1. **Kernel (SBPL):** deny all outbound except
   `127.0.0.1:<proxy_port>` (and DNS to `mDNSResponder`).
2. **Application (proxy):** the sandboxed process has `HTTP_PROXY` /
   `HTTPS_PROXY` pointed at `127.0.0.1:<proxy_port>`, so every HTTPS
   request arrives as an `HTTP CONNECT <hostname>:443` on that socket.
   The proxy checks the hostname against the allowlist **before** it
   opens any upstream connection.

This lets sbe filter by domain without MITMing TLS: the proxy never
sees the plaintext, it only sees the `CONNECT` line and then blindly
copies bytes between the two sockets.

### 6.2 Server Anatomy

```
ProxyServer::bind(allowlist, shutdown_rx) -> (self, port)
    │
    └─ TcpListener::bind("127.0.0.1:0")      // ephemeral port
       local_addr().port()                    // return to caller

ProxyServer::run(self)
    │
    loop { tokio::select! {
        accept => spawn(handle_connection)
        shutdown.changed() => break
    }}

handle_connection(client, addr, allowlist)
    │
    ├─ BufReader::new(client)
    ├─ read_line() → "CONNECT registry.npmjs.org:443 HTTP/1.1"
    ├─ parse method + target
    │    - non-CONNECT → 405 Method Not Allowed
    │    - malformed   → 400 Bad Request
    ├─ parse_host_port (handles [v6]:port)
    ├─ drain headers until blank line
    ├─ allowlist.is_allowed(host)
    │    - no → 403 with explanatory body, close
    │    - yes → TcpStream::connect("host:port")
    ├─ write "200 Connection Established"
    ├─ flush + forward any buffered bytes left in the BufReader
    └─ tokio::io::copy_bidirectional(&mut client, &mut upstream)
```

Important details the code gets right (see `server.rs`):

- **Buffered-data replay.** After `read_line` and header draining, the
  `BufReader`'s internal buffer may contain bytes that belong to the
  tunnelled TLS stream (the client has no reason to wait for a response
  before starting TLS). Those bytes are pulled out via `.buffer()` and
  written to the upstream socket before the bidirectional copy starts.
  Missing this would silently break some clients.
- **Case-insensitive matching.** `DomainAllowlist::new` lowercases all
  patterns, and `is_allowed` lowercases the input. Hostnames are ASCII
  case-insensitive by RFC 1035.
- **Wildcard semantics.** `*.example.com` matches `example.com` itself
  **and** any subdomain (`foo.example.com`, `deep.sub.example.com`).
  Bare wildcards (`*`) are not supported — a typo'd allowlist should
  fail closed, not open.
- **No HTTP/1.1 methods other than CONNECT.** A compromised build tool
  cannot, for example, GET `http://evil.com/x` through this proxy even
  if `evil.com` were somehow on the list.

### 6.3 Environment Injection

The executor injects these variables into the child:

```
HTTP_PROXY  = http://127.0.0.1:<port>
HTTPS_PROXY = http://127.0.0.1:<port>
http_proxy  = http://127.0.0.1:<port>   # lowercase twins for tools that check them
https_proxy = http://127.0.0.1:<port>
NO_PROXY    = localhost,127.0.0.1
no_proxy    = localhost,127.0.0.1
```

Uppercase and lowercase variants are both set because the ecosystem is
inconsistent: some tools (Rust's `ureq`, Python's `requests`) respect
one or the other; some respect both.

### 6.4 Failure Modes

| Failure                              | User sees                                          |
|--------------------------------------|----------------------------------------------------|
| Domain not in allowlist              | `403 Forbidden` with explanatory body              |
| Upstream DNS / connect error         | `ProxyError::UpstreamConnect` logged; tunnel drops |
| Non-CONNECT method                   | `405 Method Not Allowed`                           |
| Malformed request line               | `400 Bad Request`                                  |
| Sandbox blocks 127.0.0.1:<port>      | tool prints TLS/DNS error; `--audit` explains      |

## 7. Audit Subsystem

`apps/cli/src/audit.rs` optionally tails `/usr/bin/log stream --style
compact --predicate 'process == "sandboxd"'` for the duration of the
sandboxed run.

- **Activation:** `--audit` (to stderr) or `--audit-log <path>` (to file).
- **Parsing is intentionally shallow.** `parse_sandbox_event` looks for
  the substring `deny` and bucketizes the operation into one of
  `file-write`, `file-read`, `network`, `process-exec`, or `other`,
  then uses the last space-separated token as the target.
  sandboxd's log format is not stable API, so a robust parser would be
  false precision; the goal is a fast, greppable hint.
- **Summary.** On shutdown, `AuditHandle::stop_and_summarize` prints a
  `Violation summary:` block sorted by operation frequency.

The audit loop uses a select over `lines.next_line()` and a 100ms
`sleep`, with `AtomicBool` as the cancel signal, so that a dead
`log stream` child doesn't hang the host after the sandboxed process
exits.

## 8. Security Properties and Caveats

### 8.1 Properties We Expect to Hold

1. **Secret exfiltration.** Any attempt to read a file matched by
   `common.denyRead` is blocked by the kernel. This covers
   `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gcloud`,
   `~/.kube/config`, `~/Library/Keychains`, `~/.docker/config.json`,
   `~/.netrc`, `~/.cargo/credentials*`, `~/.pypirc`, `~/.hex/hex_api_key`,
   `~/.config/gh`, `.env{,.local,.production}`, and common browser profiles.
2. **Secret-channel exfiltration via subprocess.** `osascript`,
   `security`, `screencapture`, `open`, `pbcopy`, and `pbpaste` are
   in `deny_exec`. A malicious build step cannot shell out to them.
3. **Second-stage download.** `curl` and `wget` are **not** in the
   default `allow_exec`. Without `allow_fetch`, attempts to invoke them
   are denied at the kernel level.
4. **Direct C2.** The kernel policy denies every outbound socket except
   to the proxy. The proxy rejects every `CONNECT` to a domain not on
   the ecosystem's allowlist with HTTP 403.
5. **Write persistence.** `~/.cargo/bin`, `~/.local/bin`, and
   `/usr/local/bin` are **not** writable by default — so a malicious
   postinstall cannot drop a trojaned `cargo` or `pip`. The project
   directory itself is writable, which is necessary for builds.

### 8.2 Caveats the User Should Know

- **TCC (Transparency, Consent, Control).** `sandbox-exec` operates at
  the Seatbelt / TrustedBSD MAC layer, which is separate from macOS's
  user-space TCC database. If the parent process has already been
  granted Full Disk Access, the sandboxed child inherits that grant —
  but SBPL's `deny file-read*` on e.g. `~/.ssh` still applies and
  trumps TCC. The two layers compose as an **intersection**: both must
  allow for the read to proceed.
- **`.git` is readable.** Most build tools read Git metadata; sbe does
  not block this. A malicious tool can therefore exfiltrate commit
  history to an allowed domain. This is considered acceptable because
  the commit history is already in the remote repository.
- **Same-host lateral movement.** `(allow network-inbound (local ip
  "localhost:*"))` means a compromised child can connect to whatever
  else happens to be listening on loopback. Users running sensitive
  loopback services (local databases, metrics sidecars) should be
  aware. Closing this would break common development tools.
- **Apple has deprecated `sandbox-exec`.** It still works and is shipped
  with every macOS release, but Apple's documentation warns that it is
  "unsupported" for third-party use. There is no drop-in successor for
  per-process sandboxing of arbitrary binaries, so sbe will ride it
  until it breaks.
- **SBPL is undocumented.** The rule language was reverse-engineered
  by the community (notably Dionysus Blazakis's "The Apple Sandbox"
  paper). Apple is free to change it in any minor OS update. sbe's
  integration tests and fixtures exist to catch such drift quickly.

### 8.3 Out-of-Scope Attacks

- **Kernel exploits.** If the sandboxed process can escape via a kernel
  vulnerability, sbe cannot help.
- **Side channels.** CPU, cache, and timing side channels are not
  addressed.
- **DNS-based tunneling.** `mDNSResponder` is reachable; a sufficiently
  clever tool could exfiltrate over DNS. This is a well-known limitation
  of any proxy-based allowlisting scheme.
- **Malicious config.** A user who puts
  `allowDomains: ["*"]` into `.sbe.yaml` gets what they asked for.

## 9. Extensibility

### 9.1 Adding a New Ecosystem

1. Add a variant to `Ecosystem` (`crates/core/src/detect.rs`) and
   corresponding arms in `Display`, `FromStr`, and the `ALL` array.
2. Extend `detect_from_command` and `detect_from_files` with the new
   command names and marker files.
3. Add a block under `profiles:` in
   `crates/core/src/profile/defaults.yaml` containing `allowWrite`,
   `allowDomains`, and `allowExec`.
4. If the ecosystem has irregular layout (cache dirs outside `$HOME`,
   target dirs controlled by env vars, etc.), add a branch in
   `for_ecosystem` alongside the existing Node/Rust/Java quirks.
5. Add a fixture under `fixtures/<eco>/` with a minimal "hello world"
   project and extend the integration tests.

### 9.2 Adding a CLI Override

1. Add the flag to `RunArgs` (and mirror it in `InspectArgs` +
   `InspectArgs::as_run_args` if it should work under `inspect`).
2. Add the corresponding field to `ProfileOverrides`
   (`profile::mod.rs`).
3. Extend `executor::build_overrides` to populate it from `RunArgs`.
4. Consume it in `SandboxProfile::merge_overrides` (or `finalize` if it
   has knock-on effects on other fields).

### 9.3 Custom Profiles in YAML

Users can define new profile names that extend a built-in one:

```yaml
profiles:
  my-app:
    extends: node
    allowDomains:
      - "internal-registry.mycompany.com"
    allowWrite:
      - "./dist"
    env:
      NODE_ENV: production
```

The profile name is then selectable at the CLI with
`sbe run -p my-app -- ...`. (Note: `extends` currently resolves only
within a single YAML file; cross-file inheritance is not supported by
design.)

## 10. Dependencies and Build

- **Workspace:** Cargo workspace with `resolver = "3"` and Rust 2024
  edition, pinned via `rust-toolchain.toml`.
- **Crates in the dependency graph:** `tokio` (multi-thread, macros,
  net, process, signal, fs, sync, time), `clap` (derive), `serde` +
  `serde_yaml` + `serde_json`, `thiserror`, `anyhow`, `tempfile`,
  `tracing` + `tracing-subscriber`, `dirs`. All pure Rust; no OpenSSL
  linkage, no FFI.
- **No MSRV declaration.** The toolchain is pinned to stable via
  `rust-toolchain.toml`.
- **CI / Make targets:** `make build`, `make test` (cargo-nextest),
  `make check` (fmt + clippy + test), `make install`.

## 11. Testing Strategy

- **Unit tests** live next to their modules under `#[cfg(test)]`:
  - `profile::tests` — defaults parsing, merge behavior, finalize,
    symlink resolution fallback.
  - `config::tests` — path expansion, YAML parsing, `apply_to`.
  - `detect::tests` — command and markerfile detection.
  - `sbpl::tests` — asserts generated SBPL contains the expected
    s-expressions for each mode (proxy, no-proxy, allow-all,
    per-ecosystem).
  - `proxy::allowlist::tests` — exact / wildcard / case insensitivity.
  - `proxy::server::tests` — `parse_host_port` edge cases (IPv6).
- **Fixtures under `fixtures/`** provide per-language minimal projects
  used by integration tests to verify that the real SBPL actually works
  against the real toolchains. These are the first line of defense
  against Apple silently changing SBPL semantics.

## 12. File-by-File Pointer Map

| File                                      | Responsibility                                    |
|-------------------------------------------|---------------------------------------------------|
| `apps/cli/src/main.rs`                    | tokio entry, logging init, subcommand dispatch    |
| `apps/cli/src/cli.rs`                     | clap definitions for `run`, `inspect`, `profiles` |
| `apps/cli/src/executor.rs`                | lifecycle orchestration (see §3)                  |
| `apps/cli/src/audit.rs`                   | `log stream` tailer + violation summary           |
| `crates/core/src/lib.rs`                  | module roots                                      |
| `crates/core/src/detect.rs`               | `Ecosystem`, command + markerfile detection       |
| `crates/core/src/config.rs`               | YAML loading, merging, `expand_path`, `SandboxPath` |
| `crates/core/src/profile/mod.rs`          | `SandboxProfile`, overrides, symlink/quirk logic  |
| `crates/core/src/profile/defaults.yaml`   | embedded per-ecosystem defaults                   |
| `crates/core/src/sbpl.rs`                 | SBPL string emitter                               |
| `crates/core/src/error.rs`                | `CoreError`                                       |
| `crates/proxy/src/lib.rs`                 | re-exports                                        |
| `crates/proxy/src/server.rs`              | `ProxyServer`, CONNECT handler                    |
| `crates/proxy/src/allowlist.rs`           | `DomainAllowlist`                                 |
| `crates/proxy/src/error.rs`               | `ProxyError`                                      |
