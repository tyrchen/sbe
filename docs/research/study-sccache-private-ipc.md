# Study: sccache 0.17 private IPC under SBE

Status: Done · Owner: SBE · Date: 2026-08-28 · Source revision:
Upstream sccache commit `c037e117c7625a2668633574028a6addf2a96a6e`

> **Historical research.** The private-IPC experiment remains valid evidence,
> but [Usable Security Design](../../specs/usable-security-design.md) rejects a
> product-specific managed sccache adapter and source vendoring.

## Why this study

SBE 0.4.0 blocks a globally configured Homebrew `sccache` before Cargo can
query rustc. A project-level workaround must grant the resolved executable,
cache writes, and `allowAllNetwork`, weakening the primary network boundary.
This study answers whether SBE can support sccache with no ambient local
service access and no broad network grant.

## Architecture map

```text
SBE trusted parent
│
├─ creates mode-0700 per-run root
│  ├─ startup notification socket
│  └─ sccache server socket
│
└─ sandbox domain
   ├─ managed sccache server ────────▶ persistent data-only cache
   │          ▲                                  no execute right
   │          │ private pathname UDS
   │          ▼
   ├─ sccache compiler clients
   │          │ SCCACHE_CLIENT_SIDE=1
   │          ▼
   └─ rustc executes inside the same sandbox domain

All Internet and ambient local-service connections remain governed by the
ordinary SBE network mode.
```

## Hot path walkthrough

1. sccache selects `SCCACHE_SERVER_UDS` before falling back to TCP
   `127.0.0.1:4226`
   ([commands.rs:46](https://github.com/mozilla/sccache/blob/c037e117c7625a2668633574028a6addf2a96a6e/src/commands.rs#L46)).
2. If that socket is absent, the client creates a second startup-notification
   Unix socket below `TMPDIR`, re-executes itself with
   `SCCACHE_START_SERVER=1`, and waits for readiness
   ([commands.rs:89](https://github.com/mozilla/sccache/blob/c037e117c7625a2668633574028a6addf2a96a6e/src/commands.rs#L89)).
3. The server removes a stale pathname, binds the configured Unix listener,
   and reports the actual address
   ([server.rs:495](https://github.com/mozilla/sccache/blob/c037e117c7625a2668633574028a6addf2a96a6e/src/server.rs#L495)).
4. With `SCCACHE_CLIENT_SIDE=1`, compiler discovery, hashing, cache-hit
   materialization, fallback compilation, and output handling run in the CLI
   process. The daemon implements cache storage IPC and stats aggregation
   ([commands.rs:652](https://github.com/mozilla/sccache/blob/c037e117c7625a2668633574028a6addf2a96a6e/src/commands.rs#L652),
   [Architecture.md:103](https://github.com/mozilla/sccache/blob/c037e117c7625a2668633574028a6addf2a96a6e/docs/Architecture.md#L103)).
5. Without `SCCACHE_NO_DAEMON=1`, the server daemonizes
   ([util.rs:900](https://github.com/mozilla/sccache/blob/c037e117c7625a2668633574028a6addf2a96a6e/src/util.rs#L900)). SBE 0.4.0 waits only
   for the wrapped command and therefore does not own that detached lifetime
   ([executor.rs:186](../../apps/cli/src/executor.rs#L186)).

## Findings

1. ✅ **A private pathname Unix socket is sufficient.** On macOS 26.5.2, a
   policy denying `network*` and allowing only `network-bind`,
   `network-inbound`, and `network-outbound` below one canonical private temp
   directory successfully ran sccache 0.17.0 over UDS and returned rustc
   1.98.0 version data. TCP and ambient Unix sockets were not granted.
2. ✅ **Linux already has most of the filesystem-side primitive.** SBE grants
   `ResolveUnix` only to the per-run 0700 root on Landlock ABI v9
   ([landlock.rs:160](../../crates/core/src/sandbox/linux/landlock.rs#L160)).
   Older ABIs need an explicit capability statement and kernel integration
   coverage; they must not be described as path-mediated.
3. ⚠️ **Client-side mode is necessary when using an external daemon, but an
   environment variable alone is not a proof.** sccache ignores client-side
   mode when error-file logging or distributed compilation is configured
   ([config.rs:1364](https://github.com/mozilla/sccache/blob/c037e117c7625a2668633574028a6addf2a96a6e/src/config.rs#L1364)). A private
   server inside the same sandbox domain removes the external-execution bypass
   even if a future sccache version changes this mode.
4. ⚠️ **Automatic daemonization is incompatible with structured cleanup.** A
   detached server can outlive the command and the private temp directory.
   SBE must start a foreground server itself, wait for readiness, terminate it
   after the command, and reap it on every success, failure, cancellation, and
   signal path.
5. ⚠️ **The cache is persistent untrusted data.** The default macOS location is
   `~/Library/Caches/Mozilla.sccache`, and upstream supports only one local
   cache server at a time
   ([Local.md:1](https://github.com/mozilla/sccache/blob/c037e117c7625a2668633574028a6addf2a96a6e/docs/Local.md#L1)). It must be writable
   but never executable. Concurrent SBE invocations need one SBE-owned shared
   server or isolated cache roots; starting independent servers against one
   cache is invalid.
6. ⚠️ **Trace logging can disclose compiler environment values.** The compile
   request contains the environment passed to the compiler and is rendered
   with `Debug` at trace level
   ([commands.rs:404](https://github.com/mozilla/sccache/blob/c037e117c7625a2668633574028a6addf2a96a6e/src/commands.rs#L404)). The spike
   confirmed that this includes environment values. SBE's cleared,
   allowlisted environment remains mandatory, and tests must use synthetic
   sentinel secrets to prove they never appear in logs.

## What we will adopt

- A private, canonical pathname socket under SBE's existing per-run root.
- Narrow macOS socket rules for that root; no `allowAllNetwork` transition.
- An SBE-owned foreground server lifecycle in the sandbox domain.
- A data-only persistent cache grant and a minimal SBE-owned sccache config.
- Client-side mode as defense in depth, not as the sole isolation mechanism.
- Wrapper discovery that recognizes only the supported `sccache` adapter and
  never turns an arbitrary project-configured wrapper into executable
  authority.

## What we will avoid

- Connecting to the ambient TCP server at `127.0.0.1:4226`.
- Connecting to an ambient pathname or abstract Unix socket.
- `allowAllNetwork` or a generic localhost capability.
- Letting sccache daemonize or survive the wrapped command.
- Automatically granting an arbitrary `rustc-wrapper` path from project Cargo
  configuration.
- Treating cache contents as trusted executable artifacts.

## Decision

**GO with amendments.** Safe zero-config sccache support is feasible, but only
as a first-class SBE Rust-tool adapter with private IPC and lifecycle
supervision. Adding Homebrew paths and broad network permissions to the Rust
profile is rejected.

## Risks identified

- macOS SBPL socket filters are an implementation detail and require a real
  kernel integration test on each supported macOS release.
- Linux ABI v1-v8 behavior must be reported precisely and tested separately
  from ABI v9 pathname mediation.
- Concurrent cache ownership needs an explicit lock/server-sharing decision
  before implementation; upstream forbids independent servers over one local
  cache.
- sccache upgrades can change environment, config, or daemon semantics; pin an
  integration fixture to the minimum supported version and test the latest
  release in CI.
