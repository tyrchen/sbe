# Changelog

All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

---
## [sbexec-v0.4.1](https://github.com/tyrchen/sbe/compare/sbexec-v0.4.0..sbexec-v0.4.1) - 2026-08-28

### Usability

- Make the practical `standard` sandbox the default and preserve the 0.4
  fail-closed boundary behind `--strict`.
- Let standard builds write the workspace, execute mutable build outputs,
  inherit non-sensitive build environment variables, and use local developer
  services while retaining secret-path, descriptor, privilege, and proxy
  protections.
- Treat the selected workspace as readable input in standard mode, including
  `.env*`, so Linux can support general file creation without reimplementing
  each package manager; strict mode retains project secret-file denials.
- Keep executable output roots installable before Linux Landlock enforcement.
- Let standard sbt builds use persistent boot/dependency caches while keeping
  the global settings/plugin base private and non-persistent.
- Support globally configured sccache through ordinary executable/cache grants
  and local IPC; no sccache source or managed adapter is shipped by SBE.
- Follow pre-existing tool, cache, and source-tree symlinks in standard mode
  when their referents stay inside the authorized envelope; external writable
  cache referents require one narrow explicit grant.
- Allow explicit top-level `cargo install` commands to manage their selected
  install root instead of reimplementing Cargo's transaction format.
- Derive Cargo target/install grants from the resolved effective environment,
  and report external output symlinks with a copyable narrow approval instead
  of a later opaque `EACCES`.
- Stop requiring `--allow-insecure-linux-network` for standard Linux builds;
  inspection and runtime warnings continue to report that domain egress is
  best-effort on Linux.

### Security

- Keep strict mode behavior for positive environment allowlisting, persistent
  W^X, hard-link validation, exact workspace outputs, ambient local-service
  denial, and fail-closed Linux network capability checks.
- Keep standard-mode symlink referents subject to protected-path denials and
  filter high-confidence API-key, cloud, and database credential environment
  variables, including bare or standardized names such as `TOKEN`, `API_KEY`,
  `PASSWORD`, `PGPASSWORD`, `MYSQL_PWD`, Terraform `TF_TOKEN_*`, and npm
  `_authToken` forms.
- On Landlock ABI v9+, mediate filesystem Unix sockets independently of TCP
  policy and grant resolution only beneath SBE's private per-run root, keeping
  capability brokers such as `docker.sock` outside the standard envelope.
- Replace validated writable and executable symlink grants with canonical
  snapshots before launch, so a parallel build cannot retarget the lexical
  link between policy validation and descriptor opening.
- Create unresolved Linux output grants through the launcher's descriptor-bound
  no-symlink walk, filter Azure Pipelines `SYSTEM_ACCESSTOKEN` and OIDC token-file
  variables, and bound Linux source-symlink discovery by entry and depth budgets
  without scanning macOS workspaces that do not need referent grants.
- Preserve explicit execute denials when standard mode infers output grants,
  filter custom AWS shared-credentials paths, and permit ordinary Unix-domain
  build-service IPC in macOS standard mode while keeping strict mode isolated.
- Grant only mutable runtime subdirectories beneath the effective Gradle user
  home for standard `gradle`/`gradlew` commands, honoring the command-line
  option before inherited `GRADLE_USER_HOME` and the conventional `~/.gradle`
  default while keeping initialization scripts immutable.
- Keep macOS `DenyAll` authoritative by withholding standard-mode Unix-socket
  compatibility grants when the effective network policy denies all traffic.
- Reject Gradle and Maven project-relocation flags early, with the same
  actionable working-directory guidance used for other package managers.
- Honor Cargo's explicit `--target-dir` ahead of its environment/config paths
  and Gradle's `gradle.user.home` command-line system property ahead of its
  environment/default home when deriving standard-mode grants.
- Distinguish Maven's `-fae`, `-ff`, and `-fn` failure-mode flags from attached
  `-f<project>` relocation syntax.
- Filter ECS container-credential endpoint variables, scope Cargo target grants
  to Cargo commands, and resolve unambiguous `gradle.user.home` values from
  inherited `GRADLE_OPTS` while rejecting shell-expanded forms early.
- Resolve `gradle.user.home` from inherited `JAVA_OPTS` as well, and honor the
  JVM's last-value-wins behavior for repeated command-line system properties.
- Filter custom Docker credential-directory locators and inject standard-mode
  localhost proxy bypasses, including Java `http.nonProxyHosts`, so permitted
  local developer services do not get rejected by SBE's external proxy.
- Resolve missing writable descendants through their nearest existing symlink
  ancestor, validate the reconstructed target, and snapshot it so approved
  symlinked cache roots also work on cold builds.
- Filter custom Google Cloud SDK and Azure CLI configuration directories so
  their credential databases cannot bypass the default secret-path denials.
- Reject built-in readable or executable symlink aliases whose canonical
  referents overlap protected paths, preventing project wrappers from turning
  execute authority into credential reads.
- Include Gradle's required `.tmp` runtime directory and recognize its attached
  `-g/path` user-home form when deriving narrow persistent grants.
- Honor direct Cargo `--config build.target-dir='path'` overrides when no
  higher-precedence target CLI/environment selection exists, avoid injecting a
  fallback that masks the config, and reject opaque config-file overrides with
  actionable `--target-dir` guidance.
- Filter Docker client TLS-directory locators and derive Maven's writable local
  repository from the last `-D`/`--define maven.repo.local` property.
- Resolve Maven repository overrides from `MAVEN_OPTS` and bounded, no-follow
  project `.mvn/jvm.config` reads, preserving launcher and last-property
  precedence while rejecting ambiguous option forms.
- Include `MAVEN_ARGS` and bounded project `.mvn/maven.config` in Maven's local
  repository precedence, and filter Azure client-certificate path locators.
- Filter custom GitHub CLI credential directories and grant only Cargo's
  effective target environment path when both target variables are present.
- Require explicit approval when repository-controlled Maven config selects a
  local repository outside the workspace or conventional Maven cache envelope.
- Filter custom AWS configuration-file locators and inspect direct symlink
  entries beneath generated dependency roots so warm linked dependencies remain
  readable without recursively scanning ordinary generated contents.
- Filter GitLab job JWT variables, honor direct Cargo
  `--config install.root='path'` overrides, and reject implicit Cargo-config
  install roots before launch with explicit `--root` guidance.
- Deny both Cargo credential-file spellings beneath the effective `CARGO_HOME`,
  including custom and relative locations, without removing ordinary Cargo
  configuration from the child environment.
- Deny GitHub CLI credentials beneath an inherited `XDG_CONFIG_HOME`, filter
  custom `GNUPGHOME` locators, and reject Cargo manifests that resolve outside
  the selected workspace while retaining in-workspace `--manifest-path` usage.
- Filter AzureRM client-certificate and OIDC-token file locators, and discover
  Node monorepo roots in standard mode so parent workspace inputs, lockfiles,
  and generated dependencies remain usable from a member package.
- Pre-create missing Node workspace-root lockfiles on Linux, include that root
  in bounded linked-dependency discovery, and relocate Cargo registry/Git cache
  grants beneath the effective `CARGO_HOME` while retaining credential denials.
- Filter npm's custom `NPM_CONFIG_USERCONFIG` credential-file locator while
  preserving ordinary npm build configuration variables.

---
## [sbexec-v0.4.0](https://github.com/tyrchen/sbe/compare/sbexec-v0.3.3..sbexec-v0.4.0) - 2026-08-23

### Security

- Fail closed for empty domain allowlists and for strict Linux domain egress,
  which Landlock's destination-port rules cannot enforce.
- Clear ambient environment variables and file descriptors; add explicit
  `--keep-env` and `--env` grants with redacted inspection output.
- Treat auto-discovered project configuration as restrictive-only unless
  `--trust-project-config` is supplied, and retain grant provenance.
- Add a single-threaded Linux launcher, descriptor-based `openat2` path
  resolution, data-read/execute separation, persistent W^X validation, and
  isolated private temporary roots. Cargo intermediate artifacts and build
  scripts use the stable private `build.build-dir` split while final artifacts
  remain in `$PWD/target`.
- Block keyring access, cross-process FD duplication, asynchronous `io_uring`
  bypasses, and legacy/new mount APIs in the Linux seccomp layer.
- Bound and authenticate the CONNECT proxy; validate IDNA names, ports and all
  resolved addresses; reject special-use destinations; enforce DNS, connect,
  header, idle and maximum-lifetime limits.
- Escape and validate SBPL inputs, narrow macOS proxy/IPC access, and add direct
  Keychain and unrelated-localhost denial coverage.
- Pin workflow actions, minimize token permissions, and publish release
  checksums, SPDX SBOMs and GitHub provenance attestations from an atomic draft.

### Breaking changes

- Linux domain-filtered profiles now refuse to run by default. The explicit
  `--allow-insecure-linux-network` option enables the documented, bypassable
  destination-port compatibility mode.
- Project `.sbe.yaml` files cannot expand authority without
  `--trust-project-config`; unknown fields and unsafe values are rejected.
- Ambient credentials, agent sockets and arbitrary parent environment values
  are no longer inherited.
- Broad workspace writes, shared temporary-directory access and persistent
  writable+executable cache combinations were removed from built-in profiles.
- The setup action supports attested 0.4.0-or-newer release assets.

---
## [sbexec-v0.3.3](https://github.com/tyrchen/sbe/compare/sbexec-v0.3.2..sbexec-v0.3.3) - 2026-08-23

### Bug Fixes

- **(deps)** update `anyhow` past RUSTSEC-2026-0190 and refresh dependencies - ([1864685](https://github.com/tyrchen/sbe/commit/1864685b995bbfeabeb689fb2fe801f8383cba8f)) - Tyr Chen

### Other

- Update CHANGELOG.md - ([3cc8821](https://github.com/tyrchen/sbe/commit/3cc8821d3545b77f233bcd3d7db8097888759827)) - Tyr Chen
- dogfood setup-sbe action in build and release workflows - ([f1d2f40](https://github.com/tyrchen/sbe/commit/f1d2f402a920e9cd347aece95b4a28ecfcc26499)) - Tyr Chen

---
## [sbexec-v0.3.2](https://github.com/compare/sbexec-v0.3.1..sbexec-v0.3.2) - 2026-05-12

### Miscellaneous Chores

- remove x86 osx support and bump to 0.3.2 - ([99731b2](https://github.com/commit/99731b260b6f4a231c4e490a000d17a71054ce23)) - Tyr Chen

### Other

- Update CHANGELOG.md - ([a20fa98](https://github.com/commit/a20fa98b2e695d50329ecdd48931eaca6607c0e1)) - Tyr Chen

---
## [sbexec-v0.3.1](https://github.com/compare/sbexec-v0.3.0..sbexec-v0.3.1) - 2026-05-12

### Bug Fixes

- **(profile)** cover Homebrew-managed rustup; loosen .sbe.yaml for proxy tests - ([0810154](https://github.com/commit/081015491f21362e6184454ed9c9db226951f25d)) - Tyr Chen
- **(seccomp)** hardcode kexec_file_load syscall on aarch64 - ([a0461f8](https://github.com/commit/a0461f80372f65944ae045a5225168d81ce07685)) - Tyr Chen

### Miscellaneous Chores

- bump to 0.3.1 - ([9d14b94](https://github.com/commit/9d14b945068a0759fa1bfe3a3bc087a4724c9330)) - Tyr Chen

### Other

- Update CHANGELOG.md - ([4f139a1](https://github.com/commit/4f139a1f1eb999071e2d11705f864d81f4b166a6)) - Tyr Chen
- dogfood the sbe action in build + release workflows - ([1648d3b](https://github.com/commit/1648d3b2676a6ed4c833d0b1a44885adc18f8de0)) - Tyr Chen
- temporary diagnostic — capture cargo path + sbe inspect on runners - ([3bd3deb](https://github.com/commit/3bd3deb1d578dbaa51a6f617d1c3165c9f57da35)) - Tyr Chen
- Revert "ci: dogfood the sbe action in build + release workflows"

Diagnostic run on macos-latest revealed sbe 0.3.0's rust profile
allowExec (~/.cargo/bin/ + ~/.rustup/toolchains/) doesn't cover the
Homebrew-managed rustup shim chain that GH runners use:

  ~/.cargo/bin/cargo -> rustup
                     -> /opt/homebrew/bin/rustup-init
                     -> /opt/homebrew/Cellar/rustup/1.29.0/bin/rustup-init

sandbox-exec resolves the symlinks before matching process-exec, so
the real binary path is outside the allowlist and execvp returns
EPERM. Linux side hit a separate issue: proxy_integration tests bind
127.0.0.1:0 ephemeral, which Landlock v4 can't allow when
enableProxy: false pins egress to :443.

Both are real gaps to fix in a follow-up; reverting CI to bare cargo
until the defaults cover Homebrew rustup and the Linux loopback case
is handled.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com> - ([195eb42](https://github.com/commit/195eb42d81c1ae0fe4c202c361b78c24dd5dd5a0)) - Tyr Chen

### Tests

- run proxy_integration bare, drop .sbe.yaml override - ([11cc2f5](https://github.com/commit/11cc2f5bf983648d69e98ff6e05e698441d26331)) - Tyr Chen

---
## [sbexec-v0.3.0](https://github.com/compare/sbexec-v0.2.1..sbexec-v0.3.0) - 2026-05-12

### Features

- cross-platform sandbox backend (Linux + macOS) (#1) - ([190d0ae](https://github.com/commit/190d0aeb29d62a027799cc88bb2585a2ea39f906)) - Tyr Chen

### Other

- Update CHANGELOG.md - ([6ff093e](https://github.com/commit/6ff093e69af35289f497510c763bb6b1182efdf9)) - Tyr Chen

---
## [sbexec-v0.2.1](https://github.com/compare/sbexec-v0.2.0..sbexec-v0.2.1) - 2026-05-12

### Bug Fixes

- **(profile)** allow Homebrew elixir/erlang Cellar paths and shim helpers - ([80de8a9](https://github.com/commit/80de8a9be6eec64bc8292f5b2f09d9d105f68c37)) - Tyr Chen

### Features

- support SBPL regex paths for cargo target sibling temp dirs - ([f9087ce](https://github.com/commit/f9087cef48d15d78f4ad25a5c05eb135017a6a71)) - Tyr Chen

### Miscellaneous Chores

- update fixtures - ([fc57e04](https://github.com/commit/fc57e0406b70b3c4074a4bc0cc63a85d50d19822)) - Tyr Chen
- update arch doc - ([896628b](https://github.com/commit/896628bda9153dc09f162581d1752b2fb0177c2c)) - Tyr Chen
- update gh action to support release - ([ac60a82](https://github.com/commit/ac60a82bd76f381bff7be12effb5ce257a407bd9)) - Tyr Chen

### Other

- Update CHANGELOG.md - ([60f3565](https://github.com/commit/60f35651d2d7f7acbeadbeebefa108a6ae3b1fb9)) - Tyr Chen

### Tests

- add language fixtures for sandbox profile testing - ([4a7bc53](https://github.com/commit/4a7bc53d39baff18b21fc94212d6cab085b9db6d)) - Tyr Chen

---
## [sbexec-v0.2.0] - 2026-04-07

### Bug Fixes

- address code review findings against specs - ([669481d](https://github.com/commit/669481de5539fbd0cc2365c2625647ca96338760)) - Tyr Chen
- allow Xcode toolchain + custom CARGO_TARGET_DIR in sandbox - ([2f00ab8](https://github.com/commit/2f00ab869689818d7b70d5be465a2105857426ee)) - Tyr Chen
- allow exec from cargo target dir for build scripts and proc macros - ([80a8621](https://github.com/commit/80a86215546bc7faa4ef076b59dd00a6be27beae)) - Tyr Chen
- allow ar, ranlib, ld, and other native toolchain binaries - ([1d767b9](https://github.com/commit/1d767b9eef02699b53628f0f4194ce5f9a2e4be8)) - Tyr Chen
- add *.github.com to all ecosystem domain allowlists, support .sbe.yml - ([366706b](https://github.com/commit/366706b21ee314bb8c331c06d14b67b026dbe21f)) - Tyr Chen
- allow exec from /opt/homebrew/bin and /usr/local/bin - ([59a34ac](https://github.com/commit/59a34acfd93ef4a175699fca5712e590c64344af)) - Tyr Chen
- revert blanket /opt/homebrew/bin allow, add failure hint instead - ([e6c4365](https://github.com/commit/e6c43657949d4f40dc574b09ab22fccfda59f971)) - Tyr Chen
- resolve symlinks in allow_exec/deny_exec for SBPL correctness - ([30bd6e9](https://github.com/commit/30bd6e990029208bd5e459aa09f76738ec30d1b5)) - Tyr Chen
- resolve Homebrew symlinks to package root for sub-tool execution - ([ccb7058](https://github.com/commit/ccb7058ea6777f74f33e16141020432848eddddb)) - Tyr Chen
- allow core utils, temp exec, and Rust build tool cache dirs - ([365bc17](https://github.com/commit/365bc1796a579a1e2a5527c54dc5b0b0ce5f15d6)) - Tyr Chen
- allow process-info operations to prevent fd quota exhaustion - ([4cb25f5](https://github.com/commit/4cb25f52b0ee0ef78bef6a31ffeeac4443cc9155)) - Tyr Chen
- allow writes to /dev/null and /dev/zero in sandbox - ([0912280](https://github.com/commit/09122809f44b6b79faeef7db58c5f70a1ab4b6bc)) - Tyr Chen
- add fnm (Fast Node Manager) paths to node profile allowExec - ([0b3453e](https://github.com/commit/0b3453ecf4f384be04f3b9055214c1b9516cc81f)) - Tyr Chen
- add ~/.local/share/fnm to node profile for real path resolution - ([f005f53](https://github.com/commit/f005f53865581f578c3781475600ea00f86c667d)) - Tyr Chen
- allow git root node_modules for monorepo hoisted binaries - ([99be167](https://github.com/commit/99be167d0799143ccad97e80ab4aed473155b131)) - Tyr Chen
- allow writes to git root for monorepo package-lock.json - ([e575fc3](https://github.com/commit/e575fc36e6c315d8e8e1a95c53a5507a45f6ec56)) - Tyr Chen
- scope monorepo root writes to lockfiles and node_modules only - ([34fafce](https://github.com/commit/34fafce591aa210389d6af6b994c73b4fe66e819)) - Tyr Chen
- allow exec from $PWD/node_modules for local bin scripts - ([95b0e4e](https://github.com/commit/95b0e4ef765929ebf13ebf8bd73eec38b0d252cb)) - Tyr Chen
- only show sandbox hint for exit codes 71/126, not all failures - ([e3eebba](https://github.com/commit/e3eebbadc4a22e3c5e0cef857fd143d28bf8b4a1)) - Tyr Chen
- allow reading ~/.npmrc for yarn/npm registry configuration - ([796318e](https://github.com/commit/796318e90092986da54167a02dcc9e5a09cf2be5)) - Tyr Chen
- add Yarn cache dirs and git to common allowExec - ([7e57104](https://github.com/commit/7e57104350dda670dc103e8468cbba0badbd31dd)) - Tyr Chen

### Documentation

- add comprehensive README with architecture and developer guide - ([5bf0af9](https://github.com/commit/5bf0af988a52e6a1d646cbd13634fb284f82fe3f)) - Tyr Chen
- update README to reflect current codebase state - ([5763f1a](https://github.com/commit/5763f1ac3423236f42997cfbcd32c0e327c9449b)) - Tyr Chen

### Features

- Phase 1 — core sandbox MVP with filesystem/process sandboxing - ([c24cbac](https://github.com/commit/c24cbac51faff8237fca7fe0a995c3c34321bb69)) - Tyr Chen
- Phase 2 — network proxy with domain-filtering and integration tests - ([e7281df](https://github.com/commit/e7281df01457846860d2436acddac636a22892eb)) - Tyr Chen
- Phase 3 — audit, error handling polish, and Makefile targets - ([a2fc409](https://github.com/commit/a2fc409c72c963ca25cd135cb1dc70d08fbd7f2a)) - Tyr Chen
- add allowFetch for scoped build-time downloads, revert global curl - ([7860caa](https://github.com/commit/7860caa0e35bbb59d5ee0a28938ef7f6a37d2abb)) - Tyr Chen
- comprehensive ecosystem support review and hardening - ([c34853c](https://github.com/commit/c34853c3264c9f14c89f8dad4eae1b7289add688)) - Tyr Chen

### Miscellaneous Chores

- make all workspace crates publishable - ([48cb2d9](https://github.com/commit/48cb2d9afa91599f506fb15469d8dd73246a1a91)) - Tyr Chen
- update cargo.toml - ([5d1a3ec](https://github.com/commit/5d1a3ec8d704be2964113ca068fd8bfea2814e70)) - Tyr Chen

### Other

- comprehensive hardening of sandbox defaults - ([53084ac](https://github.com/commit/53084ac9fb4a1d675d0f960bfe5ba1e2c0697eb2)) - Tyr Chen

### Refactoring

- move all profile defaults to embedded YAML, remove hardcoded Rust files - ([b6eabd1](https://github.com/commit/b6eabd100ed765966528b921d5fac9352c8b1594)) - Tyr Chen
- replace path heuristics with explicit trailing-slash convention - ([d74d9b5](https://github.com/commit/d74d9b5fa136ea1059c46b72ab7c91b50aa7e4d0)) - Tyr Chen

### Revert

- remove unnecessary process-info SBPL permissions - ([5303bd7](https://github.com/commit/5303bd74438f979d9ae49d98b06f07789dd14c15)) - Tyr Chen

<!-- generated by git-cliff -->
