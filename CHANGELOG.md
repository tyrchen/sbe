# Changelog

All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

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
