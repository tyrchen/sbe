# Supply-chain attack matrix

Every hostile fixture (`fixtures/<eco>/`) probes the same set of attack
patterns from a build-time hook. Under sbe, every "PWNED" line below must
become a "SAFE" line. The CI test-cli workflow greps for `PWNED:` and
fails the job on any occurrence.

## Attack patterns

| ID | Category | Target | What it tries |
|---|---|---|---|
| `ssh-read`        | secret-exfil | `$HOME/.ssh/id_ed25519`     | read private key |
| `aws-read`        | secret-exfil | `$HOME/.aws/credentials`    | read cloud creds |
| `gcloud-read`     | secret-exfil | `$HOME/.config/gcloud/`     | read gcloud config |
| `gh-token-read`   | secret-exfil | `$HOME/.config/gh/hosts.yml` | read GitHub PAT |
| `env-read`        | secret-exfil | `$PWD/.env`                 | read project secrets |
| `bashrc-write`    | persistence  | `$HOME/.bashrc`             | append shell hook |
| `authorized-keys-write` | persistence | `$HOME/.ssh/authorized_keys` | add attacker key |
| `sudo-exec`       | priv-esc     | `/usr/bin/sudo -l`          | check sudoers visibility |
| `pkexec-exec`     | priv-esc     | `/usr/bin/pkexec --version` | invoke polkit helper |
| `curl-evil`       | c2 / exfil   | `https://evil.example.invalid/` | egress to non-allowlisted domain |

Each row reports one of:

- `SAFE: <id> <reason>` — the kernel/proxy denied the operation; sbe is doing its job.
- `PWNED: <id> <evidence>` — the operation succeeded; CI fails the build.

## Why these specific patterns

- **Secret exfil**: covers the four most common credential stores. macOS adds
  Keychain; Linux relies on `denyRead` (sealed forbidden-list — see
  cross-platform-backend-design.md §8).
- **Persistence**: `.bashrc` and `authorized_keys` are the two simplest ways
  a malicious build script makes its access survive the next shell login.
  Both must be outside `allowWrite`.
- **Priv-esc**: `sudo`/`pkexec` are explicitly excluded from the Linux
  per-binary `allowExec` enumeration and from the macOS denyExec list. The
  default profile must refuse to exec them.
- **C2 / exfil**: an unallowlisted outbound HTTPS request must be 403'd
  by the proxy (or denied at the kernel level on macOS / Landlock v4).

## Adding a new attack

1. Add the row to the table above.
2. Implement the probe in each fixture (`build.rs`, `check.js`,
   `hatch_build.py`, `mix.exs`, `build.sbt`).
3. Reuse the `SAFE:`/`PWNED:` reporting format so the CI grep stays generic.

## Java/Scala scope

Coverage on Linux is sbt + Maven only.

**Gradle on Linux**: Gradle's CLI talks to a separate daemon process over
TCP on a kernel-chosen random localhost port. Landlock ABI v4 filters TCP
by port number only — it cannot express "allow any port on 127.0.0.1"
the way macOS SBPL's `(remote ip "localhost:*")` does. The Gradle daemon
also doesn't accept a fixed port via any CLI flag. Until Landlock gains
IP-based filtering, Linux Gradle users must opt into
`allowAllNetwork: true` in their `.sbe.yaml` for the `java` profile,
fully aware that this disables both the kernel TCP filter AND the
domain-filtering proxy. The README documents this trade-off.

**sbt 1.x** defaults to Unix-domain-socket IPC (since 1.1), which is not
gated by `NET_CONNECT_TCP`, so it works under the default `java` profile.

**Maven** runs in a single JVM with no IPC, so it works under the default
`java` profile as well.
