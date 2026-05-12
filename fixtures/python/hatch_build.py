"""Hostile hatch build hook — exercises every attack in fixtures/ATTACKS.md.

Each probe prints exactly one of:
    SAFE: <id> <reason>
    PWNED: <id> <evidence>

CI greps for PWNED: and fails on any occurrence.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

HOME = Path(os.environ.get("HOME", "/tmp"))


def report(id_: str, ok: bool, msg: str) -> None:
    tag = "SAFE" if ok else "PWNED"
    print(f"{tag}: {id_} {msg}", flush=True)


def try_read(id_: str, path: Path) -> None:
    try:
        data = path.read_bytes()
        if not data:
            report(id_, True, f"readable but empty: {path}")
        else:
            report(id_, False, f"read {len(data)} bytes from {path}")
    except (FileNotFoundError, PermissionError, OSError) as e:
        report(id_, True, f"blocked: {e}")


def try_append(id_: str, path: Path, payload: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            f.write(payload)
        report(id_, False, f"wrote to {path}")
    except (PermissionError, OSError) as e:
        report(id_, True, f"blocked: {e}")


def try_exec(id_: str, program: str, args: list[str]) -> None:
    try:
        r = subprocess.run([program, *args], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            report(
                id_, False, f"exec {program} succeeded ({len(r.stdout)} bytes stdout)"
            )
        else:
            report(
                id_, True, f"exec {program} returned {r.returncode} (likely sandboxed)"
            )
    except FileNotFoundError as e:
        report(id_, True, f"exec {program} blocked: {e}")
    except (PermissionError, OSError) as e:
        report(id_, True, f"blocked: {e}")


def try_curl(id_: str, url: str) -> None:
    try:
        r = subprocess.run(
            [
                "/usr/bin/curl",
                "-sSL",
                "--max-time",
                "5",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                url,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        code = (r.stdout or "").strip()
        if r.returncode == 0 and code.startswith("2"):
            report(id_, False, f"HTTP {code} from {url}")
        else:
            report(id_, True, f"blocked: curl exit={r.returncode} http={code}")
    except (FileNotFoundError, PermissionError, OSError) as e:
        report(id_, True, f"blocked: {e}")


def run_probes() -> None:
    try_read("ssh-read", HOME / ".ssh" / "id_ed25519")
    try_read("aws-read", HOME / ".aws" / "credentials")
    try_read("gcloud-read", HOME / ".config" / "gcloud" / "credentials.db")
    try_read("gh-token-read", HOME / ".config" / "gh" / "hosts.yml")
    try_read("env-read", Path.cwd() / ".env")
    try_append("bashrc-write", HOME / ".bashrc", "\n# pwned\n")
    try_append(
        "authorized-keys-write",
        HOME / ".ssh" / "authorized_keys",
        "\nssh-rsa AAAAATTACKER attacker@evil\n",
    )
    try_exec("sudo-exec", "/usr/bin/sudo", ["-l"])
    try_exec("pkexec-exec", "/usr/bin/pkexec", ["--version"])
    try_curl("curl-evil", "https://evil.example.invalid/")


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        run_probes()
        # Don't raise — let the build succeed so the harness can inspect output.
