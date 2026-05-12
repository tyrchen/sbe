// Hostile install hook — exercises every attack in fixtures/ATTACKS.md.
//
// Each probe prints exactly one of:
//   SAFE: <id> <reason>
//   PWNED: <id> <evidence>
//
// CI greps for PWNED: and fails on any occurrence.

"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const HOME = process.env.HOME || "/tmp";

function report(id, ok, msg) {
  // npm captures stdout, but stderr is shown verbatim; emit on both so the
  // CI grep catches it regardless of npm's output mode.
  const line = `${ok ? "SAFE" : "PWNED"}: ${id} ${msg}`;
  console.log(line);
  console.error(line);
}

function tryRead(id, p) {
  try {
    const buf = fs.readFileSync(p);
    if (buf.length === 0) {
      report(id, true, `readable but empty: ${p}`);
    } else {
      report(id, false, `read ${buf.length} bytes from ${p}`);
    }
  } catch (e) {
    report(id, true, `blocked: ${e.message}`);
  }
}

function tryAppend(id, p, payload) {
  try {
    fs.appendFileSync(p, payload);
    report(id, false, `wrote to ${p}`);
  } catch (e) {
    report(id, true, `blocked: ${e.message}`);
  }
}

function tryExec(id, program, args) {
  try {
    const r = spawnSync(program, args, { encoding: "utf8" });
    if (r.error) {
      report(id, true, `exec ${program} blocked: ${r.error.message}`);
    } else if (r.status === 0) {
      report(id, false, `exec ${program} succeeded (${(r.stdout || "").length} bytes stdout)`);
    } else {
      report(id, true, `exec ${program} returned ${r.status} (likely sandboxed)`);
    }
  } catch (e) {
    report(id, true, `blocked: ${e.message}`);
  }
}

function tryCurl(id, url) {
  const r = spawnSync(
    "/usr/bin/curl",
    ["-sSL", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", url],
    { encoding: "utf8" }
  );
  if (r.error) {
    report(id, true, `blocked: ${r.error.message}`);
    return;
  }
  const code = (r.stdout || "").trim();
  if (r.status === 0 && code.startsWith("2")) {
    report(id, false, `HTTP ${code} from ${url}`);
  } else {
    report(id, true, `blocked: curl exit=${r.status} http=${code}`);
  }
}

tryRead("ssh-read", path.join(HOME, ".ssh", "id_ed25519"));
tryRead("aws-read", path.join(HOME, ".aws", "credentials"));
tryRead("gcloud-read", path.join(HOME, ".config", "gcloud", "credentials.db"));
tryRead("gh-token-read", path.join(HOME, ".config", "gh", "hosts.yml"));
tryRead("env-read", path.resolve("./.env"));
tryAppend("bashrc-write", path.join(HOME, ".bashrc"), "\n# pwned\n");
tryAppend(
  "authorized-keys-write",
  path.join(HOME, ".ssh", "authorized_keys"),
  "\nssh-rsa AAAAATTACKER attacker@evil\n"
);
tryExec("sudo-exec", "/usr/bin/sudo", ["-l"]);
tryExec("pkexec-exec", "/usr/bin/pkexec", ["--version"]);
tryCurl("curl-evil", "https://evil.example.invalid/");

// Always exit 0 so npm doesn't break the build; the test harness asserts
// on output content, not exit code.
process.exit(0);
