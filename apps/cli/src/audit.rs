//! Audit logging — `Auditor` trait + per-OS implementations.
//!
//! The [`Auditor`] trait is intentionally separate from `SandboxBackend`:
//! audit runs *concurrently* to the sandboxed child, whereas the backend
//! is the per-invocation lifecycle. Different lifetimes, different extension
//! points (audit-log file, summary, formatters).

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use sbe_core::BackendInfo;
use tokio::sync::Mutex;

/// Start the OS-appropriate audit stream and return its handle. Pass
/// `log_path` to also append events to a file.
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    allow(unused_variables)
)]
pub async fn start(info: &BackendInfo, log_path: Option<&Path>) -> anyhow::Result<AuditorHandle> {
    #[cfg(target_os = "macos")]
    {
        let _ = info;
        let logger = macos::MacosLogStream::new(log_path).await?;
        Ok(logger.start())
    }
    #[cfg(target_os = "linux")]
    {
        let logger = linux::LinuxSeccompLog::new(log_path, info.kernel.clone()).await?;
        Ok(logger.start())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!("audit streaming is not supported on this platform");
    }
}

/// Cross-platform view of a single sandbox violation.
#[derive(Debug, Clone)]
pub struct SandboxEvent {
    pub operation: String,
    pub target: String,
}

/// Handle returned by [`start`]. Drop or call [`stop_and_summarize`].
pub struct AuditorHandle {
    running: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
    violation_counts: Arc<Mutex<HashMap<String, u64>>>,
}

impl AuditorHandle {
    /// Stop the audit logger and print a summary.
    pub async fn stop_and_summarize(self) {
        self.running.store(false, Ordering::Relaxed);
        let _ = self.handle.await;

        let counts = self.violation_counts.lock().await;
        if !counts.is_empty() {
            eprintln!("\n[sbe:audit] Violation summary:");
            let mut sorted: Vec<_> = counts.iter().collect();
            sorted.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
            for (op, count) in sorted {
                eprintln!("  {op}: {count}");
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        process::Command,
    };
    use tracing::debug;

    use super::*;

    /// macOS `sandboxd` log stream auditor.
    pub struct MacosLogStream {
        running: Arc<AtomicBool>,
        log_file: Option<tokio::fs::File>,
        violation_counts: Arc<Mutex<HashMap<String, u64>>>,
    }

    impl MacosLogStream {
        pub async fn new(log_path: Option<&Path>) -> anyhow::Result<Self> {
            let log_file = match log_path {
                Some(p) => Some(
                    tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(p)
                        .await?,
                ),
                None => None,
            };

            Ok(Self {
                running: Arc::new(AtomicBool::new(true)),
                log_file,
                violation_counts: Arc::new(Mutex::new(HashMap::new())),
            })
        }

        pub fn start(mut self) -> AuditorHandle {
            let running = Arc::clone(&self.running);
            let counts = Arc::clone(&self.violation_counts);

            let handle = tokio::spawn(async move {
                if let Err(e) = self.stream_logs().await {
                    debug!(error = %e, "audit log stream ended");
                }
            });

            AuditorHandle {
                running,
                handle,
                violation_counts: counts,
            }
        }

        async fn stream_logs(&mut self) -> anyhow::Result<()> {
            let mut child = Command::new("/usr/bin/log")
                .args([
                    "stream",
                    "--style",
                    "compact",
                    "--predicate",
                    "process == \"sandboxd\"",
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()?;

            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("no stdout from log stream"))?;
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            while self.running.load(Ordering::Relaxed) {
                let line = tokio::select! {
                    result = lines.next_line() => {
                        match result {
                            Ok(Some(line)) => line,
                            Ok(None) => break,
                            Err(e) => {
                                debug!(error = %e, "error reading log stream");
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                        if !self.running.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    }
                };

                if let Some(event) = parse_macos_event(&line) {
                    let formatted =
                        format!("[sbe:audit] DENIED {} {}\n", event.operation, event.target);
                    eprint!("{formatted}");

                    if let Some(ref mut f) = self.log_file {
                        let _ = f.write_all(formatted.as_bytes()).await;
                    }

                    let mut counts = self.violation_counts.lock().await;
                    *counts.entry(event.operation).or_insert(0) += 1;
                }
            }

            let _ = child.kill().await;

            Ok(())
        }
    }

    fn parse_macos_event(line: &str) -> Option<SandboxEvent> {
        if !line.contains("deny") {
            return None;
        }

        let operation = if line.contains("file-write") {
            "file-write"
        } else if line.contains("file-read") {
            "file-read"
        } else if line.contains("network") {
            "network"
        } else if line.contains("process-exec") {
            "process-exec"
        } else {
            "other"
        };

        let target = line
            .rsplit_once(' ')
            .map(|(_, t)| t.to_owned())
            .unwrap_or_default();

        Some(SandboxEvent {
            operation: operation.to_owned(),
            target,
        })
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use tokio::{
        fs::File,
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    };
    use tracing::debug;

    use super::*;

    /// Linux `/dev/kmsg` reader filtered to the current pid for seccomp
    /// audit lines. Best-effort: requires CAP_SYSLOG on locked-down hosts.
    pub struct LinuxSeccompLog {
        running: Arc<AtomicBool>,
        log_file: Option<tokio::fs::File>,
        kernel: String,
        violation_counts: Arc<Mutex<HashMap<String, u64>>>,
    }

    impl LinuxSeccompLog {
        pub async fn new(log_path: Option<&Path>, kernel: String) -> anyhow::Result<Self> {
            let log_file = match log_path {
                Some(p) => Some(
                    tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(p)
                        .await?,
                ),
                None => None,
            };

            Ok(Self {
                running: Arc::new(AtomicBool::new(true)),
                log_file,
                kernel,
                violation_counts: Arc::new(Mutex::new(HashMap::new())),
            })
        }

        pub fn start(mut self) -> AuditorHandle {
            let running = Arc::clone(&self.running);
            let counts = Arc::clone(&self.violation_counts);

            let handle = tokio::spawn(async move {
                if let Err(e) = self.stream_kmsg().await {
                    debug!(error = %e, kernel = %self.kernel, "audit log stream ended");
                }
            });

            AuditorHandle {
                running,
                handle,
                violation_counts: counts,
            }
        }

        async fn stream_kmsg(&mut self) -> anyhow::Result<()> {
            let file = match File::open("/dev/kmsg").await {
                Ok(f) => f,
                Err(e) => {
                    debug!(error = %e, "cannot open /dev/kmsg — audit will be best-effort");
                    eprintln!(
                        "[sbe:audit] /dev/kmsg unavailable; Linux audit requires CAP_SYSLOG or \
                         world-readable kmsg. Violations will still surface as EACCES/EPERM from \
                         the sandboxed program."
                    );
                    return Ok(());
                }
            };
            let mut lines = BufReader::new(file).lines();

            while self.running.load(Ordering::Relaxed) {
                let line = tokio::select! {
                    result = lines.next_line() => match result {
                        Ok(Some(line)) => line,
                        Ok(None) => break,
                        Err(_) => break,
                    },
                    _ = tokio::time::sleep(std::time::Duration::from_millis(150)) => {
                        if !self.running.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    }
                };

                if let Some(event) = parse_kmsg_event(&line) {
                    let formatted =
                        format!("[sbe:audit] DENIED {} {}\n", event.operation, event.target);
                    eprint!("{formatted}");

                    if let Some(ref mut f) = self.log_file {
                        let _ = f.write_all(formatted.as_bytes()).await;
                    }

                    let mut counts = self.violation_counts.lock().await;
                    *counts.entry(event.operation).or_insert(0) += 1;
                }
            }
            Ok(())
        }
    }

    fn parse_kmsg_event(line: &str) -> Option<SandboxEvent> {
        // Kernel seccomp audit lines look like:
        //   "audit: type=1326 audit(...): auid=... syscall=44 comm=\"foo\" exe=\"...\""
        // We match on `audit(` and `seccomp` keywords.
        if !line.contains("audit") {
            return None;
        }
        if line.contains("syscall=") {
            let syscall = line
                .split_once("syscall=")
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .unwrap_or("?");
            let exe = line
                .split_once("exe=")
                .and_then(|(_, rest)| rest.split('"').nth(1))
                .unwrap_or("");
            return Some(SandboxEvent {
                operation: format!("seccomp:{syscall}"),
                target: exe.to_owned(),
            });
        }
        if line.contains("LANDLOCK") || line.contains("landlock") {
            return Some(SandboxEvent {
                operation: "landlock".to_owned(),
                target: line.trim().to_owned(),
            });
        }
        None
    }
}
