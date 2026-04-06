use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};
use tracing::debug;

/// Audit logger that monitors macOS sandboxd for sandbox violations.
///
/// Spawns `log stream` to capture real-time sandbox deny events.
pub struct AuditLogger {
    running: Arc<AtomicBool>,
    log_file: Option<tokio::fs::File>,
    violation_counts: Arc<tokio::sync::Mutex<HashMap<String, u64>>>,
}

impl AuditLogger {
    /// Create a new audit logger.
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
            violation_counts: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Start streaming sandbox violations. Returns a handle that can be used to stop.
    pub fn start(mut self) -> AuditHandle {
        let running = Arc::clone(&self.running);
        let counts = Arc::clone(&self.violation_counts);

        let handle = tokio::spawn(async move {
            if let Err(e) = self.stream_logs().await {
                debug!(error = %e, "audit log stream ended");
            }
        });

        AuditHandle {
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

            // Parse sandboxd log lines to extract violation info
            if let Some(event) = parse_sandbox_event(&line) {
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

        // Kill the log stream process
        let _ = child.kill().await;

        Ok(())
    }
}

/// Handle to a running audit logger.
pub struct AuditHandle {
    running: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
    violation_counts: Arc<tokio::sync::Mutex<HashMap<String, u64>>>,
}

impl AuditHandle {
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

struct SandboxEvent {
    operation: String,
    target: String,
}

fn parse_sandbox_event(line: &str) -> Option<SandboxEvent> {
    // sandboxd log lines typically contain "deny" and the operation
    // Example: "sandboxd: (npm) deny(1) file-write-create /Library/Caches/..."
    if !line.contains("deny") {
        return None;
    }

    // Try to extract operation and path
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

    // Extract the target path/address — it's usually the last space-separated token
    let target = line
        .rsplit_once(' ')
        .map(|(_, t)| t.to_owned())
        .unwrap_or_default();

    Some(SandboxEvent {
        operation: operation.to_owned(),
        target,
    })
}
