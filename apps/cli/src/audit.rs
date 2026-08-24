//! Audit logging — `Auditor` trait + per-OS implementations.
//!
//! The [`Auditor`] trait is intentionally separate from `SandboxBackend`:
//! audit runs *concurrently* to the sandboxed child, whereas the backend
//! is the per-invocation lifecycle. Different lifetimes, different extension
//! points (audit-log file, summary, formatters).

use std::{
    collections::HashMap,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use sbe_core::BackendInfo;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt},
    sync::Mutex,
};

const MAX_AUDIT_RECORD_BYTES: usize = 16 * 1024;

enum AuditRecord {
    Line(Vec<u8>),
    Dropped,
    Eof,
}

/// Start the OS-appropriate audit stream and return its handle. Pass
/// `log_path` to also append events to a file.
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    allow(unused_variables)
)]
pub async fn start(
    info: &BackendInfo,
    log_path: Option<&Path>,
    pid: u32,
) -> anyhow::Result<AuditorHandle> {
    #[cfg(target_os = "macos")]
    {
        let _ = info;
        let logger = macos::MacosLogStream::new(log_path, pid).await?;
        Ok(logger.start())
    }
    #[cfg(target_os = "linux")]
    {
        let logger = linux::LinuxSeccompLog::new(log_path, info.kernel.clone(), pid).await?;
        Ok(logger.start())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!("audit streaming is not supported on this platform");
    }
}

#[allow(clippy::disallowed_types)] // O_NOFOLLOW/O_CLOEXEC require Unix std OpenOptions.
async fn open_audit_log(path: &Path) -> anyhow::Result<tokio::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("audit log path is not a regular file: {}", path.display());
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(tokio::fs::File::from_std(file))
}

async fn read_audit_record<R>(reader: &mut R) -> std::io::Result<AuditRecord>
where
    R: AsyncBufRead + Unpin,
{
    let mut output = Vec::new();
    let mut exceeded = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if output.is_empty() && !exceeded {
                Ok(AuditRecord::Eof)
            } else if exceeded {
                Ok(AuditRecord::Dropped)
            } else {
                Ok(AuditRecord::Line(output))
            };
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if !exceeded {
            if output.len().saturating_add(consumed) > MAX_AUDIT_RECORD_BYTES {
                exceeded = true;
                output.clear();
            } else {
                output.extend_from_slice(&available[..consumed]);
            }
        }
        let complete = available[..consumed].last() == Some(&b'\n');
        reader.consume(consumed);
        if complete {
            return if exceeded {
                Ok(AuditRecord::Dropped)
            } else {
                Ok(AuditRecord::Line(output))
            };
        }
    }
}

fn sanitize_event_field(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| character.escape_default())
        .take(4096)
        .collect()
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
        io::{AsyncWriteExt, BufReader},
        process::Command,
    };
    use tracing::debug;

    use super::*;

    /// macOS `sandboxd` log stream auditor.
    pub struct MacosLogStream {
        running: Arc<AtomicBool>,
        log_file: Option<tokio::fs::File>,
        violation_counts: Arc<Mutex<HashMap<String, u64>>>,
        pid: u32,
    }

    impl MacosLogStream {
        pub async fn new(log_path: Option<&Path>, pid: u32) -> anyhow::Result<Self> {
            let log_file = match log_path {
                Some(p) => Some(open_audit_log(p).await?),
                None => None,
            };

            Ok(Self {
                running: Arc::new(AtomicBool::new(true)),
                log_file,
                violation_counts: Arc::new(Mutex::new(HashMap::new())),
                pid,
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
            let predicate = format!(
                "process == \"sandboxd\" AND eventMessage CONTAINS[c] \"({})\"",
                self.pid
            );
            let mut child = Command::new("/usr/bin/log")
                .args(["stream", "--style", "compact", "--predicate", &predicate])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()?;

            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("no stdout from log stream"))?;
            let mut reader = BufReader::new(stdout);

            while self.running.load(Ordering::Relaxed) {
                let line = tokio::select! {
                    result = read_audit_record(&mut reader) => {
                        match result {
                            Ok(AuditRecord::Line(line)) => String::from_utf8_lossy(&line).into_owned(),
                            Ok(AuditRecord::Dropped) => {
                                let mut counts = self.violation_counts.lock().await;
                                *counts.entry("audit-record-dropped".to_owned()).or_insert(0) += 1;
                                continue;
                            }
                            Ok(AuditRecord::Eof) => break,
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

                if let Some(event) = parse_macos_event(&line, self.pid) {
                    let operation = sanitize_event_field(&event.operation);
                    let target = sanitize_event_field(&event.target);
                    let formatted = format!("[sbe:audit] DENIED {operation} {target}\n");
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

    fn parse_macos_event(line: &str, pid: u32) -> Option<SandboxEvent> {
        if !line.contains("deny") || !line.contains(&format!("({pid})")) {
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
    use anyhow::Context as _;
    use tokio::{
        fs::File,
        io::{AsyncWriteExt, BufReader},
    };
    use tracing::debug;

    use super::*;

    /// Linux `/dev/kmsg` reader filtered to the current pid for seccomp
    /// audit lines. Best-effort: requires CAP_SYSLOG on locked-down hosts.
    pub struct LinuxSeccompLog {
        running: Arc<AtomicBool>,
        source: Option<File>,
        log_file: Option<tokio::fs::File>,
        kernel: String,
        violation_counts: Arc<Mutex<HashMap<String, u64>>>,
        pid: u32,
    }

    impl LinuxSeccompLog {
        pub async fn new(
            log_path: Option<&Path>,
            kernel: String,
            pid: u32,
        ) -> anyhow::Result<Self> {
            let source = File::open("/dev/kmsg")
                .await
                .context("open /dev/kmsg for Linux audit")?;
            let log_file = match log_path {
                Some(p) => Some(open_audit_log(p).await?),
                None => None,
            };

            Ok(Self {
                running: Arc::new(AtomicBool::new(true)),
                source: Some(source),
                log_file,
                kernel,
                violation_counts: Arc::new(Mutex::new(HashMap::new())),
                pid,
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
            let file = self
                .source
                .take()
                .ok_or_else(|| anyhow::anyhow!("Linux audit source already consumed"))?;
            let mut reader = BufReader::new(file);

            while self.running.load(Ordering::Relaxed) {
                let line = tokio::select! {
                    result = read_audit_record(&mut reader) => match result {
                        Ok(AuditRecord::Line(line)) => String::from_utf8_lossy(&line).into_owned(),
                        Ok(AuditRecord::Dropped) => {
                            let mut counts = self.violation_counts.lock().await;
                            *counts.entry("audit-record-dropped".to_owned()).or_insert(0) += 1;
                            continue;
                        }
                        Ok(AuditRecord::Eof) => break,
                        Err(_) => break,
                    },
                    _ = tokio::time::sleep(std::time::Duration::from_millis(150)) => {
                        if !self.running.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    }
                };

                if let Some(event) = parse_kmsg_event(&line, self.pid) {
                    let operation = sanitize_event_field(&event.operation);
                    let target = sanitize_event_field(&event.target);
                    let formatted = format!("[sbe:audit] DENIED {operation} {target}\n");
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

    fn parse_kmsg_event(line: &str, pid: u32) -> Option<SandboxEvent> {
        // Kernel seccomp audit lines look like:
        //   "audit: type=1326 audit(...): auid=... syscall=44 comm=\"foo\" exe=\"...\""
        // We match on `audit(` and `seccomp` keywords.
        if !line.contains("audit")
            || (!line.contains(&format!("pid={pid}")) && !line.contains(&format!("ppid={pid}")))
        {
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tokio::io::AsyncWriteExt as _;

    use super::*;

    #[tokio::test]
    async fn oversized_audit_record_is_dropped_without_desynchronizing() {
        let (mut writer, reader) = tokio::io::duplex(MAX_AUDIT_RECORD_BYTES * 2);
        tokio::spawn(async move {
            writer
                .write_all(&vec![b'x'; MAX_AUDIT_RECORD_BYTES + 1])
                .await
                .unwrap();
            writer.write_all(b"\nvalid\n").await.unwrap();
        });
        let mut reader = tokio::io::BufReader::new(reader);
        assert!(matches!(
            read_audit_record(&mut reader).await.unwrap(),
            AuditRecord::Dropped
        ));
        let AuditRecord::Line(line) = read_audit_record(&mut reader).await.unwrap() else {
            panic!("expected line after dropped record");
        };
        assert_eq!(line, b"valid\n");
    }

    #[tokio::test]
    async fn audit_log_is_private_and_refuses_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("audit.log");
        drop(open_audit_log(&log).await.unwrap());
        assert_eq!(
            tokio::fs::metadata(&log)
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let target = directory.path().join("target.log");
        tokio::fs::write(&target, "sentinel").await.unwrap();
        let link = directory.path().join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_audit_log(&link).await.is_err());
        assert_eq!(tokio::fs::read_to_string(target).await.unwrap(), "sentinel");
    }
}
