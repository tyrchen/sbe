use std::{path::Path, process::ExitCode};

use anyhow::{Context, bail};
use sbe_core::{
    config::{expand_path, load_configs, resolve_profile},
    detect::{self, Ecosystem},
    profile::{DomainPattern, ProfileOverrides, SandboxProfile},
    sbpl,
};
use sbe_proxy::{ProxyServer, allowlist::DomainAllowlist};
use tempfile::NamedTempFile;
use tokio::{process::Command, sync::watch};
use tracing::{debug, info, warn};

use crate::{audit::AuditLogger, cli::RunArgs};

/// sbe exit codes for its own errors (matching docker run / env conventions).
const EXIT_SBE_ERROR: u8 = 125;
const EXIT_SANDBOX_FAILED: u8 = 126;

/// Execute a command inside the macOS sandbox.
pub async fn execute(args: &RunArgs) -> ExitCode {
    match execute_inner(args).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sbe: {e:#}");
            ExitCode::from(EXIT_SBE_ERROR)
        }
    }
}

async fn execute_inner(args: &RunArgs) -> anyhow::Result<ExitCode> {
    // Verify we're on macOS with sandbox-exec available
    verify_platform()?;

    let pwd = std::env::current_dir().context("failed to get current directory")?;
    let home = dirs::home_dir().context("could not determine home directory")?;

    // Determine ecosystem
    let command_name = &args.command[0];
    let ecosystem = resolve_ecosystem(command_name, &args.profile, &pwd)?;

    info!(ecosystem = %ecosystem, command = %command_name, "detected ecosystem");

    // Build and resolve profile
    let mut profile = SandboxProfile::for_ecosystem(ecosystem, &home, &pwd);
    let configs = load_configs(&pwd, args.config.as_deref()).await?;
    resolve_profile(&mut profile, &configs, &home, &pwd);

    let overrides = build_overrides(args, &home, &pwd);
    profile.merge_overrides(&overrides);

    // Start proxy if needed
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy_port = start_proxy_if_needed(&profile, shutdown_rx).await?;

    // Generate SBPL
    let sbpl_content = sbpl::generate(&profile, proxy_port);

    // Dry run / inspect: print SBPL and config, then exit
    if args.dry_run {
        print_inspect_output(&profile, &sbpl_content);
        let _ = shutdown_tx.send(true);
        return Ok(ExitCode::SUCCESS);
    }

    // Write SBPL to temp file
    let sbpl_file = write_sbpl_tempfile(&sbpl_content).await?;
    let sbpl_path = sbpl_file.path().to_path_buf();
    debug!(path = %sbpl_path.display(), "wrote SBPL profile");

    // Start audit logger if requested
    let audit_handle = if args.audit || args.audit_log.is_some() {
        let logger = AuditLogger::new(args.audit_log.as_deref()).await?;
        Some(logger.start())
    } else {
        None
    };

    // Build and run sandbox-exec
    let status = run_sandboxed_command(args, &sbpl_path, &profile, proxy_port).await?;

    // Cleanup
    let _ = shutdown_tx.send(true);

    if let Some(handle) = audit_handle {
        handle.stop_and_summarize().await;
    }

    // Map exit status
    let code = match status.code() {
        Some(code) if (0..=255).contains(&code) => code as u8,
        Some(_) => EXIT_SBE_ERROR,
        None => {
            warn!("sandboxed process terminated by signal");
            EXIT_SANDBOX_FAILED
        }
    };

    Ok(ExitCode::from(code))
}

/// Verify that sandbox-exec is available on this platform.
fn verify_platform() -> anyhow::Result<()> {
    if cfg!(not(target_os = "macos")) {
        bail!("sbe requires macOS — sandbox-exec is not available on this platform");
    }
    if !Path::new("/usr/bin/sandbox-exec").exists() {
        bail!(
            "sandbox-exec not found at /usr/bin/sandbox-exec.\nThis may indicate System Integrity \
             Protection (SIP) issues or a non-standard macOS installation."
        );
    }
    Ok(())
}

/// Resolve the ecosystem from CLI flags or auto-detection.
fn resolve_ecosystem(
    command_name: &str,
    profile_flag: &Option<String>,
    pwd: &Path,
) -> anyhow::Result<Ecosystem> {
    if let Some(profile_name) = profile_flag {
        profile_name
            .parse::<Ecosystem>()
            .map_err(|e| anyhow::anyhow!("{e}"))
    } else {
        detect::detect(command_name, pwd).ok_or_else(|| {
            anyhow::anyhow!(
                "could not detect ecosystem from command '{command_name}' or working \
                 directory.\nSupported ecosystems: node, rust, python, elixir, java\nUse \
                 --profile <ecosystem> to specify explicitly."
            )
        })
    }
}

/// Start the domain-filtering proxy if the profile requires it.
async fn start_proxy_if_needed(
    profile: &SandboxProfile,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<Option<u16>> {
    if !profile.enable_proxy || profile.allow_all_network || profile.allow_domains.is_empty() {
        return Ok(None);
    }

    let domain_strings: Vec<String> = profile.allow_domains.iter().map(|d| d.0.clone()).collect();
    let allowlist = DomainAllowlist::new(&domain_strings);
    let (server, port) = ProxyServer::bind(allowlist, shutdown_rx).await?;
    info!(port, "proxy started");

    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            eprintln!("sbe: proxy error: {e}");
        }
    });

    Ok(Some(port))
}

/// Build and spawn the sandboxed command.
async fn run_sandboxed_command(
    args: &RunArgs,
    sbpl_path: &Path,
    profile: &SandboxProfile,
    proxy_port: Option<u16>,
) -> anyhow::Result<std::process::ExitStatus> {
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-f").arg(sbpl_path);
    cmd.arg(&args.command[0]);
    cmd.args(&args.command[1..]);

    // Inject proxy env vars
    if let Some(port) = proxy_port {
        let proxy_url = format!("http://127.0.0.1:{port}");
        cmd.env("HTTP_PROXY", &proxy_url);
        cmd.env("HTTPS_PROXY", &proxy_url);
        cmd.env("http_proxy", &proxy_url);
        cmd.env("https_proxy", &proxy_url);
        cmd.env("NO_PROXY", "localhost,127.0.0.1");
        cmd.env("no_proxy", "localhost,127.0.0.1");
    }

    // Inject profile env vars
    for (k, v) in &profile.env {
        cmd.env(k, v);
    }

    // Forward stdin/stdout/stderr
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    cmd.status().await.context("failed to spawn sandbox-exec")
}

/// Print resolved config and SBPL for inspect/dry-run mode.
fn print_inspect_output(profile: &SandboxProfile, sbpl_content: &str) {
    eprintln!("--- Resolved profile ---");
    if let Ok(yaml) = serde_yaml::to_string(profile) {
        eprintln!("{yaml}");
    }
    println!("{sbpl_content}");
}

fn build_overrides(args: &RunArgs, home: &Path, pwd: &Path) -> ProfileOverrides {
    ProfileOverrides {
        allow_write: args
            .allow_write
            .iter()
            .map(|p| expand_path(&p.to_string_lossy(), home, pwd))
            .collect(),
        deny_read: args
            .deny_read
            .iter()
            .map(|p| expand_path(&p.to_string_lossy(), home, pwd))
            .collect(),
        allow_domains: args
            .allow_domain
            .iter()
            .map(|d| DomainPattern(d.clone()))
            .collect(),
        deny_domains: args
            .deny_domain
            .iter()
            .map(|d| DomainPattern(d.clone()))
            .collect(),
        allow_exec: args
            .allow_exec
            .iter()
            .map(|p| expand_path(&p.to_string_lossy(), home, pwd))
            .collect(),
        deny_exec: args
            .deny_exec
            .iter()
            .map(|p| expand_path(&p.to_string_lossy(), home, pwd))
            .collect(),
        allow_all_network: args.allow_all_network,
        no_proxy: args.no_proxy,
        env: Default::default(),
    }
}

async fn write_sbpl_tempfile(content: &str) -> anyhow::Result<NamedTempFile> {
    let file = NamedTempFile::with_prefix("sbe-").context("failed to create SBPL temp file")?;

    tokio::fs::write(file.path(), content)
        .await
        .context("failed to write SBPL temp file")?;

    // Set permissions to read-only (0400)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o400);
        tokio::fs::set_permissions(file.path(), perms)
            .await
            .context("failed to set SBPL file permissions")?;
    }

    Ok(file)
}

/// Print available profiles and their defaults (for `sbe profiles` command).
pub fn print_profiles() {
    let home = dirs::home_dir().unwrap_or_else(|| "/Users/user".into());
    let pwd = std::env::current_dir().unwrap_or_else(|_| "/tmp".into());

    for eco in Ecosystem::ALL {
        let profile = SandboxProfile::for_ecosystem(eco, &home, &pwd);
        println!("=== {} ===", profile.name);
        println!("  Write paths:");
        for p in &profile.allow_write {
            println!("    - {}", p.display());
        }
        println!("  Denied read paths:");
        for p in &profile.deny_read {
            println!("    - {}", p.display());
        }
        println!("  Allowed domains:");
        for d in &profile.allow_domains {
            println!("    - {d}");
        }
        println!("  Denied executables:");
        for p in &profile.deny_exec {
            println!("    - {}", p.display());
        }
        println!("  Allowed executables:");
        for p in &profile.allow_exec {
            println!("    - {}", p.display());
        }
        println!();
    }
}
