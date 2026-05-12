use std::{collections::HashMap, path::Path, process::ExitCode};

use anyhow::Context;
use sbe_core::{
    BackendOptions, Sandbox, SandboxBackend,
    config::{expand_path, load_configs, resolve_profile},
    detect::{self, Ecosystem},
    error::CoreError,
    profile::{DomainPattern, ProfileOverrides, SandboxProfile},
};
use sbe_proxy::{ProxyServer, allowlist::DomainAllowlist};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::cli::RunArgs;

/// sbe exit codes for its own errors (matching docker run / env conventions).
const EXIT_SBE_ERROR: u8 = 125;
const EXIT_SANDBOX_FAILED: u8 = 126;

/// Execute a command inside the sandbox.
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
    let cli_allow_degraded = overrides.allow_degraded;
    profile.merge_overrides(&overrides);
    profile.finalize();

    // Construct backend (kernel probe runs once here).
    let backend_options = BackendOptions {
        allow_degraded: cli_allow_degraded || profile.allow_degraded,
    };
    let backend = Sandbox::new_with_options(backend_options).map_err(|e| anyhow::anyhow!("{e}"))?;
    info!(
        backend = backend.name(),
        kernel = %backend.info().kernel,
        "sandbox backend ready"
    );

    // Start proxy if needed
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy_port = start_proxy_if_needed(&profile, shutdown_rx).await?;

    // Dry run / inspect: print policy and exit
    if args.dry_run {
        print_inspect_output(&profile, &backend, proxy_port);
        let _ = shutdown_tx.send(true);
        return Ok(ExitCode::SUCCESS);
    }

    // Start audit logger if requested
    let audit_handle = if args.audit || args.audit_log.is_some() {
        Some(crate::audit::start(backend.info(), args.audit_log.as_deref()).await?)
    } else {
        None
    };

    let extra_env = build_extra_env(&profile, proxy_port);
    let status = backend
        .run(&profile, proxy_port, &args.command, &extra_env)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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

    if matches!(code, 71 | 126) && !args.audit {
        eprintln!(
            "sbe: command exited with code {code} (likely a sandbox denial). Re-run with --audit \
             to see details, or add allowExec/allowFetch to .sbe.yaml"
        );
    }

    Ok(ExitCode::from(code))
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

fn build_extra_env(profile: &SandboxProfile, proxy_port: Option<u16>) -> HashMap<String, String> {
    let mut env = HashMap::new();
    if let Some(port) = proxy_port {
        let proxy_url = format!("http://127.0.0.1:{port}");
        env.insert("HTTP_PROXY".to_owned(), proxy_url.clone());
        env.insert("HTTPS_PROXY".to_owned(), proxy_url.clone());
        env.insert("http_proxy".to_owned(), proxy_url.clone());
        env.insert("https_proxy".to_owned(), proxy_url);
        env.insert("NO_PROXY".to_owned(), "localhost,127.0.0.1".to_owned());
        env.insert("no_proxy".to_owned(), "localhost,127.0.0.1".to_owned());
    }
    for (k, v) in &profile.env {
        env.insert(k.clone(), v.clone());
    }
    env
}

fn print_inspect_output(profile: &SandboxProfile, backend: &Sandbox, proxy_port: Option<u16>) {
    eprintln!("--- Backend ---");
    eprintln!("name:    {}", backend.name());
    eprintln!("kernel:  {}", backend.info().kernel);
    eprintln!("features:");
    let f = &backend.info().features;
    eprintln!("  fs_write       : {}", f.fs_write);
    eprintln!("  fs_read        : {}", f.fs_read);
    eprintln!("  exec_allowlist : {}", f.exec_allowlist);
    eprintln!("  net_port_filter: {}", f.net_port_filter);
    eprintln!("  audit_stream   : {}", f.audit_stream);
    eprintln!();
    eprintln!("--- Resolved profile ---");
    if let Ok(yaml) = serde_yaml::to_string(profile) {
        eprintln!("{yaml}");
    }
    println!("{}", backend.render_policy(profile, proxy_port));
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
        allow_read: Vec::new(),
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
        allow_fetch: args
            .allow_fetch
            .iter()
            .map(|d| DomainPattern(d.clone()))
            .collect(),
        allow_all_network: args.allow_all_network,
        no_proxy: args.no_proxy,
        allow_degraded: args.allow_degraded,
        env: Default::default(),
    }
}

/// Print available profiles and their defaults (for `sbe profiles` command).
pub fn print_profiles() -> anyhow::Result<()> {
    let home = dirs::home_dir().context("could not determine home directory")?;
    let pwd = std::env::current_dir().context("failed to get current directory")?;

    for eco in Ecosystem::ALL {
        let profile = SandboxProfile::for_ecosystem(eco, &home, &pwd);
        println!("=== {} ===", profile.name);
        println!("  Write paths:");
        for p in &profile.allow_write {
            println!("    - {p}");
        }
        println!("  Denied read paths:");
        for p in &profile.deny_read {
            println!("    - {p}");
        }
        println!("  Allowed domains:");
        for d in &profile.allow_domains {
            println!("    - {d}");
        }
        println!("  Denied executables:");
        for p in &profile.deny_exec {
            println!("    - {p}");
        }
        println!("  Allowed executables:");
        for p in &profile.allow_exec {
            println!("    - {p}");
        }
        println!();
    }
    Ok(())
}

#[allow(dead_code)]
fn _core_error_compile_check(err: CoreError) -> CoreError {
    err
}
