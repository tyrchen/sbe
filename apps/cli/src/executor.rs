#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeSet;
use std::{
    collections::HashMap,
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sbe_core::{
    BackendOptions, Sandbox, SandboxBackend, SecurityMode,
    config::{PathKind, SandboxPath, expand_path, load_configs, resolve_profile},
    detect::{self, Ecosystem},
    error::CoreError,
    profile::{
        DomainPattern, GrantKind, GrantOrigin, GrantRecord, NetworkMode, ProfileOverrides,
        SandboxProfile,
    },
};
use sbe_proxy::{ProxyEndpoint, ProxyServer, allowlist::DomainAllowlist};
use tokio::{io::AsyncWriteExt, sync::watch};
use tracing::{info, warn};

use crate::cli::RunArgs;

/// sbe exit codes for its own errors (matching docker run / env conventions).
const EXIT_SBE_ERROR: u8 = 125;
const EXIT_SANDBOX_FAILED: u8 = 126;
const STANDARD_NO_PROXY: &str = "localhost,.localhost,127.0.0.1,::1";
const STANDARD_JAVA_NON_PROXY_HOSTS: &str = "localhost|*.localhost|127.*|[::1]";
const STANDARD_GRADLE_MUTABLE_SUBDIRECTORIES: &[&str] = &[
    ".tmp",
    "caches",
    "daemon",
    "jdks",
    "native",
    "notifications",
    "workers",
    "wrapper",
];
#[cfg(target_os = "linux")]
const MAX_SOURCE_SYMLINK_SCAN_ENTRIES: usize = 100_000;
#[cfg(target_os = "linux")]
const MAX_SOURCE_SYMLINK_SCAN_DEPTH: usize = 128;

const SAFE_PARENT_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "COLORTERM",
    "TZ",
    "JAVA_HOME",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "NVM_DIR",
    "MIX_HOME",
    "HEX_HOME",
    "GRADLE_USER_HOME",
];

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
    reject_project_relocation(&args.command, &pwd)?;

    // Determine ecosystem
    let command_name = &args.command[0];
    let ecosystem = resolve_ecosystem(command_name, &args.profile, &pwd)?;

    info!(ecosystem = %ecosystem, command = %command_name, "detected ecosystem");

    // Build and resolve profile
    let mut profile = SandboxProfile::for_ecosystem(ecosystem, &home, &pwd);
    if args.strict && ecosystem == Ecosystem::Node {
        configure_node_workspace(&mut profile, &args.command, &pwd)?;
    }
    let configs = load_configs(&pwd, args.config.as_deref(), args.trust_project_config).await?;
    resolve_profile(&mut profile, &configs, &home, &pwd)?;

    let overrides = build_overrides(args, &home, &pwd)?;
    let cli_allow_degraded = overrides.allow_degraded;
    profile.merge_overrides(&overrides);
    for (name, value) in resolve_cli_environment(args)? {
        profile.env.insert(name.clone(), value);
        profile.grant_origins.push(GrantRecord {
            kind: GrantKind::Environment,
            value: name,
            origin: GrantOrigin::Cli,
        });
    }
    profile.finalize();
    protect_effective_credential_paths(&mut profile, &home, &pwd);
    if args.strict {
        enable_existing_dependency_execution(&mut profile, &args.command);
    } else {
        apply_standard_profile(&mut profile, &args.command, &home, &pwd)?;
        #[cfg(target_os = "macos")]
        if !args.dry_run {
            prepare_standard_gradle_directories(&profile, &args.command, &home, &pwd)?;
        }
        resolve_standard_path_aliases(&mut profile, &home, &pwd)?;
    }

    if args.strict && !args.dry_run {
        if cargo_uses_persistent_target(&args.command) {
            ensure_child_directory(&pwd, c"target")?;
        }
        #[cfg(target_os = "linux")]
        ensure_literal_write_targets(&profile, &args.command, &pwd)?;
    }

    // Give each invocation an isolated temporary tree. The handle remains
    // alive until the child and proxy have stopped.
    let runtime_temp = tempfile::Builder::new()
        .prefix("sbe-")
        .tempdir()
        .context("failed to create private sandbox temporary directory")?;
    let runtime_temp_path = tokio::fs::canonicalize(runtime_temp.path())
        .await
        .context("failed to resolve private sandbox temporary directory")?;
    profile
        .allow_write
        .push(SandboxPath::dir(runtime_temp_path.clone()));
    profile.grant_origins.push(GrantRecord {
        kind: GrantKind::AllowWrite,
        value: runtime_temp_path.to_string_lossy().into_owned(),
        origin: GrantOrigin::Runtime,
    });
    profile
        .allow_exec
        .push(SandboxPath::dir(runtime_temp_path.clone()));
    profile.grant_origins.push(GrantRecord {
        kind: GrantKind::AllowExec,
        value: runtime_temp_path.to_string_lossy().into_owned(),
        origin: GrantOrigin::Runtime,
    });
    profile.ephemeral_write_exec.push(runtime_temp_path.clone());
    // Normal execution performs the filesystem identity scan exactly once in
    // the platform backend immediately before spawn. Inspection has no spawn,
    // so its branch below runs the complete validation explicitly.
    if args.strict {
        profile.validate_structural_security_invariants()?;
    }

    // Construct backend (kernel probe runs once here).
    let backend_options = BackendOptions {
        allow_degraded: cli_allow_degraded,
        allow_insecure_network: args.allow_insecure_linux_network || cli_allow_degraded,
    };
    let security_mode = if args.strict {
        SecurityMode::Strict
    } else {
        SecurityMode::Standard
    };
    let backend = Sandbox::new_with_mode(backend_options, security_mode)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    info!(
        backend = backend.name(),
        kernel = %backend.info().kernel,
        "sandbox backend ready"
    );

    // Start proxy if needed
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut proxy = start_proxy_if_needed(&profile, shutdown_rx).await?;
    let proxy_port = proxy.as_ref().map(|runtime| runtime.endpoint.port);
    let extra_env = build_extra_env(
        &mut profile,
        proxy.as_ref().map(|runtime| &runtime.endpoint),
        &runtime_temp_path,
        &home,
        &pwd,
        &args.command,
        args.strict,
    )
    .await?;

    // Dry run / inspect: print policy and exit
    if args.dry_run {
        if args.strict {
            profile.validate_security_invariants()?;
        }
        print_inspect_output(&profile, &backend, proxy_port, &extra_env, args.strict)?;
        let _ = shutdown_tx.send(true);
        if let Some(runtime) = proxy.take() {
            await_proxy_shutdown(runtime).await?;
        }
        return Ok(ExitCode::SUCCESS);
    }

    let wants_audit = args.audit || args.audit_log.is_some();
    if wants_audit && !backend.info().features.audit_stream {
        anyhow::bail!("audit stream is unavailable on this host");
    }
    let (pid_tx, pid_rx) = if wants_audit {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };
    let child = backend.run(&profile, proxy_port, &args.command, &extra_env, pid_tx);
    tokio::pin!(child);
    let mut early_status = None;
    let audit_handle = if let Some(receiver) = pid_rx {
        tokio::select! {
            pid = receiver => {
                let pid = pid.context("sandbox process exited before reporting its PID")?;
                Some(crate::audit::start(backend.info(), args.audit_log.as_deref(), pid).await?)
            }
            result = &mut child => {
                early_status = Some(result.map_err(|e| anyhow::anyhow!("{e}"))?);
                None
            }
        }
    } else {
        None
    };

    let status = if let Some(status) = early_status {
        status
    } else if let Some(runtime) = proxy.as_mut() {
        tokio::select! {
            result = &mut child => result.map_err(|e| anyhow::anyhow!("{e}"))?,
            proxy_result = &mut runtime.task => {
                let detail = match proxy_result {
                    Ok(Ok(())) => "proxy stopped before the sandboxed command".to_owned(),
                    Ok(Err(error)) => format!("proxy failed: {error}"),
                    Err(error) => format!("proxy task failed: {error}"),
                };
                anyhow::bail!(detail);
            }
        }
    } else {
        child.await.map_err(|e| anyhow::anyhow!("{e}"))?
    };

    let _ = shutdown_tx.send(true);
    if let Some(runtime) = proxy.take() {
        await_proxy_shutdown(runtime).await?;
    }

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
        if backend.info().features.audit_stream {
            eprintln!(
                "sbe: command exited with code {code} (likely a sandbox denial). Re-run with \
                 --audit to see details, or inspect the effective policy"
            );
        } else {
            eprintln!(
                "sbe: command exited with code {code} (likely a sandbox denial). Audit streaming \
                 is unavailable on this host; inspect the effective policy and command error"
            );
        }
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
struct ProxyRuntime {
    endpoint: ProxyEndpoint,
    task: tokio::task::JoinHandle<Result<(), sbe_proxy::error::ProxyError>>,
}

async fn start_proxy_if_needed(
    profile: &SandboxProfile,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<Option<ProxyRuntime>> {
    if profile.network_mode != NetworkMode::Proxy {
        return Ok(None);
    }

    let domain_strings: Vec<String> = profile.allow_domains.iter().map(|d| d.0.clone()).collect();
    let allowlist = DomainAllowlist::new(&domain_strings)
        .map_err(|error| anyhow::anyhow!("invalid proxy allowlist: {error}"))?;
    let (server, endpoint) = ProxyServer::bind(allowlist, shutdown_rx).await?;
    info!(port = endpoint.port, "proxy started");
    let task = tokio::spawn(server.run());
    Ok(Some(ProxyRuntime { endpoint, task }))
}

async fn await_proxy_shutdown(runtime: ProxyRuntime) -> anyhow::Result<()> {
    match runtime.task.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(anyhow::anyhow!("proxy failed during shutdown: {error}")),
        Err(error) => Err(anyhow::anyhow!(
            "proxy task failed during shutdown: {error}"
        )),
    }
}

async fn build_extra_env(
    profile: &mut SandboxProfile,
    proxy_endpoint: Option<&ProxyEndpoint>,
    runtime_temp: &Path,
    home: &Path,
    project_dir: &Path,
    command: &[String],
    strict: bool,
) -> anyhow::Result<HashMap<String, String>> {
    let mut env = filter_parent_environment(std::env::vars(), strict);
    let mut inherited: Vec<String> = env.keys().cloned().collect();
    inherited.sort();
    for name in inherited {
        record_effective_environment(profile, &name, GrantOrigin::ParentEnvironment);
    }
    let temp = runtime_temp.to_string_lossy().into_owned();
    insert_runtime_environment(profile, &mut env, "TMPDIR", temp.clone());
    insert_runtime_environment(profile, &mut env, "TMP", temp.clone());
    insert_runtime_environment(profile, &mut env, "TEMP", temp.clone());
    insert_runtime_environment(profile, &mut env, "XDG_RUNTIME_DIR", temp.clone());
    let profile_name = profile.name.clone();
    match (strict, profile_name.as_str()) {
        (true, "rust") => {
            let target_dir = if cargo_executes_target(command) {
                runtime_temp.join("cargo-target")
            } else {
                project_dir.join("target")
            };
            insert_runtime_environment(
                profile,
                &mut env,
                "CARGO_TARGET_DIR",
                target_dir.to_string_lossy().into_owned(),
            );
            insert_runtime_environment(
                profile,
                &mut env,
                "CARGO_BUILD_BUILD_DIR",
                runtime_temp
                    .join("cargo-build")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        (true, "python") => {
            insert_runtime_environment(
                profile,
                &mut env,
                "PIP_CACHE_DIR",
                runtime_temp
                    .join("pip-cache")
                    .to_string_lossy()
                    .into_owned(),
            );
            insert_runtime_environment(
                profile,
                &mut env,
                "UV_CACHE_DIR",
                runtime_temp.join("uv-cache").to_string_lossy().into_owned(),
            );
        }
        (true, "elixir") => {
            insert_runtime_environment(
                profile,
                &mut env,
                "MIX_BUILD_ROOT",
                project_dir.join("_build").to_string_lossy().into_owned(),
            );
            insert_runtime_environment(
                profile,
                &mut env,
                "MIX_DEPS_PATH",
                project_dir.join("deps").to_string_lossy().into_owned(),
            );
            insert_runtime_environment(
                profile,
                &mut env,
                "REBAR_CACHE_DIR",
                runtime_temp
                    .join("rebar-cache")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        (true, "java") => {
            insert_runtime_environment(
                profile,
                &mut env,
                "GRADLE_USER_HOME",
                runtime_temp
                    .join("gradle-home")
                    .to_string_lossy()
                    .into_owned(),
            );
            insert_runtime_environment(
                profile,
                &mut env,
                "COURSIER_CACHE",
                runtime_temp
                    .join("coursier-cache")
                    .to_string_lossy()
                    .into_owned(),
            );
            let sbt_root = runtime_temp.join("sbt");
            insert_runtime_environment(
                profile,
                &mut env,
                "SBT_OPTS",
                format!(
                    "-Dsbt.global.base={} -Dsbt.boot.directory={} -Dsbt.ivy.home={}",
                    sbt_root.join("global").display(),
                    sbt_root.join("boot").display(),
                    sbt_root.join("ivy2").display(),
                ),
            );
        }
        (false, "java") => {
            // Keep ordinary dependency caches persistent, but put sbt's
            // mutable global base in the private run root. The default global
            // base also contains settings and plugins, so granting ~/.sbt
            // broadly would let an untrusted build persist executable code.
            let inherited = env.get("SBT_OPTS").cloned().unwrap_or_default();
            let separator = if inherited.is_empty() { "" } else { " " };
            insert_runtime_environment(
                profile,
                &mut env,
                "SBT_OPTS",
                format!(
                    "{inherited}{separator}-Dsbt.global.base={} -Dsbt.boot.directory={} \
                     -Dsbt.ivy.home={}",
                    runtime_temp.join("sbt-global").display(),
                    home.join(".sbt/boot").display(),
                    home.join(".ivy2").display(),
                ),
            );
        }
        _ => {}
    }
    if !strict
        && profile_name == "rust"
        && !env.contains_key("CARGO_TARGET_DIR")
        && !env.contains_key("CARGO_BUILD_TARGET_DIR")
        && !profile.env.contains_key("CARGO_TARGET_DIR")
        && !profile.env.contains_key("CARGO_BUILD_TARGET_DIR")
        && command_option_value(command, "--target-dir").is_none()
        && cargo_config_target_dir(command)?.is_none()
    {
        insert_runtime_environment(
            profile,
            &mut env,
            "CARGO_TARGET_DIR",
            project_dir.join("target").to_string_lossy().into_owned(),
        );
    }
    if let Some(endpoint) = proxy_endpoint {
        let proxy_url = endpoint.url();
        insert_runtime_environment(profile, &mut env, "HTTP_PROXY", proxy_url.clone());
        insert_runtime_environment(profile, &mut env, "HTTPS_PROXY", proxy_url.clone());
        insert_runtime_environment(profile, &mut env, "http_proxy", proxy_url.clone());
        insert_runtime_environment(profile, &mut env, "https_proxy", proxy_url);
        let no_proxy = if strict { "" } else { STANDARD_NO_PROXY };
        insert_runtime_environment(profile, &mut env, "NO_PROXY", no_proxy.to_owned());
        insert_runtime_environment(profile, &mut env, "no_proxy", no_proxy.to_owned());
        if profile.name == "java" {
            let agent_path = install_java_proxy_agent(runtime_temp).await?;
            let non_proxy_hosts = if strict {
                ""
            } else {
                STANDARD_JAVA_NON_PROXY_HOSTS
            };
            for (name, value) in endpoint.java_environment(&agent_path, &temp, non_proxy_hosts) {
                insert_runtime_environment(profile, &mut env, name, value);
            }
        }
    }
    let profile_environment: Vec<(String, String)> = profile
        .env
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    for (name, value) in profile_environment {
        env.insert(name.clone(), value);
        let origin = profile
            .grant_origins
            .iter()
            .rev()
            .find(|record| {
                record.kind == GrantKind::Environment
                    && record.value == name
                    && !matches!(
                        record.origin,
                        GrantOrigin::ParentEnvironment | GrantOrigin::Runtime
                    )
            })
            .map(|record| record.origin.clone())
            .unwrap_or(GrantOrigin::Runtime);
        record_effective_environment(profile, &name, origin);
    }
    Ok(env)
}

async fn install_java_proxy_agent(runtime_temp: &Path) -> anyhow::Result<String> {
    const AGENT_B64: &str =
        include_str!("../assets/java-proxy-agent/java-proxy-auth-agent.jar.b64");

    let path = runtime_temp.join("java-proxy-auth-agent.jar");
    let path_text = path
        .to_str()
        .context("private Java proxy agent path is not valid UTF-8")?;
    if path_text.chars().any(|character| {
        character.is_control() || character.is_ascii_whitespace() || "'\"\\".contains(character)
    }) {
        anyhow::bail!("private Java proxy agent path contains unsupported option characters");
    }

    let jar = BASE64_STANDARD
        .decode(AGENT_B64.trim())
        .context("embedded Java proxy authentication agent is corrupt")?;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&path)
        .await
        .context("failed to create private Java proxy authentication agent")?;
    file.write_all(&jar)
        .await
        .context("failed to write private Java proxy authentication agent")?;
    file.sync_all()
        .await
        .context("failed to persist private Java proxy authentication agent")?;
    Ok(path_text.to_owned())
}

fn insert_runtime_environment(
    profile: &mut SandboxProfile,
    environment: &mut HashMap<String, String>,
    name: &str,
    value: String,
) {
    environment.insert(name.to_owned(), value);
    record_effective_environment(profile, name, GrantOrigin::Runtime);
}

fn record_effective_environment(profile: &mut SandboxProfile, name: &str, origin: GrantOrigin) {
    profile.grant_origins.push(GrantRecord {
        kind: GrantKind::Environment,
        value: name.to_owned(),
        origin,
    });
}

fn filter_parent_environment<I>(variables: I, strict: bool) -> HashMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    variables
        .into_iter()
        .filter(|(name, _)| {
            if strict {
                SAFE_PARENT_ENV.contains(&name.as_str())
            } else {
                !is_sensitive_environment_name(name)
            }
        })
        .collect()
}

fn is_sensitive_environment_name(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONFIG_FILE",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "AZURE_CLIENT_SECRET",
        "AZURE_CONFIG_DIR",
        "CLOUDSDK_CONFIG",
        "CREDENTIAL",
        "CREDENTIALS",
        "CI_JOB_JWT",
        "CI_JOB_JWT_V2",
        "DATABASE_URL",
        "DOCKER_AUTH_CONFIG",
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "GPG_AGENT_INFO",
        "GH_CONFIG_DIR",
        "GNUPGHOME",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "KUBECONFIG",
        "MONGODB_URI",
        "MONGO_URL",
        "MYSQL_PWD",
        "PASSWORD",
        "PASSWD",
        "PGPASSFILE",
        "PGPASSWORD",
        "PRIVATE_KEY",
        "REDISCLI_AUTH",
        "SECRET",
        "SSH_AGENT_PID",
        "SSH_AUTH_SOCK",
        "SYSTEM_ACCESSTOKEN",
        "TOKEN",
    ];
    const RESERVED: &[&str] = &[
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "TMPDIR",
        "TMP",
        "TEMP",
        "XDG_RUNTIME_DIR",
        "SBE_PROXY_TOKEN",
    ];

    let upper = name.to_ascii_uppercase();
    EXACT.contains(&upper.as_str())
        || RESERVED.contains(&upper.as_str())
        || upper.starts_with("DYLD_")
        || upper.starts_with("TF_TOKEN_")
        || upper == "LD_PRELOAD"
        || upper == "LD_LIBRARY_PATH"
        || [
            "_TOKEN",
            "_TOKEN_FILE",
            "_API_KEY",
            "_SECRET",
            "_PASSWORD",
            "_PASSWD",
            "_PRIVATE_KEY",
            "_CREDENTIAL",
            "_CREDENTIALS",
            "_CREDENTIALS_FILE",
            "_DATABASE_URL",
            "_DATABASE_URI",
            "_AUTH",
            "_AUTHTOKEN",
        ]
        .iter()
        .any(|suffix| upper.ends_with(suffix))
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode resolves conventional outputs before granting their canonical \
              referents"
)]
fn apply_standard_profile(
    profile: &mut SandboxProfile,
    command: &[String],
    home: &Path,
    project_dir: &Path,
) -> anyhow::Result<()> {
    remove_builtin_workspace_read_denials(profile, project_dir);
    let project_outputs = replace_builtin_project_writes(profile, project_dir);

    insert_builtin_path_grant(
        profile,
        GrantKind::AllowWrite,
        SandboxPath::dir(project_dir.to_path_buf()),
    );
    for output in project_outputs {
        if resolves_within(&output, project_dir) {
            // The Linux backend must open an executable directory before it
            // installs Landlock. Keep the narrower write grant alongside the
            // workspace grant so a missing output root is created safely
            // before its execute rule is compiled.
            insert_builtin_path_grant(
                profile,
                GrantKind::AllowWrite,
                SandboxPath::dir(output.clone()),
            );
            insert_builtin_path_grant(profile, GrantKind::AllowExec, SandboxPath::dir(output));
            continue;
        }

        let resolved = std::fs::canonicalize(&output).with_context(|| {
            format!(
                "could not resolve conventional output path '{}'",
                output.display()
            )
        })?;
        if !resolved.is_dir() {
            anyhow::bail!(
                "conventional output path '{}' must resolve to a directory",
                output.display()
            );
        }
        if !explicit_write_covers(profile, &resolved) {
            return Err(external_write_approval_error(&output, &resolved));
        }
        // The explicit grant supplies write authority. Output intent also
        // authorizes execution, but only for the approved canonical subtree.
        insert_builtin_path_grant(profile, GrantKind::AllowExec, SandboxPath::dir(resolved));
    }

    if profile.name == "java" {
        if let Some(repository) =
            effective_maven_local_repository(profile, command, home, project_dir)?
        {
            if repository.project_controlled
                && !project_maven_repository_is_approved(
                    profile,
                    &repository.path,
                    home,
                    project_dir,
                )
            {
                let resolved = resolve_existing_ancestor(&repository.path)
                    .unwrap_or_else(|| repository.path.clone());
                return Err(external_write_approval_error(&repository.path, &resolved));
            }
            replace_builtin_write_path(
                profile,
                &home.join(".m2/repository"),
                SandboxPath::dir(repository.path),
            );
        }
        // Standard mode uses the package manager's ordinary persistent
        // caches. Strict mode redirects these into the private runtime root.
        for cache in [
            home.join(".sbt/boot"),
            home.join(".ivy2/cache"),
            home.join(".cache/coursier"),
        ] {
            insert_builtin_path_grant(profile, GrantKind::AllowWrite, SandboxPath::dir(cache));
        }
        #[cfg(target_os = "macos")]
        insert_builtin_path_grant(
            profile,
            GrantKind::AllowWrite,
            SandboxPath::dir(home.join("Library/Caches/Coursier")),
        );

        if let Some(gradle_home) = effective_gradle_user_home(profile, command, home, project_dir)?
        {
            // Keep init.d and root-level initialization scripts immutable.
            // Standard mode accepts cache poisoning, but should not provide a
            // direct unsandboxed-startup persistence mechanism.
            for name in STANDARD_GRADLE_MUTABLE_SUBDIRECTORIES {
                let path = gradle_home.join(name);
                insert_builtin_path_grant(
                    profile,
                    GrantKind::AllowWrite,
                    SandboxPath::dir(path.clone()),
                );
                insert_builtin_path_grant(profile, GrantKind::AllowExec, SandboxPath::dir(path));
            }
        }
    }

    if command_is(command, "cargo") {
        let cargo_cli_target = command_option_value(command, "--target-dir").map(PathBuf::from);
        if let Some(path) = cargo_cli_target {
            let path = if path.is_absolute() {
                path
            } else {
                project_dir.join(path)
            };
            insert_builtin_path_grant(
                profile,
                GrantKind::AllowWrite,
                SandboxPath::dir(path.clone()),
            );
            insert_builtin_path_grant(profile, GrantKind::AllowExec, SandboxPath::dir(path));
        } else {
            let environment_target = effective_environment_path(profile, "CARGO_TARGET_DIR")
                .or_else(|| effective_environment_path(profile, "CARGO_BUILD_TARGET_DIR"));
            let has_environment_target = environment_target.is_some();
            if let Some(path) = environment_target {
                let path = if path.is_absolute() {
                    path
                } else {
                    project_dir.join(path)
                };
                insert_builtin_path_grant(
                    profile,
                    GrantKind::AllowWrite,
                    SandboxPath::dir(path.clone()),
                );
                insert_builtin_path_grant(profile, GrantKind::AllowExec, SandboxPath::dir(path));
            }
            if !has_environment_target && let Some(path) = cargo_config_target_dir(command)? {
                let path = if path.is_absolute() {
                    path
                } else {
                    project_dir.join(path)
                };
                insert_builtin_path_grant(
                    profile,
                    GrantKind::AllowWrite,
                    SandboxPath::dir(path.clone()),
                );
                insert_builtin_path_grant(profile, GrantKind::AllowExec, SandboxPath::dir(path));
            }
        }
    }
    if command_is(command, "cargo") && top_level_subcommand(command).is_command(&["install"]) {
        let explicit_root = command_option_value(command, "--root").map(PathBuf::from);
        let environment_root = effective_environment_path(profile, "CARGO_INSTALL_ROOT");
        let config_root = if explicit_root.is_none() && environment_root.is_none() {
            cargo_config_install_root(command)?
        } else {
            None
        };
        let cargo_home = effective_environment_path(profile, "CARGO_HOME")
            .unwrap_or_else(|| home.join(".cargo"));
        if explicit_root.is_none() && environment_root.is_none() && config_root.is_none() {
            reject_implicit_cargo_install_root(project_dir, &cargo_home)?;
        }
        let cargo_root = explicit_root
            .or(environment_root)
            .or(config_root)
            .unwrap_or(cargo_home);
        let cargo_root = if cargo_root.is_absolute() {
            cargo_root
        } else {
            project_dir.join(cargo_root)
        };
        insert_builtin_path_grant(
            profile,
            GrantKind::AllowWrite,
            SandboxPath::dir(cargo_root.clone()),
        );
        insert_builtin_path_grant(
            profile,
            GrantKind::AllowExec,
            SandboxPath::dir(cargo_root.join("bin")),
        );
    }
    Ok(())
}

fn effective_environment_path(profile: &SandboxProfile, name: &str) -> Option<PathBuf> {
    profile
        .env
        .get(name)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os(name).map(PathBuf::from))
}

fn protect_effective_credential_paths(
    profile: &mut SandboxProfile,
    home: &Path,
    project_dir: &Path,
) {
    let cargo_home =
        effective_environment_path(profile, "CARGO_HOME").unwrap_or_else(|| home.join(".cargo"));
    let cargo_home = if cargo_home.is_absolute() {
        cargo_home
    } else {
        project_dir.join(cargo_home)
    };
    for name in ["credentials.toml", "credentials"] {
        insert_builtin_read_denial(profile, SandboxPath::file(cargo_home.join(name)));
    }

    // Ambient GH_CONFIG_DIR is filtered as a sensitive locator. When it is absent from the
    // resolved profile, gh falls back to XDG_CONFIG_HOME/gh before ~/.config/gh.
    if !profile.env.contains_key("GH_CONFIG_DIR") {
        let github_config = effective_environment_path(profile, "XDG_CONFIG_HOME")
            .map(|directory| {
                if directory.is_absolute() {
                    directory.join("gh")
                } else {
                    project_dir.join(directory).join("gh")
                }
            })
            .unwrap_or_else(|| home.join(".config/gh"));
        insert_builtin_read_denial(profile, SandboxPath::dir(github_config));
    }
}

fn insert_builtin_read_denial(profile: &mut SandboxProfile, denial: SandboxPath) {
    if profile.deny_read.iter().any(|existing| existing == &denial) {
        return;
    }
    let value = denial.path.to_string_lossy().into_owned();
    profile.deny_read.push(denial);
    profile.grant_origins.push(GrantRecord {
        kind: GrantKind::DenyRead,
        value,
        origin: GrantOrigin::BuiltIn,
    });
}

fn effective_gradle_user_home(
    profile: &SandboxProfile,
    command: &[String],
    home: &Path,
    project_dir: &Path,
) -> anyhow::Result<Option<PathBuf>> {
    if !command_is(command, "gradle") && !command_is(command, "gradlew") {
        return Ok(None);
    }
    let command_home = command_aliased_option_value(command, "--gradle-user-home", "-g")
        .map(PathBuf::from)
        .or_else(|| command_system_property(command, "gradle.user.home").map(PathBuf::from));
    let inherited_jvm_home = if command_home.is_none() {
        let gradle_opts = jvm_options_gradle_user_home(profile, "GRADLE_OPTS")?;
        if gradle_opts.is_some() {
            gradle_opts
        } else {
            jvm_options_gradle_user_home(profile, "JAVA_OPTS")?
        }
    } else {
        None
    };
    let selected = command_home
        .or(inherited_jvm_home)
        .or_else(|| effective_environment_path(profile, "GRADLE_USER_HOME"))
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".gradle"));
    Ok(Some(if selected.is_absolute() {
        selected
    } else {
        project_dir.join(selected)
    }))
}

struct MavenRepositorySelection {
    path: PathBuf,
    project_controlled: bool,
}

fn effective_maven_local_repository(
    profile: &SandboxProfile,
    command: &[String],
    home: &Path,
    project_dir: &Path,
) -> anyhow::Result<Option<MavenRepositorySelection>> {
    if !command_is(command, "mvn") && !command_is(command, "mvnw") {
        return Ok(None);
    }
    let command_value = command_maven_property(command, "maven.repo.local").map(PathBuf::from);
    let maven_args_value = if command_value.is_none() {
        let arguments = profile
            .env
            .get("MAVEN_ARGS")
            .cloned()
            .or_else(|| std::env::var("MAVEN_ARGS").ok());
        arguments
            .as_deref()
            .map(|arguments| maven_args_local_repository(arguments, "MAVEN_ARGS"))
            .transpose()?
            .flatten()
    } else {
        None
    };
    let maven_config_value = if command_value.is_none() && maven_args_value.is_none() {
        let path = project_dir.join(".mvn/maven.config");
        read_bounded_project_file(&path)?
            .map(|contents| {
                let contents = std::str::from_utf8(&contents).with_context(|| {
                    format!("Maven argument config is not UTF-8: {}", path.display())
                })?;
                let mut arguments = vec!["mvn".to_owned()];
                arguments.extend(
                    contents
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty() && !line.starts_with('#'))
                        .map(str::to_owned),
                );
                maven_argument_list_local_repository(&arguments, ".mvn/maven.config", true)
            })
            .transpose()?
            .flatten()
    } else {
        None
    };
    let has_argument_value =
        command_value.is_some() || maven_args_value.is_some() || maven_config_value.is_some();
    let maven_opts_value = if !has_argument_value {
        let options = profile
            .env
            .get("MAVEN_OPTS")
            .cloned()
            .or_else(|| std::env::var("MAVEN_OPTS").ok());
        options
            .as_deref()
            .map(|options| maven_options_local_repository(options, "MAVEN_OPTS"))
            .transpose()?
            .flatten()
    } else {
        None
    };
    let project_jvm_value = if !has_argument_value && maven_opts_value.is_none() {
        let path = project_dir.join(".mvn/jvm.config");
        read_bounded_project_file(&path)?
            .map(|contents| {
                let contents = std::str::from_utf8(&contents).with_context(|| {
                    format!("Maven JVM config is not UTF-8: {}", path.display())
                })?;
                maven_options_local_repository(contents, ".mvn/jvm.config")
            })
            .transpose()?
            .flatten()
    } else {
        None
    };
    let selected = command_value
        .map(|path| MavenRepositorySelection {
            path,
            project_controlled: false,
        })
        .or_else(|| {
            maven_args_value.map(|path| MavenRepositorySelection {
                path,
                project_controlled: false,
            })
        })
        .or_else(|| {
            maven_config_value.map(|path| MavenRepositorySelection {
                path,
                project_controlled: true,
            })
        })
        .or_else(|| {
            maven_opts_value.map(|path| MavenRepositorySelection {
                path,
                project_controlled: false,
            })
        })
        .or_else(|| {
            project_jvm_value.map(|path| MavenRepositorySelection {
                path,
                project_controlled: true,
            })
        });
    let Some(mut selected) = selected else {
        return Ok(None);
    };
    if selected.path.as_os_str().is_empty() {
        anyhow::bail!("maven.repo.local must be a non-empty path");
    }
    if !selected.path.is_absolute() {
        selected.path = project_dir.join(selected.path);
    }
    if selected.path == home.join(".m2/repository") {
        return Ok(None);
    }
    Ok(Some(selected))
}

fn project_maven_repository_is_approved(
    profile: &SandboxProfile,
    repository: &Path,
    home: &Path,
    project_dir: &Path,
) -> bool {
    let resolved =
        resolve_existing_ancestor(repository).unwrap_or_else(|| repository.to_path_buf());
    let project =
        resolve_existing_ancestor(project_dir).unwrap_or_else(|| project_dir.to_path_buf());
    resolved.starts_with(project)
        || repository.starts_with(home.join(".m2/repository"))
        || explicit_write_covers(profile, &resolved)
}

fn maven_args_local_repository(arguments: &str, source: &str) -> anyhow::Result<Option<PathBuf>> {
    let mut command = vec!["mvn".to_owned()];
    command.extend(arguments.split_whitespace().map(str::to_owned));
    maven_argument_list_local_repository(&command, source, true)
}

fn maven_argument_list_local_repository(
    arguments: &[String],
    source: &str,
    reject_shell_syntax: bool,
) -> anyhow::Result<Option<PathBuf>> {
    let selected = command_maven_property(arguments, "maven.repo.local");
    if let Some(value) = selected {
        if value.is_empty()
            || value.chars().any(char::is_control)
            || (reject_shell_syntax
                && value.chars().any(|character| {
                    matches!(character, '$' | '`' | '\\' | '\'' | '"' | '*' | '?' | '[')
                }))
        {
            anyhow::bail!(
                "{source} selects maven.repo.local in a form that sbe cannot resolve safely; use \
                 -Dmaven.repo.local=/unambiguous/path"
            );
        }
        return Ok(Some(PathBuf::from(value)));
    }
    if arguments
        .iter()
        .any(|argument| argument.contains("maven.repo.local"))
    {
        anyhow::bail!(
            "{source} selects maven.repo.local in an unsupported form; use \
             -Dmaven.repo.local=/unambiguous/path"
        );
    }
    Ok(None)
}

fn maven_options_local_repository(options: &str, source: &str) -> anyhow::Result<Option<PathBuf>> {
    let mut selected = None;
    for token in options.split_whitespace() {
        let Some(value) = token.strip_prefix("-Dmaven.repo.local=") else {
            continue;
        };
        if value.is_empty()
            || value.chars().any(|character| {
                matches!(character, '$' | '`' | '\\' | '\'' | '"' | '*' | '?' | '[')
            })
        {
            anyhow::bail!(
                "{source} selects maven.repo.local in a form that sbe cannot resolve safely; use \
                 -Dmaven.repo.local=/unambiguous/path"
            );
        }
        selected = Some(PathBuf::from(value));
    }
    if selected.is_none() && options.contains("-Dmaven.repo.local") {
        anyhow::bail!(
            "{source} selects maven.repo.local in an unsupported form; use \
             -Dmaven.repo.local=/unambiguous/path"
        );
    }
    Ok(selected)
}

fn jvm_options_gradle_user_home(
    profile: &SandboxProfile,
    variable: &str,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(options) = profile
        .env
        .get(variable)
        .cloned()
        .or_else(|| std::env::var(variable).ok())
    else {
        return Ok(None);
    };
    let mut selected = None;
    for token in options.split_whitespace() {
        let Some(value) = token.strip_prefix("-Dgradle.user.home=") else {
            continue;
        };
        if value.is_empty()
            || value
                .chars()
                .any(|character| matches!(character, '$' | '`' | '\\' | '\'' | '"'))
        {
            anyhow::bail!(
                "{variable} selects gradle.user.home with quoting or expansion that sbe cannot \
                 resolve safely; use --gradle-user-home or GRADLE_USER_HOME"
            );
        }
        // JVM system properties use the last repeated value.
        selected = Some(PathBuf::from(value));
    }
    if selected.is_none() && options.contains("-Dgradle.user.home") {
        anyhow::bail!(
            "{variable} selects gradle.user.home in an unsupported form; use --gradle-user-home \
             or GRADLE_USER_HOME"
        );
    }
    Ok(selected)
}

#[cfg(target_os = "macos")]
#[allow(
    clippy::disallowed_methods,
    reason = "the trusted parent prepares exact Gradle runtime directories before sandboxing"
)]
fn prepare_standard_gradle_directories(
    profile: &SandboxProfile,
    command: &[String],
    home: &Path,
    project_dir: &Path,
) -> anyhow::Result<()> {
    let Some(gradle_home) = effective_gradle_user_home(profile, command, home, project_dir)? else {
        return Ok(());
    };
    for name in STANDARD_GRADLE_MUTABLE_SUBDIRECTORIES {
        let path = gradle_home.join(name);
        std::fs::create_dir_all(&path).with_context(|| {
            format!(
                "could not prepare Gradle runtime directory '{}'",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn remove_builtin_workspace_read_denials(profile: &mut SandboxProfile, project_dir: &Path) {
    let removed: Vec<PathBuf> = profile
        .deny_read
        .iter()
        .filter(|grant| grant.path.parent() == Some(project_dir))
        .filter(|grant| {
            grant.path.file_name().is_some_and(|name| {
                matches!(
                    name.to_str(),
                    Some(".env" | ".env.local" | ".env.production")
                )
            })
        })
        .filter(|grant| {
            !profile.grant_origins.iter().any(|record| {
                record.kind == GrantKind::DenyRead
                    && record.origin != GrantOrigin::BuiltIn
                    && record.value == grant.path.to_string_lossy()
            })
        })
        .map(|grant| grant.path.clone())
        .collect();
    profile
        .deny_read
        .retain(|grant| !removed.contains(&grant.path));
    profile.grant_origins.retain(|record| {
        record.kind != GrantKind::DenyRead
            || record.origin != GrantOrigin::BuiltIn
            || !removed
                .iter()
                .any(|path| record.value == path.to_string_lossy())
    });
}

fn replace_builtin_project_writes(
    profile: &mut SandboxProfile,
    project_dir: &Path,
) -> Vec<PathBuf> {
    let built_in_boundary = profile
        .first_user_allow_write
        .min(profile.allow_write.len());
    let mut project_outputs = Vec::new();
    let mut removed = Vec::new();
    let mut retained = Vec::with_capacity(profile.allow_write.len());
    for (index, grant) in profile.allow_write.drain(..).enumerate() {
        if index < built_in_boundary
            && grant.path != project_dir
            && grant.path.starts_with(project_dir)
        {
            if grant.kind == sbe_core::config::PathKind::Subpath {
                project_outputs.push(grant.path.clone());
            }
            removed.push(grant.path);
        } else {
            retained.push(grant);
        }
    }
    profile.allow_write = retained;
    profile.first_user_allow_write = built_in_boundary.saturating_sub(removed.len());
    profile.grant_origins.retain(|record| {
        record.kind != GrantKind::AllowWrite
            || record.origin != GrantOrigin::BuiltIn
            || !removed
                .iter()
                .any(|path| record.value == path.to_string_lossy())
    });
    project_outputs
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode resolves existing ancestors before granting executable project output"
)]
fn resolves_within(path: &Path, root: &Path) -> bool {
    let Ok(root) = std::fs::canonicalize(root) else {
        return false;
    };
    let mut existing = Some(path);
    while let Some(candidate) = existing {
        match std::fs::canonicalize(candidate) {
            Ok(resolved) => return resolved.starts_with(&root),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing = candidate.parent();
            }
            Err(_) => return false,
        }
    }
    false
}

fn insert_builtin_path_grant(profile: &mut SandboxProfile, kind: GrantKind, grant: SandboxPath) {
    // Post-finalization compatibility grants must not undo a higher-precedence
    // execute denial. Landlock cannot subtract a denied child from an allowed
    // directory, so any overlap suppresses the complete inferred grant.
    if kind == GrantKind::AllowExec
        && profile
            .deny_exec
            .iter()
            .any(|denied| paths_overlap(&grant.path, &denied.path))
    {
        return;
    }
    let paths = match kind {
        GrantKind::AllowWrite => &mut profile.allow_write,
        GrantKind::AllowExec => &mut profile.allow_exec,
        _ => return,
    };
    if paths.iter().any(|existing| existing == &grant) {
        return;
    }
    let value = grant.path.to_string_lossy().into_owned();
    match kind {
        GrantKind::AllowWrite => {
            let index = profile.first_user_allow_write.min(paths.len());
            paths.insert(index, grant);
            profile.first_user_allow_write = index + 1;
        }
        GrantKind::AllowExec => {
            let index = profile.first_user_allow_exec.min(paths.len());
            paths.insert(index, grant);
            profile.first_user_allow_exec = index + 1;
        }
        _ => return,
    }
    profile.grant_origins.push(GrantRecord {
        kind,
        value,
        origin: GrantOrigin::BuiltIn,
    });
}

fn replace_builtin_write_path(
    profile: &mut SandboxProfile,
    current: &Path,
    replacement: SandboxPath,
) {
    if replacement.path == current {
        return;
    }
    let built_in_boundary = profile
        .first_user_allow_write
        .min(profile.allow_write.len());
    let mut removed = 0_usize;
    profile.allow_write = profile
        .allow_write
        .drain(..)
        .enumerate()
        .filter_map(|(index, grant)| {
            if index < built_in_boundary && grant.path == current {
                removed += 1;
                None
            } else {
                Some(grant)
            }
        })
        .collect();
    profile.first_user_allow_write = built_in_boundary.saturating_sub(removed);
    profile.grant_origins.retain(|record| {
        record.kind != GrantKind::AllowWrite
            || record.origin != GrantOrigin::BuiltIn
            || record.value != current.to_string_lossy()
    });
    insert_builtin_path_grant(profile, GrantKind::AllowWrite, replacement);
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode snapshots pre-existing user tool and cache symlinks before launch"
)]
fn resolve_standard_path_aliases(
    profile: &mut SandboxProfile,
    home: &Path,
    project_dir: &Path,
) -> anyhow::Result<()> {
    snapshot_standard_write_aliases(profile, home, project_dir)?;
    snapshot_standard_exec_aliases(profile)?;
    snapshot_standard_read_aliases(profile)?;
    #[cfg(target_os = "linux")]
    append_standard_workspace_read_aliases(profile, project_dir)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn append_standard_workspace_read_aliases(
    profile: &mut SandboxProfile,
    project_dir: &Path,
) -> anyhow::Result<()> {
    let read_aliases = workspace_read_aliases(profile, project_dir)?;
    for alias in read_aliases {
        if !profile.allow_read.contains(&alias) {
            profile.grant_origins.push(GrantRecord {
                kind: GrantKind::AllowRead,
                value: alias.path.to_string_lossy().into_owned(),
                origin: GrantOrigin::Runtime,
            });
            profile.allow_read.push(alias);
        }
    }
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode snapshots executable symlink referents before launching untrusted code"
)]
fn snapshot_standard_exec_aliases(profile: &mut SandboxProfile) -> anyhow::Result<()> {
    let built_in_boundary = profile.first_user_allow_exec.min(profile.allow_exec.len());
    let original = profile.allow_exec.clone();
    let mut snapped = Vec::with_capacity(original.len());
    let mut records = Vec::new();
    for (index, grant) in original.into_iter().enumerate() {
        let Ok(resolved) = std::fs::canonicalize(&grant.path) else {
            snapped.push(grant);
            continue;
        };
        if resolved != grant.path
            && index < built_in_boundary
            && overlaps_denied_read(profile, &resolved)
        {
            return Err(protected_builtin_alias_error(
                "executable",
                &grant.path,
                &resolved,
            ));
        }
        if resolved != grant.path {
            records.push(GrantRecord {
                kind: GrantKind::AllowExec,
                value: resolved.to_string_lossy().into_owned(),
                origin: GrantOrigin::Runtime,
            });
            snapped.push(SandboxPath {
                path: resolved,
                kind: grant.kind,
            });
        } else {
            snapped.push(grant);
        }
    }
    profile.allow_exec = snapped;
    profile.grant_origins.extend(records);
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode snapshots readable symlink referents before launching untrusted code"
)]
fn snapshot_standard_read_aliases(profile: &mut SandboxProfile) -> anyhow::Result<()> {
    let built_in_boundary = profile.first_user_allow_read.min(profile.allow_read.len());
    let original = profile.allow_read.clone();
    let mut snapped = Vec::with_capacity(original.len());
    let mut records = Vec::new();
    for (index, grant) in original.into_iter().enumerate() {
        let Ok(resolved) = std::fs::canonicalize(&grant.path) else {
            snapped.push(grant);
            continue;
        };
        if resolved != grant.path
            && index < built_in_boundary
            && overlaps_denied_read(profile, &resolved)
        {
            return Err(protected_builtin_alias_error(
                "readable",
                &grant.path,
                &resolved,
            ));
        }
        if resolved != grant.path {
            records.push(GrantRecord {
                kind: GrantKind::AllowRead,
                value: resolved.to_string_lossy().into_owned(),
                origin: GrantOrigin::Runtime,
            });
            snapped.push(SandboxPath {
                path: resolved,
                kind: grant.kind,
            });
        } else {
            snapped.push(grant);
        }
    }
    profile.allow_read = snapped;
    profile.grant_origins.extend(records);
    Ok(())
}

fn protected_builtin_alias_error(kind: &str, lexical: &Path, resolved: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "built-in {kind} path '{}' resolves into protected read path '{}'; protected referents \
         cannot be inferred from a built-in grant",
        lexical.display(),
        resolved.display()
    )
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode validates built-in write symlinks against the approved authority \
              envelope"
)]
fn snapshot_standard_write_aliases(
    profile: &mut SandboxProfile,
    home: &Path,
    project_dir: &Path,
) -> anyhow::Result<()> {
    let built_in_boundary = profile
        .first_user_allow_write
        .min(profile.allow_write.len());
    let home_referent = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let project_referent =
        std::fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let cache_envelopes = [
        home_referent.join(".cache"),
        home_referent.join("Library/Caches"),
    ];
    let original = profile.allow_write.clone();
    let built_in_envelopes: Vec<SandboxPath> = original[..built_in_boundary]
        .iter()
        .map(|grant| SandboxPath {
            path: remap_to_referent(
                &grant.path,
                home,
                &home_referent,
                project_dir,
                &project_referent,
            ),
            kind: grant.kind,
        })
        .collect();
    let explicit_envelopes: Vec<SandboxPath> = original[built_in_boundary..]
        .iter()
        .filter_map(resolve_explicit_grant)
        .collect();
    let mut snapped = Vec::with_capacity(original.len());
    let mut records = Vec::new();

    for (index, grant) in original.into_iter().enumerate() {
        let Some(resolved) = resolve_existing_ancestor(&grant.path) else {
            snapped.push(grant);
            continue;
        };
        let expected = remap_to_referent(
            &grant.path,
            home,
            &home_referent,
            project_dir,
            &project_referent,
        );
        let approved = resolved == expected
            || resolved.starts_with(&project_referent)
            || cache_envelopes
                .iter()
                .any(|envelope| resolved.starts_with(envelope))
            || built_in_envelopes
                .iter()
                .any(|envelope| grant_covers(envelope, &resolved))
            || explicit_envelopes
                .iter()
                .any(|explicit| grant_covers(explicit, &resolved));
        if index < built_in_boundary && !approved {
            return Err(external_write_approval_error(&grant.path, &resolved));
        }

        if resolved != grant.path {
            records.push(GrantRecord {
                kind: GrantKind::AllowWrite,
                value: resolved.to_string_lossy().into_owned(),
                origin: GrantOrigin::Runtime,
            });
            snapped.push(SandboxPath {
                path: resolved,
                kind: grant.kind,
            });
        } else {
            snapped.push(grant);
        }
    }
    // The launcher opens only these canonical snapshots, never the mutable
    // lexical symlink that was validated above.
    profile.allow_write = snapped;
    profile.grant_origins.extend(records);
    Ok(())
}

fn remap_to_referent(
    path: &Path,
    home: &Path,
    home_referent: &Path,
    project_dir: &Path,
    project_referent: &Path,
) -> PathBuf {
    if let Ok(relative) = path.strip_prefix(project_dir) {
        project_referent.join(relative)
    } else if let Ok(relative) = path.strip_prefix(home) {
        home_referent.join(relative)
    } else {
        path.to_path_buf()
    }
}

fn resolve_explicit_grant(grant: &SandboxPath) -> Option<SandboxPath> {
    Some(SandboxPath {
        path: resolve_existing_ancestor(&grant.path)?,
        kind: grant.kind,
    })
}

fn explicit_write_covers(profile: &SandboxProfile, target: &Path) -> bool {
    let built_in_boundary = profile
        .first_user_allow_write
        .min(profile.allow_write.len());
    profile.allow_write[built_in_boundary..]
        .iter()
        .filter_map(resolve_explicit_grant)
        .any(|explicit| grant_covers(&explicit, target))
}

fn external_write_approval_error(lexical: &Path, resolved: &Path) -> anyhow::Error {
    let mut approval = resolved.display().to_string();
    if resolved.is_dir() && !approval.ends_with(std::path::MAIN_SEPARATOR) {
        approval.push(std::path::MAIN_SEPARATOR);
    }
    anyhow::anyhow!(
        "built-in writable path '{}' resolves outside the standard writable envelope to '{}'; \
         approve that target explicitly with --allow-write '{}'",
        lexical.display(),
        resolved.display(),
        approval
    )
}

fn grant_covers(grant: &SandboxPath, target: &Path) -> bool {
    match grant.kind {
        PathKind::Subpath => target.starts_with(&grant.path),
        PathKind::Literal => target == grant.path && !target.is_dir(),
        PathKind::Regex => false,
    }
}

#[cfg(target_os = "linux")]
fn workspace_read_aliases(
    profile: &SandboxProfile,
    project_dir: &Path,
) -> anyhow::Result<Vec<SandboxPath>> {
    workspace_read_aliases_with_limits(
        profile,
        project_dir,
        MAX_SOURCE_SYMLINK_SCAN_ENTRIES,
        MAX_SOURCE_SYMLINK_SCAN_DEPTH,
    )
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode snapshots source symlink referents before launching untrusted code"
)]
#[cfg(any(target_os = "linux", test))]
fn workspace_read_aliases_with_limits(
    profile: &SandboxProfile,
    project_dir: &Path,
    max_entries: usize,
    max_depth: usize,
) -> anyhow::Result<Vec<SandboxPath>> {
    const DERIVED_DIRECTORIES: &[&str] = &[
        ".git",
        ".gradle",
        ".venv",
        ".yarn",
        "_build",
        "build",
        "deps",
        "dist",
        "node_modules",
        "target",
        "venv",
    ];
    const MAGIC_ROOTS: &[&str] = &["/dev", "/proc", "/sys"];

    let project_referent =
        std::fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let mut pending = vec![(project_dir.to_path_buf(), 0_usize, false)];
    let mut visited_directories = BTreeSet::new();
    let mut resolved_paths = BTreeSet::new();
    let mut inspected_entries = 0_usize;
    while let Some((directory, depth, symlinks_only)) = pending.pop() {
        if depth > max_depth {
            anyhow::bail!(
                "source symlink discovery exceeds the maximum depth of {max_depth} below '{}'",
                project_dir.display()
            );
        }
        let directory = match std::fs::canonicalize(&directory) {
            Ok(directory) => directory,
            Err(error) => {
                warn!(path = %directory.display(), %error, "could not resolve source directory");
                continue;
            }
        };
        if !visited_directories.insert((directory.clone(), symlinks_only)) {
            continue;
        }
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                warn!(path = %directory.display(), %error, "could not inspect workspace symlinks");
                continue;
            }
        };
        for entry in entries {
            inspected_entries = inspected_entries.saturating_add(1);
            if inspected_entries > max_entries {
                anyhow::bail!(
                    "source symlink discovery exceeds the {max_entries}-entry scan budget below \
                     '{}'",
                    project_dir.display()
                );
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    warn!(path = %directory.display(), %error, "could not inspect workspace entry");
                    continue;
                }
            };
            let path = entry.path();
            let is_derived_directory = entry
                .file_name()
                .to_str()
                .is_some_and(|name| DERIVED_DIRECTORIES.contains(&name));
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    warn!(path = %path.display(), %error, "could not inspect workspace entry type");
                    continue;
                }
            };
            if file_type.is_symlink() {
                let Ok(resolved) = std::fs::canonicalize(&path) else {
                    continue;
                };
                if resolved.starts_with(&project_referent)
                    || MAGIC_ROOTS.iter().any(|root| resolved.starts_with(root))
                    || overlaps_denied_read(profile, &resolved)
                {
                    continue;
                }
                resolved_paths.insert(resolved.clone());
                if std::fs::metadata(&resolved).is_ok_and(|metadata| metadata.is_dir()) {
                    pending.push((resolved, depth + 1, is_derived_directory));
                }
            } else if file_type.is_dir() && !symlinks_only {
                pending.push((path, depth + 1, is_derived_directory));
            }
        }
    }

    Ok(resolved_paths
        .into_iter()
        .filter_map(|path| {
            let metadata = std::fs::metadata(&path).ok()?;
            Some(if metadata.is_dir() {
                SandboxPath::dir(path)
            } else {
                SandboxPath::file(path)
            })
        })
        .collect())
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode compares source symlink referents with protected paths before launch"
)]
fn overlaps_denied_read(profile: &SandboxProfile, candidate: &Path) -> bool {
    profile.deny_read.iter().any(|denied| {
        let denied = resolve_existing_ancestor(&denied.path).unwrap_or_else(|| denied.path.clone());
        candidate.starts_with(&denied) || denied.starts_with(candidate)
    })
}

#[allow(
    clippy::disallowed_methods,
    reason = "standard mode resolves a protected path's existing ancestor before comparison"
)]
fn resolve_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut existing = path;
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(existing) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Some(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(existing.file_name()?.to_os_string());
                existing = existing.parent()?;
            }
            Err(_) => return None,
        }
    }
}

fn command_is(command: &[String], expected: &str) -> bool {
    Path::new(command.first().map_or("", String::as_str))
        .file_name()
        .is_some_and(|name| name == expected)
}

#[allow(
    clippy::disallowed_methods,
    reason = "policy preparation resolves Cargo's selected manifest before comparing its workspace"
)]
fn reject_project_relocation(command: &[String], project_dir: &Path) -> anyhow::Result<()> {
    let Some(option) = project_relocation_option(command) else {
        if command_is(command, "cargo")
            && let Some(manifest) = command_option_value(command, "--manifest-path")
        {
            let manifest = PathBuf::from(manifest);
            let manifest = if manifest.is_absolute() {
                manifest
            } else {
                project_dir.join(manifest)
            };
            let project =
                std::fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
            let resolved = resolve_existing_ancestor(&manifest).unwrap_or(manifest);
            if !resolved.starts_with(&project) {
                anyhow::bail!(
                    "Cargo manifest '{}' resolves outside the sandbox workspace '{}'; change \
                     directory before invoking sbe",
                    resolved.display(),
                    project.display()
                );
            }
        }
        return Ok(());
    };
    anyhow::bail!(
        "project relocation option '{option}' is unsupported because sandbox grants are anchored \
         to the current directory; change directory before invoking sbe"
    )
}

fn project_relocation_option(command: &[String]) -> Option<&str> {
    let program = Path::new(command.first()?.as_str())
        .file_name()
        .and_then(|name| name.to_str())?;
    let options: &[&str] = match program {
        "cargo" => &["-C"],
        "npm" => &["--prefix"],
        "yarn" | "bun" => &["--cwd"],
        "pnpm" => &["--dir", "-C"],
        "uv" => &["--directory", "--project"],
        "poetry" | "pdm" => &["--directory", "--project", "-C", "-P", "-p"],
        "gradle" | "gradlew" => &["--project-dir", "-p"],
        "mvn" | "mvnw" => &["--file", "-f"],
        _ => return None,
    };
    command
        .iter()
        .skip(1)
        .take_while(|argument| argument.as_str() != "--")
        .filter(|argument| {
            !matches!(program, "mvn" | "mvnw")
                || !["-fae", "-ff", "-fn"].contains(&argument.as_str())
        })
        .find_map(|argument| {
            options.iter().copied().find(|option| {
                argument == *option
                    || argument.strip_prefix(*option).is_some_and(|suffix| {
                        suffix.starts_with('=') || (!option.starts_with("--") && !suffix.is_empty())
                    })
            })
        })
}

fn command_has_flag(command: &[String], flags: &[&str]) -> bool {
    command
        .iter()
        .skip(1)
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| flags.contains(&argument.as_str()))
}

fn command_option_value<'a>(command: &'a [String], option: &str) -> Option<&'a str> {
    let mut arguments = command
        .iter()
        .skip(1)
        .take_while(|argument| argument.as_str() != "--");
    while let Some(argument) = arguments.next() {
        if argument == option {
            return arguments.next().map(String::as_str);
        }
        if let Some(value) = argument
            .strip_prefix(option)
            .and_then(|suffix| suffix.strip_prefix('='))
        {
            return Some(value);
        }
    }
    None
}

fn command_aliased_option_value<'a>(
    command: &'a [String],
    long: &str,
    short: &str,
) -> Option<&'a str> {
    let mut arguments = command
        .iter()
        .skip(1)
        .take_while(|argument| argument.as_str() != "--");
    let mut selected = None;
    while let Some(argument) = arguments.next() {
        if argument == long || argument == short {
            selected = arguments.next().map(String::as_str);
            continue;
        }
        if let Some(value) = argument
            .strip_prefix(long)
            .and_then(|suffix| suffix.strip_prefix('='))
        {
            selected = Some(value);
            continue;
        }
        if let Some(suffix) = argument.strip_prefix(short) {
            selected = Some(suffix.strip_prefix('=').unwrap_or(suffix));
        }
    }
    selected.filter(|value| !value.is_empty())
}

fn cargo_config_target_dir(command: &[String]) -> anyhow::Result<Option<PathBuf>> {
    if !command_is(command, "cargo") {
        return Ok(None);
    }
    let mut arguments = command
        .iter()
        .skip(1)
        .take_while(|argument| argument.as_str() != "--");
    let mut selected = None;
    while let Some(argument) = arguments.next() {
        let config = if argument == "--config" {
            arguments
                .next()
                .map(String::as_str)
                .context("cargo --config requires a value")?
        } else if let Some(value) = argument.strip_prefix("--config=") {
            value
        } else {
            continue;
        };
        let Some((key, value)) = config.split_once('=') else {
            anyhow::bail!(
                "cargo --config file paths cannot be inspected safely for build.target-dir or \
                 install.root; use --target-dir, --root, or a direct KEY='path' override"
            );
        };
        let key = key.trim();
        if key == "build.target-dir" {
            selected = Some(parse_cargo_config_path(value, key, "--target-dir")?);
        } else if key == "build" || key.contains("target-dir") {
            anyhow::bail!(
                "cargo --config target-directory override '{key}' is unsupported; use \
                 --target-dir or a direct --config build.target-dir='path' override"
            );
        }
    }
    Ok(selected)
}

fn cargo_config_install_root(command: &[String]) -> anyhow::Result<Option<PathBuf>> {
    let mut arguments = command
        .iter()
        .skip(1)
        .take_while(|argument| argument.as_str() != "--");
    let mut selected = None;
    while let Some(argument) = arguments.next() {
        let config = if argument == "--config" {
            arguments
                .next()
                .map(String::as_str)
                .context("cargo --config requires a value")?
        } else if let Some(value) = argument.strip_prefix("--config=") {
            value
        } else {
            continue;
        };
        let Some((key, value)) = config.split_once('=') else {
            anyhow::bail!(
                "cargo --config file paths cannot be inspected safely for install.root; use \
                 --root or a direct --config install.root='path' override"
            );
        };
        let key = key.trim();
        if key == "install.root" {
            selected = Some(parse_cargo_config_path(value, key, "--root")?);
        } else if key == "include" {
            anyhow::bail!(
                "cargo --config include files cannot be inspected safely for install.root; use \
                 --root to select the install destination explicitly"
            );
        } else if key == "install" || key.starts_with("install.root.") {
            anyhow::bail!(
                "cargo --config install-root override '{key}' is unsupported; use --root or a \
                 direct --config install.root='path' override"
            );
        }
    }
    Ok(selected)
}

fn parse_cargo_config_path(
    value: &str,
    key: &str,
    preferred_option: &str,
) -> anyhow::Result<PathBuf> {
    let value = value.trim();
    let path = if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        let path = &value[1..value.len() - 1];
        if path.contains('\'') {
            anyhow::bail!("cargo {key} contains an unsupported quoted path");
        }
        path
    } else if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let path = &value[1..value.len() - 1];
        if path.contains('\\') || path.contains('"') {
            anyhow::bail!("cargo {key} contains unsupported TOML escapes");
        }
        path
    } else {
        anyhow::bail!(
            "cargo {key} must be a simple quoted path; use {preferred_option} for complex values"
        );
    };
    if path.is_empty() || path.chars().any(char::is_control) {
        anyhow::bail!("cargo {key} must be a non-empty path without control characters");
    }
    Ok(PathBuf::from(path))
}

fn reject_implicit_cargo_install_root(project_dir: &Path, cargo_home: &Path) -> anyhow::Result<()> {
    for directory in project_dir.ancestors() {
        reject_cargo_install_root_in_config(&directory.join(".cargo"))?;
    }
    reject_cargo_install_root_in_config(cargo_home)
}

fn reject_cargo_install_root_in_config(config_dir: &Path) -> anyhow::Result<()> {
    for name in ["config", "config.toml"] {
        let path = config_dir.join(name);
        let Some(contents) = read_bounded_cargo_config(&path)? else {
            continue;
        };
        let contents = std::str::from_utf8(&contents)
            .with_context(|| format!("Cargo config is not UTF-8: {}", path.display()))?;
        if cargo_config_may_define_install_root(contents) {
            anyhow::bail!(
                "Cargo config '{}' selects or may include install.root, which SBE cannot safely \
                 reproduce; use an explicit cargo install --root path",
                path.display()
            );
        }
        // Cargo gives the legacy extensionless spelling precedence when both exist.
        break;
    }
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "Cargo itself follows config symlinks; policy preparation resolves the selected file \
              before applying the bounded no-follow reader"
)]
fn read_bounded_cargo_config(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    let resolved = match std::fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("resolve Cargo config: {}", path.display()));
        }
    };
    read_bounded_project_file(&resolved)
}

fn cargo_config_may_define_install_root(contents: &str) -> bool {
    let mut in_install_table = false;
    let mut at_root = true;
    for line in contents.lines() {
        let line = strip_toml_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let table = line.trim_matches(['[', ']']).trim();
            in_install_table = simple_toml_key_path(table).is_some_and(|path| path == ["install"]);
            at_root = false;
            continue;
        }
        let Some((key, _value)) = line.split_once('=') else {
            continue;
        };
        let Some(key) = simple_toml_key_path(key.trim()) else {
            continue;
        };
        if key == ["install", "root"]
            || (in_install_table && key == ["root"])
            || (!in_install_table && key == ["install"])
            || (at_root && key == ["include"])
        {
            return true;
        }
    }
    false
}

fn simple_toml_key_path(key: &str) -> Option<Vec<&str>> {
    key.split('.')
        .map(|component| {
            let component = component.trim();
            if component.len() >= 2
                && ((component.starts_with('\'') && component.ends_with('\''))
                    || (component.starts_with('"') && component.ends_with('"')))
            {
                Some(&component[1..component.len() - 1])
            } else if !component.is_empty()
                && component
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
            {
                Some(component)
            } else {
                None
            }
        })
        .collect()
}

fn strip_toml_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match (quote, character) {
            (Some('"'), '\\') => escaped = true,
            (Some(active), current) if active == current => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, '#') => return &line[..index],
            _ => {}
        }
    }
    line
}

fn command_system_property<'a>(command: &'a [String], name: &str) -> Option<&'a str> {
    let mut arguments = command
        .iter()
        .skip(1)
        .take_while(|argument| argument.as_str() != "--");
    let mut selected = None;
    while let Some(argument) = arguments.next() {
        let property = if argument == "-D" || argument == "--system-prop" {
            arguments.next().map(String::as_str)
        } else {
            argument
                .strip_prefix("-D")
                .or_else(|| argument.strip_prefix("--system-prop="))
        };
        if let Some(value) = property.and_then(|property| {
            property
                .strip_prefix(name)
                .and_then(|suffix| suffix.strip_prefix('='))
        }) {
            selected = Some(value);
        }
    }
    selected
}

fn command_maven_property<'a>(command: &'a [String], name: &str) -> Option<&'a str> {
    let mut arguments = command
        .iter()
        .skip(1)
        .take_while(|argument| argument.as_str() != "--");
    let mut selected = None;
    while let Some(argument) = arguments.next() {
        let property = if argument == "-D" || argument == "--define" {
            arguments.next().map(String::as_str)
        } else {
            argument
                .strip_prefix("-D")
                .or_else(|| argument.strip_prefix("--define="))
        };
        if let Some(value) = property.and_then(|property| {
            property
                .strip_prefix(name)
                .and_then(|suffix| suffix.strip_prefix('='))
        }) {
            selected = Some(value);
        }
    }
    selected
}

#[cfg(target_os = "linux")]
fn command_option_equals(command: &[String], option: &str, expected: &str) -> bool {
    let mut arguments = command
        .iter()
        .skip(1)
        .take_while(|argument| argument.as_str() != "--")
        .peekable();
    while let Some(argument) = arguments.next() {
        if argument
            .strip_prefix(option)
            .and_then(|suffix| suffix.strip_prefix('='))
            .is_some_and(|value| value.eq_ignore_ascii_case(expected))
        {
            return true;
        }
        if argument == option
            && arguments
                .peek()
                .is_some_and(|value| value.eq_ignore_ascii_case(expected))
        {
            return true;
        }
    }
    false
}

fn configure_node_workspace(
    profile: &mut SandboxProfile,
    command: &[String],
    project_dir: &Path,
) -> anyhow::Result<()> {
    let program = command
        .first()
        .and_then(|program| Path::new(program).file_name())
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let manager = match program {
        "npm" | "npx" => "npm",
        "yarn" => "yarn",
        "pnpm" => "pnpm",
        "bun" => "bun",
        _ => return Ok(()),
    };
    let workspace_root = discover_node_workspace_root(project_dir, manager)?;
    if workspace_root == project_dir {
        return Ok(());
    }

    let mut grants = vec![SandboxPath::dir(workspace_root.join("node_modules"))];
    match manager {
        "npm" => grants.push(SandboxPath::file(workspace_root.join("package-lock.json"))),
        "yarn" => grants.extend([
            SandboxPath::file(workspace_root.join("yarn.lock")),
            SandboxPath::dir(workspace_root.join(".yarn")),
            SandboxPath::file(workspace_root.join(".pnp.cjs")),
            SandboxPath::file(workspace_root.join(".pnp.loader.mjs")),
        ]),
        "pnpm" => grants.push(SandboxPath::file(workspace_root.join("pnpm-lock.yaml"))),
        "bun" => {
            grants.push(SandboxPath::file(workspace_root.join("bun.lock")));
            if command_has_flag(command, &["--yarn"]) {
                grants.push(SandboxPath::file(workspace_root.join("yarn.lock")));
            }
        }
        _ => return Ok(()),
    }

    let mut insertion = profile
        .first_user_allow_write
        .min(profile.allow_write.len());
    for grant in grants {
        if profile
            .allow_write
            .iter()
            .any(|existing| existing == &grant)
        {
            continue;
        }
        profile.grant_origins.push(GrantRecord {
            kind: GrantKind::AllowWrite,
            value: grant.path.to_string_lossy().into_owned(),
            origin: GrantOrigin::BuiltIn,
        });
        profile.allow_write.insert(insertion, grant);
        insertion += 1;
    }
    profile.first_user_allow_write = insertion;
    Ok(())
}

/// Return the package manager's top-level subcommand. Options (and the values
/// of known value-taking global options) are skipped so an option value or a
/// nested command cannot accidentally select a write policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParsedTopLevel<'a> {
    Command(&'a str),
    NoCommand,
    Ambiguous,
}

impl ParsedTopLevel<'_> {
    fn is_command(self, candidates: &[&str]) -> bool {
        matches!(self, Self::Command(command) if candidates.contains(&command))
    }
}

fn top_level_subcommand(command: &[String]) -> ParsedTopLevel<'_> {
    let Some(program) = command
        .first()
        .and_then(|program| Path::new(program).file_name())
    else {
        return ParsedTopLevel::NoCommand;
    };
    let program = program.to_str().unwrap_or_default();
    let mut arguments = command.iter().skip(1).peekable();
    while let Some(argument) = arguments.next() {
        let argument = argument.as_str();
        if argument == "--" {
            return ParsedTopLevel::NoCommand;
        }
        if program == "cargo" && argument.starts_with('+') {
            continue;
        }
        if !argument.starts_with('-') || argument == "-" {
            return ParsedTopLevel::Command(argument);
        }
        if option_takes_value(program, argument) {
            if !option_has_attached_value(argument) {
                arguments.next();
            }
            continue;
        }
        if option_is_known_boolean(program, argument) {
            continue;
        }
        // Unknown options are deliberately ambiguous. Guessing that they are
        // boolean could mistake their value for a mutating subcommand and
        // create a file the user never requested.
        return ParsedTopLevel::Ambiguous;
    }
    ParsedTopLevel::NoCommand
}

fn option_takes_value(program: &str, option: &str) -> bool {
    let option = option.split_once('=').map_or(option, |(name, _)| name);
    let option = if program == "cargo" && option.len() > 2 {
        option
            .get(..2)
            .filter(|prefix| matches!(*prefix, "-C" | "-Z"))
            .unwrap_or(option)
    } else {
        option
    };
    match program {
        "cargo" => matches!(
            option,
            "--color" | "--config" | "--explain" | "--target-dir" | "-C" | "-Z"
        ),
        "npm" => matches!(
            option,
            "--cache"
                | "--location"
                | "--loglevel"
                | "--prefix"
                | "--registry"
                | "--userconfig"
                | "--workspace"
        ),
        "yarn" => matches!(
            option,
            "--cache-folder"
                | "--cwd"
                | "--modules-folder"
                | "--mutex"
                | "--network-concurrency"
                | "--network-timeout"
                | "--registry"
                | "--use-yarnrc"
        ),
        "pnpm" => matches!(
            option,
            "--cache-dir"
                | "--config-dir"
                | "--dir"
                | "--global-bin-dir"
                | "--global-dir"
                | "--state-dir"
                | "--store-dir"
                | "--virtual-store-dir"
        ),
        "uv" => matches!(
            option,
            "--color" | "--config-file" | "--directory" | "--project" | "--python"
        ),
        "poetry" | "pdm" => {
            matches!(option, "--directory" | "--project" | "-C" | "-P" | "-p")
        }
        _ => false,
    }
}

fn option_has_attached_value(option: &str) -> bool {
    option.contains('=')
        || (option.len() > 2 && (option.starts_with("-C") || option.starts_with("-Z")))
}

fn option_is_known_boolean(program: &str, option: &str) -> bool {
    match program {
        "cargo" => matches!(
            option,
            "--frozen"
                | "--help"
                | "--list"
                | "--locked"
                | "--offline"
                | "--quiet"
                | "--verbose"
                | "--version"
                | "-V"
                | "-h"
                | "-q"
                | "-v"
                | "-vv"
        ),
        "npm" | "pnpm" | "bun" => matches!(
            option,
            "--global"
                | "--help"
                | "--json"
                | "--silent"
                | "--version"
                | "--workspaces"
                | "-g"
                | "-h"
                | "-v"
        ),
        "yarn" => matches!(
            option,
            "--help"
                | "--immutable"
                | "--immutable-cache"
                | "--inline-builds"
                | "--json"
                | "--silent"
                | "--version"
                | "-h"
                | "-v"
        ),
        "uv" | "poetry" | "pdm" => matches!(
            option,
            "--help" | "--no-ansi" | "--quiet" | "--verbose" | "--version" | "-h" | "-q" | "-v"
        ),
        _ => false,
    }
}

fn cargo_executes_target(command: &[String]) -> bool {
    command_is(command, "cargo")
        && top_level_subcommand(command).is_command(&["bench", "nextest", "run", "test", "r", "t"])
}

fn cargo_uses_persistent_target(command: &[String]) -> bool {
    command_is(command, "cargo")
        && top_level_subcommand(command)
            .is_command(&["build", "check", "doc", "install", "rustc", "b", "c", "d"])
}

/// Installed dependency trees are mutable during package-manager operations,
/// but commands that explicitly run project tools need the opposite side of
/// the W^X boundary. Replace only matching built-in write grants with
/// read/execute grants. User-supplied write grants remain intact and will
/// still trip the persistent W^X lint instead of being silently weakened.
fn enable_existing_dependency_execution(profile: &mut SandboxProfile, command: &[String]) {
    let root_names: &[&str] = match profile.name.as_str() {
        "node" if node_command_executes_dependencies(command) => &["node_modules"],
        "python" if python_command_executes_environment(command) => &[".venv", "venv"],
        _ => return,
    };

    replace_builtin_write_roots_with_execute(profile, root_names);
}

fn replace_builtin_write_roots_with_execute(profile: &mut SandboxProfile, root_names: &[&str]) {
    if root_names.is_empty() {
        return;
    }

    let built_in_boundary = profile
        .first_user_allow_write
        .min(profile.allow_write.len());
    let mut dependency_roots = Vec::new();
    let mut retained = Vec::with_capacity(profile.allow_write.len());
    for (index, grant) in profile.allow_write.drain(..).enumerate() {
        if index < built_in_boundary
            && grant
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| root_names.contains(&name))
        {
            dependency_roots.push(grant.path);
        } else {
            retained.push(grant);
        }
    }
    profile.allow_write = retained;
    profile.first_user_allow_write = built_in_boundary.saturating_sub(dependency_roots.len());

    profile.grant_origins.retain(|record| {
        record.kind != GrantKind::AllowWrite
            || record.origin != GrantOrigin::BuiltIn
            || !dependency_roots
                .iter()
                .any(|root| record.value == root.to_string_lossy())
    });

    for root in dependency_roots {
        // A higher-precedence deny must continue to win. Landlock cannot
        // subtract a denied child from a directory execute rule, so skip the
        // complete runtime grant on any overlap.
        if profile
            .deny_exec
            .iter()
            .any(|denied| paths_overlap(&root, &denied.path))
            || profile
                .allow_exec
                .iter()
                .any(|allowed| allowed.path == root)
        {
            continue;
        }
        profile.allow_exec.push(SandboxPath::dir(root.clone()));
        profile.grant_origins.push(GrantRecord {
            kind: GrantKind::AllowExec,
            value: root.to_string_lossy().into_owned(),
            origin: GrantOrigin::Runtime,
        });
    }
}

fn python_command_executes_environment(command: &[String]) -> bool {
    let program = Path::new(command.first().map_or("", String::as_str))
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let subcommand = top_level_subcommand(command);
    match program {
        "pip" | "pip3" | "virtualenv" => false,
        "uv" => subcommand.is_command(&["run"]),
        "poetry" => subcommand.is_command(&["run", "shell"]),
        "pdm" | "rye" => subcommand.is_command(&["run"]),
        "python" | "python3"
            if command.windows(2).any(|arguments| {
                arguments[0] == "-m" && matches!(arguments[1].as_str(), "pip" | "venv")
            }) =>
        {
            false
        }
        // Direct virtualenv entry points such as `.venv/bin/pytest`, an
        // activated `pytest` found through PATH, and ordinary Python scripts
        // all execute an already-installed environment rather than mutate it.
        _ => true,
    }
}

fn node_command_executes_dependencies(command: &[String]) -> bool {
    let subcommand = top_level_subcommand(command);
    if command_is(command, "npx") {
        return !matches!(
            subcommand,
            ParsedTopLevel::NoCommand | ParsedTopLevel::Ambiguous
        );
    }
    if command_is(command, "npm") {
        return subcommand.is_command(&[
            "exec",
            "explore",
            "restart",
            "run",
            "run-script",
            "start",
            "stop",
            "t",
            "test",
            "tst",
            "x",
        ]);
    }
    if command_is(command, "pnpm") {
        return subcommand.is_command(&["exec", "restart", "run", "start", "stop", "test"]);
    }
    if command_is(command, "bun") {
        return subcommand.is_command(&["exec", "restart", "run", "start", "stop", "test", "x"]);
    }
    command_is(command, "yarn")
        && subcommand.is_command(&["exec", "node", "restart", "run", "start", "stop", "test"])
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

/// Atomically create or verify a direct child directory without following a
/// final-component symlink. The parent descriptor fixes the target directory
/// even if another process renames a path component concurrently.
fn ensure_child_directory(parent: &Path, name: &std::ffi::CStr) -> anyhow::Result<()> {
    let parent =
        CString::new(parent.as_os_str().as_bytes()).context("project directory contains NUL")?;
    // SAFETY: both C strings are NUL-terminated and remain alive for each
    // syscall; successful descriptors are immediately owned and closed.
    let parent_fd = unsafe {
        libc::open(
            parent.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if parent_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open project directory safely");
    }
    let parent_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(parent_fd) };
    let created = unsafe { libc::mkdirat(parent_fd.as_raw_fd(), name.as_ptr(), 0o700) };
    if created < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).context("create dedicated build output directory");
        }
    }
    let child_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if child_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("build output must be a real directory, not a symlink");
    }
    drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(child_fd) });
    Ok(())
}

/// Landlock can grant writes to an existing file inode, but creating one
/// requires directory-wide `MakeReg`. Pre-create only the built-in outputs
/// selected for the invoked package-manager operation plus user-requested
/// literal outputs. This avoids creating mutually exclusive files as a side
/// effect of an unrelated or read-only command.
#[cfg(target_os = "linux")]
fn ensure_literal_write_targets(
    profile: &SandboxProfile,
    command: &[String],
    project_dir: &Path,
) -> anyhow::Result<()> {
    use std::os::fd::OwnedFd;

    use sbe_core::config::PathKind;

    reject_project_relocation(command, project_dir)?;
    let program = command
        .first()
        .and_then(|program| Path::new(program).file_name())
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let refuses_lockfile_creation = command_has_flag(
        command,
        &["--frozen", "--frozen-lockfile", "--immutable", "--locked"],
    ) || (program == "bun"
        && command_has_flag(command, &["--no-save"]))
        || (program == "npm"
            && (command_has_flag(command, &["--no-package-lock"])
                || command_option_equals(command, "--package-lock", "false")));
    let manager_is_informational = matches!(program, "yarn" | "bun")
        && command_has_flag(command, &["--help", "--version", "-h", "-v"]);
    let subcommand = top_level_subcommand(command);
    let built_in_outputs = if refuses_lockfile_creation || manager_is_informational {
        Vec::new()
    } else {
        match program {
            "cargo"
                if subcommand.is_command(&[
                    "bench",
                    "build",
                    "check",
                    "doc",
                    "fetch",
                    "generate-lockfile",
                    "metadata",
                    "run",
                    "test",
                    "tree",
                    "update",
                    "b",
                    "c",
                    "d",
                    "r",
                    "t",
                ]) =>
            {
                vec![project_dir.join("Cargo.lock")]
            }
            "npm"
                if subcommand.is_command(&[
                    "add",
                    "dedupe",
                    "i",
                    "install",
                    "r",
                    "remove",
                    "rm",
                    "un",
                    "uninstall",
                    "unlink",
                    "up",
                    "update",
                ]) =>
            {
                vec![
                    selected_node_output_root(profile, project_dir, "package-lock.json")
                        .join("package-lock.json"),
                ]
            }
            "yarn"
                if subcommand == ParsedTopLevel::NoCommand
                    || subcommand.is_command(&["add", "dedupe", "install", "remove", "up"]) =>
            {
                let output_root = selected_node_output_root(profile, project_dir, "yarn.lock");
                let (uses_pnp, uses_esm_loader) = yarn_pnp_configuration(&output_root)?;
                let mut outputs = vec![output_root.join("yarn.lock")];
                if uses_pnp {
                    outputs.push(output_root.join(".pnp.cjs"));
                }
                if uses_esm_loader {
                    outputs.push(output_root.join(".pnp.loader.mjs"));
                }
                outputs
            }
            "pnpm"
                if subcommand.is_command(&[
                    "add",
                    "dedupe",
                    "i",
                    "import",
                    "install",
                    "remove",
                    "rm",
                    "uninstall",
                    "up",
                    "update",
                ]) =>
            {
                vec![
                    selected_node_output_root(profile, project_dir, "pnpm-lock.yaml")
                        .join("pnpm-lock.yaml"),
                ]
            }
            "bun"
                if subcommand.is_command(&[
                    "add",
                    "i",
                    "install",
                    "remove",
                    "rm",
                    "uninstall",
                    "update",
                ]) =>
            {
                let output_root = selected_node_output_root(profile, project_dir, "bun.lock");
                let mut outputs = vec![output_root.join("bun.lock")];
                if command_has_flag(command, &["--yarn"]) {
                    outputs.push(output_root.join("yarn.lock"));
                }
                outputs
            }
            "uv" if subcommand.is_command(&["add", "lock", "remove", "run", "sync", "tree"]) => {
                vec![project_dir.join("uv.lock")]
            }
            "poetry" if subcommand.is_command(&["add", "install", "lock", "remove", "update"]) => {
                vec![project_dir.join("poetry.lock")]
            }
            "pdm"
                if subcommand
                    .is_command(&["add", "install", "lock", "remove", "run", "sync", "update"]) =>
            {
                vec![project_dir.join("pdm.lock")]
            }
            "mix"
                if subcommand.is_command(&[
                    "deps.get",
                    "deps.update",
                    "local.hex",
                    "local.rebar",
                ]) =>
            {
                vec![project_dir.join("mix.lock")]
            }
            _ => Vec::new(),
        }
    };

    for (index, target) in profile.allow_write.iter().enumerate() {
        if target.kind != PathKind::Literal {
            continue;
        }
        if index < profile.first_user_allow_write && !built_in_outputs.contains(&target.path) {
            continue;
        }
        let parent = target
            .path
            .parent()
            .context("literal write target has no parent directory")?;
        let name = target
            .path
            .file_name()
            .context("literal write target has no file name")?;
        let parent_fd = open_directory_no_symlinks(parent)?;
        let name = CString::new(name.as_bytes()).context("literal write target contains NUL")?;
        let flags = libc::O_WRONLY
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK;
        let fd = unsafe { libc::openat(parent_fd.as_raw_fd(), name.as_ptr(), flags, 0o666) };
        let fd = if fd >= 0 {
            fd
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error).with_context(|| {
                    format!(
                        "create literal write target safely: {}",
                        target.path.display()
                    )
                });
            }
            let existing_flags =
                libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
            let existing =
                unsafe { libc::openat(parent_fd.as_raw_fd(), name.as_ptr(), existing_flags) };
            if existing < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "open literal write target safely: {}",
                        target.path.display()
                    )
                });
            }
            existing
        };
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut metadata) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("inspect literal write target: {}", target.path.display())
            });
        }
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
            anyhow::bail!(
                "literal write target is not a regular file: {}",
                target.path.display()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn selected_node_output_root(
    profile: &SandboxProfile,
    project_dir: &Path,
    lockfile: &str,
) -> PathBuf {
    let mut candidates: Vec<PathBuf> = profile.allow_write[..profile
        .first_user_allow_write
        .min(profile.allow_write.len())]
        .iter()
        .filter(|target| target.kind == sbe_core::config::PathKind::Literal)
        .filter(|target| target.path.file_name().is_some_and(|name| name == lockfile))
        .filter_map(|target| target.path.parent().map(Path::to_path_buf))
        .filter(|root| project_dir.starts_with(root))
        .collect();
    candidates.sort_by_key(|root| std::cmp::Reverse(root.components().count()));
    candidates.dedup();

    for root in candidates {
        if root != project_dir {
            return root;
        }
    }
    project_dir.to_path_buf()
}

fn discover_node_workspace_root(project_dir: &Path, program: &str) -> anyhow::Result<PathBuf> {
    if !matches!(program, "npm" | "yarn" | "pnpm" | "bun") {
        return Ok(project_dir.to_path_buf());
    }
    let git_boundary = project_git_boundary(project_dir)?;
    if git_boundary.as_deref() == Some(project_dir) {
        return Ok(project_dir.to_path_buf());
    }
    let mut candidate = project_dir.parent();
    while let Some(root) = candidate {
        if node_workspace_contains(root, project_dir, program)? {
            return Ok(root.to_path_buf());
        }
        if git_boundary.as_deref() == Some(root) {
            break;
        }
        candidate = root.parent();
    }
    Ok(project_dir.to_path_buf())
}

#[allow(
    clippy::disallowed_methods,
    reason = "workspace discovery inspects .git without following a project-controlled symlink"
)]
fn project_git_boundary(project_dir: &Path) -> anyhow::Result<Option<PathBuf>> {
    for ancestor in project_dir.ancestors() {
        match std::fs::symlink_metadata(ancestor.join(".git")) {
            Ok(_) => return Ok(Some(ancestor.to_path_buf())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect Git workspace boundary: {}", ancestor.display())
                });
            }
        }
    }
    Ok(None)
}

fn node_workspace_contains(root: &Path, project_dir: &Path, program: &str) -> anyhow::Result<bool> {
    let relative = project_dir
        .strip_prefix(root)
        .context("Node workspace candidate is not an ancestor of the project")?;
    if relative.as_os_str().is_empty() {
        return Ok(true);
    }

    let mut patterns = Vec::new();
    if program != "pnpm"
        && let Some(contents) = read_bounded_project_file(&root.join("package.json"))?
    {
        let package: serde_json::Value = serde_json::from_slice(&contents).with_context(|| {
            format!("parse workspace metadata: {}/package.json", root.display())
        })?;
        if let Some(workspaces) = package.get("workspaces") {
            let values = match workspaces {
                serde_json::Value::Array(values) => values,
                serde_json::Value::Object(mapping) => mapping
                    .get("packages")
                    .and_then(serde_json::Value::as_array)
                    .context("package.json workspaces.packages must be an array")?,
                _ => anyhow::bail!("package.json workspaces must be an array or mapping"),
            };
            for value in values {
                patterns.push(
                    value
                        .as_str()
                        .context("package.json workspace pattern must be a string")?
                        .to_owned(),
                );
            }
        }
    }

    if program == "pnpm"
        && let Some(contents) = read_bounded_project_file(&root.join("pnpm-workspace.yaml"))?
    {
        let workspace: serde_yaml::Value = serde_yaml::from_slice(&contents)
            .context("parse pnpm-workspace.yaml for output policy")?;
        let values = workspace
            .as_mapping()
            .and_then(|mapping| mapping.get(serde_yaml::Value::String("packages".to_owned())))
            .and_then(serde_yaml::Value::as_sequence)
            .context("pnpm-workspace.yaml packages must be an array")?;
        for value in values {
            patterns.push(
                value
                    .as_str()
                    .context("pnpm workspace pattern must be a string")?
                    .to_owned(),
            );
        }
    }

    let relative = relative
        .to_str()
        .context("Node workspace path is not valid UTF-8")?;
    let mut included = false;
    for pattern in patterns {
        let (exclude, pattern) = pattern
            .strip_prefix('!')
            .map_or((false, pattern.as_str()), |pattern| (true, pattern));
        if workspace_glob_matches_prefix(pattern.trim_matches('/'), relative) {
            included = !exclude;
        }
    }
    Ok(included)
}

fn workspace_glob_matches_prefix(pattern: &str, path: &str) -> bool {
    fn matches(pattern: &[&str], path: &[&str]) -> bool {
        let Some((component, remaining_pattern)) = pattern.split_first() else {
            return true;
        };
        if *component == "**" {
            return matches(remaining_pattern, path)
                || path
                    .split_first()
                    .is_some_and(|(_, remaining_path)| matches(pattern, remaining_path));
        }
        path.split_first()
            .is_some_and(|(path_component, remaining_path)| {
                workspace_component_matches(component, path_component)
                    && matches(remaining_pattern, remaining_path)
            })
    }

    let pattern: Vec<&str> = pattern.split('/').filter(|part| !part.is_empty()).collect();
    let path: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    !pattern.is_empty() && matches(&pattern, &path)
}

fn workspace_component_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut matched = vec![false; value.len() + 1];
    matched[0] = true;
    for token in pattern {
        let mut next = vec![false; value.len() + 1];
        match token {
            b'*' => {
                next[0] = matched[0];
                for index in 1..=value.len() {
                    next[index] = matched[index] || next[index - 1];
                }
            }
            b'?' => {
                next[1..].copy_from_slice(&matched[..value.len()]);
            }
            literal => {
                for index in 1..=value.len() {
                    next[index] = matched[index - 1] && value[index - 1] == *literal;
                }
            }
        }
        matched = next;
    }
    matched[value.len()]
}

/// Determine which Yarn linker outputs are required without executing Yarn or
/// following project-controlled symlinks. Yarn Berry uses PnP by default when
/// a `.yarnrc.yml` is present; `packageManager: yarn@2+` is the other explicit
/// modern-Yarn signal. Classic/unspecified Yarn remains lockfile-only so SBE
/// does not create an unrelated empty `.pnp.cjs`.
#[cfg(target_os = "linux")]
fn yarn_pnp_configuration(project_dir: &Path) -> anyhow::Result<(bool, bool)> {
    if let Some(contents) = read_bounded_project_file(&project_dir.join(".yarnrc.yml"))? {
        let config: serde_yaml::Value =
            serde_yaml::from_slice(&contents).context("parse .yarnrc.yml for output policy")?;
        let mapping = if config.is_null() {
            None
        } else {
            Some(
                config
                    .as_mapping()
                    .context(".yarnrc.yml must contain a mapping")?,
            )
        };
        let linker = mapping
            .and_then(|mapping| mapping.get(serde_yaml::Value::String("nodeLinker".to_owned())))
            .and_then(serde_yaml::Value::as_str);
        let uses_pnp = match linker {
            None | Some("pnp") => true,
            Some("node-modules" | "pnpm") => false,
            Some(other) => anyhow::bail!("unsupported Yarn nodeLinker value '{other}'"),
        };
        let uses_esm_loader = uses_pnp
            && mapping
                .and_then(|mapping| {
                    mapping.get(serde_yaml::Value::String("pnpEnableEsmLoader".to_owned()))
                })
                .and_then(serde_yaml::Value::as_bool)
                .unwrap_or(false);
        return Ok((uses_pnp, uses_esm_loader));
    }

    let Some(contents) = read_bounded_project_file(&project_dir.join("package.json"))? else {
        return Ok((false, false));
    };
    let package: serde_json::Value =
        serde_json::from_slice(&contents).context("parse package.json for Yarn output policy")?;
    let modern_yarn = package
        .get("packageManager")
        .and_then(serde_json::Value::as_str)
        .and_then(|manager| manager.strip_prefix("yarn@"))
        .is_some_and(|version| {
            version == "berry"
                || version
                    .split('.')
                    .next()
                    .and_then(|major| major.parse::<u64>().ok())
                    .is_some_and(|major| major >= 2)
        });
    Ok((modern_yarn, false))
}

#[allow(
    clippy::disallowed_types,
    reason = "bounded synchronous policy metadata reads use O_NOFOLLOW before sandbox launch"
)]
fn read_bounded_project_file(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

    const MAX_PROJECT_METADATA_BYTES: u64 = 256 * 1024;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("open project metadata safely: {}", path.display()));
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect project metadata: {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("project metadata is not a regular file: {}", path.display());
    }
    if metadata.len() > MAX_PROJECT_METADATA_BYTES {
        anyhow::bail!("project metadata is too large: {}", path.display());
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PROJECT_METADATA_BYTES + 1)
        .read_to_end(&mut contents)
        .with_context(|| format!("read project metadata: {}", path.display()))?;
    if contents.len() as u64 > MAX_PROJECT_METADATA_BYTES {
        anyhow::bail!(
            "project metadata grew beyond the size limit: {}",
            path.display()
        );
    }
    Ok(Some(contents))
}

#[cfg(target_os = "linux")]
fn open_directory_no_symlinks(path: &Path) -> anyhow::Result<std::os::fd::OwnedFd> {
    use std::os::fd::OwnedFd;

    if !path.is_absolute() {
        anyhow::bail!("literal write parent is not absolute: {}", path.display());
    }
    let root_fd = unsafe { libc::open(c"/".as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open filesystem root");
    }
    let root_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };
    if path == Path::new("/") {
        return Ok(root_fd);
    }
    let relative = path.strip_prefix("/").expect("absolute path has root");
    let relative = CString::new(relative.as_os_str().as_bytes())
        .context("literal write parent contains NUL")?;
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            relative.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        ) as libc::c_int
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open literal write parent safely: {}", path.display()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn print_inspect_output(
    profile: &SandboxProfile,
    backend: &Sandbox,
    proxy_port: Option<u16>,
    effective_environment: &HashMap<String, String>,
    strict: bool,
) -> anyhow::Result<()> {
    eprintln!("--- Backend ---");
    eprintln!("name:    {}", backend.name());
    eprintln!("kernel:  {}", backend.info().kernel);
    eprintln!(
        "securityMode: {}",
        if strict { "strict" } else { "standard" }
    );
    eprintln!("features:");
    let f = &backend.info().features;
    eprintln!("  fs_write       : {}", f.fs_write);
    eprintln!("  fs_read        : {}", f.fs_read);
    eprintln!("  exec_allowlist : {}", f.exec_allowlist);
    eprintln!("  net_port_filter: {}", f.net_port_filter);
    eprintln!("  audit_stream   : {}", f.audit_stream);
    eprintln!();
    eprintln!("--- Resolved profile ---");
    let mut redacted = profile.clone();
    for value in redacted.env.values_mut() {
        *value = "<redacted>".to_owned();
    }
    let yaml = serde_yaml::to_string(&redacted).context("serialize resolved profile")?;
    eprintln!("{yaml}");
    eprintln!("effectiveEnvironment:");
    let mut names: Vec<&String> = effective_environment.keys().collect();
    names.sort();
    for name in names {
        let origin = profile
            .grant_origins
            .iter()
            .rev()
            .find(|record| record.kind == GrantKind::Environment && record.value == *name)
            .map(|record| record.origin.clone())
            .unwrap_or(GrantOrigin::Runtime);
        eprintln!(
            "  - name: {}\n    value: <redacted>\n    origin: {}",
            serde_json::to_string(name)?,
            serde_json::to_string(&origin)?
        );
    }
    println!("{}", backend.render_policy(profile, proxy_port)?);
    Ok(())
}

fn resolve_cli_environment(args: &RunArgs) -> anyhow::Result<HashMap<String, String>> {
    const RESERVED: &[&str] = &[
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "TMPDIR",
        "TMP",
        "TEMP",
        "XDG_RUNTIME_DIR",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_BUILD_BUILD_DIR",
        "PIP_CACHE_DIR",
        "UV_CACHE_DIR",
        "MIX_BUILD_ROOT",
        "MIX_DEPS_PATH",
        "REBAR_CACHE_DIR",
        "GRADLE_USER_HOME",
        "COURSIER_CACHE",
        "SBT_OPTS",
        "JAVA_TOOL_OPTIONS",
        "SBE_PROXY_TOKEN",
    ];
    let mut env = HashMap::new();
    for name in &args.keep_env {
        validate_env_name(name)?;
        if RESERVED.contains(&name.as_str()) {
            anyhow::bail!("environment variable '{name}' is reserved by sbe");
        }
        if let Ok(value) = std::env::var(name) {
            env.insert(name.clone(), value);
        }
    }
    for assignment in &args.env {
        let (name, value) = assignment
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--env requires NAME=VALUE"))?;
        validate_env_name(name)?;
        if RESERVED.contains(&name) {
            anyhow::bail!("environment variable '{name}' is reserved by sbe");
        }
        if value.contains('\0') {
            anyhow::bail!("environment variable '{name}' contains NUL");
        }
        env.insert(name.to_owned(), value.to_owned());
    }
    Ok(env)
}

fn validate_env_name(name: &str) -> anyhow::Result<()> {
    let mut bytes = name.bytes();
    if !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        anyhow::bail!("invalid environment variable name '{name}'");
    }
    Ok(())
}

fn build_overrides(args: &RunArgs, home: &Path, pwd: &Path) -> anyhow::Result<ProfileOverrides> {
    Ok(ProfileOverrides {
        allow_write: args
            .allow_write
            .iter()
            .map(|path| expand_cli_path(path, home, pwd))
            .collect::<anyhow::Result<_>>()?,
        deny_read: args
            .deny_read
            .iter()
            .map(|path| expand_cli_path(path, home, pwd))
            .collect::<anyhow::Result<_>>()?,
        allow_read: Vec::new(),
        allow_domains: args
            .allow_domain
            .iter()
            .map(|domain| DomainPattern::new(domain).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<_>>()?,
        deny_domains: args
            .deny_domain
            .iter()
            .map(|domain| DomainPattern::new(domain).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<_>>()?,
        allow_exec: args
            .allow_exec
            .iter()
            .map(|path| expand_cli_path(path, home, pwd))
            .collect::<anyhow::Result<_>>()?,
        deny_exec: args
            .deny_exec
            .iter()
            .map(|path| expand_cli_path(path, home, pwd))
            .collect::<anyhow::Result<_>>()?,
        allow_fetch: args
            .allow_fetch
            .iter()
            .map(|domain| DomainPattern::new(domain).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<_>>()?,
        allow_all_network: args.allow_all_network,
        no_proxy: args.no_proxy,
        allow_degraded: args.allow_degraded,
        env: Default::default(),
    })
}

fn expand_cli_path(path: &Path, home: &Path, pwd: &Path) -> anyhow::Result<SandboxPath> {
    let raw = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("sandbox path is not valid UTF-8: {path:?}"))?;
    if raw.contains('\0') || raw.chars().any(char::is_control) {
        anyhow::bail!("sandbox path contains a control character: {path:?}");
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        anyhow::bail!("sandbox path must not contain '..': {path:?}");
    }
    Ok(expand_path(raw, home, pwd))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambient_credentials_are_not_inherited() {
        let inherited = filter_parent_environment(
            [
                ("PATH".to_owned(), "/usr/bin".to_owned()),
                ("LANG".to_owned(), "C.UTF-8".to_owned()),
                ("RUSTFLAGS".to_owned(), "-Cdebuginfo=1".to_owned()),
                ("GITHUB_TOKEN".to_owned(), "sentinel".to_owned()),
                (
                    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI".to_owned(),
                    "/v2/credentials/task".to_owned(),
                ),
                (
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI".to_owned(),
                    "http://127.0.0.1/credentials".to_owned(),
                ),
                ("AWS_SECRET_ACCESS_KEY".to_owned(), "sentinel".to_owned()),
                ("AWS_CONFIG_FILE".to_owned(), "/tmp/aws-config".to_owned()),
                ("CI_JOB_JWT".to_owned(), "sentinel".to_owned()),
                ("CI_JOB_JWT_V2".to_owned(), "sentinel".to_owned()),
                (
                    "AWS_SHARED_CREDENTIALS_FILE".to_owned(),
                    "/tmp/aws-credentials".to_owned(),
                ),
                (
                    "AWS_WEB_IDENTITY_TOKEN_FILE".to_owned(),
                    "/tmp/aws-oidc-token".to_owned(),
                ),
                (
                    "AZURE_FEDERATED_TOKEN_FILE".to_owned(),
                    "/tmp/azure-oidc-token".to_owned(),
                ),
                (
                    "AZURE_CONFIG_DIR".to_owned(),
                    "/tmp/azure-config".to_owned(),
                ),
                (
                    "AZURE_CLIENT_CERTIFICATE_PATH".to_owned(),
                    "/tmp/azure-client.pem".to_owned(),
                ),
                (
                    "CLOUDSDK_CONFIG".to_owned(),
                    "/tmp/gcloud-config".to_owned(),
                ),
                ("SSH_AUTH_SOCK".to_owned(), "/tmp/agent".to_owned()),
                ("SYSTEM_ACCESSTOKEN".to_owned(), "sentinel".to_owned()),
                ("NPM_TOKEN".to_owned(), "sentinel".to_owned()),
                ("OPENAI_API_KEY".to_owned(), "sentinel".to_owned()),
                ("TOKEN".to_owned(), "sentinel".to_owned()),
                ("API_KEY".to_owned(), "sentinel".to_owned()),
                ("SECRET".to_owned(), "sentinel".to_owned()),
                ("PASSWORD".to_owned(), "sentinel".to_owned()),
                ("PASSWD".to_owned(), "sentinel".to_owned()),
                ("PRIVATE_KEY".to_owned(), "sentinel".to_owned()),
                ("CREDENTIAL".to_owned(), "sentinel".to_owned()),
                ("CREDENTIALS".to_owned(), "sentinel".to_owned()),
                ("DATABASE_URL".to_owned(), "sentinel".to_owned()),
                (
                    "DOCKER_CERT_PATH".to_owned(),
                    "/tmp/docker-certs".to_owned(),
                ),
                ("DOCKER_CONFIG".to_owned(), "/tmp/docker-config".to_owned()),
                ("TEST_DATABASE_URL".to_owned(), "sentinel".to_owned()),
                ("PGPASSWORD".to_owned(), "sentinel".to_owned()),
                ("PGPASSFILE".to_owned(), "sentinel".to_owned()),
                ("MYSQL_PWD".to_owned(), "sentinel".to_owned()),
                ("REDISCLI_AUTH".to_owned(), "sentinel".to_owned()),
                ("MONGODB_URI".to_owned(), "sentinel".to_owned()),
                ("NPM_CONFIG__AUTH".to_owned(), "sentinel".to_owned()),
                (
                    "NPM_CONFIG_//REGISTRY.NPMJS.ORG/:_AUTHTOKEN".to_owned(),
                    "sentinel".to_owned(),
                ),
                (
                    "TF_TOKEN_APP_TERRAFORM_IO".to_owned(),
                    "sentinel".to_owned(),
                ),
                (
                    "GOOGLE_APPLICATION_CREDENTIALS".to_owned(),
                    "/tmp/google-credentials.json".to_owned(),
                ),
                ("GH_CONFIG_DIR".to_owned(), "/tmp/gh-config".to_owned()),
                ("GNUPGHOME".to_owned(), "/tmp/gnupg".to_owned()),
            ],
            false,
        );
        assert_eq!(inherited.len(), 3);
        assert_eq!(inherited.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(
            inherited.get("RUSTFLAGS").map(String::as_str),
            Some("-Cdebuginfo=1")
        );
        assert!(!inherited.values().any(|value| value == "sentinel"));

        let strict = filter_parent_environment(
            [
                ("PATH".to_owned(), "/usr/bin".to_owned()),
                ("RUSTFLAGS".to_owned(), "-Cdebuginfo=1".to_owned()),
            ],
            true,
        );
        assert!(strict.contains_key("PATH"));
        assert!(!strict.contains_key("RUSTFLAGS"));
    }

    #[test]
    fn custom_cargo_home_credential_files_remain_denied() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        profile
            .env
            .insert("CARGO_HOME".to_owned(), "custom-cargo".to_owned());

        profile
            .env
            .insert("XDG_CONFIG_HOME".to_owned(), "custom-config".to_owned());

        protect_effective_credential_paths(&mut profile, home.path(), project.path());

        for name in ["credentials.toml", "credentials"] {
            let denied = SandboxPath::file(project.path().join("custom-cargo").join(name));
            assert!(profile.deny_read.contains(&denied));
            assert!(profile.grant_origins.iter().any(|record| {
                record.kind == GrantKind::DenyRead
                    && record.origin == GrantOrigin::BuiltIn
                    && record.value == denied.path.to_string_lossy()
            }));
        }
        assert!(
            profile
                .deny_read
                .contains(&SandboxPath::dir(project.path().join("custom-config/gh")))
        );
    }

    #[tokio::test]
    async fn java_runtime_isolates_sbt_state() {
        let project = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Java, Path::new("/home/test"), project.path());

        let environment = build_extra_env(
            &mut profile,
            None,
            runtime.path(),
            Path::new("/home/test"),
            project.path(),
            &[],
            true,
        )
        .await
        .unwrap();
        let sbt_options = environment.get("SBT_OPTS").unwrap();

        assert!(sbt_options.contains("-Dsbt.boot.directory="));
        assert!(sbt_options.contains("-Dsbt.ivy.home="));
    }

    #[tokio::test]
    async fn rust_runtime_places_executable_artifacts_in_private_temp() {
        let project = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, Path::new("/home/test"), project.path());

        let environment = build_extra_env(
            &mut profile,
            None,
            runtime.path(),
            Path::new("/home/test"),
            project.path(),
            &["cargo".to_owned(), "test".to_owned()],
            true,
        )
        .await
        .unwrap();

        assert_eq!(
            environment.get("CARGO_TARGET_DIR").map(String::as_str),
            runtime.path().join("cargo-target").to_str()
        );
        assert_ne!(
            environment.get("CARGO_TARGET_DIR").map(String::as_str),
            project.path().join("target").to_str()
        );

        let build_environment = build_extra_env(
            &mut profile,
            None,
            runtime.path(),
            Path::new("/home/test"),
            project.path(),
            &["cargo".to_owned(), "build".to_owned()],
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            build_environment
                .get("CARGO_TARGET_DIR")
                .map(String::as_str),
            project.path().join("target").to_str()
        );
        assert!(cargo_uses_persistent_target(&[
            "cargo".to_owned(),
            "build".to_owned()
        ]));
        assert!(!cargo_uses_persistent_target(&[
            "cargo".to_owned(),
            "test".to_owned()
        ]));

        let nextest_environment = build_extra_env(
            &mut profile,
            None,
            runtime.path(),
            Path::new("/home/test"),
            project.path(),
            &["cargo".to_owned(), "nextest".to_owned(), "run".to_owned()],
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            nextest_environment
                .get("CARGO_TARGET_DIR")
                .map(String::as_str),
            runtime.path().join("cargo-target").to_str()
        );
        assert!(cargo_executes_target(&[
            "cargo".to_owned(),
            "nextest".to_owned(),
            "run".to_owned(),
        ]));
    }

    #[tokio::test]
    async fn standard_rust_profile_keeps_normal_outputs_and_wrapper_support() {
        let project = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            Path::new("/Users/test"),
            project.path(),
        );
        apply_standard_profile(
            &mut profile,
            &["cargo".to_owned(), "test".to_owned()],
            Path::new("/Users/test"),
            project.path(),
        )
        .unwrap();

        assert!(
            profile
                .allow_write
                .contains(&SandboxPath::dir(project.path().to_path_buf()))
        );
        assert!(
            profile
                .allow_exec
                .contains(&SandboxPath::dir(project.path().join("target")))
        );
        assert!(
            profile
                .allow_write
                .contains(&SandboxPath::dir(project.path().join("target")))
        );
        assert!(!profile.deny_read.iter().any(|grant| {
            grant.path.parent() == Some(project.path())
                && grant.path.file_name().is_some_and(|name| name == ".env")
        }));
        assert!(
            profile.validate_structural_security_invariants().is_err(),
            "standard mode deliberately permits mutable executable build output"
        );

        let environment = build_extra_env(
            &mut profile,
            None,
            runtime.path(),
            Path::new("/Users/test"),
            project.path(),
            &["cargo".to_owned(), "test".to_owned()],
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            environment.get("CARGO_TARGET_DIR").map(String::as_str),
            project.path().join("target").to_str()
        );
        assert!(!environment.contains_key("SCCACHE_CLIENT_SIDE"));
        assert!(!environment.contains_key("CARGO_BUILD_BUILD_DIR"));

        let configured_environment = build_extra_env(
            &mut profile,
            None,
            runtime.path(),
            Path::new("/Users/test"),
            project.path(),
            &[
                "cargo".to_owned(),
                "build".to_owned(),
                "--config".to_owned(),
                "build.target-dir='configured-target'".to_owned(),
            ],
            false,
        )
        .await
        .unwrap();
        assert!(
            !configured_environment.contains_key("CARGO_TARGET_DIR"),
            "the standard fallback must not override Cargo command-line configuration"
        );
    }

    #[test]
    fn standard_profile_preserves_explicit_output_execute_denials() {
        let project = tempfile::tempdir().unwrap();
        let output = project.path().join("target");
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            Path::new("/Users/test"),
            project.path(),
        );
        profile.merge_overrides(&ProfileOverrides {
            deny_exec: vec![SandboxPath::dir(output.clone())],
            ..ProfileOverrides::default()
        });
        profile.finalize();

        apply_standard_profile(
            &mut profile,
            &["cargo".to_owned(), "test".to_owned()],
            Path::new("/Users/test"),
            project.path(),
        )
        .unwrap();

        assert!(
            profile
                .deny_exec
                .contains(&SandboxPath::dir(output.clone()))
        );
        assert!(
            !profile
                .allow_exec
                .iter()
                .any(|allowed| paths_overlap(&allowed.path, &output)),
            "an inferred output grant must not override an explicit execute denial"
        );
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the unit test creates an isolated Gradle home and project fixture"
    )]
    fn standard_gradle_profile_grants_the_effective_user_home() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = root.path().join("project");
        let inherited_home = root.path().join("inherited-gradle");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();

        let mut inherited = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        inherited.env.insert(
            "GRADLE_USER_HOME".to_owned(),
            inherited_home.to_string_lossy().into_owned(),
        );
        apply_standard_profile(
            &mut inherited,
            &["./gradlew".to_owned(), "build".to_owned()],
            &home,
            &project,
        )
        .unwrap();
        for name in STANDARD_GRADLE_MUTABLE_SUBDIRECTORIES {
            let path = inherited_home.join(name);
            assert!(
                inherited
                    .allow_write
                    .contains(&SandboxPath::dir(path.clone()))
            );
            assert!(inherited.allow_exec.contains(&SandboxPath::dir(path)));
        }
        assert!(
            !inherited
                .allow_write
                .contains(&SandboxPath::dir(inherited_home.clone()))
        );
        assert!(
            !inherited
                .allow_write
                .iter()
                .any(|grant| grant.path.starts_with(inherited_home.join("init.d")))
        );

        #[cfg(target_os = "macos")]
        {
            prepare_standard_gradle_directories(
                &inherited,
                &["./gradlew".to_owned(), "build".to_owned()],
                &home,
                &project,
            )
            .unwrap();
            for name in STANDARD_GRADLE_MUTABLE_SUBDIRECTORIES {
                assert!(inherited_home.join(name).is_dir());
            }
            assert!(!inherited_home.join("init.d").exists());
        }

        let cli_home = PathBuf::from(".cache/gradle-cli");
        let mut cli = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        cli.env.insert(
            "GRADLE_USER_HOME".to_owned(),
            root.path()
                .join("ignored-gradle")
                .to_string_lossy()
                .into_owned(),
        );
        apply_standard_profile(
            &mut cli,
            &[
                "gradle".to_owned(),
                "--gradle-user-home".to_owned(),
                cli_home.to_string_lossy().into_owned(),
                "build".to_owned(),
            ],
            &home,
            &project,
        )
        .unwrap();
        let cli_home = project.join(cli_home);
        for name in STANDARD_GRADLE_MUTABLE_SUBDIRECTORIES {
            let path = cli_home.join(name);
            assert!(cli.allow_write.contains(&SandboxPath::dir(path.clone())));
            assert!(cli.allow_exec.contains(&SandboxPath::dir(path)));
        }
        assert!(!cli.allow_write.contains(&SandboxPath::dir(cli_home)));

        let attached_home = root.path().join("attached-gradle");
        let mut attached = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        attached.env.insert(
            "GRADLE_USER_HOME".to_owned(),
            root.path()
                .join("ignored-attached-environment")
                .to_string_lossy()
                .into_owned(),
        );
        apply_standard_profile(
            &mut attached,
            &[
                "gradle".to_owned(),
                format!("-g{}", attached_home.display()),
                "help".to_owned(),
            ],
            &home,
            &project,
        )
        .unwrap();
        for name in STANDARD_GRADLE_MUTABLE_SUBDIRECTORIES {
            let path = attached_home.join(name);
            assert!(
                attached
                    .allow_write
                    .contains(&SandboxPath::dir(path.clone()))
            );
            assert!(attached.allow_exec.contains(&SandboxPath::dir(path)));
        }

        let property_home = root.path().join("property-gradle");
        let mut property = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        property.env.insert(
            "GRADLE_USER_HOME".to_owned(),
            root.path()
                .join("ignored-environment-gradle")
                .to_string_lossy()
                .into_owned(),
        );
        apply_standard_profile(
            &mut property,
            &[
                "gradle".to_owned(),
                format!(
                    "-Dgradle.user.home={}",
                    root.path().join("ignored-first-property").display()
                ),
                format!("-Dgradle.user.home={}", property_home.display()),
                "build".to_owned(),
            ],
            &home,
            &project,
        )
        .unwrap();
        for name in STANDARD_GRADLE_MUTABLE_SUBDIRECTORIES {
            let path = property_home.join(name);
            assert!(
                property
                    .allow_write
                    .contains(&SandboxPath::dir(path.clone()))
            );
            assert!(property.allow_exec.contains(&SandboxPath::dir(path)));
        }

        let opts_home = root.path().join("opts-gradle");
        let mut opts = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        opts.env.insert(
            "GRADLE_OPTS".to_owned(),
            format!(
                "-Xmx1g -Dgradle.user.home={} -Dfile.encoding=UTF-8",
                opts_home.display()
            ),
        );
        apply_standard_profile(
            &mut opts,
            &["gradle".to_owned(), "build".to_owned()],
            &home,
            &project,
        )
        .unwrap();
        for name in STANDARD_GRADLE_MUTABLE_SUBDIRECTORIES {
            let path = opts_home.join(name);
            assert!(opts.allow_write.contains(&SandboxPath::dir(path.clone())));
            assert!(opts.allow_exec.contains(&SandboxPath::dir(path)));
        }

        let java_opts_home = root.path().join("java-opts-gradle");
        let mut java_opts = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        java_opts.env.insert(
            "JAVA_OPTS".to_owned(),
            format!("-Dgradle.user.home={}", java_opts_home.display()),
        );
        java_opts.env.insert(
            "GRADLE_USER_HOME".to_owned(),
            root.path()
                .join("ignored-environment-home")
                .to_string_lossy()
                .into_owned(),
        );
        apply_standard_profile(
            &mut java_opts,
            &["gradle".to_owned(), "build".to_owned()],
            &home,
            &project,
        )
        .unwrap();
        for name in STANDARD_GRADLE_MUTABLE_SUBDIRECTORIES {
            let path = java_opts_home.join(name);
            assert!(
                java_opts
                    .allow_write
                    .contains(&SandboxPath::dir(path.clone()))
            );
            assert!(java_opts.allow_exec.contains(&SandboxPath::dir(path)));
        }

        let mut ambiguous = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        ambiguous.env.insert(
            "GRADLE_OPTS".to_owned(),
            "-Dgradle.user.home='$HOME/Gradle Home'".to_owned(),
        );
        let error = apply_standard_profile(
            &mut ambiguous,
            &["gradle".to_owned(), "build".to_owned()],
            &home,
            &project,
        )
        .unwrap_err();
        assert!(error.to_string().contains("--gradle-user-home"));
        assert_eq!(
            effective_gradle_user_home(
                &ambiguous,
                &[
                    "gradle".to_owned(),
                    "-g".to_owned(),
                    "explicit-gradle".to_owned(),
                    "build".to_owned(),
                ],
                &home,
                &project,
            )
            .unwrap(),
            Some(project.join("explicit-gradle")),
            "a higher-precedence explicit home must bypass ambiguous lower-precedence options"
        );
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the unit test builds and resolves an isolated external output symlink"
    )]
    fn standard_profile_requires_approval_for_external_project_outputs() {
        let project = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(external.path(), project.path().join("target")).unwrap();
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            Path::new("/Users/test"),
            project.path(),
        );

        let error = apply_standard_profile(
            &mut profile,
            &["cargo".to_owned(), "build".to_owned()],
            Path::new("/Users/test"),
            project.path(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("--allow-write"));
        assert!(error.to_string().contains(&format!(
            "{}{sep}",
            external.path().display(),
            sep = std::path::MAIN_SEPARATOR
        )));

        let mut approved = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            Path::new("/Users/test"),
            project.path(),
        );
        approved
            .allow_write
            .push(SandboxPath::dir(external.path().to_path_buf()));
        apply_standard_profile(
            &mut approved,
            &["cargo".to_owned(), "build".to_owned()],
            Path::new("/Users/test"),
            project.path(),
        )
        .unwrap();
        resolve_standard_path_aliases(&mut approved, Path::new("/Users/test"), project.path())
            .unwrap();

        assert!(approved.allow_write.contains(&SandboxPath::dir(
            std::fs::canonicalize(project.path()).unwrap()
        )));
        assert!(approved.allow_write.contains(&SandboxPath::dir(
            std::fs::canonicalize(external.path()).unwrap()
        )));
        assert!(approved.allow_exec.contains(&SandboxPath::dir(
            std::fs::canonicalize(external.path()).unwrap()
        )));
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the unit test builds and resolves isolated cache symlink fixtures"
    )]
    fn standard_profile_requires_approval_for_cache_symlinks_outside_the_envelope() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = root.path().join("project");
        let persistence = home.join(".config/autostart");
        std::fs::create_dir_all(&persistence).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::os::unix::fs::symlink(&persistence, home.join(".npm")).unwrap();

        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &project);
        apply_standard_profile(
            &mut profile,
            &["npm".to_owned(), "install".to_owned()],
            &home,
            &project,
        )
        .unwrap();
        let error = resolve_standard_path_aliases(&mut profile, &home, &project).unwrap_err();
        assert!(error.to_string().contains("--allow-write"));
        assert!(
            error
                .to_string()
                .contains(&persistence.display().to_string())
        );

        let mut approved = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &project);
        approved
            .allow_write
            .push(SandboxPath::dir(persistence.clone()));
        apply_standard_profile(
            &mut approved,
            &["npm".to_owned(), "install".to_owned()],
            &home,
            &project,
        )
        .unwrap();
        resolve_standard_path_aliases(&mut approved, &home, &project).unwrap();
        assert!(approved.allow_write.contains(&SandboxPath::dir(
            std::fs::canonicalize(persistence).unwrap()
        )));
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the unit test builds and resolves an isolated cache symlink fixture"
    )]
    fn standard_profile_follows_cache_symlinks_within_the_cache_envelope() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = root.path().join("project");
        let cache = home.join(".cache/npm");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::os::unix::fs::symlink(&cache, home.join(".npm")).unwrap();

        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Node, &home, &project);
        apply_standard_profile(
            &mut profile,
            &["npm".to_owned(), "install".to_owned()],
            &home,
            &project,
        )
        .unwrap();
        resolve_standard_path_aliases(&mut profile, &home, &project).unwrap();

        assert!(
            profile
                .allow_write
                .contains(&SandboxPath::dir(std::fs::canonicalize(cache).unwrap()))
        );
        assert!(
            !profile
                .allow_write
                .iter()
                .any(|grant| grant.path == home.join(".npm")),
            "the launcher must not reopen the mutable lexical symlink"
        );
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the unit test resolves isolated malicious wrapper and read symlinks"
    )]
    fn standard_profile_rejects_protected_builtin_aliases() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = root.path().join("project");
        let ssh = home.join(".ssh");
        let private_key = ssh.join("id_rsa");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(&private_key, "sentinel").unwrap();
        std::os::unix::fs::symlink(&private_key, project.join("gradlew")).unwrap();

        let mut executable = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        apply_standard_profile(
            &mut executable,
            &["./gradlew".to_owned(), "build".to_owned()],
            &home,
            &project,
        )
        .unwrap();
        let error = resolve_standard_path_aliases(&mut executable, &home, &project).unwrap_err();
        assert!(error.to_string().contains("built-in executable"));
        assert!(error.to_string().contains("gradlew"));
        assert!(error.to_string().contains("id_rsa"));

        let read_alias = home.join("read-alias");
        std::os::unix::fs::symlink(&ssh, &read_alias).unwrap();
        let mut readable = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        readable.allow_read = vec![SandboxPath::dir(read_alias)];
        readable.first_user_allow_read = 1;
        let error = snapshot_standard_read_aliases(&mut readable).unwrap_err();
        assert!(error.to_string().contains("built-in readable"));
        assert!(error.to_string().contains(".ssh"));
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the unit test resolves a missing cache directory beneath an isolated symlink"
    )]
    fn standard_profile_resolves_missing_descendants_beneath_approved_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let project = root.path().join("project");
        let external_cache = root.path().join("external-cache");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&external_cache).unwrap();
        std::os::unix::fs::symlink(&external_cache, home.join(".cache")).unwrap();
        let resolved_cache = std::fs::canonicalize(&external_cache)
            .unwrap()
            .join("coursier");

        let mut unapproved = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        apply_standard_profile(
            &mut unapproved,
            &["sbt".to_owned(), "update".to_owned()],
            &home,
            &project,
        )
        .unwrap();
        let error = resolve_standard_path_aliases(&mut unapproved, &home, &project).unwrap_err();
        assert!(error.to_string().contains("--allow-write"));
        assert!(
            error
                .to_string()
                .contains(&resolved_cache.display().to_string())
        );

        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Java, &home, &project);
        profile
            .allow_write
            .push(SandboxPath::dir(external_cache.clone()));
        apply_standard_profile(
            &mut profile,
            &["sbt".to_owned(), "update".to_owned()],
            &home,
            &project,
        )
        .unwrap();
        resolve_standard_path_aliases(&mut profile, &home, &project).unwrap();

        assert!(!resolved_cache.exists());
        assert!(
            profile
                .allow_write
                .contains(&SandboxPath::dir(resolved_cache)),
            "resolved grants: {:?}",
            profile.allow_write
        );
        assert!(
            !profile
                .allow_write
                .iter()
                .any(|grant| grant.path == home.join(".cache/coursier")),
            "the launcher must receive the reconstructed canonical target, not its symlinked spelling"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the unit test builds and resolves an isolated temporary symlink fixture"
    )]
    fn standard_profile_reads_source_symlink_referents_outside_project() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let source = project.join("src");
        let shared = root.path().join("shared");
        let nested = root.path().join("nested");
        let protected = root.path().join(".aws");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(&protected).unwrap();
        std::os::unix::fs::symlink("../../shared", source.join("shared")).unwrap();
        std::os::unix::fs::symlink("../nested", shared.join("nested")).unwrap();
        std::os::unix::fs::symlink("../../.aws", source.join("credentials")).unwrap();
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, root.path(), &project);

        apply_standard_profile(
            &mut profile,
            &["cargo".to_owned(), "build".to_owned()],
            root.path(),
            &project,
        )
        .unwrap();
        resolve_standard_path_aliases(&mut profile, root.path(), &project).unwrap();

        assert!(
            profile
                .allow_read
                .contains(&SandboxPath::dir(std::fs::canonicalize(shared).unwrap()))
        );
        assert!(
            profile
                .allow_read
                .contains(&SandboxPath::dir(std::fs::canonicalize(nested).unwrap()))
        );
        assert!(
            !profile
                .allow_read
                .iter()
                .any(|grant| { grant.path == std::fs::canonicalize(&protected).unwrap() }),
            "protected referents must not receive an inferred read grant"
        );
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the unit test builds an isolated bounded source traversal fixture"
    )]
    fn standard_source_symlink_discovery_is_bounded() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let source = project.join("src");
        let external = root.path().join("external");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&external).unwrap();
        std::os::unix::fs::symlink(&external, source.join("external")).unwrap();
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, root.path(), &project);

        let entry_error =
            workspace_read_aliases_with_limits(&profile, &project, 1, 128).unwrap_err();
        assert!(entry_error.to_string().contains("entry scan budget"));

        let depth_error =
            workspace_read_aliases_with_limits(&profile, &project, 100, 1).unwrap_err();
        assert!(depth_error.to_string().contains("maximum depth"));
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the unit test builds an isolated linked-dependency fixture"
    )]
    fn standard_source_symlink_discovery_reads_linked_generated_dependencies() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let dependencies = project.join("node_modules");
        let ordinary_dependency = dependencies.join("ordinary");
        let linked = root.path().join("linked");
        let ignored = root.path().join("ignored");
        std::fs::create_dir_all(&ordinary_dependency).unwrap();
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::create_dir_all(&ignored).unwrap();
        std::os::unix::fs::symlink("../../linked", dependencies.join("local")).unwrap();
        std::os::unix::fs::symlink("../../../ignored", ordinary_dependency.join("nested")).unwrap();
        let profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, root.path(), &project);

        let aliases = workspace_read_aliases_with_limits(&profile, &project, 100, 128).unwrap();

        assert!(aliases.contains(&SandboxPath::dir(std::fs::canonicalize(linked).unwrap())));
        assert!(
            !aliases.contains(&SandboxPath::dir(std::fs::canonicalize(ignored).unwrap())),
            "ordinary generated dependency contents must not be recursively scanned"
        );
    }

    #[test]
    fn standard_profile_preserves_explicit_workspace_read_denials() {
        let project = tempfile::tempdir().unwrap();
        let denied = project.path().join(".env");
        let mut profile = SandboxProfile::for_ecosystem(
            Ecosystem::Rust,
            Path::new("/Users/test"),
            project.path(),
        );
        profile.grant_origins.push(GrantRecord {
            kind: GrantKind::DenyRead,
            value: denied.to_string_lossy().into_owned(),
            origin: GrantOrigin::Project(project.path().join(".sbe.yaml")),
        });

        apply_standard_profile(
            &mut profile,
            &["cargo".to_owned(), "build".to_owned()],
            Path::new("/Users/test"),
            project.path(),
        )
        .unwrap();

        assert!(profile.deny_read.contains(&SandboxPath::file(denied)));
    }

    #[tokio::test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the test creates an isolated Maven JVM configuration fixture"
    )]
    async fn standard_java_profile_uses_normal_persistent_caches() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Java, home.path(), project.path());

        apply_standard_profile(
            &mut profile,
            &["sbt".to_owned(), "compile".to_owned()],
            home.path(),
            project.path(),
        )
        .unwrap();

        for cache in [".sbt/boot", ".ivy2/cache", ".cache/coursier"] {
            assert!(
                profile
                    .allow_write
                    .contains(&SandboxPath::dir(home.path().join(cache))),
                "missing standard cache grant for {cache}"
            );
        }
        assert!(
            !profile
                .allow_write
                .contains(&SandboxPath::dir(home.path().join(".sbt"))),
            "the sbt global plugin/settings root must remain non-writable"
        );

        let environment = build_extra_env(
            &mut profile,
            None,
            runtime.path(),
            home.path(),
            project.path(),
            &["sbt".to_owned(), "compile".to_owned()],
            false,
        )
        .await
        .unwrap();
        let sbt_options = environment.get("SBT_OPTS").unwrap();
        assert!(sbt_options.contains(&format!(
            "-Dsbt.global.base={}",
            runtime.path().join("sbt-global").display()
        )));
        assert!(sbt_options.contains(&format!(
            "-Dsbt.boot.directory={}",
            home.path().join(".sbt/boot").display()
        )));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let proxy = start_proxy_if_needed(&profile, shutdown_rx)
            .await
            .unwrap()
            .unwrap();
        let proxied = build_extra_env(
            &mut profile,
            Some(&proxy.endpoint),
            runtime.path(),
            home.path(),
            project.path(),
            &["sbt".to_owned(), "compile".to_owned()],
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            proxied.get("NO_PROXY").map(String::as_str),
            Some(STANDARD_NO_PROXY)
        );
        assert_eq!(
            proxied.get("no_proxy").map(String::as_str),
            Some(STANDARD_NO_PROXY)
        );
        assert!(
            proxied
                .get("JAVA_TOOL_OPTIONS")
                .is_some_and(|options| options.contains(&format!(
                    "-Dhttp.nonProxyHosts={STANDARD_JAVA_NON_PROXY_HOSTS}"
                )))
        );
        let _ = shutdown_tx.send(true);
        await_proxy_shutdown(proxy).await.unwrap();

        let custom_repository = tempfile::tempdir().unwrap();
        let mut maven = SandboxProfile::for_ecosystem(Ecosystem::Java, home.path(), project.path());
        maven.env.insert(
            "MAVEN_OPTS".to_owned(),
            "-Dmaven.repo.local=/ignored-lower-precedence-repository".to_owned(),
        );
        apply_standard_profile(
            &mut maven,
            &[
                "mvn".to_owned(),
                format!("-Dmaven.repo.local={}", custom_repository.path().display()),
                "package".to_owned(),
            ],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            maven
                .allow_write
                .contains(&SandboxPath::dir(custom_repository.path().to_path_buf()))
        );
        assert!(
            !maven
                .allow_write
                .contains(&SandboxPath::dir(home.path().join(".m2/repository"))),
            "the selected Maven repository must replace the default write grant"
        );

        let jvm_repository = project.path().join("jvm-config-repository");
        std::fs::create_dir_all(project.path().join(".mvn")).unwrap();
        std::fs::write(
            project.path().join(".mvn/jvm.config"),
            format!("-Dmaven.repo.local={}\n", jvm_repository.display()),
        )
        .unwrap();
        let mut jvm_config =
            SandboxProfile::for_ecosystem(Ecosystem::Java, home.path(), project.path());
        jvm_config
            .env
            .insert("MAVEN_OPTS".to_owned(), "-Xmx1g".to_owned());
        apply_standard_profile(
            &mut jvm_config,
            &["mvn".to_owned(), "validate".to_owned()],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            jvm_config
                .allow_write
                .contains(&SandboxPath::dir(jvm_repository.clone()))
        );

        let opts_repository = tempfile::tempdir().unwrap();
        let mut maven_opts =
            SandboxProfile::for_ecosystem(Ecosystem::Java, home.path(), project.path());
        maven_opts.env.insert(
            "MAVEN_OPTS".to_owned(),
            format!(
                "-Dmaven.repo.local={} -Dmaven.repo.local={}",
                jvm_repository.display(),
                opts_repository.path().display()
            ),
        );
        apply_standard_profile(
            &mut maven_opts,
            &["mvn".to_owned(), "validate".to_owned()],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            maven_opts
                .allow_write
                .contains(&SandboxPath::dir(opts_repository.path().to_path_buf()))
        );
        assert!(
            !maven_opts
                .allow_write
                .contains(&SandboxPath::dir(jvm_repository)),
            "MAVEN_OPTS is appended after .mvn/jvm.config and its last property wins"
        );

        let config_repository = project.path().join("maven-config-repository");
        std::fs::write(
            project.path().join(".mvn/maven.config"),
            format!("-Dmaven.repo.local={}\n", config_repository.display()),
        )
        .unwrap();
        let mut maven_config =
            SandboxProfile::for_ecosystem(Ecosystem::Java, home.path(), project.path());
        maven_config
            .env
            .insert("MAVEN_ARGS".to_owned(), "-B".to_owned());
        maven_config.env.insert(
            "MAVEN_OPTS".to_owned(),
            format!("-Dmaven.repo.local={}", opts_repository.path().display()),
        );
        apply_standard_profile(
            &mut maven_config,
            &["mvn".to_owned(), "validate".to_owned()],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            maven_config
                .allow_write
                .contains(&SandboxPath::dir(config_repository.clone())),
            "project Maven arguments override JVM system-property sources"
        );

        let external_project_repository = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join(".mvn/maven.config"),
            format!(
                "-Dmaven.repo.local={}\n",
                external_project_repository.path().display()
            ),
        )
        .unwrap();
        let mut unapproved =
            SandboxProfile::for_ecosystem(Ecosystem::Java, home.path(), project.path());
        unapproved
            .env
            .insert("MAVEN_ARGS".to_owned(), "-B".to_owned());
        unapproved
            .env
            .insert("MAVEN_OPTS".to_owned(), "-Xmx1g".to_owned());
        let error = apply_standard_profile(
            &mut unapproved,
            &["mvn".to_owned(), "validate".to_owned()],
            home.path(),
            project.path(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("--allow-write"));

        let mut approved =
            SandboxProfile::for_ecosystem(Ecosystem::Java, home.path(), project.path());
        approved
            .env
            .insert("MAVEN_ARGS".to_owned(), "-B".to_owned());
        approved.allow_write.push(SandboxPath::dir(
            external_project_repository.path().to_path_buf(),
        ));
        apply_standard_profile(
            &mut approved,
            &["mvn".to_owned(), "validate".to_owned()],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(approved.allow_write.contains(&SandboxPath::dir(
            external_project_repository.path().to_path_buf()
        )));

        let args_repository = tempfile::tempdir().unwrap();
        let mut maven_args =
            SandboxProfile::for_ecosystem(Ecosystem::Java, home.path(), project.path());
        maven_args.env.insert(
            "MAVEN_ARGS".to_owned(),
            format!("-Dmaven.repo.local={}", args_repository.path().display()),
        );
        apply_standard_profile(
            &mut maven_args,
            &["mvn".to_owned(), "validate".to_owned()],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            maven_args
                .allow_write
                .contains(&SandboxPath::dir(args_repository.path().to_path_buf()))
        );
        assert!(
            !maven_args
                .allow_write
                .contains(&SandboxPath::dir(config_repository)),
            "MAVEN_ARGS is passed as CLI input and overrides project Maven arguments"
        );

        let mut ambiguous_args =
            SandboxProfile::for_ecosystem(Ecosystem::Java, home.path(), project.path());
        ambiguous_args.env.insert(
            "MAVEN_ARGS".to_owned(),
            "-Dmaven.repo.local='$HOME/maven repository'".to_owned(),
        );
        let error = apply_standard_profile(
            &mut ambiguous_args,
            &["mvn".to_owned(), "validate".to_owned()],
            home.path(),
            project.path(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unambiguous"));
    }

    #[test]
    fn standard_cargo_install_only_executes_the_install_bin_directory() {
        let project = tempfile::tempdir().unwrap();
        let home = Path::new("/Users/test");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, home, project.path());
        apply_standard_profile(
            &mut profile,
            &[
                "cargo".to_owned(),
                "install".to_owned(),
                "ripgrep".to_owned(),
            ],
            home,
            project.path(),
        )
        .unwrap();

        let cargo_root = std::env::var_os("CARGO_INSTALL_ROOT")
            .or_else(|| std::env::var_os("CARGO_HOME"))
            .map_or_else(|| home.join(".cargo"), PathBuf::from);
        let cargo_root = if cargo_root.is_absolute() {
            cargo_root
        } else {
            project.path().join(cargo_root)
        };
        assert!(
            profile
                .allow_write
                .contains(&SandboxPath::dir(cargo_root.clone()))
        );
        assert!(
            profile
                .allow_exec
                .contains(&SandboxPath::dir(cargo_root.join("bin")))
        );
        assert!(!profile.allow_exec.contains(&SandboxPath::dir(cargo_root)));
    }

    #[test]
    fn standard_cargo_paths_use_the_resolved_profile_environment() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let config_target = tempfile::tempdir().unwrap();
        let install_root = tempfile::tempdir().unwrap();

        let mut build_profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        build_profile.env.insert(
            "CARGO_TARGET_DIR".to_owned(),
            target.path().to_string_lossy().into_owned(),
        );
        apply_standard_profile(
            &mut build_profile,
            &["cargo".to_owned(), "build".to_owned()],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            build_profile
                .allow_write
                .contains(&SandboxPath::dir(target.path().to_path_buf()))
        );
        assert!(
            build_profile
                .allow_exec
                .contains(&SandboxPath::dir(target.path().to_path_buf()))
        );

        let mut cli_build_profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        cli_build_profile.env.insert(
            "CARGO_TARGET_DIR".to_owned(),
            target.path().to_string_lossy().into_owned(),
        );
        apply_standard_profile(
            &mut cli_build_profile,
            &[
                "cargo".to_owned(),
                "build".to_owned(),
                "--target-dir=cli-target".to_owned(),
            ],
            home.path(),
            project.path(),
        )
        .unwrap();
        let cli_target = project.path().join("cli-target");
        assert!(
            cli_build_profile
                .allow_write
                .contains(&SandboxPath::dir(cli_target.clone()))
        );
        assert!(
            cli_build_profile
                .allow_exec
                .contains(&SandboxPath::dir(cli_target))
        );
        assert!(
            !cli_build_profile
                .allow_write
                .contains(&SandboxPath::dir(target.path().to_path_buf())),
            "the CLI target directory must replace the lower-precedence environment path"
        );

        let mut config_build_profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        apply_standard_profile(
            &mut config_build_profile,
            &[
                "cargo".to_owned(),
                "build".to_owned(),
                "--config".to_owned(),
                format!("build.target-dir='{}'", config_target.path().display()),
            ],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            config_build_profile
                .allow_write
                .contains(&SandboxPath::dir(config_target.path().to_path_buf()))
        );
        assert!(
            config_build_profile
                .allow_exec
                .contains(&SandboxPath::dir(config_target.path().to_path_buf()))
        );

        let mut environment_over_config =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        environment_over_config.env.insert(
            "CARGO_TARGET_DIR".to_owned(),
            target.path().to_string_lossy().into_owned(),
        );
        environment_over_config.env.insert(
            "CARGO_BUILD_TARGET_DIR".to_owned(),
            config_target.path().to_string_lossy().into_owned(),
        );
        apply_standard_profile(
            &mut environment_over_config,
            &[
                "cargo".to_owned(),
                "build".to_owned(),
                "--config".to_owned(),
                format!("build.target-dir='{}'", config_target.path().display()),
            ],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            environment_over_config
                .allow_write
                .contains(&SandboxPath::dir(target.path().to_path_buf()))
        );
        assert!(
            !environment_over_config
                .allow_write
                .contains(&SandboxPath::dir(config_target.path().to_path_buf())),
            "Cargo target environment variables take precedence over --config"
        );

        let mut config_file_profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        let error = apply_standard_profile(
            &mut config_file_profile,
            &[
                "cargo".to_owned(),
                "--config".to_owned(),
                "cargo-extra.toml".to_owned(),
                "build".to_owned(),
            ],
            home.path(),
            project.path(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("--target-dir"));

        let mut node_profile =
            SandboxProfile::for_ecosystem(Ecosystem::Node, home.path(), project.path());
        node_profile.env.insert(
            "CARGO_TARGET_DIR".to_owned(),
            target.path().to_string_lossy().into_owned(),
        );
        apply_standard_profile(
            &mut node_profile,
            &["npm".to_owned(), "install".to_owned()],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            !node_profile
                .allow_write
                .contains(&SandboxPath::dir(target.path().to_path_buf())),
            "Cargo configuration must not expand a non-Cargo command's authority"
        );
        assert!(
            !node_profile
                .allow_exec
                .contains(&SandboxPath::dir(target.path().to_path_buf()))
        );

        let mut install_profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        install_profile.env.insert(
            "CARGO_INSTALL_ROOT".to_owned(),
            install_root.path().to_string_lossy().into_owned(),
        );
        install_profile.env.insert(
            "CARGO_HOME".to_owned(),
            home.path().join("ignored-cargo-home").display().to_string(),
        );
        apply_standard_profile(
            &mut install_profile,
            &[
                "cargo".to_owned(),
                "install".to_owned(),
                "ripgrep".to_owned(),
            ],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            install_profile
                .allow_write
                .contains(&SandboxPath::dir(install_root.path().to_path_buf()))
        );
        assert!(
            install_profile
                .allow_exec
                .contains(&SandboxPath::dir(install_root.path().join("bin")))
        );
    }

    #[test]
    fn standard_cargo_install_honors_explicit_root() {
        let project = tempfile::tempdir().unwrap();
        let install_root = tempfile::tempdir().unwrap();
        let home = Path::new("/Users/test");
        let mut profile = SandboxProfile::for_ecosystem(Ecosystem::Rust, home, project.path());
        apply_standard_profile(
            &mut profile,
            &[
                "cargo".to_owned(),
                "install".to_owned(),
                "--root".to_owned(),
                install_root.path().to_string_lossy().into_owned(),
                "ripgrep".to_owned(),
            ],
            home,
            project.path(),
        )
        .unwrap();

        assert!(
            profile
                .allow_write
                .contains(&SandboxPath::dir(install_root.path().to_path_buf()))
        );
        assert!(
            profile
                .allow_exec
                .contains(&SandboxPath::dir(install_root.path().join("bin")))
        );
        assert_eq!(
            command_option_value(
                &[
                    "cargo".to_owned(),
                    "install".to_owned(),
                    "--root=relative".to_owned()
                ],
                "--root"
            ),
            Some("relative")
        );
    }

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the unit test writes isolated Cargo configuration fixtures"
    )]
    fn standard_cargo_install_handles_configured_roots_before_launch() {
        let project = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let direct_root = tempfile::tempdir().unwrap();
        let configured_root = tempfile::tempdir().unwrap();
        let mut direct =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        apply_standard_profile(
            &mut direct,
            &[
                "cargo".to_owned(),
                "install".to_owned(),
                "--config".to_owned(),
                format!("install.root='{}'", direct_root.path().display()),
                "ripgrep".to_owned(),
            ],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            direct
                .allow_write
                .contains(&SandboxPath::dir(direct_root.path().to_path_buf()))
        );
        assert!(
            direct
                .allow_exec
                .contains(&SandboxPath::dir(direct_root.path().join("bin")))
        );

        let mut environment =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        environment.env.insert(
            "CARGO_INSTALL_ROOT".to_owned(),
            configured_root.path().display().to_string(),
        );
        apply_standard_profile(
            &mut environment,
            &[
                "cargo".to_owned(),
                "install".to_owned(),
                "--config".to_owned(),
                format!("install.root='{}'", direct_root.path().display()),
                "ripgrep".to_owned(),
            ],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            environment
                .allow_write
                .contains(&SandboxPath::dir(configured_root.path().to_path_buf())),
            "CARGO_INSTALL_ROOT takes precedence over the Cargo config value"
        );
        assert!(
            !environment
                .allow_write
                .contains(&SandboxPath::dir(direct_root.path().to_path_buf()))
        );

        let cargo_config = project.path().join(".cargo/config.toml");
        std::fs::create_dir_all(cargo_config.parent().unwrap()).unwrap();
        std::fs::write(
            &cargo_config,
            format!("[install]\nroot = '{}'\n", configured_root.path().display()),
        )
        .unwrap();
        let mut implicit =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        let error = apply_standard_profile(
            &mut implicit,
            &[
                "cargo".to_owned(),
                "install".to_owned(),
                "ripgrep".to_owned(),
            ],
            home.path(),
            project.path(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cargo install --root"));

        let mut explicit =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, home.path(), project.path());
        apply_standard_profile(
            &mut explicit,
            &[
                "cargo".to_owned(),
                "install".to_owned(),
                "--root".to_owned(),
                direct_root.path().display().to_string(),
                "ripgrep".to_owned(),
            ],
            home.path(),
            project.path(),
        )
        .unwrap();
        assert!(
            explicit
                .allow_write
                .contains(&SandboxPath::dir(direct_root.path().to_path_buf())),
            "an explicit root must override an implicit Cargo config"
        );

        assert!(cargo_config_may_define_install_root(
            "[\"install\"]\n\"root\" = '/tmp/cargo' # selected root"
        ));
        assert!(cargo_config_may_define_install_root(
            "'install'.'root' = '/tmp/cargo'"
        ));
        assert!(cargo_config_may_define_install_root(
            "include = ['shared.toml']"
        ));
        assert!(!cargo_config_may_define_install_root(
            "[build]\ntarget-dir = 'install/root' # not an install setting"
        ));
    }

    #[test]
    fn node_tool_commands_switch_builtin_dependencies_from_write_to_execute() {
        let project_directory = tempfile::tempdir().unwrap();
        let project = project_directory.path();
        let base_profile =
            SandboxProfile::for_ecosystem(Ecosystem::Node, Path::new("/Users/test"), project);
        for command in [
            vec!["npm".to_owned(), "test".to_owned()],
            vec!["npm".to_owned(), "exec".to_owned(), "eslint".to_owned()],
            vec!["npx".to_owned(), "eslint".to_owned()],
            vec!["bun".to_owned(), "run".to_owned(), "test".to_owned()],
        ] {
            let mut profile = base_profile.clone();
            enable_existing_dependency_execution(&mut profile, &command);

            let dependencies = project.join("node_modules");
            assert!(
                !profile
                    .allow_write
                    .iter()
                    .any(|grant| grant.path == dependencies),
                "{command:?} retained a writable dependency tree"
            );
            assert!(
                profile
                    .allow_exec
                    .iter()
                    .any(|grant| grant.path == dependencies),
                "{command:?} did not authorize installed tools"
            );
            profile.validate_security_invariants().unwrap();
        }

        let mut install_profile = base_profile.clone();
        enable_existing_dependency_execution(
            &mut install_profile,
            &["npm".to_owned(), "install".to_owned()],
        );
        assert!(
            install_profile
                .allow_write
                .iter()
                .any(|grant| grant.path == project.join("node_modules"))
        );
        assert!(
            !install_profile
                .allow_exec
                .iter()
                .any(|grant| grant.path == project.join("node_modules"))
        );

        let mut denied_profile = base_profile;
        denied_profile.deny_exec.push(SandboxPath::file(
            project.join("node_modules/eslint/bin/eslint.js"),
        ));
        enable_existing_dependency_execution(
            &mut denied_profile,
            &["npm".to_owned(), "test".to_owned()],
        );
        assert!(
            !denied_profile
                .allow_exec
                .iter()
                .any(|grant| grant.path == project.join("node_modules")),
            "a higher-precedence executable denial must not be re-authorized"
        );
    }

    #[test]
    fn python_run_commands_switch_builtin_virtualenvs_from_write_to_execute() {
        let project_directory = tempfile::tempdir().unwrap();
        let project = project_directory.path();
        let base_profile =
            SandboxProfile::for_ecosystem(Ecosystem::Python, Path::new("/Users/test"), project);
        for command in [
            vec!["uv".to_owned(), "run".to_owned(), "pytest".to_owned()],
            vec!["poetry".to_owned(), "run".to_owned(), "pytest".to_owned()],
            vec![
                project
                    .join(".venv/bin/pytest")
                    .to_string_lossy()
                    .into_owned(),
            ],
            vec!["pytest".to_owned()],
        ] {
            let mut profile = base_profile.clone();
            enable_existing_dependency_execution(&mut profile, &command);

            for environment in [project.join(".venv"), project.join("venv")] {
                assert!(
                    !profile
                        .allow_write
                        .iter()
                        .any(|grant| grant.path == environment),
                    "{command:?} retained a writable virtualenv"
                );
                assert!(
                    profile
                        .allow_exec
                        .iter()
                        .any(|grant| grant.path == environment),
                    "{command:?} did not authorize the existing virtualenv"
                );
            }
            profile.validate_security_invariants().unwrap();
        }

        for command in [
            vec!["uv".to_owned(), "sync".to_owned()],
            vec!["pip".to_owned(), "install".to_owned(), "pytest".to_owned()],
            vec!["poetry".to_owned(), "install".to_owned()],
            vec![
                "python".to_owned(),
                "-m".to_owned(),
                "venv".to_owned(),
                ".venv".to_owned(),
            ],
        ] {
            let mut profile = base_profile.clone();
            enable_existing_dependency_execution(&mut profile, &command);
            assert!(
                profile
                    .allow_write
                    .iter()
                    .any(|grant| grant.path == project.join(".venv")),
                "{command:?} lost the writable virtualenv required for installation"
            );
            assert!(
                !profile
                    .allow_exec
                    .iter()
                    .any(|grant| grant.path == project.join(".venv"))
            );
        }

        let mut explicitly_writable_profile = base_profile.clone();
        explicitly_writable_profile
            .allow_write
            .push(SandboxPath::dir(project.join(".venv")));
        enable_existing_dependency_execution(
            &mut explicitly_writable_profile,
            &["pytest".to_owned()],
        );
        assert!(
            explicitly_writable_profile
                .allow_write
                .iter()
                .any(|grant| grant.path == project.join(".venv")),
            "a user-supplied write grant must not be silently removed"
        );
        assert!(
            explicitly_writable_profile
                .validate_security_invariants()
                .is_err(),
            "a user-supplied write grant must still conflict with runtime execution"
        );

        let mut denied_profile = base_profile;
        denied_profile
            .deny_exec
            .push(SandboxPath::file(project.join(".venv/bin/pytest")));
        enable_existing_dependency_execution(&mut denied_profile, &["pytest".to_owned()]);
        assert!(
            !denied_profile
                .allow_exec
                .iter()
                .any(|grant| grant.path == project.join(".venv")),
            "a higher-precedence virtualenv executable denial must not be re-authorized"
        );
    }

    #[test]
    fn top_level_command_parsing_ignores_option_values_and_nested_commands() {
        assert_eq!(
            top_level_subcommand(&[
                "cargo".to_owned(),
                "+stable".to_owned(),
                "--color".to_owned(),
                "always".to_owned(),
                "build".to_owned(),
            ]),
            ParsedTopLevel::Command("build")
        );
        assert!(cargo_uses_persistent_target(&[
            "cargo".to_owned(),
            "build".to_owned(),
            "--package".to_owned(),
            "test".to_owned(),
        ]));
        assert!(!cargo_executes_target(&[
            "cargo".to_owned(),
            "build".to_owned(),
            "--package".to_owned(),
            "test".to_owned(),
        ]));
        assert!(cargo_executes_target(&[
            "cargo".to_owned(),
            "test".to_owned(),
            "--package".to_owned(),
            "build".to_owned(),
        ]));
        assert_eq!(
            top_level_subcommand(&["poetry".to_owned(), "run".to_owned(), "install".to_owned(),]),
            ParsedTopLevel::Command("run")
        );
        assert_eq!(
            top_level_subcommand(&[
                "npm".to_owned(),
                "--future-option".to_owned(),
                "install".to_owned(),
                "view".to_owned(),
            ]),
            ParsedTopLevel::Ambiguous
        );
    }

    #[test]
    fn project_relocation_options_are_rejected_before_policy_preparation() {
        let project = tempfile::tempdir().unwrap();
        for command in [
            vec!["npm", "--prefix", "subproject", "install"],
            vec!["npm", "install", "--prefix=subproject"],
            vec!["yarn", "--cwd", "subproject", "install"],
            vec!["pnpm", "-Csubproject", "install"],
            vec!["bun", "--cwd=subproject", "install"],
            vec!["uv", "--project", "subproject", "sync"],
            vec!["poetry", "-P", "subproject", "install"],
            vec!["cargo", "-Csubproject", "build"],
            vec!["./gradlew", "--project-dir", "subproject", "build"],
            vec!["gradle", "-psubproject", "build"],
            vec!["./mvnw", "--file=subproject/pom.xml", "package"],
            vec!["mvn", "-fsubproject/pom.xml", "package"],
        ] {
            let command: Vec<String> = command.into_iter().map(str::to_owned).collect();
            assert!(
                reject_project_relocation(&command, project.path()).is_err(),
                "relocating command was accepted: {command:?}"
            );
        }
        assert!(
            reject_project_relocation(
                &[
                    "npm".to_owned(),
                    "install".to_owned(),
                    "--".to_owned(),
                    "--prefix".to_owned(),
                    "payload".to_owned(),
                ],
                project.path(),
            )
            .is_ok()
        );
        for flag in ["-fae", "-ff", "-fn"] {
            assert!(
                reject_project_relocation(
                    &["mvn".to_owned(), flag.to_owned(), "test".to_owned(),],
                    project.path(),
                )
                .is_ok(),
                "Maven failure-mode flag was treated as a project path: {flag}"
            );
        }

        let external = tempfile::tempdir().unwrap();
        assert!(
            reject_project_relocation(
                &[
                    "cargo".to_owned(),
                    "build".to_owned(),
                    "--manifest-path".to_owned(),
                    external.path().join("Cargo.toml").display().to_string(),
                ],
                project.path(),
            )
            .unwrap_err()
            .to_string()
            .contains("outside the sandbox workspace")
        );
        assert!(
            reject_project_relocation(
                &[
                    "cargo".to_owned(),
                    "build".to_owned(),
                    "--manifest-path=apps/cli/Cargo.toml".to_owned(),
                ],
                project.path(),
            )
            .is_ok(),
            "in-workspace manifests used by release workflows must remain supported"
        );
    }

    #[test]
    fn cli_paths_reject_parent_traversal() {
        assert!(
            expand_cli_path(
                Path::new("$PWD/output/../.ssh/"),
                Path::new("/home/test"),
                Path::new("/work/project"),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn java_proxy_agent_is_private_and_refuses_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let runtime = tempfile::tempdir().unwrap();
        let path = install_java_proxy_agent(runtime.path()).await.unwrap();
        let metadata = tokio::fs::metadata(&path).await.unwrap();
        let bytes = tokio::fs::read(&path).await.unwrap();

        assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
        assert!(bytes.starts_with(b"PK\x03\x04"));
        assert!(install_java_proxy_agent(runtime.path()).await.is_err());
    }

    #[test]
    fn dedicated_output_directory_refuses_symlinks() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join("target")).unwrap();
        assert!(ensure_child_directory(project.path(), c"target").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "synchronous filesystem setup is isolated to this launcher helper unit test"
    )]
    fn literal_write_targets_only_create_the_selected_managers_lockfile() {
        let project = tempfile::tempdir().unwrap();
        let profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, Path::new("/home/test"), project.path());
        let lockfile = project.path().join("Cargo.lock");
        ensure_literal_write_targets(
            &profile,
            &["/usr/bin/cargo".to_owned(), "build".to_owned()],
            project.path(),
        )
        .unwrap();
        assert!(lockfile.is_file());

        let profile =
            SandboxProfile::for_ecosystem(Ecosystem::Node, Path::new("/home/test"), project.path());
        ensure_literal_write_targets(
            &profile,
            &["npm".to_owned(), "install".to_owned()],
            project.path(),
        )
        .unwrap();
        assert!(project.path().join("package-lock.json").is_file());
        assert!(!project.path().join("yarn.lock").exists());
        assert!(!project.path().join("pnpm-lock.yaml").exists());
        assert!(!project.path().join("bun.lock").exists());
        assert!(!project.path().join(".pnp.cjs").exists());

        let bun_project = tempfile::tempdir().unwrap();
        let bun_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            bun_project.path(),
        );
        ensure_literal_write_targets(
            &bun_profile,
            &["bun".to_owned(), "install".to_owned()],
            bun_project.path(),
        )
        .unwrap();
        assert!(bun_project.path().join("bun.lock").is_file());
        assert!(!bun_project.path().join("package-lock.json").exists());
        assert!(!bun_project.path().join("yarn.lock").exists());
        assert!(!bun_project.path().join("pnpm-lock.yaml").exists());

        let bun_yarn_project = tempfile::tempdir().unwrap();
        let bun_yarn_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            bun_yarn_project.path(),
        );
        ensure_literal_write_targets(
            &bun_yarn_profile,
            &["bun".to_owned(), "install".to_owned(), "--yarn".to_owned()],
            bun_yarn_project.path(),
        )
        .unwrap();
        assert!(bun_yarn_project.path().join("bun.lock").is_file());
        assert!(bun_yarn_project.path().join("yarn.lock").is_file());
        assert!(!bun_yarn_project.path().join("package-lock.json").exists());
        assert!(!bun_yarn_project.path().join("pnpm-lock.yaml").exists());

        let frozen_bun_project = tempfile::tempdir().unwrap();
        let frozen_bun_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            frozen_bun_project.path(),
        );
        ensure_literal_write_targets(
            &frozen_bun_profile,
            &[
                "bun".to_owned(),
                "install".to_owned(),
                "--frozen-lockfile".to_owned(),
            ],
            frozen_bun_project.path(),
        )
        .unwrap();
        assert!(!frozen_bun_project.path().join("bun.lock").exists());

        let informational_bun_project = tempfile::tempdir().unwrap();
        let informational_bun_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            informational_bun_project.path(),
        );
        ensure_literal_write_targets(
            &informational_bun_profile,
            &["bun".to_owned(), "--help".to_owned(), "install".to_owned()],
            informational_bun_project.path(),
        )
        .unwrap();
        assert!(!informational_bun_project.path().join("bun.lock").exists());

        let read_only_project = tempfile::tempdir().unwrap();
        let profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            read_only_project.path(),
        );
        ensure_literal_write_targets(
            &profile,
            &["npm".to_owned(), "--version".to_owned()],
            read_only_project.path(),
        )
        .unwrap();
        assert!(!read_only_project.path().join("package-lock.json").exists());

        let relocated_project = tempfile::tempdir().unwrap();
        let relocated_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            relocated_project.path(),
        );
        assert!(
            ensure_literal_write_targets(
                &relocated_profile,
                &[
                    "npm".to_owned(),
                    "--prefix".to_owned(),
                    "subproject".to_owned(),
                    "install".to_owned(),
                ],
                relocated_project.path(),
            )
            .is_err()
        );
        assert!(!relocated_project.path().join("package-lock.json").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "synchronous filesystem setup is isolated to this launcher helper unit test"
    )]
    fn literal_write_targets_select_one_node_workspace_root() {
        let repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(repository.path().join(".git")).unwrap();
        let workspace = repository.path().join("frontend");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(
            workspace.join("package.json"),
            r#"{"name":"workspace","workspaces":["packages/*"]}"#,
        )
        .unwrap();
        let member = workspace.join("packages/app");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("package.json"), r#"{"name":"app"}"#).unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Node, Path::new("/home/test"), &member);
        configure_node_workspace(
            &mut profile,
            &["npm".to_owned(), "install".to_owned()],
            &member,
        )
        .unwrap();
        ensure_literal_write_targets(&profile, &["npm".to_owned(), "install".to_owned()], &member)
            .unwrap();
        assert!(workspace.join("package-lock.json").is_file());
        assert!(!member.join("package-lock.json").exists());
        assert!(!repository.path().join("package-lock.json").exists());
        assert!(
            profile
                .allow_write
                .contains(&SandboxPath::dir(workspace.join("node_modules")))
        );
        assert!(
            !profile
                .allow_write
                .contains(&SandboxPath::file(workspace.join("yarn.lock")))
        );
        assert!(
            !profile
                .allow_write
                .contains(&SandboxPath::dir(repository.path().join("node_modules")))
        );

        let standalone_repository = tempfile::tempdir().unwrap();
        std::fs::create_dir(standalone_repository.path().join(".git")).unwrap();
        std::fs::write(
            standalone_repository.path().join("package.json"),
            r#"{"name":"unrelated-root"}"#,
        )
        .unwrap();
        let standalone = standalone_repository.path().join("nested");
        std::fs::create_dir(&standalone).unwrap();
        std::fs::write(standalone.join("package.json"), r#"{"name":"standalone"}"#).unwrap();
        let mut standalone_profile =
            SandboxProfile::for_ecosystem(Ecosystem::Node, Path::new("/home/test"), &standalone);
        configure_node_workspace(
            &mut standalone_profile,
            &["npm".to_owned(), "install".to_owned()],
            &standalone,
        )
        .unwrap();
        ensure_literal_write_targets(
            &standalone_profile,
            &["npm".to_owned(), "install".to_owned()],
            &standalone,
        )
        .unwrap();
        assert!(standalone.join("package-lock.json").is_file());
        assert!(
            !standalone_repository
                .path()
                .join("package-lock.json")
                .exists()
        );

        assert!(workspace_glob_matches_prefix(
            "packages/*",
            "packages/app/src"
        ));
        assert!(!workspace_glob_matches_prefix("examples/*", "packages/app"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "synchronous filesystem setup is isolated to this launcher helper unit test"
    )]
    fn literal_write_targets_handle_aliases_defaults_and_nested_commands() {
        let npm_project = tempfile::tempdir().unwrap();
        let npm_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            npm_project.path(),
        );
        ensure_literal_write_targets(
            &npm_profile,
            &["npm".to_owned(), "i".to_owned()],
            npm_project.path(),
        )
        .unwrap();
        assert!(npm_project.path().join("package-lock.json").is_file());

        for command in [
            vec!["npm", "install", "--no-package-lock"],
            vec!["npm", "install", "--package-lock=false"],
            vec!["npm", "install", "--package-lock", "false"],
        ] {
            let no_lock_project = tempfile::tempdir().unwrap();
            let no_lock_profile = SandboxProfile::for_ecosystem(
                Ecosystem::Node,
                Path::new("/home/test"),
                no_lock_project.path(),
            );
            let command: Vec<String> = command.into_iter().map(str::to_owned).collect();
            ensure_literal_write_targets(&no_lock_profile, &command, no_lock_project.path())
                .unwrap();
            assert!(!no_lock_project.path().join("package-lock.json").exists());
        }

        let yarn_project = tempfile::tempdir().unwrap();
        let yarn_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            yarn_project.path(),
        );
        ensure_literal_write_targets(&yarn_profile, &["yarn".to_owned()], yarn_project.path())
            .unwrap();
        assert!(yarn_project.path().join("yarn.lock").is_file());
        assert!(!yarn_project.path().join(".pnp.cjs").exists());

        let modern_yarn_project = tempfile::tempdir().unwrap();
        std::fs::write(
            modern_yarn_project.path().join("package.json"),
            r#"{"name":"modern","packageManager":"yarn@4.9.2"}"#,
        )
        .unwrap();
        let modern_yarn_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            modern_yarn_project.path(),
        );
        ensure_literal_write_targets(
            &modern_yarn_profile,
            &["yarn".to_owned(), "install".to_owned()],
            modern_yarn_project.path(),
        )
        .unwrap();
        assert!(modern_yarn_project.path().join("yarn.lock").is_file());
        assert!(modern_yarn_project.path().join(".pnp.cjs").is_file());
        assert!(!modern_yarn_project.path().join(".pnp.loader.mjs").exists());

        let esm_yarn_project = tempfile::tempdir().unwrap();
        std::fs::write(
            esm_yarn_project.path().join(".yarnrc.yml"),
            "pnpEnableEsmLoader: true\n",
        )
        .unwrap();
        let esm_yarn_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            esm_yarn_project.path(),
        );
        ensure_literal_write_targets(
            &esm_yarn_profile,
            &["yarn".to_owned()],
            esm_yarn_project.path(),
        )
        .unwrap();
        assert!(esm_yarn_project.path().join(".pnp.cjs").is_file());
        assert!(esm_yarn_project.path().join(".pnp.loader.mjs").is_file());

        let node_modules_yarn_project = tempfile::tempdir().unwrap();
        std::fs::write(
            node_modules_yarn_project.path().join(".yarnrc.yml"),
            "nodeLinker: node-modules\n",
        )
        .unwrap();
        let node_modules_yarn_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            node_modules_yarn_project.path(),
        );
        ensure_literal_write_targets(
            &node_modules_yarn_profile,
            &["yarn".to_owned(), "install".to_owned()],
            node_modules_yarn_project.path(),
        )
        .unwrap();
        assert!(node_modules_yarn_project.path().join("yarn.lock").is_file());
        assert!(!node_modules_yarn_project.path().join(".pnp.cjs").exists());

        let yarn_info_project = tempfile::tempdir().unwrap();
        let yarn_info_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            yarn_info_project.path(),
        );
        ensure_literal_write_targets(
            &yarn_info_profile,
            &["yarn".to_owned(), "--version".to_owned()],
            yarn_info_project.path(),
        )
        .unwrap();
        assert!(!yarn_info_project.path().join("yarn.lock").exists());

        let read_only_node = tempfile::tempdir().unwrap();
        let node_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Node,
            Path::new("/home/test"),
            read_only_node.path(),
        );
        ensure_literal_write_targets(
            &node_profile,
            &["npm".to_owned(), "view".to_owned(), "install".to_owned()],
            read_only_node.path(),
        )
        .unwrap();
        assert!(!read_only_node.path().join("package-lock.json").exists());
        ensure_literal_write_targets(
            &node_profile,
            &[
                "npm".to_owned(),
                "--future-option".to_owned(),
                "install".to_owned(),
                "view".to_owned(),
            ],
            read_only_node.path(),
        )
        .unwrap();
        assert!(!read_only_node.path().join("package-lock.json").exists());

        let python_project = tempfile::tempdir().unwrap();
        let python_profile = SandboxProfile::for_ecosystem(
            Ecosystem::Python,
            Path::new("/home/test"),
            python_project.path(),
        );
        ensure_literal_write_targets(
            &python_profile,
            &["uv".to_owned(), "pip".to_owned(), "install".to_owned()],
            python_project.path(),
        )
        .unwrap();
        ensure_literal_write_targets(
            &python_profile,
            &["poetry".to_owned(), "run".to_owned(), "install".to_owned()],
            python_project.path(),
        )
        .unwrap();
        assert!(!python_project.path().join("uv.lock").exists());
        assert!(!python_project.path().join("poetry.lock").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "synchronous filesystem setup is isolated to this launcher helper unit test"
    )]
    fn literal_write_targets_refuse_symlinked_parents_and_files() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join("redirect")).unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, Path::new("/home/test"), project.path());
        profile.allow_write = vec![SandboxPath::file(project.path().join("redirect/lock"))];
        profile.first_user_allow_write = 0;
        assert!(
            ensure_literal_write_targets(
                &profile,
                &["cargo".to_owned(), "build".to_owned()],
                project.path(),
            )
            .is_err()
        );

        let target = project.path().join("real-lock");
        std::fs::write(&target, "sentinel").unwrap();
        let link = project.path().join("Cargo.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        profile.allow_write = vec![SandboxPath::file(link)];
        assert!(
            ensure_literal_write_targets(
                &profile,
                &["cargo".to_owned(), "build".to_owned()],
                project.path(),
            )
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(target).unwrap(), "sentinel");
    }
}
