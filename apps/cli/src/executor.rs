use std::{
    collections::HashMap,
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
    process::ExitCode,
};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sbe_core::{
    BackendOptions, Sandbox, SandboxBackend,
    config::{SandboxPath, expand_path, load_configs, resolve_profile},
    detect::{self, Ecosystem},
    error::CoreError,
    profile::{
        DomainPattern, GrantKind, GrantOrigin, GrantRecord, NetworkMode, ProfileOverrides,
        SandboxProfile,
    },
};
use sbe_proxy::{ProxyEndpoint, ProxyServer, allowlist::DomainAllowlist};
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::cli::RunArgs;

/// sbe exit codes for its own errors (matching docker run / env conventions).
const EXIT_SBE_ERROR: u8 = 125;
const EXIT_SANDBOX_FAILED: u8 = 126;

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

    // Determine ecosystem
    let command_name = &args.command[0];
    let ecosystem = resolve_ecosystem(command_name, &args.profile, &pwd)?;

    info!(ecosystem = %ecosystem, command = %command_name, "detected ecosystem");

    // Build and resolve profile
    let mut profile = SandboxProfile::for_ecosystem(ecosystem, &home, &pwd);
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

    // Cargo atomically initializes a missing target directory through a
    // sibling `targetXXXXXX` path. Creating the fixed output root before the
    // untrusted command avoids granting a broad `target*` write pattern.
    if !args.dry_run {
        if ecosystem == Ecosystem::Rust {
            ensure_child_directory(&pwd, c"target")?;
        }
        #[cfg(target_os = "linux")]
        ensure_literal_write_targets(&profile)?;
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
    profile.validate_security_invariants()?;

    // Construct backend (kernel probe runs once here).
    let backend_options = BackendOptions {
        allow_degraded: cli_allow_degraded,
        allow_insecure_network: args.allow_insecure_linux_network || cli_allow_degraded,
    };
    let backend = Sandbox::new_with_options(backend_options).map_err(|e| anyhow::anyhow!("{e}"))?;
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
        &pwd,
    )
    .await?;

    // Dry run / inspect: print policy and exit
    if args.dry_run {
        print_inspect_output(&profile, &backend, proxy_port, &extra_env)?;
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
    project_dir: &Path,
) -> anyhow::Result<HashMap<String, String>> {
    let mut env = filter_parent_environment(std::env::vars());
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
    match profile_name.as_str() {
        "rust" => {
            insert_runtime_environment(
                profile,
                &mut env,
                "CARGO_TARGET_DIR",
                project_dir.join("target").to_string_lossy().into_owned(),
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
        "python" => {
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
        "elixir" => {
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
        "java" => {
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
        _ => {}
    }
    if let Some(endpoint) = proxy_endpoint {
        let proxy_url = endpoint.url();
        insert_runtime_environment(profile, &mut env, "HTTP_PROXY", proxy_url.clone());
        insert_runtime_environment(profile, &mut env, "HTTPS_PROXY", proxy_url.clone());
        insert_runtime_environment(profile, &mut env, "http_proxy", proxy_url.clone());
        insert_runtime_environment(profile, &mut env, "https_proxy", proxy_url);
        insert_runtime_environment(profile, &mut env, "NO_PROXY", String::new());
        insert_runtime_environment(profile, &mut env, "no_proxy", String::new());
        if profile.name == "java" {
            let agent_path = install_java_proxy_agent(runtime_temp).await?;
            for (name, value) in endpoint.java_environment(&agent_path, &temp) {
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

fn filter_parent_environment<I>(variables: I) -> HashMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    variables
        .into_iter()
        .filter(|(name, _)| SAFE_PARENT_ENV.contains(&name.as_str()))
        .collect()
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
/// requires directory-wide `MakeReg`. Pre-create only the explicitly listed
/// literal outputs through a no-symlink parent descriptor so fresh lockfiles
/// work without broadening source-directory authority.
#[cfg(target_os = "linux")]
fn ensure_literal_write_targets(profile: &SandboxProfile) -> anyhow::Result<()> {
    use sbe_core::config::PathKind;
    use std::os::fd::OwnedFd;

    for target in &profile.allow_write {
        if target.kind != PathKind::Literal {
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
) -> anyhow::Result<()> {
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
        let inherited = filter_parent_environment([
            ("PATH".to_owned(), "/usr/bin".to_owned()),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
            ("GITHUB_TOKEN".to_owned(), "sentinel".to_owned()),
            ("AWS_SECRET_ACCESS_KEY".to_owned(), "sentinel".to_owned()),
            ("SSH_AUTH_SOCK".to_owned(), "/tmp/agent".to_owned()),
            ("NPM_TOKEN".to_owned(), "sentinel".to_owned()),
        ]);
        assert_eq!(inherited.len(), 2);
        assert_eq!(inherited.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert!(!inherited.values().any(|value| value == "sentinel"));
    }

    #[tokio::test]
    async fn java_runtime_isolates_sbt_state() {
        let project = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Java, Path::new("/home/test"), project.path());

        let environment = build_extra_env(&mut profile, None, runtime.path(), project.path())
            .await
            .unwrap();
        let sbt_options = environment.get("SBT_OPTS").unwrap();

        assert!(sbt_options.contains("-Dsbt.boot.directory="));
        assert!(sbt_options.contains("-Dsbt.ivy.home="));
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
    fn literal_write_targets_are_created_without_broad_parent_grants() {
        let project = tempfile::tempdir().unwrap();
        let mut profile =
            SandboxProfile::for_ecosystem(Ecosystem::Rust, Path::new("/home/test"), project.path());
        let lockfile = project.path().join("Cargo.lock");
        profile.allow_write = vec![SandboxPath::file(lockfile.clone())];
        ensure_literal_write_targets(&profile).unwrap();
        assert!(lockfile.is_file());
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
        assert!(ensure_literal_write_targets(&profile).is_err());

        let target = project.path().join("real-lock");
        std::fs::write(&target, "sentinel").unwrap();
        let link = project.path().join("Cargo.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        profile.allow_write = vec![SandboxPath::file(link)];
        assert!(ensure_literal_write_targets(&profile).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "sentinel");
    }
}
