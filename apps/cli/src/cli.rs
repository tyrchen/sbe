use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// sbe — Run commands in a macOS sandbox with supply chain attack protection.
///
/// Wraps any command in a macOS sandbox-exec sandbox with sensible defaults
/// per language ecosystem (Node.js, Rust, Python, Elixir, Java).
#[derive(Debug, Parser)]
#[command(name = "sbe", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Execute a command inside the sandbox.
    Run(RunArgs),

    /// Print resolved config and generated SBPL without executing.
    Inspect(InspectArgs),

    /// List available profiles and their defaults.
    Profiles,
}

/// Arguments shared between `run` and `inspect`.
#[derive(Debug, Parser)]
pub struct RunArgs {
    /// Use a specific profile (overrides auto-detect).
    #[arg(short = 'p', long)]
    pub profile: Option<String>,

    /// Add domain to network allowlist (repeatable).
    #[arg(short = 'n', long = "allow-domain", action = clap::ArgAction::Append)]
    pub allow_domain: Vec<String>,

    /// Remove domain from network allowlist (repeatable).
    #[arg(short = 'N', long = "deny-domain", action = clap::ArgAction::Append)]
    pub deny_domain: Vec<String>,

    /// Add writable path (repeatable).
    #[arg(short = 'w', long = "allow-write", action = clap::ArgAction::Append)]
    pub allow_write: Vec<PathBuf>,

    /// Add read-denied path (repeatable).
    #[arg(short = 'r', long = "deny-read", action = clap::ArgAction::Append)]
    pub deny_read: Vec<PathBuf>,

    /// Allow execution of binary (repeatable).
    #[arg(short = 'e', long = "allow-exec", action = clap::ArgAction::Append)]
    pub allow_exec: Vec<PathBuf>,

    /// Deny execution of binary (repeatable).
    #[arg(short = 'E', long = "deny-exec", action = clap::ArgAction::Append)]
    pub deny_exec: Vec<PathBuf>,

    /// Disable network sandboxing entirely.
    #[arg(long)]
    pub allow_all_network: bool,

    /// Disable proxy (use SBPL-only network rules).
    #[arg(long)]
    pub no_proxy: bool,

    /// Stream sandbox violations to stderr.
    #[arg(long)]
    pub audit: bool,

    /// Write violations to file.
    #[arg(long)]
    pub audit_log: Option<PathBuf>,

    /// Print SBPL to stdout, do not execute.
    #[arg(long)]
    pub dry_run: bool,

    /// Use specific config file.
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,

    /// Verbose output.
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// The command and arguments to run inside the sandbox.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct InspectArgs {
    /// Use a specific profile (overrides auto-detect).
    #[arg(short = 'p', long)]
    pub profile: Option<String>,

    /// Add domain to network allowlist (repeatable).
    #[arg(short = 'n', long = "allow-domain", action = clap::ArgAction::Append)]
    pub allow_domain: Vec<String>,

    /// Remove domain from network allowlist (repeatable).
    #[arg(short = 'N', long = "deny-domain", action = clap::ArgAction::Append)]
    pub deny_domain: Vec<String>,

    /// Add writable path (repeatable).
    #[arg(short = 'w', long = "allow-write", action = clap::ArgAction::Append)]
    pub allow_write: Vec<PathBuf>,

    /// Add read-denied path (repeatable).
    #[arg(short = 'r', long = "deny-read", action = clap::ArgAction::Append)]
    pub deny_read: Vec<PathBuf>,

    /// Allow execution of binary (repeatable).
    #[arg(short = 'e', long = "allow-exec", action = clap::ArgAction::Append)]
    pub allow_exec: Vec<PathBuf>,

    /// Deny execution of binary (repeatable).
    #[arg(short = 'E', long = "deny-exec", action = clap::ArgAction::Append)]
    pub deny_exec: Vec<PathBuf>,

    /// Disable network sandboxing entirely.
    #[arg(long)]
    pub allow_all_network: bool,

    /// Disable proxy (use SBPL-only network rules).
    #[arg(long)]
    pub no_proxy: bool,

    /// Use specific config file.
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,

    /// The command and arguments to inspect.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

impl InspectArgs {
    /// Convert inspect args into equivalent run args for profile resolution.
    pub fn as_run_args(&self) -> RunArgs {
        RunArgs {
            profile: self.profile.clone(),
            allow_domain: self.allow_domain.clone(),
            deny_domain: self.deny_domain.clone(),
            allow_write: self.allow_write.clone(),
            deny_read: self.deny_read.clone(),
            allow_exec: self.allow_exec.clone(),
            deny_exec: self.deny_exec.clone(),
            allow_all_network: self.allow_all_network,
            no_proxy: self.no_proxy,
            audit: false,
            audit_log: None,
            dry_run: true,
            config: self.config.clone(),
            verbose: false,
            command: self.command.clone(),
        }
    }
}
