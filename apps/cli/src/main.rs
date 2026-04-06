mod audit;
mod cli;
mod executor;

use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Commands};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Determine log level
    let verbose = matches!(&cli.command, Commands::Run(args) if args.verbose);
    let filter = if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::Run(args) => executor::execute(&args).await,
        Commands::Inspect(args) => {
            let run_args = args.as_run_args();
            executor::execute(&run_args).await
        }
        Commands::Profiles => {
            executor::print_profiles();
            ExitCode::SUCCESS
        }
    }
}
