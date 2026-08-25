mod audit;
mod cli;
mod executor;

use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Commands};

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    if let Some(code) = sbe_core::maybe_run_launcher() {
        return code;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("sbe: failed to start runtime: {error}");
            return ExitCode::from(125);
        }
    };
    runtime.block_on(async_main())
}

async fn async_main() -> ExitCode {
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
        Commands::Profiles => match executor::print_profiles() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sbe: {e:#}");
                ExitCode::from(125)
            }
        },
    }
}
