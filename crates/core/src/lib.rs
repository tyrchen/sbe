//! sbe-core: Core library for the sbe macOS sandbox executor.
//!
//! Provides profile definitions, ecosystem detection, SBPL generation,
//! and configuration loading for the sbe CLI.

pub mod config;
pub mod detect;
pub mod error;
pub mod profile;
pub mod sbpl;
