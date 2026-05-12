//! sbe-core: Core library for the sbe sandbox executor.
//!
//! Provides profile definitions, ecosystem detection, configuration loading,
//! and the [`sandbox`] backend abstraction used to enforce policies on the
//! host. Backends are selected at compile time per target OS; outside this
//! crate, callers reference the alias `sandbox::Sandbox` rather than the
//! concrete backend type.

pub mod config;
pub mod detect;
pub mod error;
pub mod profile;
pub mod sandbox;

pub use sandbox::{BackendFeatures, BackendInfo, BackendOptions, Sandbox, SandboxBackend};
