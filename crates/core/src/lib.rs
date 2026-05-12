// Core crate — shared types, configuration, logging, and error handling.
// All other crates in the workspace depend on this crate.

pub mod config;
pub mod error;
pub mod logging;
pub mod types;

pub use config::AppConfig;
pub use error::TemuError;
pub use types::{Asset, AssetType, Scope, Severity, Target, Vulnerability};
