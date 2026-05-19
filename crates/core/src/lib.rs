// Core crate — shared types, configuration, logging, and error handling.
// All other crates in the workspace depend on this crate.

pub mod config;
pub mod error;
pub mod logging;
pub mod macros;
pub mod resilience;
pub mod types;

pub use config::AppConfig;
pub use error::TemuError;
pub use logging::{init_logging, init_logging_with_file};
pub use resilience::{AdaptiveRateLimiter, ResilienceMetrics, retry_delay};
pub use types::{Asset, AssetType, Scope, Severity, Target, Vulnerability};
