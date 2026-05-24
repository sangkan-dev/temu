use reqwest::header::HeaderMap;

use crate::types::TechStack;

/// Compile-time extension point for custom fingerprint modules.
pub trait FingerprintModule {
    /// Stable module identifier used in diagnostics.
    fn id(&self) -> &'static str;

    /// Detects technologies from response headers and a bounded response body.
    fn detect(&self, headers: &HeaderMap, body: &str) -> Vec<TechStack>;
}
