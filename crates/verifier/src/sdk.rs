use temu_core::{AppConfig, Vulnerability};
use vulnerability::Rule;

use crate::VerifyResult;

/// Compile-time extension point for custom verifier modules.
pub trait VerifierModule {
    /// Stable module identifier used in diagnostics.
    fn id(&self) -> &'static str;

    /// Returns true when this module can verify `vulnerability`.
    fn supports(&self, vulnerability: &Vulnerability, rule: Option<&Rule>) -> bool;

    /// Verifies one finding using module-specific logic.
    fn verify(
        &self,
        vulnerability: &Vulnerability,
        rule: Option<&Rule>,
        config: &AppConfig,
    ) -> VerifyResult;
}
