use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use temu_core::Severity;

/// Exploitability context used for risk prioritization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exploitability {
    KnownExploited,
    PocAvailable,
    Theoretical,
}

impl Exploitability {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Exploitability::KnownExploited => "known_exploited",
            Exploitability::PocAvailable => "poc_available",
            Exploitability::Theoretical => "theoretical",
        }
    }

    pub(crate) fn from_str(value: &str) -> Self {
        match value {
            "known_exploited" => Exploitability::KnownExploited,
            "poc_available" => Exploitability::PocAvailable,
            _ => Exploitability::Theoretical,
        }
    }
}

/// A normalized CVE entry stored in the local SQLite cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub cve_id: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: f32,
    pub cpe_match: Vec<String>,
    pub published_date: Option<String>,
    pub last_modified: Option<String>,
    pub exploitability: Exploitability,
    /// EPSS probability in the range 0.0 to 1.0, when supplied by FIRST.
    #[serde(default)]
    pub epss_score: Option<f32>,
    pub source: String,
    pub cached_at: DateTime<Utc>,
}

impl CveEntry {
    /// Calculates a triage score using exploitation evidence, EPSS, and CVSS.
    pub fn priority_score(&self) -> f32 {
        let exploitation_boost = match self.exploitability {
            Exploitability::KnownExploited => 100.0,
            Exploitability::PocAvailable => 30.0,
            Exploitability::Theoretical => 0.0,
        };
        exploitation_boost + self.epss_score.unwrap_or(0.0) * 50.0 + self.cvss_score
    }
}
