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
    pub source: String,
    pub cached_at: DateTime<Utc>,
}
