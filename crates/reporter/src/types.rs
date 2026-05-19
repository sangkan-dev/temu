use std::collections::HashMap;

use chrono::{DateTime, Utc};
use fingerprint::TechStack;
use serde::{Deserialize, Serialize};
use temu_core::{Asset, Severity, Vulnerability};

/// Complete output of one scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Domain / URL that was scanned.
    pub target: String,
    /// All discovered assets (subdomains, paths).
    pub assets: Vec<Asset>,
    /// Technology stacks detected per URL.
    pub tech_stacks: HashMap<String, Vec<TechStack>>,
    /// All confirmed vulnerabilities.
    pub vulnerabilities: Vec<Vulnerability>,
    /// Per-target summaries for aggregate multi-target reports.
    #[serde(default)]
    pub target_summaries: Vec<TargetSummary>,
    pub scan_started_at: DateTime<Utc>,
    pub scan_finished_at: DateTime<Utc>,
    pub stats: ScanStats,
}

/// Summary for one target inside a multi-target aggregate report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSummary {
    pub target: String,
    pub assets_total: usize,
    pub vulnerabilities_total: usize,
    pub highest_severity: Option<Severity>,
    pub duration_secs: f64,
}

/// High-level counters for the scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub subdomains_found: u32,
    pub paths_found: u32,
    pub parameters_found: u32,
    pub vulns_found: u32,
    pub duration_secs: f64,
}
