use std::collections::HashMap;

use chrono::{DateTime, Utc};
use fingerprint::TechStack;
use serde::{Deserialize, Serialize};
use temu_core::{Asset, ServiceEvidence, Severity, Vulnerability};

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
    /// Protocol-aware evidence collected from reachable TCP services.
    #[serde(default)]
    pub services: Vec<ServiceEvidence>,
    /// Per-target summaries for aggregate multi-target reports.
    #[serde(default)]
    pub target_summaries: Vec<TargetSummary>,
    /// OAST/collaborator callback events associated with this scan.
    #[serde(default)]
    pub callback_events: Vec<CallbackEvent>,
    pub scan_started_at: DateTime<Utc>,
    pub scan_finished_at: DateTime<Utc>,
    pub stats: ScanStats,
}

/// One callback event captured by `temu collaborator serve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackEvent {
    pub correlation_id: String,
    pub protocol: String,
    pub method: String,
    pub path: String,
    pub remote_addr: String,
    pub user_agent: Option<String>,
    pub received_at: DateTime<Utc>,
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
