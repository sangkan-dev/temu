use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use temu_core::{Severity, TemuError, Vulnerability};
use tracing::info;

use crate::graph::build_asset_graph;
use crate::types::ScanResult;

/// Operator-defined suppression for an accepted or temporarily ignored finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRule {
    pub finding_id: String,
    #[serde(default)]
    pub url_contains: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// A suppressed finding and the operator rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedFinding {
    pub finding_id: String,
    pub url: String,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
struct TomlSuppressionFile {
    #[serde(default)]
    suppression: Vec<SuppressionRule>,
}

/// Baseline classification for one finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    New,
    Fixed,
    Unchanged,
    SeverityChanged,
}

/// One finding relationship across scan runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDiff {
    pub key: String,
    pub status: DiffStatus,
    pub finding_id: String,
    pub url: String,
    pub previous_severity: Option<Severity>,
    pub current_severity: Option<Severity>,
}

/// Comparison of a previous report to a current report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiff {
    pub baseline_target: String,
    pub current_target: String,
    pub generated_at: DateTime<Utc>,
    pub findings: Vec<FindingDiff>,
    pub suppressed: Vec<SuppressedFinding>,
    pub new_count: usize,
    pub fixed_count: usize,
    pub unchanged_count: usize,
    pub severity_changed_count: usize,
}

/// Historical point shown in trend output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPoint {
    pub scan_started_at: String,
    pub vulnerabilities: u32,
    pub assets: usize,
    pub cve_findings: usize,
    pub duration_secs: f64,
}

/// Loads suppression rules from TOML, JSON, or YAML.
pub fn load_suppressions(path: &Path) -> Result<Vec<SuppressionRule>, TemuError> {
    let content = std::fs::read_to_string(path).map_err(TemuError::Io)?;
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => serde_json::from_str(&content)
            .map_err(|error| TemuError::Parse(format!("Invalid suppression JSON: {error}"))),
        Some("yaml" | "yml") => serde_yaml::from_str(&content)
            .map_err(|error| TemuError::Parse(format!("Invalid suppression YAML: {error}"))),
        _ => toml::from_str::<TomlSuppressionFile>(&content)
            .map(|file| file.suppression)
            .map_err(|error| TemuError::Parse(format!("Invalid suppression TOML: {error}"))),
    }
}

/// Compares a current scan with a previous baseline while applying active suppressions.
pub fn compare_reports(
    baseline: &ScanResult,
    current: &ScanResult,
    suppressions: &[SuppressionRule],
) -> BaselineDiff {
    let baseline_map = finding_map(&baseline.vulnerabilities);
    let mut current_map = finding_map(&current.vulnerabilities);
    let now = Utc::now();
    let mut suppressed = Vec::new();
    let active_suppression_keys = current_map
        .iter()
        .filter_map(|(key, finding)| {
            suppressions
                .iter()
                .find(|suppression| suppression_matches(suppression, finding, now))
                .map(|_| key.clone())
        })
        .collect::<BTreeSet<_>>();
    current_map.retain(|_, finding| {
        let suppression = suppressions
            .iter()
            .find(|suppression| suppression_matches(suppression, finding, now));
        if let Some(suppression) = suppression {
            suppressed.push(SuppressedFinding {
                finding_id: finding.id.clone(),
                url: finding.url.clone(),
                reason: suppression.reason.clone(),
                expires_at: suppression.expires_at,
            });
            false
        } else {
            true
        }
    });
    let baseline_map = baseline_map
        .into_iter()
        .filter(|(key, _)| !active_suppression_keys.contains(key))
        .collect::<BTreeMap<_, _>>();

    let keys = baseline_map
        .keys()
        .chain(current_map.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();
    for key in keys {
        let before = baseline_map.get(&key);
        let after = current_map.get(&key);
        let status = match (before, after) {
            (None, Some(_)) => DiffStatus::New,
            (Some(_), None) => DiffStatus::Fixed,
            (Some(left), Some(right)) if left.severity != right.severity => {
                DiffStatus::SeverityChanged
            }
            (Some(_), Some(_)) => DiffStatus::Unchanged,
            (None, None) => continue,
        };
        let Some(finding) = after.or(before) else {
            continue;
        };
        findings.push(FindingDiff {
            key,
            status,
            finding_id: finding.id.clone(),
            url: finding.url.clone(),
            previous_severity: before.map(|finding| finding.severity.clone()),
            current_severity: after.map(|finding| finding.severity.clone()),
        });
    }

    BaselineDiff {
        baseline_target: baseline.target.clone(),
        current_target: current.target.clone(),
        generated_at: now,
        new_count: findings
            .iter()
            .filter(|finding| matches!(finding.status, DiffStatus::New))
            .count(),
        fixed_count: findings
            .iter()
            .filter(|finding| matches!(finding.status, DiffStatus::Fixed))
            .count(),
        unchanged_count: findings
            .iter()
            .filter(|finding| matches!(finding.status, DiffStatus::Unchanged))
            .count(),
        severity_changed_count: findings
            .iter()
            .filter(|finding| matches!(finding.status, DiffStatus::SeverityChanged))
            .count(),
        findings,
        suppressed,
    }
}

/// Writes baseline comparison output as JSON.
pub fn generate_diff_json(diff: &BaselineDiff, output_dir: &Path) -> Result<PathBuf, TemuError> {
    std::fs::create_dir_all(output_dir).map_err(TemuError::Io)?;
    let path = output_dir.join(format!(
        "{}_{}_diff.json",
        diff.generated_at.format("%Y-%m-%d"),
        sanitize_target(&diff.current_target)
    ));
    write_pretty_json(&path, diff)?;
    Ok(path)
}

/// Records one scan run to the local trend history database.
pub fn record_scan_history(result: &ScanResult, output_dir: &Path) -> Result<PathBuf, TemuError> {
    let cache_dir = output_dir.join(".cache");
    std::fs::create_dir_all(&cache_dir).map_err(TemuError::Io)?;
    let path = cache_dir.join("scan_history.sqlite");
    let conn = Connection::open(&path)
        .map_err(|error| TemuError::Parse(format!("Failed to open history cache: {error}")))?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS scan_history (
            target TEXT NOT NULL,
            scan_started_at TEXT NOT NULL,
            vulnerabilities INTEGER NOT NULL,
            assets INTEGER NOT NULL,
            cve_findings INTEGER NOT NULL,
            duration_secs REAL NOT NULL,
            PRIMARY KEY (target, scan_started_at)
        );
        "#,
    )
    .map_err(|error| TemuError::Parse(format!("Failed to initialize history cache: {error}")))?;
    let cve_findings = result
        .vulnerabilities
        .iter()
        .filter(|finding| finding.id.starts_with("CVE-"))
        .count();
    conn.execute(
        r#"
        INSERT OR REPLACE INTO scan_history
        (target, scan_started_at, vulnerabilities, assets, cve_findings, duration_secs)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![
            result.target,
            result.scan_started_at.to_rfc3339(),
            result.vulnerabilities.len() as i64,
            result.assets.len() as i64,
            cve_findings as i64,
            result.stats.duration_secs
        ],
    )
    .map_err(|error| TemuError::Parse(format!("Failed to write scan history: {error}")))?;
    Ok(path)
}

/// Writes target history as a JSON trend artifact for dashboards.
pub fn generate_trend_json(result: &ScanResult, output_dir: &Path) -> Result<PathBuf, TemuError> {
    let points = load_trend_points(result, output_dir)?;
    let path = output_dir.join(format!(
        "{}_{}_trend.json",
        result.scan_started_at.format("%Y-%m-%d"),
        sanitize_target(&result.target)
    ));
    write_pretty_json(&path, &points)?;
    Ok(path)
}

/// Loads up to 100 historical trend points for one target.
pub fn load_trend_points(
    result: &ScanResult,
    output_dir: &Path,
) -> Result<Vec<TrendPoint>, TemuError> {
    let database = output_dir.join(".cache").join("scan_history.sqlite");
    if !database.exists() {
        return Ok(Vec::new());
    }
    let conn = Connection::open(&database)
        .map_err(|error| TemuError::Parse(format!("Failed to open history cache: {error}")))?;
    let mut statement = conn
        .prepare(
            r#"
            SELECT scan_started_at, vulnerabilities, assets, cve_findings, duration_secs
            FROM scan_history WHERE target = ?1
            ORDER BY scan_started_at ASC LIMIT 100
            "#,
        )
        .map_err(|error| TemuError::Parse(format!("Failed to query scan history: {error}")))?;
    let rows = statement
        .query_map([&result.target], |row| {
            Ok(TrendPoint {
                scan_started_at: row.get(0)?,
                vulnerabilities: row.get::<_, i64>(1)? as u32,
                assets: row.get::<_, i64>(2)? as usize,
                cve_findings: row.get::<_, i64>(3)? as usize,
                duration_secs: row.get(4)?,
            })
        })
        .map_err(|error| TemuError::Parse(format!("Failed to load trend rows: {error}")))?;
    let mut points = Vec::new();
    for row in rows {
        points.push(
            row.map_err(|error| TemuError::Parse(format!("Failed to read trend row: {error}")))?,
        );
    }
    Ok(points)
}

/// Writes a SARIF 2.1.0 report suitable for GitHub code scanning import.
pub fn generate_sarif(result: &ScanResult, output_dir: &Path) -> Result<PathBuf, TemuError> {
    std::fs::create_dir_all(output_dir).map_err(TemuError::Io)?;
    let rules = result
        .vulnerabilities
        .iter()
        .map(|finding| {
            (
                finding.id.clone(),
                json!({
                    "id": finding.id,
                    "name": finding.name,
                    "shortDescription": {"text": finding.name},
                    "properties": {"security-severity": finding.cvss_score.to_string()}
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let results = result
        .vulnerabilities
        .iter()
        .map(|finding| {
            json!({
                "ruleId": finding.id,
                "level": sarif_level(&finding.severity),
                "message": {"text": finding.name},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.url}}}]
            })
        })
        .collect::<Vec<_>>();
    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "Temu", "rules": rules.into_values().collect::<Vec<_>>() }},
            "results": results
        }]
    });
    let path = output_dir.join(format!(
        "{}_{}.sarif",
        result.scan_started_at.format("%Y-%m-%d"),
        sanitize_target(&result.target)
    ));
    write_pretty_json(&path, &sarif)?;
    Ok(path)
}

/// Writes a Markdown remediation summary suitable for tickets or pull requests.
pub fn generate_markdown(result: &ScanResult, output_dir: &Path) -> Result<PathBuf, TemuError> {
    std::fs::create_dir_all(output_dir).map_err(TemuError::Io)?;
    let graph = build_asset_graph(result);
    let mut markdown = format!(
        "# Temu Remediation Summary\n\nTarget: `{}`\n\nFindings: {} | Assets: {}\n\n## Prioritized Actions\n\n",
        result.target,
        result.vulnerabilities.len(),
        result.assets.len()
    );
    if graph.top_remediation_actions.is_empty() {
        markdown.push_str("No remediation actions recorded.\n");
    } else {
        for (index, action) in graph.top_remediation_actions.iter().enumerate() {
            markdown.push_str(&format!(
                "{}. **{}** (risk {:.1}, {} finding(s)): {}\n",
                index + 1,
                action.title,
                action.risk_score,
                action.affected_findings,
                action.remediation
            ));
        }
    }
    let path = output_dir.join(format!(
        "{}_{}_remediation.md",
        result.scan_started_at.format("%Y-%m-%d"),
        sanitize_target(&result.target)
    ));
    std::fs::write(&path, markdown).map_err(TemuError::Io)?;
    info!("Markdown summary written to {:?}", path);
    Ok(path)
}

/// Constructs a concise notification body for Slack/Discord-compatible webhooks.
pub fn webhook_summary(result: &ScanResult) -> serde_json::Value {
    let graph = build_asset_graph(result);
    json!({
        "content": format!(
            "Temu scan complete for {}: {} finding(s), {} deduplicated, {} prioritized action(s).",
            result.target,
            result.vulnerabilities.len(),
            graph.deduped_findings.len(),
            graph.top_remediation_actions.len()
        )
    })
}

fn finding_map(findings: &[Vulnerability]) -> BTreeMap<String, &Vulnerability> {
    findings
        .iter()
        .map(|finding| (finding_key(finding), finding))
        .collect()
}

fn finding_key(finding: &Vulnerability) -> String {
    format!(
        "{}:{}:{}",
        finding.id,
        finding.url,
        finding.parameter.as_deref().unwrap_or("-")
    )
}

fn suppression_matches(
    suppression: &SuppressionRule,
    finding: &Vulnerability,
    now: DateTime<Utc>,
) -> bool {
    suppression.finding_id == finding.id
        && suppression
            .url_contains
            .as_ref()
            .is_none_or(|pattern| finding.url.contains(pattern))
        && suppression.expires_at.is_none_or(|expiry| expiry > now)
}

fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "note",
    }
}

fn sanitize_target(target: &str) -> String {
    target
        .replace("https://", "")
        .replace("http://", "")
        .replace(['/', ':', '.'], "_")
        .trim_matches('_')
        .to_string()
}

fn write_pretty_json(path: &Path, value: &impl Serialize) -> Result<(), TemuError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| TemuError::Parse(format!("Failed to serialize artifact: {error}")))?;
    std::fs::write(path, json).map_err(TemuError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::types::ScanStats;

    fn result(vulnerabilities: Vec<Vulnerability>) -> ScanResult {
        ScanResult {
            target: "https://example.com".to_string(),
            assets: Vec::new(),
            tech_stacks: HashMap::new(),
            vulnerabilities,
            target_summaries: Vec::new(),
            callback_events: Vec::new(),
            scan_started_at: Utc::now(),
            scan_finished_at: Utc::now(),
            stats: ScanStats {
                subdomains_found: 0,
                paths_found: 0,
                parameters_found: 0,
                vulns_found: 0,
                duration_secs: 1.0,
            },
        }
    }

    fn finding(id: &str, severity: Severity) -> Vulnerability {
        Vulnerability::new(id, id, severity, 5.0, "proof", "https://example.com/a")
    }

    #[test]
    fn test_compare_reports_tracks_status_and_suppression() {
        let baseline = result(vec![
            finding("OLD", Severity::Low),
            finding("CHANGED", Severity::Low),
        ]);
        let current = result(vec![
            finding("NEW", Severity::High),
            finding("CHANGED", Severity::High),
        ]);
        let suppressions = vec![SuppressionRule {
            finding_id: "NEW".to_string(),
            url_contains: None,
            reason: "accepted".to_string(),
            expires_at: None,
        }];
        let diff = compare_reports(&baseline, &current, &suppressions);

        assert_eq!(diff.new_count, 0);
        assert_eq!(diff.fixed_count, 1);
        assert_eq!(diff.severity_changed_count, 1);
        assert_eq!(diff.suppressed.len(), 1);
    }

    #[test]
    fn test_generate_sarif_and_history_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let result = result(vec![finding("TEST", Severity::High)]);

        let sarif = generate_sarif(&result, temp.path()).unwrap();
        let _history = record_scan_history(&result, temp.path()).unwrap();
        let trend = generate_trend_json(&result, temp.path()).unwrap();

        assert!(sarif.exists());
        assert!(trend.exists());
    }
}
