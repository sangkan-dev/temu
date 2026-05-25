use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use temu_core::{Asset, ServiceEvidence, Severity, TemuError, Vulnerability};
use tera::{Context, Tera};
use tracing::info;

use crate::types::ScanResult;

/// Renders a self-contained HTML report for `result` into `output_dir`.
///
/// Filename pattern: `{YYYY-MM-DD}_{sanitized_domain}.html`.
pub fn generate_html(result: &ScanResult, output_dir: &Path) -> Result<PathBuf, TemuError> {
    std::fs::create_dir_all(output_dir).map_err(|e| {
        TemuError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to create output directory {:?}: {e}", output_dir),
        ))
    })?;

    let tera = build_templates()?;
    let context = Context::from_serialize(ReportView::from_result(result, output_dir))
        .map_err(|e| TemuError::Parse(format!("Failed to build HTML context: {e}")))?;
    let html = tera
        .render("report.html", &context)
        .map_err(|e| TemuError::Parse(format!("Failed to render HTML report: {e}")))?;

    let date = result.scan_started_at.format("%Y-%m-%d").to_string();
    let filename = format!("{date}_{}.html", sanitize_target(&result.target));
    let path = output_dir.join(filename);
    std::fs::write(&path, html).map_err(|e| {
        TemuError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to write {:?}: {e}", path),
        ))
    })?;

    info!("HTML report written to {:?}", path);
    Ok(path)
}

fn build_templates() -> Result<Tera, TemuError> {
    let mut tera = Tera::default();
    tera.add_raw_templates(vec![
        (
            "report.html",
            include_str!("../../../templates/report.html"),
        ),
        (
            "partials/header.html",
            include_str!("../../../templates/partials/header.html"),
        ),
        (
            "partials/summary.html",
            include_str!("../../../templates/partials/summary.html"),
        ),
        (
            "partials/vulns_table.html",
            include_str!("../../../templates/partials/vulns_table.html"),
        ),
        (
            "partials/assets_table.html",
            include_str!("../../../templates/partials/assets_table.html"),
        ),
        (
            "partials/services_table.html",
            include_str!("../../../templates/partials/services_table.html"),
        ),
        (
            "partials/tech_stack.html",
            include_str!("../../../templates/partials/tech_stack.html"),
        ),
        (
            "partials/callback_events.html",
            include_str!("../../../templates/partials/callback_events.html"),
        ),
        (
            "partials/asset_graph.html",
            include_str!("../../../templates/partials/asset_graph.html"),
        ),
        (
            "partials/trend.html",
            include_str!("../../../templates/partials/trend.html"),
        ),
        (
            "partials/footer.html",
            include_str!("../../../templates/partials/footer.html"),
        ),
    ])
    .map_err(|e| TemuError::Parse(format!("Failed to load HTML templates: {e}")))?;
    Ok(tera)
}

fn sanitize_target(target: &str) -> String {
    target
        .replace("https://", "")
        .replace("http://", "")
        .replace(['/', ':', '.'], "_")
        .trim_matches('_')
        .to_string()
}

#[derive(Debug, Serialize)]
struct ReportView {
    target: String,
    generated_at: String,
    scan_started_at: String,
    scan_finished_at: String,
    duration_secs: f64,
    risk_rating: String,
    stats: StatsView,
    severity_counts: BTreeMap<String, usize>,
    target_summaries: Vec<TargetSummaryView>,
    vulnerabilities: Vec<VulnerabilityView>,
    assets: Vec<Asset>,
    services: Vec<ServiceView>,
    tech_groups: Vec<TechGroupView>,
    callback_events: Vec<CallbackEventView>,
    graph: GraphSummaryView,
    trend: Vec<TrendPointView>,
}

impl ReportView {
    fn from_result(result: &ScanResult, output_dir: &Path) -> Self {
        let vulnerabilities = result
            .vulnerabilities
            .iter()
            .map(VulnerabilityView::from_vulnerability)
            .collect::<Vec<_>>();
        let severity_counts = severity_counts(&result.vulnerabilities);
        let graph = crate::graph::build_asset_graph(result);
        let trend = crate::enterprise::load_trend_points(result, output_dir).unwrap_or_default();

        Self {
            target: result.target.clone(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            scan_started_at: result.scan_started_at.to_rfc3339(),
            scan_finished_at: result.scan_finished_at.to_rfc3339(),
            duration_secs: result.stats.duration_secs,
            risk_rating: risk_rating(&result.vulnerabilities).to_string(),
            stats: StatsView {
                subdomains_found: result.stats.subdomains_found,
                paths_found: result.stats.paths_found,
                parameters_found: result.stats.parameters_found,
                vulns_found: result.stats.vulns_found,
                assets_total: result.assets.len(),
                tech_total: result.tech_stacks.values().map(Vec::len).sum(),
            },
            severity_counts,
            target_summaries: result
                .target_summaries
                .iter()
                .map(TargetSummaryView::from_summary)
                .collect(),
            vulnerabilities,
            assets: result.assets.clone(),
            services: result
                .services
                .iter()
                .map(ServiceView::from_evidence)
                .collect(),
            tech_groups: tech_groups(result),
            callback_events: result
                .callback_events
                .iter()
                .map(CallbackEventView::from_event)
                .collect(),
            graph: GraphSummaryView::from_graph(&graph),
            trend: trend.iter().map(TrendPointView::from_point).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct TrendPointView {
    scan_started_at: String,
    vulnerabilities: u32,
    assets: usize,
    cve_findings: usize,
    duration_secs: String,
}

impl TrendPointView {
    fn from_point(point: &crate::enterprise::TrendPoint) -> Self {
        Self {
            scan_started_at: point.scan_started_at.clone(),
            vulnerabilities: point.vulnerabilities,
            assets: point.assets,
            cve_findings: point.cve_findings,
            duration_secs: format!("{:.1}", point.duration_secs),
        }
    }
}

#[derive(Debug, Serialize)]
struct GraphSummaryView {
    nodes_total: usize,
    edges_total: usize,
    deduped_findings: Vec<GraphFindingView>,
    attack_path_hints: Vec<GraphHintView>,
    top_remediation_actions: Vec<GraphActionView>,
}

impl GraphSummaryView {
    fn from_graph(graph: &crate::graph::AssetGraph) -> Self {
        Self {
            nodes_total: graph.nodes.len(),
            edges_total: graph.edges.len(),
            deduped_findings: graph
                .deduped_findings
                .iter()
                .take(10)
                .map(GraphFindingView::from_finding)
                .collect(),
            attack_path_hints: graph
                .attack_path_hints
                .iter()
                .map(GraphHintView::from_hint)
                .collect(),
            top_remediation_actions: graph
                .top_remediation_actions
                .iter()
                .map(GraphActionView::from_action)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct GraphFindingView {
    rule_id: String,
    name: String,
    severity: String,
    severity_class: String,
    representative_url: String,
    occurrences: usize,
    risk_score: String,
}

impl GraphFindingView {
    fn from_finding(finding: &crate::graph::DedupedFinding) -> Self {
        let severity = finding.severity.to_string();
        Self {
            rule_id: finding.rule_id.clone(),
            name: finding.name.clone(),
            severity_class: severity.to_lowercase(),
            severity,
            representative_url: finding.representative_url.clone(),
            occurrences: finding.occurrences,
            risk_score: format!("{:.1}", finding.risk_score),
        }
    }
}

#[derive(Debug, Serialize)]
struct GraphHintView {
    title: String,
    score: String,
    evidence: Vec<String>,
}

impl GraphHintView {
    fn from_hint(hint: &crate::graph::AttackPathHint) -> Self {
        Self {
            title: hint.title.clone(),
            score: format!("{:.1}", hint.score),
            evidence: hint.evidence.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct GraphActionView {
    title: String,
    risk_score: String,
    affected_findings: usize,
    affected_assets: usize,
    remediation: String,
}

impl GraphActionView {
    fn from_action(action: &crate::graph::RemediationAction) -> Self {
        Self {
            title: action.title.clone(),
            risk_score: format!("{:.1}", action.risk_score),
            affected_findings: action.affected_findings,
            affected_assets: action.affected_assets,
            remediation: action.remediation.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CallbackEventView {
    correlation_id: String,
    protocol: String,
    method: String,
    path: String,
    remote_addr: String,
    user_agent: String,
    received_at: String,
}

impl CallbackEventView {
    fn from_event(event: &crate::types::CallbackEvent) -> Self {
        Self {
            correlation_id: event.correlation_id.clone(),
            protocol: event.protocol.clone(),
            method: event.method.clone(),
            path: event.path.clone(),
            remote_addr: event.remote_addr.clone(),
            user_agent: event.user_agent.clone().unwrap_or_else(|| "-".to_string()),
            received_at: event.received_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
struct TargetSummaryView {
    target: String,
    assets_total: usize,
    vulnerabilities_total: usize,
    highest_severity: String,
    highest_severity_class: String,
    duration_secs: f64,
}

impl TargetSummaryView {
    fn from_summary(summary: &crate::types::TargetSummary) -> Self {
        let highest_severity = summary
            .highest_severity
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "None".to_string());
        Self {
            target: summary.target.clone(),
            assets_total: summary.assets_total,
            vulnerabilities_total: summary.vulnerabilities_total,
            highest_severity_class: highest_severity.to_lowercase(),
            highest_severity,
            duration_secs: summary.duration_secs,
        }
    }
}

#[derive(Debug, Serialize)]
struct StatsView {
    subdomains_found: u32,
    paths_found: u32,
    parameters_found: u32,
    vulns_found: u32,
    assets_total: usize,
    tech_total: usize,
}

#[derive(Debug, Serialize)]
struct VulnerabilityView {
    id: String,
    name: String,
    severity: String,
    severity_class: String,
    cvss_score: f32,
    proof: String,
    url: String,
    parameter: String,
    verified: bool,
    remediation: String,
}

impl VulnerabilityView {
    fn from_vulnerability(vuln: &Vulnerability) -> Self {
        let severity = vuln.severity.to_string();
        Self {
            id: vuln.id.clone(),
            name: vuln.name.clone(),
            severity_class: severity.to_lowercase(),
            severity,
            cvss_score: vuln.cvss_score,
            proof: crate::redaction::redact_sensitive_text(&vuln.proof),
            url: vuln.url.clone(),
            parameter: vuln.parameter.clone().unwrap_or_else(|| "-".to_string()),
            verified: vuln.verified,
            remediation: vuln
                .remediation
                .clone()
                .unwrap_or_else(|| "Review and patch the affected component.".to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
struct TechGroupView {
    category: String,
    technologies: Vec<TechView>,
}

#[derive(Debug, Serialize)]
struct ServiceView {
    endpoint: String,
    protocol: String,
    product: String,
    version: String,
    confidence: String,
    tls: String,
    auth_required: String,
    evidence: String,
}

impl ServiceView {
    fn from_evidence(service: &ServiceEvidence) -> Self {
        Self {
            endpoint: service.endpoint.clone(),
            protocol: service.protocol.clone(),
            product: service
                .product
                .clone()
                .unwrap_or_else(|| "Unknown".to_string()),
            version: service.version.clone().unwrap_or_else(|| "-".to_string()),
            confidence: format!("{:.0}%", service.confidence * 100.0),
            tls: service
                .tls
                .as_ref()
                .filter(|tls| tls.detected)
                .and_then(|tls| tls.protocol_version.clone())
                .unwrap_or_else(|| "No TLS observed".to_string()),
            auth_required: service
                .auth_required
                .map(|required| required.to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
            evidence: crate::redaction::redact_sensitive_text(
                service.handshake.as_deref().unwrap_or("-"),
            ),
        }
    }
}

#[derive(Debug, Serialize)]
struct TechView {
    url: String,
    name: String,
    version: String,
    confidence: String,
}

fn severity_counts(vulns: &[Vulnerability]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::from([
        ("Critical".to_string(), 0),
        ("High".to_string(), 0),
        ("Medium".to_string(), 0),
        ("Low".to_string(), 0),
        ("Info".to_string(), 0),
    ]);
    for vuln in vulns {
        *counts.entry(vuln.severity.to_string()).or_insert(0) += 1;
    }
    counts
}

fn risk_rating(vulns: &[Vulnerability]) -> &'static str {
    if vulns.iter().any(|v| v.severity == Severity::Critical) {
        "Critical"
    } else if vulns.iter().any(|v| v.severity == Severity::High) {
        "High"
    } else if vulns.iter().any(|v| v.severity == Severity::Medium) {
        "Medium"
    } else if vulns.iter().any(|v| v.severity == Severity::Low) {
        "Low"
    } else {
        "Informational"
    }
}

fn tech_groups(result: &ScanResult) -> Vec<TechGroupView> {
    let mut grouped: BTreeMap<String, Vec<TechView>> = BTreeMap::new();
    for (url, techs) in &result.tech_stacks {
        for tech in techs {
            grouped
                .entry(format!("{:?}", tech.category))
                .or_default()
                .push(TechView {
                    url: url.clone(),
                    name: tech.name.clone(),
                    version: tech.version.clone().unwrap_or_else(|| "-".to_string()),
                    confidence: format!("{:.0}%", tech.confidence * 100.0),
                });
        }
    }

    grouped
        .into_iter()
        .map(|(category, mut technologies)| {
            technologies.sort_by(|a, b| a.name.cmp(&b.name).then(a.url.cmp(&b.url)));
            TechGroupView {
                category,
                technologies,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use fingerprint::{TechCategory, TechStack};
    use std::collections::HashMap;
    use temu_core::{Asset, AssetType, ServiceEvidence, TlsEvidence};

    fn make_result() -> ScanResult {
        let mut tech_stacks = HashMap::new();
        tech_stacks.insert(
            "https://example.com".to_string(),
            vec![TechStack::new(
                "nginx",
                Some("1.18.0".to_string()),
                0.95,
                TechCategory::WebServer,
            )],
        );

        ScanResult {
            target: "https://example.com".to_string(),
            assets: vec![Asset::new(
                "https://example.com/.env",
                AssetType::Path,
                "test",
            )],
            tech_stacks,
            vulnerabilities: vec![Vulnerability::new(
                "SENSITIVE-FILES-ENV",
                "Exposed .env file",
                Severity::High,
                7.5,
                "status=200",
                "https://example.com/.env",
            )],
            services: vec![ServiceEvidence {
                endpoint: "tcp://127.0.0.1:6379".to_string(),
                port: 6379,
                protocol: "redis".to_string(),
                product: Some("Redis".to_string()),
                version: None,
                confidence: 0.98,
                banner: Some("+PONG".to_string()),
                handshake: Some("+PONG".to_string()),
                auth_required: Some(false),
                tls: Some(TlsEvidence {
                    detected: true,
                    protocol_version: Some("TLS 1.2 or newer".to_string()),
                    cipher_suite: None,
                }),
            }],
            target_summaries: vec![],
            callback_events: vec![],
            scan_started_at: Utc::now(),
            scan_finished_at: Utc::now(),
            stats: crate::types::ScanStats {
                subdomains_found: 0,
                paths_found: 1,
                parameters_found: 0,
                vulns_found: 1,
                duration_secs: 1.2,
            },
        }
    }

    #[test]
    fn test_generate_html_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = generate_html(&make_result(), tmp.path()).unwrap();

        assert!(path.exists());
        assert_eq!(path.extension().and_then(|e| e.to_str()), Some("html"));
    }

    #[test]
    fn test_generate_html_contains_report_sections() {
        let tmp = tempfile::tempdir().unwrap();
        let path = generate_html(&make_result(), tmp.path()).unwrap();
        let html = std::fs::read_to_string(path).unwrap();

        assert!(html.contains("Temu Security Report"));
        assert!(html.contains("Executive Summary"));
        assert!(html.contains("SENSITIVE-FILES-ENV"));
        assert!(html.contains("nginx"));
        assert!(html.contains("Network Services"));
        assert!(html.contains("127.0.0.1"));
        assert!(html.contains("6379"));
        assert!(html.contains("Redis"));
    }
}
