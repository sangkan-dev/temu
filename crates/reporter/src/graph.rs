use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::Utc;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use temu_core::{AssetType, Severity, TemuError, Vulnerability};
use tracing::info;

use crate::types::ScanResult;

/// Node type used in the asset graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeKind {
    Domain,
    Subdomain,
    Ip,
    Port,
    Service,
    Technology,
    Endpoint,
    Cve,
    Finding,
    Exposure,
}

/// One graph node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub kind: GraphNodeKind,
    pub label: String,
    pub risk_score: f32,
}

/// Directed graph edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
}

/// Deduplicated finding group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupedFinding {
    pub key: String,
    pub rule_id: String,
    pub name: String,
    pub severity: Severity,
    pub representative_url: String,
    pub occurrences: usize,
    pub risk_score: f32,
    pub remediation: Option<String>,
}

/// Prioritized attack path hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathHint {
    pub title: String,
    pub score: f32,
    pub evidence: Vec<String>,
}

/// One prioritized remediation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    pub title: String,
    pub risk_score: f32,
    pub affected_findings: usize,
    pub affected_assets: usize,
    pub remediation: String,
}

/// Asset relationship graph and prioritization summary for one scan result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetGraph {
    pub target: String,
    pub generated_at: chrono::DateTime<Utc>,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub deduped_findings: Vec<DedupedFinding>,
    pub attack_path_hints: Vec<AttackPathHint>,
    pub top_remediation_actions: Vec<RemediationAction>,
}

/// Builds an asset graph from a scan result.
pub fn build_asset_graph(result: &ScanResult) -> AssetGraph {
    let mut builder = GraphBuilder::default();
    let target_id = node_id("domain", &result.target);
    builder.add_node(&target_id, GraphNodeKind::Domain, &result.target, 0.0);

    for asset in &result.assets {
        let (kind, label) = graph_kind_and_label(asset.asset_type.clone(), &asset.url);
        let id = node_id(kind_prefix(&kind), &label);
        builder.add_node(&id, kind, &label, 0.0);
        builder.add_edge(&target_id, &id, "contains");

        if let Some((service_id, port_id)) = service_nodes(&asset.url) {
            builder.add_node(&service_id, GraphNodeKind::Service, &asset.url, 0.0);
            builder.add_node(&port_id, GraphNodeKind::Port, &port_id, 0.0);
            builder.add_edge(&service_id, &port_id, "listens_on");
        }
    }

    for service in &result.services {
        let host = host_from_url(&service.endpoint).unwrap_or_else(|| service.endpoint.clone());
        let host_id = node_id("ip", &host);
        let service_id = node_id("service", &service.endpoint);
        let port_id = format!("port:{}", service.port);
        let exposure = if service
            .signals
            .iter()
            .any(|signal| signal == "publicly_routable")
        {
            "internet_facing"
        } else {
            "internal_or_private"
        };
        let exposure_id = node_id("exposure", exposure);
        builder.add_node(&host_id, GraphNodeKind::Ip, &host, 0.0);
        builder.add_node(
            &service_id,
            GraphNodeKind::Service,
            &service.endpoint,
            service_risk_score(service),
        );
        builder.add_node(
            &port_id,
            GraphNodeKind::Port,
            &service.port.to_string(),
            0.0,
        );
        builder.add_node(
            &exposure_id,
            GraphNodeKind::Exposure,
            exposure,
            if exposure == "internet_facing" {
                55.0
            } else {
                10.0
            },
        );
        builder.add_edge(&target_id, &host_id, "contains_host");
        builder.add_edge(&host_id, &service_id, "exposes");
        builder.add_edge(&service_id, &port_id, "listens_on");
        builder.add_edge(&service_id, &exposure_id, "has_exposure");
        if let Some(product) = &service.product {
            let label = if let Some(version) = &service.version {
                format!("{product}/{version}")
            } else {
                product.clone()
            };
            let product_id = node_id("tech", &label);
            builder.add_node(
                &product_id,
                GraphNodeKind::Technology,
                &label,
                service.confidence * 10.0,
            );
            builder.add_edge(&service_id, &product_id, "runs");
        }
    }

    for (url, techs) in &result.tech_stacks {
        let endpoint_id = node_id("endpoint", url);
        builder.add_node(&endpoint_id, GraphNodeKind::Endpoint, url, 0.0);
        builder.add_edge(&target_id, &endpoint_id, "has_endpoint");
        for tech in techs {
            let label = if let Some(version) = &tech.version {
                format!("{}/{}", tech.name, version)
            } else {
                tech.name.clone()
            };
            let tech_id = node_id("tech", &label);
            builder.add_node(
                &tech_id,
                GraphNodeKind::Technology,
                &label,
                tech.confidence * 10.0,
            );
            builder.add_edge(&endpoint_id, &tech_id, "runs");
        }
    }

    let deduped_findings = deduplicate_findings(&result.vulnerabilities);
    for finding in &deduped_findings {
        let finding_id = node_id("finding", &finding.key);
        builder.add_node(
            &finding_id,
            GraphNodeKind::Finding,
            &finding.name,
            finding.risk_score,
        );
        let endpoint_id = node_id("endpoint", &finding.representative_url);
        builder.add_node(
            &endpoint_id,
            GraphNodeKind::Endpoint,
            &finding.representative_url,
            0.0,
        );
        builder.add_edge(&endpoint_id, &finding_id, "has_finding");
        if finding.representative_url.starts_with("tcp://") {
            let service_id = node_id("service", &finding.representative_url);
            builder.add_node(
                &service_id,
                GraphNodeKind::Service,
                &finding.representative_url,
                finding.risk_score,
            );
            builder.add_edge(&service_id, &finding_id, "has_finding");
        }
        if finding.rule_id.starts_with("CVE-") {
            let cve_id = node_id("cve", &finding.rule_id);
            builder.add_node(
                &cve_id,
                GraphNodeKind::Cve,
                &finding.rule_id,
                finding.risk_score,
            );
            builder.add_edge(&finding_id, &cve_id, "references");
            if let Some(service) = result
                .services
                .iter()
                .find(|service| service.endpoint == finding.representative_url)
                && let Some(product) = &service.product
            {
                let label = service
                    .version
                    .as_ref()
                    .map(|version| format!("{product}/{version}"))
                    .unwrap_or_else(|| product.clone());
                let product_id = node_id("tech", &label);
                builder.add_node(
                    &product_id,
                    GraphNodeKind::Technology,
                    &label,
                    service.confidence * 10.0,
                );
                builder.add_edge(&product_id, &cve_id, "affected_by");
            }
        }
    }

    let attack_path_hints = attack_path_hints(result, &deduped_findings);
    let top_remediation_actions = top_remediation_actions(result, &deduped_findings);

    AssetGraph {
        target: result.target.clone(),
        generated_at: Utc::now(),
        nodes: builder.nodes.into_values().collect(),
        edges: builder.edges.into_iter().map(GraphEdge::from).collect(),
        deduped_findings,
        attack_path_hints,
        top_remediation_actions,
    }
}

/// Writes an asset graph JSON artifact next to the regular reports.
pub fn generate_graph_json(result: &ScanResult, output_dir: &Path) -> Result<PathBuf, TemuError> {
    std::fs::create_dir_all(output_dir).map_err(|e| {
        TemuError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to create output directory {:?}: {e}", output_dir),
        ))
    })?;
    let graph = build_asset_graph(result);
    let path = output_dir.join(format!(
        "{}_{}_graph.json",
        result.scan_started_at.format("%Y-%m-%d"),
        sanitize_target(&result.target)
    ));
    let json = serde_json::to_string_pretty(&graph)
        .map_err(|e| TemuError::Parse(format!("Failed to serialize asset graph: {e}")))?;
    std::fs::write(&path, json).map_err(|e| {
        TemuError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to write {:?}: {e}", path),
        ))
    })?;
    info!("Asset graph written to {:?}", path);
    Ok(path)
}

/// Stores the latest asset graph in a local SQLite cache.
pub fn generate_graph_cache(result: &ScanResult, output_dir: &Path) -> Result<PathBuf, TemuError> {
    let cache_dir = output_dir.join(".cache");
    std::fs::create_dir_all(&cache_dir).map_err(TemuError::Io)?;
    let path = cache_dir.join("asset_graph.sqlite");
    let conn = Connection::open(&path)
        .map_err(|e| TemuError::Parse(format!("Failed to open asset graph cache: {e}")))?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS asset_graphs (
            target TEXT NOT NULL,
            scan_started_at TEXT NOT NULL,
            graph_json TEXT NOT NULL,
            PRIMARY KEY (target, scan_started_at)
        );
        "#,
    )
    .map_err(|e| TemuError::Parse(format!("Failed to initialize asset graph cache: {e}")))?;
    let graph = build_asset_graph(result);
    let graph_json = serde_json::to_string(&graph)
        .map_err(|e| TemuError::Parse(format!("Failed to serialize graph cache: {e}")))?;
    conn.execute(
        r#"
        INSERT OR REPLACE INTO asset_graphs (target, scan_started_at, graph_json)
        VALUES (?1, ?2, ?3)
        "#,
        params![
            result.target,
            result.scan_started_at.to_rfc3339(),
            graph_json
        ],
    )
    .map_err(|e| TemuError::Parse(format!("Failed to write asset graph cache: {e}")))?;
    Ok(path)
}

#[derive(Default)]
struct GraphBuilder {
    nodes: BTreeMap<String, GraphNode>,
    edges: BTreeSet<GraphEdgeKey>,
}

impl GraphBuilder {
    fn add_node(&mut self, id: &str, kind: GraphNodeKind, label: &str, risk_score: f32) {
        self.nodes
            .entry(id.to_string())
            .and_modify(|node| node.risk_score = node.risk_score.max(risk_score))
            .or_insert_with(|| GraphNode {
                id: id.to_string(),
                kind,
                label: label.to_string(),
                risk_score,
            });
    }

    fn add_edge(&mut self, from: &str, to: &str, relation: &str) {
        self.edges.insert(GraphEdgeKey {
            from: from.to_string(),
            to: to.to_string(),
            relation: relation.to_string(),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GraphEdgeKey {
    from: String,
    to: String,
    relation: String,
}

impl From<GraphEdgeKey> for GraphEdge {
    fn from(value: GraphEdgeKey) -> Self {
        Self {
            from: value.from,
            to: value.to,
            relation: value.relation,
        }
    }
}

fn deduplicate_findings(vulnerabilities: &[Vulnerability]) -> Vec<DedupedFinding> {
    let mut groups: BTreeMap<String, Vec<&Vulnerability>> = BTreeMap::new();
    for vulnerability in vulnerabilities {
        groups
            .entry(root_cause_key(vulnerability))
            .or_default()
            .push(vulnerability);
    }

    let mut findings = groups
        .into_iter()
        .map(|(key, group)| {
            let representative = group
                .iter()
                .max_by(|left, right| {
                    risk_score(left)
                        .partial_cmp(&risk_score(right))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .copied()
                .unwrap_or(group[0]);
            let affected_assets = group
                .iter()
                .map(|vulnerability| vulnerability.url.as_str())
                .collect::<BTreeSet<_>>()
                .len();
            DedupedFinding {
                key,
                rule_id: representative.id.clone(),
                name: representative.name.clone(),
                severity: representative.severity.clone(),
                representative_url: representative.url.clone(),
                occurrences: group.len().max(affected_assets),
                risk_score: risk_score(representative),
                remediation: representative.remediation.clone(),
            }
        })
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        right
            .risk_score
            .partial_cmp(&left.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(left.rule_id.cmp(&right.rule_id))
    });
    findings
}

fn attack_path_hints(
    result: &ScanResult,
    deduped_findings: &[DedupedFinding],
) -> Vec<AttackPathHint> {
    let has_admin = result.assets.iter().any(|asset| {
        let url = asset.url.to_ascii_lowercase();
        url.contains("/admin") || url.contains("/debug") || url.contains("/manage")
    });
    let has_cve = deduped_findings
        .iter()
        .any(|finding| finding.rule_id.starts_with("CVE-"));
    let has_missing_headers = deduped_findings
        .iter()
        .any(|finding| finding.rule_id.starts_with("SEC-HEADER-"));
    let has_public_service = result.assets.iter().any(|asset| {
        matches!(asset.asset_type, AssetType::Service | AssetType::Url)
            && is_public_surface(&asset.url)
    });
    let public_services = result
        .services
        .iter()
        .filter(|service| {
            service
                .signals
                .iter()
                .any(|signal| signal == "publicly_routable")
        })
        .collect::<Vec<_>>();
    let public_database_without_tls = public_services.iter().any(|service| {
        matches!(
            service.protocol.as_str(),
            "postgresql" | "mysql" | "mssql" | "mongodb"
        ) && service.tls.as_ref().is_none_or(|tls| !tls.detected)
    });
    let public_unauthenticated_redis = public_services
        .iter()
        .any(|service| service.protocol == "redis" && service.auth_required == Some(false));
    let public_remote_management = public_services.iter().any(|service| {
        service
            .signals
            .iter()
            .any(|signal| signal == "remote_management_service")
    });

    let mut hints = Vec::new();
    if has_admin && has_missing_headers && has_public_service {
        hints.push(AttackPathHint {
            title: "Public administrative surface with weak browser hardening".to_string(),
            score: 72.0,
            evidence: vec![
                "Administrative/debug endpoint discovered".to_string(),
                "Missing security header finding exists".to_string(),
                "Public URL or service is present".to_string(),
            ],
        });
    }
    if has_cve && has_public_service {
        hints.push(AttackPathHint {
            title: "Known CVE exposure on reachable service".to_string(),
            score: 86.0,
            evidence: vec![
                "CVE-related finding exists".to_string(),
                "Reachable service is present".to_string(),
            ],
        });
    }
    if public_database_without_tls {
        hints.push(AttackPathHint {
            title: "Internet-facing database with weak transport boundary".to_string(),
            score: 92.0,
            evidence: vec![
                "Database listener is publicly routable".to_string(),
                "TLS was not observed on the database listener".to_string(),
                "Compromise would provide direct access to a data-plane service".to_string(),
            ],
        });
    }
    if public_unauthenticated_redis {
        hints.push(AttackPathHint {
            title: "Internet-facing Redis accepts unauthenticated commands".to_string(),
            score: 98.0,
            evidence: vec![
                "Redis listener is publicly routable".to_string(),
                "Unauthenticated command response was observed".to_string(),
            ],
        });
    }
    if public_remote_management {
        hints.push(AttackPathHint {
            title: "Internet-facing remote management path".to_string(),
            score: 84.0,
            evidence: vec![
                "Remote-management protocol is publicly routable".to_string(),
                "Restrict access through a VPN or bastion host".to_string(),
            ],
        });
    }
    hints.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hints
}

fn top_remediation_actions(
    result: &ScanResult,
    findings: &[DedupedFinding],
) -> Vec<RemediationAction> {
    let mut grouped: HashMap<String, Vec<&DedupedFinding>> = HashMap::new();
    for finding in findings {
        grouped
            .entry(
                finding
                    .remediation
                    .clone()
                    .unwrap_or_else(|| format!("Review and remediate {}", finding.name)),
            )
            .or_default()
            .push(finding);
    }
    let mut actions = grouped
        .into_iter()
        .map(|(remediation, group)| {
            let risk_score = group.iter().map(|finding| finding.risk_score).sum::<f32>();
            let affected_assets = group
                .iter()
                .map(|finding| finding.representative_url.as_str())
                .collect::<BTreeSet<_>>()
                .len();
            RemediationAction {
                title: group[0].name.clone(),
                risk_score,
                affected_findings: group.len(),
                affected_assets,
                remediation,
            }
        })
        .collect::<Vec<_>>();
    let segmentation_services = result
        .services
        .iter()
        .filter(|service| {
            service.signals.iter().any(|signal| {
                matches!(
                    signal.as_str(),
                    "database_or_cache_service"
                        | "message_broker_service"
                        | "remote_management_service"
                        | "administrative_interface"
                )
            })
        })
        .collect::<Vec<_>>();
    if !segmentation_services.is_empty() {
        let public_count = segmentation_services
            .iter()
            .filter(|service| {
                service
                    .signals
                    .iter()
                    .any(|signal| signal == "publicly_routable")
            })
            .count();
        actions.push(RemediationAction {
            title: "Segment sensitive network services".to_string(),
            risk_score: if public_count > 0 { 95.0 } else { 55.0 },
            affected_findings: public_count,
            affected_assets: segmentation_services.len(),
            remediation: "Place databases, caches, message brokers, and management protocols in dedicated network segments; allow access only from approved application, administration, or bastion subnets.".to_string(),
        });
    }
    actions.sort_by(|left, right| {
        right
            .risk_score
            .partial_cmp(&left.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    actions.truncate(10);
    actions
}

fn service_risk_score(service: &temu_core::ServiceEvidence) -> f32 {
    let public = service
        .signals
        .iter()
        .any(|signal| signal == "publicly_routable");
    let sensitive = service.signals.iter().any(|signal| {
        matches!(
            signal.as_str(),
            "database_or_cache_service"
                | "message_broker_service"
                | "remote_management_service"
                | "administrative_interface"
        )
    });
    let unauthenticated = service.auth_required == Some(false);
    match (public, sensitive, unauthenticated) {
        (true, true, true) => 95.0,
        (true, true, false) => 75.0,
        (true, false, _) => 55.0,
        (false, true, true) => 45.0,
        (false, true, false) => 25.0,
        _ => 5.0,
    }
}

fn risk_score(vulnerability: &Vulnerability) -> f32 {
    let severity = match vulnerability.severity {
        Severity::Critical => 10.0,
        Severity::High => 8.0,
        Severity::Medium => 5.5,
        Severity::Low => 2.5,
        Severity::Info => 0.5,
    };
    let verification = if vulnerability.verified { 1.2 } else { 1.0 };
    let cve = if vulnerability.id.starts_with("CVE-") {
        1.2
    } else {
        1.0
    };
    let kev = if vulnerability.proof.to_ascii_lowercase().contains("kev") {
        1.25
    } else {
        1.0
    };
    let epss = if vulnerability.proof.to_ascii_lowercase().contains("epss") {
        1.1
    } else {
        1.0
    };
    let proof = vulnerability.proof.to_ascii_lowercase();
    let auth = if proof.contains("auth required") || proof.contains("authenticated") {
        0.85
    } else {
        1.0
    };
    let target = vulnerability.url.to_ascii_lowercase();
    let exposure = if !is_public_surface(&target) {
        0.9
    } else {
        1.1
    };
    ((vulnerability.cvss_score.max(severity) * 10.0)
        * verification
        * cve
        * kev
        * epss
        * auth
        * exposure)
        .min(100.0)
}

fn root_cause_key(vulnerability: &Vulnerability) -> String {
    let host = host_from_url(&vulnerability.url).unwrap_or_else(|| vulnerability.url.clone());
    let scope = if vulnerability.id.starts_with("SEC-HEADER-") {
        host
    } else {
        format!(
            "{}:{}",
            host,
            vulnerability.parameter.as_deref().unwrap_or("-")
        )
    };
    format!("{}:{scope}", vulnerability.id)
}

fn host_from_url(value: &str) -> Option<String> {
    let after_scheme = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .and_then(|authority| authority.split('@').next_back())?;
    if let Some(ipv6) = authority.strip_prefix('[') {
        return ipv6
            .split_once(']')
            .map(|(host, _)| host.to_string())
            .filter(|host| !host.is_empty());
    }
    authority
        .split(':')
        .next()
        .filter(|host| !host.is_empty())
        .map(str::to_string)
}

fn is_public_surface(value: &str) -> bool {
    let Some(host) = host_from_url(value) else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast())
        }
        Ok(IpAddr::V6(ip)) => {
            !(ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified())
        }
        Err(_) => true,
    }
}

fn graph_kind_and_label(asset_type: AssetType, value: &str) -> (GraphNodeKind, String) {
    let kind = match asset_type {
        AssetType::Subdomain => GraphNodeKind::Subdomain,
        AssetType::Ip => GraphNodeKind::Ip,
        AssetType::Service => GraphNodeKind::Service,
        AssetType::Path | AssetType::Parameter | AssetType::Url | AssetType::ApiEndpoint => {
            GraphNodeKind::Endpoint
        }
    };
    (kind, value.to_string())
}

fn service_nodes(value: &str) -> Option<(String, String)> {
    let (_, port) = value.rsplit_once(':')?;
    let port = port
        .split(|ch: char| !ch.is_ascii_digit())
        .next()
        .filter(|part| !part.is_empty())?;
    Some((node_id("service", value), format!("port:{port}")))
}

fn node_id(prefix: &str, value: &str) -> String {
    format!("{prefix}:{}", value.to_ascii_lowercase())
}

fn kind_prefix(kind: &GraphNodeKind) -> &'static str {
    match kind {
        GraphNodeKind::Domain => "domain",
        GraphNodeKind::Subdomain => "subdomain",
        GraphNodeKind::Ip => "ip",
        GraphNodeKind::Port => "port",
        GraphNodeKind::Service => "service",
        GraphNodeKind::Technology => "tech",
        GraphNodeKind::Endpoint => "endpoint",
        GraphNodeKind::Cve => "cve",
        GraphNodeKind::Finding => "finding",
        GraphNodeKind::Exposure => "exposure",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanStats;
    use fingerprint::{TechCategory, TechStack};
    use temu_core::{Asset, AssetType, Vulnerability};

    #[test]
    fn test_build_asset_graph_deduplicates_security_headers() {
        let mut tech_stacks = HashMap::new();
        tech_stacks.insert(
            "https://example.com".to_string(),
            vec![TechStack::new("nginx", None, 0.9, TechCategory::WebServer)],
        );
        let result = ScanResult {
            target: "https://example.com".to_string(),
            assets: vec![
                Asset::new("https://example.com", AssetType::Url, "test"),
                Asset::new("tcp://127.0.0.1:443 (https)", AssetType::Service, "test"),
            ],
            tech_stacks,
            vulnerabilities: vec![
                Vulnerability::new(
                    "SEC-HEADER-HSTS",
                    "Strict-Transport-Security",
                    Severity::Info,
                    0.0,
                    "missing",
                    "https://example.com",
                ),
                Vulnerability::new(
                    "SEC-HEADER-HSTS",
                    "Strict-Transport-Security",
                    Severity::Info,
                    0.0,
                    "missing",
                    "https://example.com/admin",
                ),
            ],
            services: vec![temu_core::ServiceEvidence {
                endpoint: "tcp://8.8.8.8:5432".to_string(),
                port: 5432,
                protocol: "postgresql".to_string(),
                product: Some("PostgreSQL".to_string()),
                version: Some("17".to_string()),
                confidence: 0.95,
                banner: None,
                handshake: None,
                auth_required: Some(true),
                tls: None,
                signals: vec![
                    "publicly_routable".to_string(),
                    "database_or_cache_service".to_string(),
                ],
            }],
            target_summaries: Vec::new(),
            callback_events: Vec::new(),
            scan_started_at: Utc::now(),
            scan_finished_at: Utc::now(),
            stats: ScanStats {
                subdomains_found: 0,
                paths_found: 1,
                parameters_found: 0,
                vulns_found: 2,
                duration_secs: 1.0,
            },
        };

        let graph = build_asset_graph(&result);

        assert_eq!(graph.deduped_findings.len(), 1);
        assert_eq!(graph.deduped_findings[0].occurrences, 2);
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.kind == GraphNodeKind::Technology)
        );
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.kind == GraphNodeKind::Exposure)
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.relation == "has_exposure")
        );
        assert!(
            graph
                .top_remediation_actions
                .iter()
                .any(|action| action.title == "Segment sensitive network services")
        );
    }

    #[test]
    fn test_private_surfaces_are_not_reported_as_public() {
        assert!(!is_public_surface("http://127.0.0.1:3000/admin"));
        assert!(!is_public_surface("http://192.168.10.5/admin"));
        assert!(!is_public_surface("http://[::1]/admin"));
        assert!(is_public_surface("https://example.com/admin"));
    }
}
