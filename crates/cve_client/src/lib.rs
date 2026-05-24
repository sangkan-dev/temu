//! CVE client crate — NVD / CISA KEV integration with SQLite cache.

pub mod cisa;
pub mod cpe;
pub mod db;
pub mod epss;
pub mod nvd;
pub mod types;

pub use cisa::{fetch_cisa_kev, fetch_cisa_kev_with_base, fetch_cisa_kev_with_cache};
pub use cpe::{ApplicabilityStatus, CpeApplicability, build_cpe, explain_cpe_applicability};
pub use db::{
    cache_cve_entries, cache_kev_entries, init_database, mark_known_exploited, query_cves_by_cpe,
};
pub use epss::{enrich_epss_scores, fetch_epss_scores, fetch_epss_scores_with_base};
pub use nvd::{fetch_cves_from_nvd, fetch_cves_from_nvd_with_base};
pub use types::{CveEntry, Exploitability};

use std::path::PathBuf;

use chrono::Utc;
use fingerprint::TechStack;
use temu_core::{AppConfig, Severity, TemuError, Vulnerability};
use tracing::{info, warn};

/// Checks CVEs for detected technologies using the local SQLite cache first.
///
/// For each versioned technology, this builds a CPE, queries the cache, fetches
/// from NVD on cache miss, stores fresh entries, and converts matches into
/// informational `Vulnerability` values.
pub async fn check_cves(
    tech_stacks: &[TechStack],
    config: &AppConfig,
) -> Result<Vec<Vulnerability>, TemuError> {
    let db_path = default_db_path(config);
    let conn = init_database(&db_path)?;
    let mut vulnerabilities = Vec::new();

    for tech in tech_stacks {
        let applicability = explain_cpe_applicability(tech);
        let Some(cpe) = applicability.cpe.clone() else {
            info!("CVE applicability skipped: {}", applicability.reason);
            continue;
        };

        let mut entries = query_cves_by_cpe(&conn, &cpe)?;
        if entries.is_empty() {
            match fetch_cves_from_nvd(&cpe, std::env::var("NVD_API_KEY").ok().as_deref()).await {
                Ok(fetched) => {
                    entries = fetched;
                    if let Err(e) = enrich_epss_scores(&mut entries).await {
                        warn!("EPSS enrichment failed for {}: {e}", tech.name);
                    }
                    cache_cve_entries(&conn, &entries)?;
                }
                Err(e) => {
                    warn!("CVE fetch failed for {} ({}): {e}", tech.name, cpe);
                }
            }
        }

        entries.sort_by(|left, right| {
            right
                .priority_score()
                .total_cmp(&left.priority_score())
                .then_with(|| left.cve_id.cmp(&right.cve_id))
        });
        vulnerabilities.extend(
            entries
                .into_iter()
                .map(|entry| cve_to_vulnerability(entry, &applicability)),
        );
    }

    info!(
        "CVE check complete: {} version-based findings",
        vulnerabilities.len()
    );

    Ok(vulnerabilities)
}

/// Initializes the CVE cache and refreshes CISA KEV metadata.
///
/// NVD updates are CPE-specific, so this command prepares the cache and stores
/// KEV entries that can be used to prioritize later NVD matches.
pub async fn update_cve_cache(config: &AppConfig) -> Result<usize, TemuError> {
    update_cve_cache_for_cpes(config, &[]).await
}

/// Initializes the CVE cache, refreshes CISA KEV, and optionally refreshes NVD
/// data for specific CPE names.
pub async fn update_cve_cache_for_cpes(
    config: &AppConfig,
    cpes: &[String],
) -> Result<usize, TemuError> {
    let db_path = default_db_path(config);
    let conn = init_database(&db_path)?;
    let kev_ids = fetch_cisa_kev().await?;
    let kev_entries: Vec<CveEntry> = kev_ids
        .iter()
        .cloned()
        .map(|cve_id| CveEntry {
            cve_id,
            description: "Known exploited vulnerability from CISA KEV catalog".to_string(),
            severity: Severity::High,
            cvss_score: 8.0,
            cpe_match: Vec::new(),
            published_date: None,
            last_modified: None,
            exploitability: Exploitability::KnownExploited,
            epss_score: None,
            source: "cisa_kev".to_string(),
            cached_at: Utc::now(),
        })
        .collect();
    cache_kev_entries(&conn, &kev_entries)?;

    let mut cached = kev_entries.len();
    for cpe in cpes {
        let mut entries =
            fetch_cves_from_nvd(cpe, std::env::var("NVD_API_KEY").ok().as_deref()).await?;
        if let Err(e) = enrich_epss_scores(&mut entries).await {
            warn!("EPSS enrichment failed for {cpe}: {e}");
        }
        cached += entries.len();
        cache_cve_entries(&conn, &entries)?;
    }
    mark_known_exploited(&conn, &kev_ids)?;

    Ok(cached)
}

fn default_db_path(config: &AppConfig) -> PathBuf {
    config.output_dir.join(".cache").join("cve_cache.sqlite")
}

fn cve_to_vulnerability(entry: CveEntry, applicability: &CpeApplicability) -> Vulnerability {
    let epss = entry
        .epss_score
        .map(|score| format!("{score:.4}"))
        .unwrap_or_else(|| "unavailable".to_string());
    let mut vuln = Vulnerability::new(
        entry.cve_id.clone(),
        format!("[Metadata only] Version-related CVE: {}", entry.cve_id),
        entry.severity.clone(),
        entry.cvss_score,
        format!(
            "Metadata-only applicability; no exploit probe executed. {}. Source: {}; exploitation: {}; EPSS: {}; priority score: {:.2}. Advisory: {}",
            applicability.reason,
            entry.source,
            entry.exploitability.as_str(),
            epss,
            entry.priority_score(),
            entry.description
        ),
        applicability.cpe.clone().unwrap_or_default(),
    );
    vuln.verified = false;
    vuln.remediation = Some("Upgrade the affected component to a patched version.".to_string());
    vuln
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint::TechCategory;
    use std::path::PathBuf;

    #[test]
    fn test_cve_to_vulnerability_maps_fields() {
        let entry = CveEntry {
            cve_id: "CVE-2024-0001".to_string(),
            description: "Example issue".to_string(),
            severity: Severity::Critical,
            cvss_score: 9.8,
            cpe_match: vec!["cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*".to_string()],
            published_date: None,
            last_modified: None,
            exploitability: Exploitability::Theoretical,
            epss_score: Some(0.8),
            source: "nvd".to_string(),
            cached_at: Utc::now(),
        };

        let tech = TechStack::new("PHP", Some("8.1".to_string()), 0.95, TechCategory::Language);
        let vuln = cve_to_vulnerability(entry, &explain_cpe_applicability(&tech));
        assert_eq!(vuln.id, "CVE-2024-0001");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cvss_score, 9.8);
        assert!(vuln.name.contains("Metadata only"));
        assert!(vuln.proof.contains("EPSS: 0.8000"));
    }

    #[test]
    fn test_build_cpe_public_export() {
        let tech = TechStack::new(
            "nginx",
            Some("1.18.0".to_string()),
            0.95,
            TechCategory::WebServer,
        );
        assert_eq!(
            build_cpe(&tech),
            Some("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*".to_string())
        );
    }

    #[tokio::test]
    async fn test_check_cves_returns_cached_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let config = AppConfig {
            rate_limit: 10,
            timeout_secs: 5,
            concurrency: 4,
            user_agent: "Temu-Test/1.0.0".to_string(),
            output_dir: tmp.path().join("results"),
            rules_dir: PathBuf::from("/tmp"),
            dictionaries_dir: PathBuf::from("/tmp"),
            max_recursion_depth: 2,
            wordlist_override: None,
            allow_risky_rules: false,
            browser_crawl_enabled: true,
            browser_crawl_max_pages: 25,
            browser_crawl_max_depth: 2,
            browser_crawl_render_js: false,
            browser_crawl_browser_path: None,
            session_profile: None,
        };
        let cpe = "cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*";
        let conn = init_database(&default_db_path(&config)).unwrap();
        cache_cve_entries(
            &conn,
            &[CveEntry {
                cve_id: "CVE-2024-9999".to_string(),
                description: "Cached PHP issue".to_string(),
                severity: Severity::High,
                cvss_score: 8.1,
                cpe_match: vec![cpe.to_string()],
                published_date: None,
                last_modified: None,
                exploitability: Exploitability::Theoretical,
                epss_score: None,
                source: "nvd".to_string(),
                cached_at: Utc::now(),
            }],
        )
        .unwrap();

        let tech = TechStack::new("PHP", Some("8.1".to_string()), 0.95, TechCategory::Language);
        let findings = check_cves(&[tech], &config).await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "CVE-2024-9999");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].proof.contains("Metadata-only applicability"));
    }
}
