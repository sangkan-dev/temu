//! CVE client crate — NVD / CISA KEV integration with SQLite cache.

pub mod cisa;
pub mod cpe;
pub mod db;
pub mod nvd;
pub mod types;

pub use cisa::{fetch_cisa_kev, fetch_cisa_kev_with_base, fetch_cisa_kev_with_cache};
pub use cpe::build_cpe;
pub use db::{cache_cve_entries, init_database, mark_known_exploited, query_cves_by_cpe};
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
        let Some(cpe) = build_cpe(tech) else {
            continue;
        };

        let mut entries = query_cves_by_cpe(&conn, &cpe)?;
        if entries.is_empty() {
            match fetch_cves_from_nvd(&cpe, std::env::var("NVD_API_KEY").ok().as_deref()).await {
                Ok(fetched) => {
                    cache_cve_entries(&conn, &fetched)?;
                    entries = fetched;
                }
                Err(e) => {
                    warn!("CVE fetch failed for {} ({}): {e}", tech.name, cpe);
                }
            }
        }

        vulnerabilities.extend(entries.into_iter().map(cve_to_vulnerability));
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
    mark_known_exploited(&conn, &kev_ids)?;
    let kev_entries: Vec<CveEntry> = kev_ids
        .into_iter()
        .map(|cve_id| CveEntry {
            cve_id,
            description: "Known exploited vulnerability from CISA KEV catalog".to_string(),
            severity: Severity::High,
            cvss_score: 8.0,
            cpe_match: Vec::new(),
            published_date: None,
            last_modified: None,
            exploitability: Exploitability::KnownExploited,
            source: "cisa_kev".to_string(),
            cached_at: Utc::now(),
        })
        .collect();
    cache_cve_entries(&conn, &kev_entries)?;

    let mut cached = kev_entries.len();
    for cpe in cpes {
        let entries =
            fetch_cves_from_nvd(cpe, std::env::var("NVD_API_KEY").ok().as_deref()).await?;
        cached += entries.len();
        cache_cve_entries(&conn, &entries)?;
    }

    Ok(cached)
}

fn default_db_path(config: &AppConfig) -> PathBuf {
    config.output_dir.join(".cache").join("cve_cache.sqlite")
}

fn cve_to_vulnerability(entry: CveEntry) -> Vulnerability {
    let mut vuln = Vulnerability::new(
        entry.cve_id.clone(),
        format!("Version-related CVE: {}", entry.cve_id),
        entry.severity.clone(),
        entry.cvss_score,
        entry.description,
        entry.cpe_match.first().cloned().unwrap_or_default(),
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
            source: "nvd".to_string(),
            cached_at: Utc::now(),
        };

        let vuln = cve_to_vulnerability(entry);
        assert_eq!(vuln.id, "CVE-2024-0001");
        assert_eq!(vuln.severity, Severity::Critical);
        assert_eq!(vuln.cvss_score, 9.8);
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
    }
}
