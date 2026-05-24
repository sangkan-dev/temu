use std::path::Path;

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use temu_core::TemuError;
use tokio::time::Duration;

const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const CACHE_TTL_SECS: i64 = 24 * 60 * 60;

/// Fetches the current CISA KEV catalog and returns known exploited CVE IDs.
pub async fn fetch_cisa_kev() -> Result<Vec<String>, TemuError> {
    fetch_cisa_kev_with_base(CISA_KEV_URL).await
}

/// Fetches CISA KEV IDs using a 24-hour local JSON cache.
pub async fn fetch_cisa_kev_with_cache(cache_dir: &Path) -> Result<Vec<String>, TemuError> {
    let cache_file = cache_dir.join("cisa_kev.json");
    if let Ok(raw) = std::fs::read_to_string(&cache_file)
        && let Ok(cache) = serde_json::from_str::<CisaKevCache>(&raw)
    {
        let age = Utc::now() - cache.cached_at;
        if age.num_seconds() < CACHE_TTL_SECS {
            return Ok(cache.cve_ids);
        }
    }

    let cve_ids = fetch_cisa_kev().await?;
    std::fs::create_dir_all(cache_dir)?;
    let cache = CisaKevCache {
        cve_ids: cve_ids.clone(),
        cached_at: Utc::now(),
    };
    let raw = serde_json::to_string_pretty(&cache).map_err(|e| TemuError::Parse(e.to_string()))?;
    std::fs::write(cache_file, raw)?;

    Ok(cve_ids)
}

/// Fetches a CISA KEV-compatible JSON document from a configurable URL.
pub async fn fetch_cisa_kev_with_base(url: &str) -> Result<Vec<String>, TemuError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Temu/1.4.0")
        .build()
        .map_err(TemuError::from_network)?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(TemuError::from_network)?;

    if !response.status().is_success() {
        return Err(TemuError::Network(format!(
            "CISA KEV returned status {}",
            response.status()
        )));
    }

    let catalog = response
        .json::<CisaKevCatalog>()
        .await
        .map_err(|e| TemuError::Parse(e.to_string()))?;

    Ok(catalog
        .vulnerabilities
        .into_iter()
        .map(|entry| entry.cve_id)
        .collect())
}

#[derive(Debug, Deserialize)]
struct CisaKevCatalog {
    #[serde(default)]
    vulnerabilities: Vec<CisaKevEntry>,
}

#[derive(Debug, Deserialize)]
struct CisaKevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CisaKevCache {
    cve_ids: Vec<String>,
    cached_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_fetch_cisa_kev_with_base() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    {"cveID": "CVE-2024-0001"},
                    {"cveID": "CVE-2024-0002"}
                ]
            })))
            .mount(&server)
            .await;

        let ids = fetch_cisa_kev_with_base(&format!("{}/kev.json", server.uri()))
            .await
            .unwrap();
        assert_eq!(ids, vec!["CVE-2024-0001", "CVE-2024-0002"]);
    }

    #[tokio::test]
    async fn test_fetch_cisa_kev_with_cache_uses_fresh_file() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = CisaKevCache {
            cve_ids: vec!["CVE-2024-CACHED".to_string()],
            cached_at: Utc::now(),
        };
        std::fs::write(
            tmp.path().join("cisa_kev.json"),
            serde_json::to_string(&cache).unwrap(),
        )
        .unwrap();

        let ids = fetch_cisa_kev_with_cache(tmp.path()).await.unwrap();
        assert_eq!(ids, vec!["CVE-2024-CACHED"]);
    }
}
