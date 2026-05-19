use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use temu_core::{Severity, TemuError};
use tokio::time::{Duration, sleep};

use crate::types::{CveEntry, Exploitability};

const NVD_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PAGE_SIZE: usize = 2000;

/// Fetches CVEs from NVD API v2.0 for a CPE name.
pub async fn fetch_cves_from_nvd(
    cpe: &str,
    api_key: Option<&str>,
) -> Result<Vec<CveEntry>, TemuError> {
    fetch_cves_from_nvd_with_base(cpe, api_key, NVD_BASE_URL).await
}

/// Fetches CVEs from a configurable NVD-compatible base URL.
pub async fn fetch_cves_from_nvd_with_base(
    cpe: &str,
    api_key: Option<&str>,
    base_url: &str,
) -> Result<Vec<CveEntry>, TemuError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Temu/1.0.0")
        .build()
        .map_err(TemuError::from_network)?;

    let mut start_index = 0usize;
    let mut total_results = None;
    let mut entries = Vec::new();

    loop {
        let response = fetch_page(&client, base_url, cpe, api_key, start_index).await?;
        total_results = total_results.or(Some(response.total_results));
        entries.extend(
            response
                .vulnerabilities
                .into_iter()
                .filter_map(|v| normalize_nvd_vulnerability(v, cpe)),
        );

        start_index += PAGE_SIZE;
        if start_index >= total_results.unwrap_or(0) {
            break;
        }
    }

    Ok(entries)
}

async fn fetch_page(
    client: &Client,
    base_url: &str,
    cpe: &str,
    api_key: Option<&str>,
    start_index: usize,
) -> Result<NvdResponse, TemuError> {
    let mut last_error = None;

    for attempt in 0..3 {
        let mut request = client.get(base_url).query(&[
            ("cpeName", cpe),
            ("resultsPerPage", &PAGE_SIZE.to_string()),
            ("startIndex", &start_index.to_string()),
        ]);

        if let Some(key) = api_key {
            request = request.header("apiKey", key);
        }

        match request.send().await {
            Ok(response) if response.status().is_success() => {
                return response
                    .json::<NvdResponse>()
                    .await
                    .map_err(|e| TemuError::Parse(e.to_string()));
            }
            Ok(response)
                if response.status().as_u16() == 429 || response.status().is_server_error() =>
            {
                last_error = Some(TemuError::Network(format!(
                    "NVD returned status {}",
                    response.status()
                )));
                sleep(Duration::from_millis(250 * 2u64.pow(attempt))).await;
            }
            Ok(response) => {
                return Err(TemuError::Network(format!(
                    "NVD returned status {}",
                    response.status()
                )));
            }
            Err(e) => {
                last_error = Some(TemuError::from_network(e));
                sleep(Duration::from_millis(250 * 2u64.pow(attempt))).await;
            }
        }
    }

    Err(last_error.unwrap_or(TemuError::Timeout))
}

fn normalize_nvd_vulnerability(
    vulnerability: NvdVulnerability,
    queried_cpe: &str,
) -> Option<CveEntry> {
    let cve = vulnerability.cve;
    let cve_id = cve.id?;
    let description = cve
        .descriptions
        .into_iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value)
        .unwrap_or_default();
    let (severity, cvss_score) = cve.metrics.score_and_severity();

    Some(CveEntry {
        cve_id,
        description,
        severity,
        cvss_score,
        cpe_match: vec![queried_cpe.to_string()],
        published_date: cve.published,
        last_modified: cve.last_modified,
        exploitability: Exploitability::Theoretical,
        source: "nvd".to_string(),
        cached_at: Utc::now(),
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    total_results: usize,
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
    id: Option<String>,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: NvdMetrics,
    published: Option<String>,
    last_modified: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetrics {
    #[serde(default)]
    cvss_metric_v31: Vec<CvssMetric>,
    #[serde(default)]
    cvss_metric_v30: Vec<CvssMetric>,
    #[serde(default)]
    cvss_metric_v2: Vec<CvssMetric>,
}

impl NvdMetrics {
    fn score_and_severity(&self) -> (Severity, f32) {
        self.cvss_metric_v31
            .first()
            .or_else(|| self.cvss_metric_v30.first())
            .or_else(|| self.cvss_metric_v2.first())
            .map(|metric| {
                (
                    parse_severity(metric.cvss_data.base_severity.as_deref()),
                    metric.cvss_data.base_score,
                )
            })
            .unwrap_or((Severity::Info, 0.0))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssMetric {
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    base_score: f32,
    base_severity: Option<String>,
}

fn parse_severity(value: Option<&str>) -> Severity {
    match value.unwrap_or_default().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_fetch_cves_from_nvd_with_base_parses_response() {
        let server = MockServer::start().await;
        let cpe = "cpe:2.3:a:php:php:8.1:*:*:*:*:*:*:*";

        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(query_param("cpeName", cpe))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalResults": 1,
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-2024-1234",
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-02T00:00:00.000",
                        "descriptions": [
                            {"lang": "en", "value": "Example vulnerability"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL"
                                }
                            }]
                        }
                    }
                }]
            })))
            .mount(&server)
            .await;

        let base = format!("{}/rest/json/cves/2.0", server.uri());
        let entries = fetch_cves_from_nvd_with_base(cpe, None, &base)
            .await
            .unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve_id, "CVE-2024-1234");
        assert_eq!(entries[0].severity, Severity::Critical);
        assert_eq!(entries[0].cvss_score, 9.8);
    }

    #[tokio::test]
    async fn test_fetch_cves_retries_on_503() {
        let server = MockServer::start().await;
        let cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*";

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalResults": 0,
                "vulnerabilities": []
            })))
            .mount(&server)
            .await;

        let entries = fetch_cves_from_nvd_with_base(cpe, None, &server.uri())
            .await
            .unwrap();
        assert!(entries.is_empty());
    }
}
