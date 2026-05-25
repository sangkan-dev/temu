use std::collections::HashMap;

use reqwest::Client;
use serde::Deserialize;
use temu_core::TemuError;
use tokio::time::Duration;

use crate::types::CveEntry;

const EPSS_BASE_URL: &str = "https://api.first.org/data/v1/epss";

/// Fetches EPSS probabilities for CVE identifiers from FIRST.
pub async fn fetch_epss_scores(cve_ids: &[String]) -> Result<HashMap<String, f32>, TemuError> {
    fetch_epss_scores_with_base(cve_ids, EPSS_BASE_URL).await
}

/// Fetches EPSS probabilities from a configurable FIRST-compatible endpoint.
pub async fn fetch_epss_scores_with_base(
    cve_ids: &[String],
    base_url: &str,
) -> Result<HashMap<String, f32>, TemuError> {
    if cve_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Temu/1.5.0")
        .build()
        .map_err(TemuError::from_network)?;
    let response = client
        .get(base_url)
        .query(&[("cve", cve_ids.join(","))])
        .send()
        .await
        .map_err(TemuError::from_network)?;
    if !response.status().is_success() {
        return Err(TemuError::Network(format!(
            "EPSS returned status {}",
            response.status()
        )));
    }

    let body = response
        .json::<EpssResponse>()
        .await
        .map_err(|e| TemuError::Parse(e.to_string()))?;
    Ok(body
        .data
        .into_iter()
        .filter_map(|item| item.epss.parse::<f32>().ok().map(|score| (item.cve, score)))
        .collect())
}

/// Applies fetched EPSS probabilities to normalized CVE entries.
pub async fn enrich_epss_scores(entries: &mut [CveEntry]) -> Result<(), TemuError> {
    let ids = entries
        .iter()
        .map(|entry| entry.cve_id.clone())
        .collect::<Vec<_>>();
    let scores = fetch_epss_scores(&ids).await?;
    for entry in entries {
        entry.epss_score = scores.get(&entry.cve_id).copied();
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    #[serde(default)]
    data: Vec<EpssEntry>,
}

#[derive(Debug, Deserialize)]
struct EpssEntry {
    cve: String,
    epss: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_fetch_epss_scores_with_base_parses_probabilities() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/epss"))
            .and(query_param("cve", "CVE-2024-0001,CVE-2024-0002"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"cve": "CVE-2024-0001", "epss": "0.875"},
                    {"cve": "CVE-2024-0002", "epss": "0.012"}
                ]
            })))
            .mount(&server)
            .await;

        let scores = fetch_epss_scores_with_base(
            &["CVE-2024-0001".to_string(), "CVE-2024-0002".to_string()],
            &format!("{}/epss", server.uri()),
        )
        .await
        .unwrap();

        assert_eq!(scores["CVE-2024-0001"], 0.875);
        assert_eq!(scores["CVE-2024-0002"], 0.012);
    }
}
