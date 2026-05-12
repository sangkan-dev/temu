// Fingerprint crate — technology detection (Wappalyzer-style rules)

pub mod body;
pub mod headers;
pub mod types;
pub mod waf;

pub use types::{TechCategory, TechStack};

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use temu_core::{AppConfig, TemuError};
use tracing::{debug, info};

use crate::body::fingerprint_from_body;
use crate::headers::fingerprint_from_headers;
use crate::waf::detect_waf;

/// Sends a GET request to `url` and detects technologies from headers + body.
///
/// Results are deduplicated by name (highest confidence wins) and sorted by
/// confidence descending.
pub async fn run_fingerprint(url: &str, config: &AppConfig) -> Result<Vec<TechStack>, TemuError> {
    debug!("Fingerprinting {url}");

    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent(&config.user_agent)
        .build()
        .map_err(|e| TemuError::Network(e.to_string()))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| TemuError::Network(format!("Fingerprint request to {url} failed: {e}")))?;

    let status = response.status().as_u16();
    let resp_headers = response.headers().clone();

    let body = response
        .text()
        .await
        .unwrap_or_default();

    let mut all: Vec<TechStack> = Vec::new();
    all.extend(fingerprint_from_headers(&resp_headers));
    all.extend(fingerprint_from_body(&body));
    if let Some(waf) = detect_waf(&resp_headers, status, &body) {
        all.push(waf);
    }

    // Dedup by name — keep highest confidence
    let mut by_name: HashMap<String, TechStack> = HashMap::new();
    for tech in all {
        by_name
            .entry(tech.name.clone())
            .and_modify(|existing| {
                if tech.confidence > existing.confidence {
                    *existing = tech.clone();
                }
            })
            .or_insert(tech);
    }

    let mut result: Vec<TechStack> = by_name.into_values().collect();
    result.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

    info!("Fingerprint {url}: {} technologies detected", result.len());

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config() -> AppConfig {
        AppConfig {
            rate_limit: 10,
            timeout_secs: 5,
            concurrency: 4,
            user_agent: "Temu-Test/0.1.0".to_string(),
            output_dir: PathBuf::from("/tmp"),
            rules_dir: PathBuf::from("/tmp"),
            dictionaries_dir: PathBuf::from("/tmp"),
        }
    }

    #[tokio::test]
    async fn test_run_fingerprint_detects_apache_from_header() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("Server", "Apache/2.4.51 (Ubuntu)")
                    .set_body_string("<html><body>Hello</body></html>"),
            )
            .mount(&mock_server)
            .await;

        let result = run_fingerprint(&mock_server.uri(), &test_config())
            .await
            .unwrap();

        assert!(result.iter().any(|t| t.name == "Apache"), "Apache not detected");
        let apache = result.iter().find(|t| t.name == "Apache").unwrap();
        assert_eq!(apache.version, Some("2.4.51".to_string()));
    }

    #[tokio::test]
    async fn test_run_fingerprint_detects_wordpress_from_body() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"<html><head><meta name="generator" content="WordPress 6.2"/></head></html>"#),
            )
            .mount(&mock_server)
            .await;

        let result = run_fingerprint(&mock_server.uri(), &test_config())
            .await
            .unwrap();

        assert!(result.iter().any(|t| t.name == "WordPress"), "WordPress not detected");
    }

    #[tokio::test]
    async fn test_run_fingerprint_deduplicates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("Server", "nginx/1.18.0")
                    .append_header("cf-ray", "abc123-IAD")
                    .set_body_string("<html></html>"),
            )
            .mount(&mock_server)
            .await;

        let result = run_fingerprint(&mock_server.uri(), &test_config())
            .await
            .unwrap();

        let nginx_count = result.iter().filter(|t| t.name == "nginx").count();
        assert_eq!(nginx_count, 1, "nginx should appear only once after dedup");
    }
}
