// Fingerprint crate — technology detection (Wappalyzer-style YAML rules)

pub mod rules;
pub mod types;

pub use types::{FingerprintRule, TechCategory, TechStack};

use std::time::Duration;

use reqwest::Client;
use temu_core::{AppConfig, TemuError};
use tracing::{info, warn};

use crate::rules::{load_fingerprint_rules, match_all_rules};

const MAX_FINGERPRINT_BODY_BYTES: usize = 1024 * 1024;

/// Sends a GET request to `url` and detects technologies using YAML fingerprint rules.
///
/// Rules are loaded from `{config.rules_dir}/fingerprint_rules.yaml`.
/// If the rules file is missing, a warning is logged and an empty list is returned.
/// Results are deduplicated by name (highest confidence wins) and sorted by confidence descending.
pub async fn run_fingerprint(url: &str, config: &AppConfig) -> Result<Vec<TechStack>, TemuError> {
    info!("Fingerprinting {url}");

    // Load rules
    let rules_path = config.rules_dir.join("fingerprint_rules.yaml");
    let rules = match load_fingerprint_rules(&rules_path) {
        Ok(r) => r,
        Err(e) => {
            warn!("Could not load fingerprint rules from {rules_path:?}: {e}");
            return Ok(vec![]);
        }
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent(&config.user_agent)
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(config.concurrency.max(1))
        .build()
        .map_err(|e| TemuError::Network(e.to_string()))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| TemuError::Network(format!("Fingerprint request to {url} failed: {e}")))?;

    let resp_headers = response.headers().clone();

    let body = read_limited_text(response, MAX_FINGERPRINT_BODY_BYTES)
        .await
        .unwrap_or_default();

    let result = match_all_rules(&rules, &resp_headers, &body);

    for tech in &result {
        info!(
            "Detected: {}{} (confidence: {:.2})",
            tech.name,
            tech.version
                .as_deref()
                .map(|v| format!("/{v}"))
                .unwrap_or_default(),
            tech.confidence
        );
    }

    info!("Fingerprint {url}: {} technologies detected", result.len());

    Ok(result)
}

async fn read_limited_text(mut response: reqwest::Response, max_bytes: usize) -> Option<String> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        let remaining = max_bytes.saturating_sub(body.len());
        if remaining > 0 {
            body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        }
    }
    Some(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Returns the workspace root rules/ directory using CARGO_MANIFEST_DIR.
    fn rules_dir() -> PathBuf {
        // crates/fingerprint → workspace root → rules/
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest.join("../../rules")
    }

    fn test_config() -> AppConfig {
        AppConfig {
            rate_limit: 10,
            timeout_secs: 5,
            concurrency: 4,
            user_agent: "Temu-Test/1.0.0".to_string(),
            output_dir: PathBuf::from("/tmp"),
            rules_dir: rules_dir(),
            dictionaries_dir: PathBuf::from("/tmp"),
            max_recursion_depth: 2,
            wordlist_override: None,
            allow_risky_rules: false,
            browser_crawl_enabled: true,
            browser_crawl_max_pages: 25,
            browser_crawl_max_depth: 2,
            browser_crawl_render_js: false,
            browser_crawl_browser_path: None,
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

        assert!(
            result.iter().any(|t| t.name == "Apache"),
            "Apache not detected"
        );
        let apache = result.iter().find(|t| t.name == "Apache").unwrap();
        assert_eq!(apache.version, Some("2.4.51".to_string()));
    }

    #[tokio::test]
    async fn test_run_fingerprint_detects_wordpress_from_body() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<html><head><meta name="generator" content="WordPress 6.2"/></head></html>"#,
            ))
            .mount(&mock_server)
            .await;

        let result = run_fingerprint(&mock_server.uri(), &test_config())
            .await
            .unwrap();

        assert!(
            result.iter().any(|t| t.name == "WordPress"),
            "WordPress not detected"
        );
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

    #[tokio::test]
    async fn test_run_fingerprint_implies_chain() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"<html><head><meta name="generator" content="WordPress 6.3"/></head><body><a href="/wp-content/themes/x">theme</a></body></html>"#),
            )
            .mount(&mock_server)
            .await;

        let result = run_fingerprint(&mock_server.uri(), &test_config())
            .await
            .unwrap();

        // WordPress implies PHP and MySQL
        assert!(
            result.iter().any(|t| t.name == "WordPress"),
            "WordPress missing"
        );
        assert!(
            result.iter().any(|t| t.name == "PHP"),
            "PHP not implied by WordPress"
        );
        assert!(
            result.iter().any(|t| t.name == "MySQL"),
            "MySQL not implied by WordPress"
        );
    }

    #[tokio::test]
    async fn test_run_fingerprint_missing_rules_returns_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
            .mount(&mock_server)
            .await;

        let config = AppConfig {
            rules_dir: PathBuf::from("/nonexistent/rules"),
            ..AppConfig::default()
        };

        let result = run_fingerprint(&mock_server.uri(), &config).await.unwrap();
        assert!(
            result.is_empty(),
            "should return empty when rules file missing"
        );
    }
}
