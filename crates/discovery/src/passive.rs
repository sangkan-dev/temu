use std::collections::HashSet;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, info};

use temu_core::TemuError;

/// A single entry from the crt.sh JSON response.
#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

/// Fetches subdomains for `domain` from Certificate Transparency logs via crt.sh.
///
/// Returns a deduplicated list of hostnames found in issued certificates.
/// Wildcard prefixes (`*.`) are stripped. Only entries that are subdomains of
/// `domain` are returned.
///
/// The `base_url` parameter allows overriding the crt.sh endpoint (useful for testing).
pub async fn fetch_crtsh_with_base(domain: &str, base_url: &str) -> Result<Vec<String>, TemuError> {
    let url = format!("{base_url}/?q=%.{domain}&output=json");

    debug!("Fetching CT logs from {url}");

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Temu/0.1.0")
        .build()
        .map_err(|e| TemuError::Network(e.to_string()))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| TemuError::Network(format!("crt.sh request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(TemuError::Network(format!(
            "crt.sh returned HTTP {}",
            response.status()
        )));
    }

    let body = response
        .text()
        .await
        .map_err(|e| TemuError::Network(format!("Failed to read crt.sh response: {e}")))?;

    let entries: Vec<CrtShEntry> = serde_json::from_str(&body)
        .map_err(|e| TemuError::Parse(format!("Failed to parse crt.sh JSON: {e}")))?;

    let domain_lower = domain.to_lowercase();
    let mut seen: HashSet<String> = HashSet::new();
    let mut results: Vec<String> = Vec::new();

    for entry in entries {
        for raw in entry.name_value.split('\n') {
            let raw = raw.trim();
            // Strip wildcard prefix
            let host = raw.strip_prefix("*.").unwrap_or(raw).to_lowercase();

            // Only keep if it's a subdomain of (or equal to) the target domain
            if host == domain_lower || host.ends_with(&format!(".{domain_lower}")) {
                if seen.insert(host.clone()) {
                    results.push(host);
                }
            }
        }
    }

    info!(
        "CT logs (crt.sh): found {} unique subdomains for {domain}",
        results.len()
    );

    Ok(results)
}

/// Fetches subdomains for `domain` from the public crt.sh Certificate Transparency log service.
pub async fn fetch_crtsh(domain: &str) -> Result<Vec<String>, TemuError> {
    fetch_crtsh_with_base(domain, "https://crt.sh").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_fetch_crtsh_parses_subdomains() {
        let mock_server = MockServer::start().await;

        let json_body = r#"[
            {"name_value": "api.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "mail.example.com\nwww.example.com"},
            {"name_value": "unrelated.other.com"}
        ]"#;

        Mock::given(method("GET"))
            .and(path("/"))
            .and(query_param("q", "%.example.com"))
            .and(query_param("output", "json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json_body))
            .mount(&mock_server)
            .await;

        let results = fetch_crtsh_with_base("example.com", &mock_server.uri())
            .await
            .unwrap();

        assert!(results.contains(&"api.example.com".to_string()));
        assert!(results.contains(&"mail.example.com".to_string()));
        assert!(results.contains(&"www.example.com".to_string()));
        // Wildcard stripped → "example.com" itself should be included
        assert!(results.contains(&"example.com".to_string()));
        // Unrelated domain filtered out
        assert!(!results.contains(&"unrelated.other.com".to_string()));
    }

    #[tokio::test]
    async fn test_fetch_crtsh_deduplicates() {
        let mock_server = MockServer::start().await;

        let json_body = r#"[
            {"name_value": "api.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "api.example.com\napi.example.com"}
        ]"#;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json_body))
            .mount(&mock_server)
            .await;

        let results = fetch_crtsh_with_base("example.com", &mock_server.uri())
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "api.example.com");
    }

    #[tokio::test]
    async fn test_fetch_crtsh_http_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let result = fetch_crtsh_with_base("example.com", &mock_server.uri()).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TemuError::Network(_)));
    }

    #[tokio::test]
    async fn test_fetch_crtsh_invalid_json() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&mock_server)
            .await;

        let result = fetch_crtsh_with_base("example.com", &mock_server.uri()).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TemuError::Parse(_)));
    }

    #[test]
    fn test_wildcard_strip_logic() {
        let raw = "*.example.com";
        let stripped = raw.strip_prefix("*.").unwrap_or(raw);
        assert_eq!(stripped, "example.com");
    }
}
