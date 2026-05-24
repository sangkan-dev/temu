use std::collections::HashSet;
use std::path::Path;
use std::time::{Duration, SystemTime};

use reqwest::Client;
use serde::Deserialize;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use temu_core::TemuError;

/// Cache TTL for CT log results (24 hours).
const CACHE_TTL_SECS: u64 = 86_400;
/// Maximum number of retry attempts on transient failures.
const MAX_RETRIES: u32 = 3;

/// A single entry from the crt.sh JSON response.
#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

/// Fetches subdomains for `domain` from Certificate Transparency logs via crt.sh,
/// with up to `MAX_RETRIES` retries using exponential backoff on 5xx / timeout errors.
///
/// The `base_url` parameter allows overriding the crt.sh endpoint (useful for testing).
pub async fn fetch_crtsh_with_base(domain: &str, base_url: &str) -> Result<Vec<String>, TemuError> {
    let url = format!("{base_url}/?q=%.{domain}&output=json");

    debug!("Fetching CT logs from {url}");

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Temu/1.4.0")
        .build()
        .map_err(|e| TemuError::Network(e.to_string()))?;

    let mut last_err = TemuError::Network("No attempts made".to_string());

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let backoff = Duration::from_secs(2u64.pow(attempt));
            warn!(
                "crt.sh attempt {}/{MAX_RETRIES} failed, retrying in {}s",
                attempt,
                backoff.as_secs()
            );
            sleep(backoff).await;
        }

        let response = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = TemuError::Network(format!("crt.sh request failed: {e}"));
                continue;
            }
        };

        if response.status().is_server_error() {
            last_err = TemuError::Network(format!("crt.sh returned HTTP {}", response.status()));
            continue;
        }

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

        return parse_crtsh_body(&body, domain);
    }

    Err(last_err)
}

/// Fetches subdomains for `domain` from the public crt.sh service, using a local
/// cache file under `cache_dir` with a 24-hour TTL.
///
/// Cache file: `{cache_dir}/crtsh_{domain}.json`
pub async fn fetch_crtsh_with_cache(
    domain: &str,
    cache_dir: &Path,
) -> Result<Vec<String>, TemuError> {
    fetch_crtsh_with_cache_and_base(domain, cache_dir, "https://crt.sh").await
}

/// Like [`fetch_crtsh_with_cache`] but allows overriding the crt.sh base URL for testing.
pub async fn fetch_crtsh_with_cache_and_base(
    domain: &str,
    cache_dir: &Path,
    base_url: &str,
) -> Result<Vec<String>, TemuError> {
    let cache_file = cache_dir.join(format!("crtsh_{}.json", domain.replace('.', "_")));

    // Try reading from cache if not expired
    if let Ok(metadata) = std::fs::metadata(&cache_file)
        && let Ok(modified) = metadata.modified()
    {
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::MAX);
        if age.as_secs() < CACHE_TTL_SECS {
            if let Ok(cached) = std::fs::read_to_string(&cache_file)
                && let Ok(hostnames) = serde_json::from_str::<Vec<String>>(&cached)
            {
                debug!(
                    "CT log cache hit for {domain} ({} entries, age {}s)",
                    hostnames.len(),
                    age.as_secs()
                );
                info!(
                    "CT logs (crt.sh cache): found {} unique subdomains for {domain}",
                    hostnames.len()
                );
                return Ok(hostnames);
            }
        } else {
            debug!("CT log cache expired for {domain} (age {}s)", age.as_secs());
        }
    }

    // Fetch from network
    let results = fetch_crtsh_with_base(domain, base_url).await?;

    // Write cache (best-effort, ignore errors)
    if let Ok(json) = serde_json::to_string(&results) {
        if let Err(e) = std::fs::create_dir_all(cache_dir) {
            warn!("Could not create CT log cache dir: {e}");
        } else if let Err(e) = std::fs::write(&cache_file, json) {
            warn!("Could not write CT log cache: {e}");
        } else {
            debug!("CT log cache written: {:?}", cache_file);
        }
    }

    Ok(results)
}

/// Fetches subdomains for `domain` from the public crt.sh Certificate Transparency log service.
pub async fn fetch_crtsh(domain: &str) -> Result<Vec<String>, TemuError> {
    fetch_crtsh_with_base(domain, "https://crt.sh").await
}

/// Parses a crt.sh JSON body and returns deduplicated subdomains of `domain`.
fn parse_crtsh_body(body: &str, domain: &str) -> Result<Vec<String>, TemuError> {
    let entries: Vec<CrtShEntry> = serde_json::from_str(body)
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
            if (host == domain_lower || host.ends_with(&format!(".{domain_lower}")))
                && seen.insert(host.clone())
            {
                results.push(host);
            }
        }
    }

    info!(
        "CT logs (crt.sh): found {} unique subdomains for {domain}",
        results.len()
    );

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
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

    #[tokio::test]
    async fn test_retry_on_502_then_success() {
        let mock_server = MockServer::start().await;

        let json_body = r#"[{"name_value": "api.example.com"}]"#;

        // First two requests return 502, third returns 200
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(502))
            .up_to_n_times(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json_body))
            .mount(&mock_server)
            .await;

        let result = fetch_crtsh_with_base("example.com", &mock_server.uri()).await;
        assert!(
            result.is_ok(),
            "should succeed after retry: {:?}",
            result.err()
        );
        assert!(result.unwrap().contains(&"api.example.com".to_string()));
    }

    #[tokio::test]
    async fn test_cache_hit_returns_without_network() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path();

        // Pre-populate cache file with valid JSON
        let cache_file = cache_dir.join("crtsh_example_com.json");
        let cached_data = r#"["api.example.com","www.example.com"]"#;
        std::fs::File::create(&cache_file)
            .unwrap()
            .write_all(cached_data.as_bytes())
            .unwrap();

        // Should return cached results without any network call
        let result = fetch_crtsh_with_cache("example.com", cache_dir).await;
        assert!(result.is_ok());
        let hostnames = result.unwrap();
        assert_eq!(hostnames.len(), 2);
        assert!(hostnames.contains(&"api.example.com".to_string()));
    }

    #[tokio::test]
    async fn test_no_cache_fetches_network_via_mock() {
        let mock_server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let cache_dir = tmp.path();

        let json_body = r#"[{"name_value": "fresh.example.com"}]"#;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(json_body))
            .mount(&mock_server)
            .await;

        // No cache file exists → should fetch from mock network
        let result =
            fetch_crtsh_with_cache_and_base("example.com", cache_dir, &mock_server.uri()).await;
        assert!(result.is_ok(), "expected Ok from mock: {:?}", result.err());
        assert!(result.unwrap().contains(&"fresh.example.com".to_string()));

        // Cache file should now exist
        let cache_file = cache_dir.join("crtsh_example_com.json");
        assert!(
            cache_file.exists(),
            "cache file should be written after fetch"
        );
    }
}
