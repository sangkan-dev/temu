use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use temu_core::AppConfig;

use crate::types::FuzzResult;

const INTERESTING_STATUSES: &[u16] = &[200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500];
const BASELINE_PATH: &str = "/temu_baseline_zxqwvnm987";

/// Sends a single GET request and returns the result, or `None` on network error.
async fn probe_path(
    client: &Client,
    base_url: &str,
    path: &str,
) -> Option<FuzzResult> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    debug!("Fuzzing {url}");

    let resp = client.get(&url).send().await.ok()?;

    let status_code = resp.status().as_u16();
    let redirect_url = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = resp.bytes().await.ok()?;
    let content_length = body.len() as u64;

    Some(FuzzResult {
        url,
        path: path.to_string(),
        status_code,
        content_length,
        content_type,
        redirect_url,
    })
}

/// Sends requests to each path in `wordlist` against `base_url`.
///
/// Uses a baseline request to detect custom 404 pages. Paths whose response
/// matches the baseline status code AND has a similar content length (within
/// 10% or less than 64 bytes difference) are treated as "not found" and
/// filtered out. Only interesting status codes are kept.
pub async fn fuzz_paths(
    base_url: &str,
    wordlist: &[String],
    config: &AppConfig,
) -> Vec<FuzzResult> {
    let client = match Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(&config.user_agent)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build HTTP client for fuzzing: {e}");
            return Vec::new();
        }
    };

    // Establish baseline (custom 404 detection)
    let baseline = probe_path(&client, base_url, BASELINE_PATH).await;
    let (baseline_status, baseline_len) = match &baseline {
        Some(b) => (Some(b.status_code), Some(b.content_length)),
        None => (None, None),
    };

    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let client = Arc::new(client);
    let base_url = base_url.to_string();

    let mut handles = Vec::with_capacity(wordlist.len());

    for path in wordlist {
        let path = path.clone();
        let client = Arc::clone(&client);
        let base = base_url.clone();
        let sem = Arc::clone(&semaphore);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            probe_path(&client, &base, &path).await
        }));
    }

    let mut results = Vec::new();

    for handle in handles {
        if let Ok(Some(result)) = handle.await {
            // Filter: skip if status is not interesting
            if !INTERESTING_STATUSES.contains(&result.status_code) {
                continue;
            }

            // Filter: skip if matches baseline (custom 404)
            if let (Some(b_status), Some(b_len)) = (baseline_status, baseline_len) {
                if result.status_code == b_status {
                    let len_diff = (result.content_length as i64 - b_len as i64).unsigned_abs();
                    let is_similar = len_diff < 64
                        || (b_len > 0
                            && (len_diff as f64 / b_len as f64) < 0.10);
                    if is_similar {
                        continue;
                    }
                }
            }

            results.push(result);
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use wiremock::matchers::{method, path as wm_path};
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
            wordlist_override: None,
        }
    }

    #[tokio::test]
    async fn test_fuzz_paths_finds_existing_paths() {
        let mock_server = MockServer::start().await;

        // Baseline path → 404
        Mock::given(method("GET"))
            .and(wm_path(BASELINE_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&mock_server)
            .await;

        // /robots.txt → 200
        Mock::given(method("GET"))
            .and(wm_path("/robots.txt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("User-agent: *\nDisallow:"),
            )
            .mount(&mock_server)
            .await;

        // /login → 302
        Mock::given(method("GET"))
            .and(wm_path("/login"))
            .respond_with(
                ResponseTemplate::new(302)
                    .append_header("Location", "/dashboard"),
            )
            .mount(&mock_server)
            .await;

        // Everything else → 404
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&mock_server)
            .await;

        let wordlist = vec![
            "/robots.txt".to_string(),
            "/login".to_string(),
            "/nonexistent".to_string(),
        ];

        let results = fuzz_paths(&mock_server.uri(), &wordlist, &test_config()).await;

        assert_eq!(results.len(), 2, "Expected 2 results (robots.txt + login)");
        assert!(results.iter().any(|r| r.path == "/robots.txt" && r.status_code == 200));
        assert!(results.iter().any(|r| r.path == "/login" && r.status_code == 302));
    }

    #[tokio::test]
    async fn test_fuzz_paths_baseline_filters_custom_404() {
        let mock_server = MockServer::start().await;

        // Custom 404 — server always returns 200 with the same body for unknown paths
        let custom_404_body = "Page not found custom";

        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(custom_404_body),
            )
            .mount(&mock_server)
            .await;

        let wordlist = vec!["/admin".to_string(), "/login".to_string()];

        let results = fuzz_paths(&mock_server.uri(), &wordlist, &test_config()).await;

        // Both paths return same body as baseline → both filtered out
        assert!(
            results.is_empty(),
            "Custom 404 pages should be filtered out, got {} results",
            results.len()
        );
    }

    #[tokio::test]
    async fn test_fuzz_result_contains_redirect_url() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(wm_path(BASELINE_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(wm_path("/admin"))
            .respond_with(
                ResponseTemplate::new(301)
                    .append_header("Location", "/admin/login"),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let results = fuzz_paths(
            &mock_server.uri(),
            &["/admin".to_string()],
            &test_config(),
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].redirect_url, Some("/admin/login".to_string()));
    }
}
