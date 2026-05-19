use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use reqwest::Url;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tracing::{debug, warn};

use temu_core::{AdaptiveRateLimiter, AppConfig, retry_delay};

use crate::types::FuzzResult;

const INTERESTING_STATUSES: &[u16] = &[200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500];
const BASELINE_PATH: &str = "/temu_baseline_zxqwvnm987";
const PARAMETER_PROBE_VALUE: &str = "test123";
const MAX_RETRIES: u32 = 3;

/// Sends a single GET request and returns the result, or `None` on network error.
async fn probe_path(
    client: &Client,
    limiter: &AdaptiveRateLimiter,
    base_url: &str,
    path: &str,
) -> Option<FuzzResult> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    debug!("Fuzzing {url}");

    let parsed = Url::parse(&url).ok();
    let host = parsed.as_ref().and_then(Url::host_str);
    let resp = send_get_with_resilience(client, limiter, &url, host).await?;

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

async fn probe_url(
    client: &Client,
    limiter: &AdaptiveRateLimiter,
    url: Url,
) -> Option<(u16, u64, String)> {
    debug!("Parameter fuzzing {url}");
    let host = url.host_str().map(str::to_string);
    let resp = send_get_with_resilience(client, limiter, url.as_str(), host.as_deref()).await?;
    let status_code = resp.status().as_u16();
    let body = resp.text().await.ok()?;
    let content_length = body.len() as u64;
    Some((status_code, content_length, body))
}

async fn send_get_with_resilience(
    client: &Client,
    limiter: &AdaptiveRateLimiter,
    url: &str,
    host: Option<&str>,
) -> Option<reqwest::Response> {
    for attempt in 0..=MAX_RETRIES {
        limiter.before_request(host).await;
        let started = Instant::now();
        let result = client.get(url).send().await;
        let elapsed = started.elapsed();
        limiter.finish_request();

        match result {
            Ok(response) => {
                let status = response.status().as_u16();
                let should_pause = limiter.observe_response(Some(status), elapsed).await;
                if status == 429 && attempt < MAX_RETRIES {
                    limiter.record_retry();
                    if should_pause {
                        limiter.pause_for_throttling().await;
                    } else {
                        sleep(retry_delay(attempt + 1)).await;
                    }
                    continue;
                }
                return Some(response);
            }
            Err(error) if is_transient_error(&error) && attempt < MAX_RETRIES => {
                limiter.record_retry();
                limiter.observe_response(None, elapsed).await;
                sleep(retry_delay(attempt + 1)).await;
            }
            Err(error) => {
                warn!("Request failed after retries for {url}: {error}");
                return None;
            }
        }
    }

    None
}

fn is_transient_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_request()
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
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(config.concurrency.max(1))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build HTTP client for fuzzing: {e}");
            return Vec::new();
        }
    };
    let limiter = AdaptiveRateLimiter::new(config.rate_limit);

    // Establish baseline (custom 404 detection)
    let baseline = probe_path(&client, &limiter, base_url, BASELINE_PATH).await;
    let (baseline_status, baseline_len) = match &baseline {
        Some(b) => (Some(b.status_code), Some(b.content_length)),
        None => (None, None),
    };

    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let client = Arc::new(client);
    let limiter = Arc::new(limiter);
    let base_url = base_url.to_string();

    let mut handles = Vec::with_capacity(wordlist.len());

    for path in wordlist {
        let path = path.clone();
        let client = Arc::clone(&client);
        let limiter = Arc::clone(&limiter);
        let base = base_url.clone();
        let sem = Arc::clone(&semaphore);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            probe_path(&client, &limiter, &base, &path).await
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
            if let (Some(b_status), Some(b_len)) = (baseline_status, baseline_len)
                && result.status_code == b_status
            {
                let len_diff = (result.content_length as i64 - b_len as i64).unsigned_abs();
                let is_similar =
                    len_diff < 64 || (b_len > 0 && (len_diff as f64 / b_len as f64) < 0.10);
                if is_similar {
                    continue;
                }
            }

            results.push(result);
        }
    }

    let metrics = limiter.metrics().await;
    debug!(
        "Fuzzing resilience metrics: active={}, total={}, retries={}, reuse_rate={:.2}, rps={}",
        metrics.active_connections,
        metrics.total_requests,
        metrics.retry_count,
        metrics.reuse_rate,
        metrics.current_rps
    );

    results
}

/// Runs recursive path fuzzing up to `config.max_recursion_depth`.
///
/// Depth `0` is the base URL. A depth of `2` fuzzes the base URL and then
/// fuzzes discovered paths up to two levels below it. Already visited base URLs
/// are skipped to avoid loops caused by redirects or repeated wordlist entries.
pub async fn fuzz_paths_recursive(
    base_url: &str,
    wordlist: &[String],
    config: &AppConfig,
) -> Vec<FuzzResult> {
    let mut visited_bases: HashSet<String> = HashSet::new();
    let mut seen_urls: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::from([(base_url.to_string(), 0)]);
    let mut all_results = Vec::new();

    while let Some((current_base, depth)) = queue.pop_front() {
        if !visited_bases.insert(current_base.clone()) {
            continue;
        }

        let results = fuzz_paths(&current_base, wordlist, config).await;
        for result in results {
            if !seen_urls.insert(result.url.clone()) {
                continue;
            }

            let should_recurse = depth < config.max_recursion_depth
                && matches!(
                    result.status_code,
                    200 | 201 | 204 | 301 | 302 | 307 | 308 | 401 | 403
                );

            if should_recurse {
                queue.push_back((result.url.clone(), depth + 1));
            }

            all_results.push(result);
        }
    }

    all_results
}

/// Attempts to discover hidden query parameters by comparing each probed
/// response with the baseline response for `url`.
///
/// A parameter is treated as discovered when it changes the status code,
/// changes content length by more than 10%, or reflects the probe value in the
/// response body.
pub async fn fuzz_parameters(
    url: &str,
    wordlist: &[String],
    config: &AppConfig,
) -> Vec<FuzzResult> {
    let client = match Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(&config.user_agent)
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(config.concurrency.max(1))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build HTTP client for parameter fuzzing: {e}");
            return Vec::new();
        }
    };
    let limiter = AdaptiveRateLimiter::new(config.rate_limit);

    let base_url = match Url::parse(url) {
        Ok(url) => url,
        Err(e) => {
            warn!("Invalid URL for parameter fuzzing '{url}': {e}");
            return Vec::new();
        }
    };

    let Some((baseline_status, baseline_len, _)) =
        probe_url(&client, &limiter, base_url.clone()).await
    else {
        return Vec::new();
    };

    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let client = Arc::new(client);
    let limiter = Arc::new(limiter);
    let mut handles = Vec::with_capacity(wordlist.len());

    for parameter in wordlist {
        let parameter = parameter.clone();
        let mut probe = base_url.clone();
        probe
            .query_pairs_mut()
            .append_pair(&parameter, PARAMETER_PROBE_VALUE);
        let client = Arc::clone(&client);
        let limiter = Arc::clone(&limiter);
        let sem = Arc::clone(&semaphore);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let (status_code, content_length, body) =
                probe_url(&client, &limiter, probe.clone()).await?;
            let status_changed = status_code != baseline_status;
            let len_diff = content_length.abs_diff(baseline_len);
            let length_changed = if baseline_len == 0 {
                content_length > 0
            } else {
                (len_diff as f64 / baseline_len as f64) > 0.10
            };
            let reflected = body.contains(PARAMETER_PROBE_VALUE);

            if status_changed || length_changed || reflected {
                Some(FuzzResult {
                    url: probe.to_string(),
                    path: parameter,
                    status_code,
                    content_length,
                    content_type: None,
                    redirect_url: None,
                })
            } else {
                None
            }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(Some(result)) = handle.await {
            results.push(result);
        }
    }

    let metrics = limiter.metrics().await;
    debug!(
        "Parameter fuzzing resilience metrics: active={}, total={}, retries={}, reuse_rate={:.2}, rps={}",
        metrics.active_connections,
        metrics.total_requests,
        metrics.retry_count,
        metrics.reuse_rate,
        metrics.current_rps
    );

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
            max_recursion_depth: 2,
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
            .respond_with(ResponseTemplate::new(200).set_body_string("User-agent: *\nDisallow:"))
            .mount(&mock_server)
            .await;

        // /login → 302
        Mock::given(method("GET"))
            .and(wm_path("/login"))
            .respond_with(ResponseTemplate::new(302).append_header("Location", "/dashboard"))
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
        assert!(
            results
                .iter()
                .any(|r| r.path == "/robots.txt" && r.status_code == 200)
        );
        assert!(
            results
                .iter()
                .any(|r| r.path == "/login" && r.status_code == 302)
        );
    }

    #[tokio::test]
    async fn test_fuzz_paths_baseline_filters_custom_404() {
        let mock_server = MockServer::start().await;

        // Custom 404 — server always returns 200 with the same body for unknown paths
        let custom_404_body = "Page not found custom";

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(custom_404_body))
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
            .respond_with(ResponseTemplate::new(301).append_header("Location", "/admin/login"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let results = fuzz_paths(&mock_server.uri(), &["/admin".to_string()], &test_config()).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].redirect_url, Some("/admin/login".to_string()));
    }

    #[tokio::test]
    async fn test_fuzz_parameters_finds_hidden_parameter() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(wiremock::matchers::query_param("id", PARAMETER_PROBE_VALUE))
            .respond_with(ResponseTemplate::new(200).set_body_string("reflected test123"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("normal"))
            .mount(&mock_server)
            .await;

        let wordlist = vec!["id".to_string(), "unused".to_string()];
        let results = fuzz_parameters(&mock_server.uri(), &wordlist, &test_config()).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "id");
        assert!(results[0].url.contains("id=test123"));
    }

    #[tokio::test]
    async fn test_fuzz_paths_recursive_discovers_nested_path() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(wm_path(BASELINE_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(wm_path("/api"))
            .respond_with(ResponseTemplate::new(200).set_body_string("api root"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(wm_path("/api/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_string("api v1"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&mock_server)
            .await;

        let wordlist = vec!["/api".to_string(), "/v1".to_string()];
        let results = fuzz_paths_recursive(&mock_server.uri(), &wordlist, &test_config()).await;

        assert!(results.iter().any(|r| r.url.ends_with("/api")));
        assert!(results.iter().any(|r| r.url.ends_with("/api/v1")));
    }
}
