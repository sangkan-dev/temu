use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use regex::Regex;
use reqwest::Client;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tracing::{debug, warn};

use temu_core::{AdaptiveRateLimiter, AppConfig, retry_delay};

const MAX_RETRIES: u32 = 3;

/// Result of an HTTP/HTTPS probe against a single host.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// The final URL that responded (http:// or https://).
    pub url: String,
    /// HTTP status code returned.
    pub status_code: u16,
    /// Redirect target if the response was a 3xx.
    pub redirect_url: Option<String>,
    /// `Content-Length` header value if present.
    pub content_length: Option<u64>,
    /// Extracted `<title>` tag content from the response body.
    pub title: Option<String>,
    /// True if another host already redirected to the same URL in this batch.
    pub is_duplicate: bool,
}

/// Probes a single host over HTTPS first, falling back to HTTP.
///
/// Returns `None` if both HTTPS and HTTP fail to connect within `timeout`.
pub async fn probe_http(host: &str, timeout: Duration) -> Option<ProbeResult> {
    let client = Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("Temu/1.3.0")
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(8)
        .build()
        .ok()?;
    let limiter = AdaptiveRateLimiter::new(50);

    probe_http_with_client(host, &client, &limiter).await
}

async fn probe_http_with_client(
    host: &str,
    client: &Client,
    limiter: &AdaptiveRateLimiter,
) -> Option<ProbeResult> {
    // Try HTTPS first, then HTTP
    for scheme in &["https", "http"] {
        let url = format!("{scheme}://{host}");
        match send_probe_request(client, limiter, &url, Some(host)).await {
            Ok(response) => {
                let status_code = response.status().as_u16();
                let redirect_url = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let content_length = response.content_length();
                let final_url = response.url().to_string();

                let body = response.text().await.unwrap_or_default();
                let title = extract_title(&body);

                debug!("Probed {url} → {status_code}");

                return Some(ProbeResult {
                    url: final_url,
                    status_code,
                    redirect_url,
                    content_length,
                    title,
                    is_duplicate: false,
                });
            }
            Err(e) => {
                debug!("Probe failed {url}: {e}");
                continue;
            }
        }
    }

    None
}

/// Probes all hosts concurrently, respecting `config.concurrency` and
/// `config.timeout_secs`. Marks duplicate redirect targets.
pub async fn probe_all(hosts: &[String], config: &AppConfig) -> Vec<ProbeResult> {
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let client = match Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(&config.user_agent)
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(config.concurrency.max(1))
        .build()
    {
        Ok(client) => Arc::new(client),
        Err(e) => {
            warn!("Failed to build HTTP probe client: {e}");
            return Vec::new();
        }
    };
    let limiter = Arc::new(AdaptiveRateLimiter::new(config.rate_limit));

    let mut handles = Vec::with_capacity(hosts.len());

    for host in hosts {
        let host = host.clone();
        let sem = Arc::clone(&semaphore);
        let client = Arc::clone(&client);
        let limiter = Arc::clone(&limiter);

        let handle = tokio::spawn(async move {
            let Ok(_permit) = sem.acquire().await else {
                warn!("HTTP probe skipped because semaphore is closed");
                return None;
            };
            probe_http_with_client(&host, &client, &limiter).await
        });

        handles.push(handle);
    }

    let mut results: Vec<ProbeResult> = Vec::new();
    for handle in handles {
        if let Ok(Some(result)) = handle.await {
            results.push(result);
        }
    }

    mark_duplicates(&mut results);
    let metrics = limiter.metrics().await;
    debug!(
        "HTTP probe resilience metrics: active={}, total={}, retries={}, reuse_rate={:.2}, rps={}",
        metrics.active_connections,
        metrics.total_requests,
        metrics.retry_count,
        metrics.reuse_rate,
        metrics.current_rps
    );
    results
}

async fn send_probe_request(
    client: &Client,
    limiter: &AdaptiveRateLimiter,
    url: &str,
    host: Option<&str>,
) -> Result<reqwest::Response, reqwest::Error> {
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
                return Ok(response);
            }
            Err(error) if is_transient_error(&error) && attempt < MAX_RETRIES => {
                limiter.record_retry();
                limiter.observe_response(None, elapsed).await;
                sleep(retry_delay(attempt + 1)).await;
            }
            Err(error) => return Err(error),
        }
    }

    client.get(url).send().await
}

fn is_transient_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_request()
}

/// Marks `ProbeResult` entries as duplicates if more than one host redirected
/// to the same final URL.
fn mark_duplicates(results: &mut [ProbeResult]) {
    let mut seen_redirects: HashSet<String> = HashSet::new();

    for result in results.iter_mut() {
        if let Some(ref redir) = result.redirect_url
            && !seen_redirects.insert(redir.clone())
        {
            result.is_duplicate = true;
            warn!("Duplicate redirect target: {redir}");
        }
    }
}

/// Extracts the text content of the first `<title>` tag in `html`.
fn extract_title(html: &str) -> Option<String> {
    static TITLE_RE: std::sync::LazyLock<Option<Regex>> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)<title[^>]*>([^<]+)</title>").ok());

    TITLE_RE
        .as_ref()?
        .captures(html)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_extract_title_basic() {
        let html = "<html><head><title>Hello World</title></head></html>";
        assert_eq!(extract_title(html), Some("Hello World".to_string()));
    }

    #[test]
    fn test_extract_title_with_attributes() {
        let html = "<title lang=\"en\">My Page</title>";
        assert_eq!(extract_title(html), Some("My Page".to_string()));
    }

    #[test]
    fn test_extract_title_case_insensitive() {
        let html = "<TITLE>Upper Case</TITLE>";
        assert_eq!(extract_title(html), Some("Upper Case".to_string()));
    }

    #[test]
    fn test_extract_title_trims_whitespace() {
        let html = "<title>  Padded Title  </title>";
        assert_eq!(extract_title(html), Some("Padded Title".to_string()));
    }

    #[test]
    fn test_extract_title_missing() {
        let html = "<html><body>No title here</body></html>";
        assert_eq!(extract_title(html), None);
    }

    #[test]
    fn test_mark_duplicates() {
        let mut results = vec![
            ProbeResult {
                url: "https://a.example.com".to_string(),
                status_code: 301,
                redirect_url: Some("https://www.example.com".to_string()),
                content_length: None,
                title: None,
                is_duplicate: false,
            },
            ProbeResult {
                url: "https://b.example.com".to_string(),
                status_code: 301,
                redirect_url: Some("https://www.example.com".to_string()),
                content_length: None,
                title: None,
                is_duplicate: false,
            },
            ProbeResult {
                url: "https://c.example.com".to_string(),
                status_code: 200,
                redirect_url: None,
                content_length: Some(1234),
                title: Some("C Page".to_string()),
                is_duplicate: false,
            },
        ];

        mark_duplicates(&mut results);
        assert!(!results[0].is_duplicate);
        assert!(results[1].is_duplicate);
        assert!(!results[2].is_duplicate);
    }

    #[tokio::test]
    async fn test_probe_http_200_with_title() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("<html><head><title>Test Page</title></head></html>")
                    .insert_header("content-type", "text/html"),
            )
            .mount(&mock_server)
            .await;

        let host = mock_server.uri().replace("http://", "");
        let result = probe_http(&host, Duration::from_secs(5)).await;

        assert!(result.is_some());
        let probe = result.unwrap();
        assert_eq!(probe.status_code, 200);
        assert_eq!(probe.title, Some("Test Page".to_string()));
        assert!(!probe.is_duplicate);
    }

    #[tokio::test]
    async fn test_probe_http_301_redirect() {
        let mock_server = MockServer::start().await;

        // Respond to both / (301) and /final (200) so reqwest can follow the redirect
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(301)
                    .insert_header("location", &format!("{}/final", mock_server.uri())),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/final"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<title>Final</title>"))
            .mount(&mock_server)
            .await;

        let host = mock_server.uri().replace("http://", "");
        let result = probe_http(&host, Duration::from_secs(5)).await;

        // reqwest follows the redirect, so final status is 200
        assert!(result.is_some());
        let probe = result.unwrap();
        assert_eq!(probe.status_code, 200);
        assert_eq!(probe.title, Some("Final".to_string()));
    }

    #[tokio::test]
    async fn test_probe_all_with_mock() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<title>Mock</title>"))
            .mount(&mock_server)
            .await;

        let host = mock_server.uri().replace("http://", "");
        let config = AppConfig::default();
        let results = probe_all(&[host], &config).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status_code, 200);
        assert_eq!(results[0].title, Some("Mock".to_string()));
    }
}
