//! Verifier crate — false positive reduction.

pub mod sdk;

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use temu_core::{AppConfig, TemuError, Vulnerability};
use tracing::{info, warn};
use vulnerability::{MatchType, Rule, load_rules};

pub use sdk::VerifierModule;

const VERIFY_PARAM_NAME: &str = "temu_verify";
const MAX_VERIFY_BODY_BYTES: usize = 1024 * 1024;
static SLEEP_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)SLEEP\(\s*\d+\s*\)").ok());
static BODY_REGEX_CACHE: LazyLock<Mutex<HashMap<String, Regex>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Result of verifying one finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerifyResult {
    Confirmed { confidence: f32, proof: String },
    FalsePositive { reason: String },
    Inconclusive { reason: String },
}

/// Verifies a time-based vulnerability by comparing baseline and payload timings.
pub async fn verify_time_based(vuln: &Vulnerability, config: &AppConfig) -> VerifyResult {
    let client = match build_client(config) {
        Ok(client) => client,
        Err(e) => {
            return VerifyResult::Inconclusive {
                reason: e.to_string(),
            };
        }
    };

    let baseline_url = baseline_url_for(vuln);
    verify_time_based_with_client(vuln, config, &client, &baseline_url, 5).await
}

/// Verifies a reflected vulnerability with a fresh benign marker string.
pub async fn verify_reflection(vuln: &Vulnerability, config: &AppConfig) -> VerifyResult {
    let client = match build_client(config) {
        Ok(client) => client,
        Err(e) => {
            return VerifyResult::Inconclusive {
                reason: e.to_string(),
            };
        }
    };

    verify_reflection_with_client(vuln, config, &client).await
}

/// Verifies that a status-code based finding is still reproducible.
pub async fn verify_status_code(vuln: &Vulnerability, config: &AppConfig) -> VerifyResult {
    let client = match build_client(config) {
        Ok(client) => client,
        Err(e) => {
            return VerifyResult::Inconclusive {
                reason: e.to_string(),
            };
        }
    };

    verify_status_code_with_client(vuln, config, &client, &[]).await
}

/// Verifies that an expected response header is still present.
pub async fn verify_header(vuln: &Vulnerability, config: &AppConfig) -> VerifyResult {
    let client = match build_client(config) {
        Ok(client) => client,
        Err(e) => {
            return VerifyResult::Inconclusive {
                reason: e.to_string(),
            };
        }
    };

    verify_header_with_client(vuln, config, &client, None, None).await
}

/// Runs verification for all vulnerabilities using rule metadata from `config.rules_dir`.
///
/// Confirmed vulnerabilities are returned with `verified = true`. Findings that
/// verify as false positives are removed from the returned list.
pub async fn run_verification(vulns: &[Vulnerability], config: &AppConfig) -> Vec<Vulnerability> {
    let rules = match load_rules(&config.rules_dir) {
        Ok(rules) => rules,
        Err(e) => {
            warn!(
                "Verifier could not load rules from {:?}: {e}",
                config.rules_dir
            );
            return vulns.to_vec();
        }
    };
    let rules_by_id: HashMap<String, Rule> = rules
        .into_iter()
        .map(|rule| (rule.id.clone(), rule))
        .collect();

    let client = match build_client(config) {
        Ok(client) => client,
        Err(e) => {
            warn!("Verifier HTTP client setup failed: {e}");
            return vulns.to_vec();
        }
    };

    let mut verified = Vec::new();
    let mut false_positives = 0usize;

    for vuln in vulns {
        if vuln.verified {
            verified.push(vuln.clone());
            continue;
        }
        let result = if let Some(rule) = rules_by_id.get(&vuln.id) {
            verify_with_rule(vuln, rule, config, &client).await
        } else {
            VerifyResult::Inconclusive {
                reason: format!("No matching rule metadata for {}", vuln.id),
            }
        };

        match result {
            VerifyResult::Confirmed { proof, .. } => {
                let mut confirmed = vuln.clone();
                confirmed.verified = true;
                confirmed.proof = format!("{}; verification: {proof}", confirmed.proof);
                verified.push(confirmed);
            }
            VerifyResult::FalsePositive { reason } => {
                false_positives += 1;
                info!("False positive removed for {}: {}", vuln.id, reason);
            }
            VerifyResult::Inconclusive { reason } => {
                warn!("Verification inconclusive for {}: {}", vuln.id, reason);
                verified.push(vuln.clone());
            }
        }
    }

    info!(
        "Verified {}/{} vulnerabilities, {} false positives removed",
        verified.iter().filter(|v| v.verified).count(),
        vulns.len(),
        false_positives
    );

    verified
}

async fn verify_with_rule(
    vuln: &Vulnerability,
    rule: &Rule,
    config: &AppConfig,
    client: &Client,
) -> VerifyResult {
    match rule.verify.match_type {
        MatchType::TimeBased => {
            let threshold = rule.verify.time_threshold_secs.unwrap_or(5);
            let baseline_url = baseline_url_for(vuln);
            verify_time_based_with_client(vuln, config, client, &baseline_url, threshold).await
        }
        MatchType::BodyContains | MatchType::BodyRegex => {
            if vuln.parameter.is_some() {
                verify_reflection_with_client(vuln, config, client).await
            } else {
                verify_body_with_client(vuln, config, client, rule).await
            }
        }
        MatchType::StatusCode => {
            verify_status_code_with_client(vuln, config, client, &rule.verify.response_codes).await
        }
        MatchType::HeaderContains => {
            verify_header_with_client(
                vuln,
                config,
                client,
                rule.verify.header_name.as_deref(),
                rule.verify.header_contains.as_deref(),
            )
            .await
        }
    }
}

async fn verify_time_based_with_client(
    vuln: &Vulnerability,
    config: &AppConfig,
    client: &Client,
    baseline_url: &str,
    threshold_secs: u64,
) -> VerifyResult {
    let required = Duration::from_secs(threshold_secs);

    for payload_url in adjusted_sleep_payload_urls(vuln, threshold_secs) {
        let mut baseline_times = Vec::new();
        let mut payload_times = Vec::new();

        for _ in 0..3 {
            let Some(baseline) = timed_get(client, config, baseline_url).await else {
                return VerifyResult::Inconclusive {
                    reason: "Baseline request failed".to_string(),
                };
            };
            let Some(payload) = timed_get(client, config, &payload_url).await else {
                return VerifyResult::Inconclusive {
                    reason: "Payload request failed".to_string(),
                };
            };
            baseline_times.push(baseline);
            payload_times.push(payload);
        }

        let baseline_avg = avg_duration(&baseline_times);
        let payload_avg = avg_duration(&payload_times);
        let delta = payload_avg.saturating_sub(baseline_avg);

        if delta >= required {
            return VerifyResult::Confirmed {
                confidence: 0.95,
                proof: format!(
                    "Average payload response exceeded baseline by {:.2}s",
                    delta.as_secs_f64()
                ),
            };
        } else if payload_avg > Duration::from_secs(config.timeout_secs) {
            return VerifyResult::Inconclusive {
                reason: "Payload timing exceeded request timeout".to_string(),
            };
        }
    }

    VerifyResult::FalsePositive {
        reason: format!("Timing delta below threshold {threshold_secs}s"),
    }
}

fn adjusted_sleep_payload_urls(vuln: &Vulnerability, threshold_secs: u64) -> Vec<String> {
    let Some(sleep_re) = SLEEP_RE.as_ref() else {
        return vec![vuln.url.clone()];
    };
    if !sleep_re.is_match(&vuln.url) {
        return vec![vuln.url.clone()];
    }

    let mut delays = vec![threshold_secs.saturating_sub(2).max(1), threshold_secs];
    delays.push(threshold_secs + 2);
    delays.sort_unstable();
    delays.dedup();

    delays
        .into_iter()
        .map(|delay| {
            sleep_re
                .replace_all(&vuln.url, format!("SLEEP({delay})"))
                .into_owned()
        })
        .collect()
}

async fn verify_reflection_with_client(
    vuln: &Vulnerability,
    config: &AppConfig,
    client: &Client,
) -> VerifyResult {
    let marker = unique_marker();
    let verification_url = match url_with_marker(vuln, &marker) {
        Some(url) => url,
        None => {
            return VerifyResult::Inconclusive {
                reason: "Could not build reflection verification URL".to_string(),
            };
        }
    };

    let mut request = client.get(verification_url.clone());
    for (name, value) in config.session_headers_for_url(&verification_url) {
        request = request.header(name, value);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(e) => {
            return VerifyResult::Inconclusive {
                reason: format!("Verification request failed: {e}"),
            };
        }
    };
    let body = read_limited_text(response, MAX_VERIFY_BODY_BYTES)
        .await
        .unwrap_or_default();

    if body.contains(&marker) || body.contains(&html_escape(&marker)) {
        let context = reflection_context(&body, &marker);
        VerifyResult::Confirmed {
            confidence: 0.9,
            proof: format!("Marker reflected in {context} context by {verification_url}"),
        }
    } else {
        VerifyResult::FalsePositive {
            reason: "Fresh marker was not reflected".to_string(),
        }
    }
}

async fn verify_body_with_client(
    vuln: &Vulnerability,
    config: &AppConfig,
    client: &Client,
    rule: &Rule,
) -> VerifyResult {
    let mut request = client.get(&vuln.url);
    for (name, value) in config.session_headers_for_url(&vuln.url) {
        request = request.header(name, value);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(e) => {
            return VerifyResult::Inconclusive {
                reason: format!("Verification request failed: {e}"),
            };
        }
    };
    let status = response.status().as_u16();
    let body = read_limited_text(response, MAX_VERIFY_BODY_BYTES)
        .await
        .unwrap_or_default();
    let status_ok =
        rule.verify.response_codes.is_empty() || rule.verify.response_codes.contains(&status);

    let body_ok = match rule.verify.match_type {
        MatchType::BodyContains => rule
            .verify
            .body_contains
            .as_deref()
            .map(|needle| body.contains(needle))
            .unwrap_or(true),
        MatchType::BodyRegex => rule
            .verify
            .body_regex
            .as_deref()
            .map(|pattern| cached_regex_match(pattern, &body))
            .unwrap_or(false),
        _ => false,
    };

    if status_ok && body_ok {
        VerifyResult::Confirmed {
            confidence: 0.85,
            proof: format!("Body matcher reproduced on status {status}"),
        }
    } else {
        VerifyResult::FalsePositive {
            reason: format!("Body matcher did not reproduce on status {status}"),
        }
    }
}

async fn verify_status_code_with_client(
    vuln: &Vulnerability,
    config: &AppConfig,
    client: &Client,
    expected_codes: &[u16],
) -> VerifyResult {
    let mut request = client.get(&vuln.url);
    for (name, value) in config.session_headers_for_url(&vuln.url) {
        request = request.header(name, value);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(e) => {
            return VerifyResult::Inconclusive {
                reason: format!("Verification request failed: {e}"),
            };
        }
    };
    let status = response.status().as_u16();

    let confirmed = if expected_codes.is_empty() {
        (200..400).contains(&status)
    } else {
        expected_codes.contains(&status)
    };

    if confirmed {
        VerifyResult::Confirmed {
            confidence: 0.8,
            proof: format!("Status code {status} reproduced"),
        }
    } else {
        VerifyResult::FalsePositive {
            reason: format!("Unexpected status code {status}"),
        }
    }
}

async fn verify_header_with_client(
    vuln: &Vulnerability,
    config: &AppConfig,
    client: &Client,
    header_name: Option<&str>,
    header_contains: Option<&str>,
) -> VerifyResult {
    let mut request = client.get(&vuln.url);
    for (name, value) in config.session_headers_for_url(&vuln.url) {
        request = request.header(name, value);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(e) => {
            return VerifyResult::Inconclusive {
                reason: format!("Verification request failed: {e}"),
            };
        }
    };

    let Some(name) = header_name else {
        return VerifyResult::Inconclusive {
            reason: "Rule has no header_name".to_string(),
        };
    };
    let needle = header_contains.unwrap_or_default();
    let matched = response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.contains(needle))
        .unwrap_or(false);

    if matched {
        VerifyResult::Confirmed {
            confidence: 0.85,
            proof: format!("Header {name} contains expected marker"),
        }
    } else {
        VerifyResult::FalsePositive {
            reason: format!("Header {name} did not contain expected marker"),
        }
    }
}

fn build_client(config: &AppConfig) -> Result<Client, TemuError> {
    Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent(&config.user_agent)
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(config.concurrency.max(1))
        .build()
        .map_err(TemuError::from_network)
}

async fn timed_get(client: &Client, config: &AppConfig, url: &str) -> Option<Duration> {
    let start = Instant::now();
    let mut request = client.get(url);
    for (name, value) in config.session_headers_for_url(url) {
        request = request.header(name, value);
    }
    request.send().await.ok()?;
    Some(start.elapsed())
}

fn avg_duration(values: &[Duration]) -> Duration {
    if values.is_empty() {
        return Duration::ZERO;
    }

    let total_nanos: u128 = values.iter().map(Duration::as_nanos).sum();
    Duration::from_nanos((total_nanos / values.len() as u128) as u64)
}

fn baseline_url_for(vuln: &Vulnerability) -> String {
    let Some(parameter) = &vuln.parameter else {
        return vuln.url.clone();
    };
    let Ok(mut url) = Url::parse(&vuln.url) else {
        return vuln.url.clone();
    };

    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != parameter)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_query(None);
    if !pairs.is_empty() {
        url.query_pairs_mut().extend_pairs(pairs);
    }
    url.to_string()
}

fn url_with_marker(vuln: &Vulnerability, marker: &str) -> Option<String> {
    let mut url = Url::parse(&vuln.url).ok()?;
    let parameter = vuln.parameter.as_deref().unwrap_or(VERIFY_PARAM_NAME);
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != parameter)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    url.set_query(None);
    {
        let mut query = url.query_pairs_mut();
        query.extend_pairs(pairs);
        query.append_pair(parameter, marker);
    }
    Some(url.to_string())
}

fn unique_marker() -> String {
    format!(
        "temu_verify_{}",
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .unsigned_abs()
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn reflection_context(body: &str, marker: &str) -> &'static str {
    let Some(marker_start) = body.find(marker) else {
        return "text";
    };
    let marker_end = marker_start.saturating_add(marker.len());
    let before = &body[..marker_start];
    let after = &body[marker_end..];
    let before_lower = before.to_ascii_lowercase();
    let after_lower = after.to_ascii_lowercase();
    let script_open = before_lower.rfind("<script");
    let script_close_before = before_lower.rfind("</script>");
    let script_close_after = after_lower.find("</script>");

    if script_open.is_some() && script_close_after.is_some() && script_open > script_close_before {
        "script"
    } else if is_attribute_context(before, after) {
        "attribute"
    } else {
        "text"
    }
}

fn is_attribute_context(before: &str, after: &str) -> bool {
    let Some(tag_start) = before.rfind('<') else {
        return false;
    };
    if before[tag_start..].contains('>') {
        return false;
    }
    let before_tag = &before[tag_start..];
    let Some(last_quote) = before_tag.rfind(['"', '\'']) else {
        return false;
    };
    let quote = before_tag.as_bytes()[last_quote] as char;
    if !before_tag[..last_quote].contains('=') {
        return false;
    }
    after.find(quote).is_some_and(|quote_index| {
        let closing_tag = after.find('>').unwrap_or(after.len());
        quote_index < closing_tag
    })
}

fn cached_regex_match(pattern: &str, text: &str) -> bool {
    let re = {
        let Ok(mut cache) = BODY_REGEX_CACHE.lock() else {
            return false;
        };
        if !cache.contains_key(pattern) {
            let Ok(re) = Regex::new(pattern) else {
                return false;
            };
            cache.insert(pattern.to_string(), re);
        }
        cache.get(pattern).cloned()
    };
    re.map(|re| re.is_match(text)).unwrap_or(false)
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
    use temu_core::{Severity, Vulnerability};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config(rules_dir: PathBuf) -> AppConfig {
        AppConfig {
            rate_limit: 10,
            timeout_secs: 5,
            concurrency: 4,
            user_agent: "Temu-Test/1.0.0".to_string(),
            output_dir: PathBuf::from("/tmp"),
            rules_dir,
            dictionaries_dir: PathBuf::from("/tmp"),
            max_recursion_depth: 2,
            wordlist_override: None,
            allow_risky_rules: false,
            browser_crawl_enabled: true,
            browser_crawl_max_pages: 25,
            browser_crawl_max_depth: 2,
            browser_crawl_render_js: false,
            browser_crawl_browser_path: None,
            session_profile: None,
            oast_callback_url: None,
            oast_correlation_id: None,
            oast_database_path: None,
            oast_wait_secs: 0,
        }
    }

    fn vuln(id: &str, url: String, parameter: Option<&str>) -> Vulnerability {
        let mut vuln = Vulnerability::new(
            id,
            "Test vulnerability",
            Severity::High,
            7.5,
            "initial proof",
            url,
        );
        vuln.parameter = parameter.map(str::to_string);
        vuln
    }

    #[test]
    fn test_adjusted_sleep_payload_urls() {
        let finding = vuln(
            "TIME-TEST",
            "https://example.com/search?q=' OR SLEEP(5) --".to_string(),
            Some("q"),
        );
        let urls = adjusted_sleep_payload_urls(&finding, 5);

        assert_eq!(urls.len(), 3);
        assert!(urls[0].contains("SLEEP(3)"));
        assert!(urls[1].contains("SLEEP(5)"));
        assert!(urls[2].contains("SLEEP(7)"));
    }

    #[test]
    fn test_reflection_context_detection() {
        assert_eq!(
            reflection_context("<script>temu_verify_1</script>", "temu_verify_1"),
            "script"
        );
        assert_eq!(
            reflection_context(r#"<input value="temu_verify_1">"#, "temu_verify_1"),
            "attribute"
        );
        assert_eq!(
            reflection_context("<p>temu_verify_1</p>", "temu_verify_1"),
            "text"
        );
    }

    #[tokio::test]
    async fn test_verify_reflection_confirmed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/search"))
            .respond_with(|request: &wiremock::Request| {
                let query = request.url.query().unwrap_or_default().to_string();
                ResponseTemplate::new(200).set_body_string(query)
            })
            .mount(&server)
            .await;

        let finding = vuln(
            "XSS-TEST",
            format!("{}/search?q=old", server.uri()),
            Some("q"),
        );
        let result = verify_reflection(&finding, &test_config(PathBuf::from("/tmp"))).await;

        assert!(matches!(result, VerifyResult::Confirmed { .. }));
    }

    #[tokio::test]
    async fn test_verify_reflection_false_positive() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("normal"))
            .mount(&server)
            .await;

        let finding = vuln(
            "XSS-TEST",
            format!("{}/search?q=old", server.uri()),
            Some("q"),
        );
        let result = verify_reflection(&finding, &test_config(PathBuf::from("/tmp"))).await;

        assert!(matches!(result, VerifyResult::FalsePositive { .. }));
    }

    #[tokio::test]
    async fn test_verify_status_code_confirmed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.env"))
            .respond_with(ResponseTemplate::new(200).set_body_string("DB_PASSWORD=secret"))
            .mount(&server)
            .await;

        let finding = vuln("ENV-TEST", format!("{}/.env", server.uri()), None);
        let result = verify_status_code(&finding, &test_config(PathBuf::from("/tmp"))).await;

        assert!(matches!(result, VerifyResult::Confirmed { .. }));
    }

    #[tokio::test]
    async fn test_verify_time_based_confirmed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/check"))
            .and(query_param("delay", "1"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(120)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/check"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let finding = vuln(
            "TIME-TEST",
            format!("{}/check?delay=1", server.uri()),
            Some("delay"),
        );
        let client = build_client(&test_config(PathBuf::from("/tmp"))).unwrap();
        let result = verify_time_based_with_client(
            &finding,
            &test_config(PathBuf::from("/tmp")),
            &client,
            &baseline_url_for(&finding),
            0,
        )
        .await;

        assert!(matches!(result, VerifyResult::Confirmed { .. }));
    }

    #[tokio::test]
    async fn test_run_verification_removes_false_positive_and_marks_confirmed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.env"))
            .respond_with(ResponseTemplate::new(200).set_body_string("DB_PASSWORD=secret"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("env.yaml"),
            r#"id: "ENV-TEST"
name: "Exposed .env"
tech_stack: []
severity: high
cvss: 7.5
payload: "/.env"
request_method: GET
verify:
  match_type: StatusCode
  response_codes: [200]
"#,
        )
        .unwrap();

        let findings = vec![
            vuln("ENV-TEST", format!("{}/.env", server.uri()), None),
            vuln("ENV-TEST", format!("{}/missing", server.uri()), None),
        ];
        let verified = run_verification(&findings, &test_config(tmp.path().to_path_buf())).await;

        assert_eq!(verified.len(), 1);
        assert!(verified[0].verified);
        assert!(verified[0].url.ends_with("/.env"));
    }
}
