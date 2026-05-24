use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use reqwest::{Client, Method, Url};
use temu_core::{AppConfig, Asset, AssetType, SessionProfile, Severity, Vulnerability};

const MAX_STATEFUL_REQUESTS: usize = 80;
const MAX_REPLAY_REQUESTS: usize = 20;
const MAX_BODY_BYTES: usize = 512 * 1024;
const FORM_MARKER: &str = "temu_stateful_probe";

static FORM_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?is)<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>"#).ok());
static INPUT_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?is)<input\b(?P<attrs>[^>]*)>"#).ok());
static ATTR_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?is)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*["']([^"']*)["']"#).ok()
});
static SECRET_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_-]?key|secret|token|password)\s*[:=]\s*["']?[A-Za-z0-9_./+=-]{8,})"#,
    )
    .ok()
});
static EMAIL_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"#).ok());
static STACK_TRACE_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)(Traceback \(most recent call last\)|Exception in thread|stack trace|at [a-z0-9_.$]+\([^)]*:\d+\)|Symfony\\Component\\|Illuminate\\|Express error|Whitelabel Error Page)"#,
    )
    .ok()
});
static CREDIT_CARD_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"\b(?:\d[ -]*?){13,19}\b"#).ok());

/// Stateful DAST output that can be merged into the main scan result.
#[derive(Debug, Clone, Default)]
pub struct StatefulScanResult {
    pub assets: Vec<Asset>,
    pub findings: Vec<Vulnerability>,
}

#[derive(Debug, Clone)]
struct HtmlForm {
    method: String,
    action: String,
    inputs: Vec<FormInput>,
    csrf: Option<FormInput>,
}

#[derive(Debug, Clone)]
struct FormInput {
    name: String,
    input_type: String,
    value: Option<String>,
}

#[derive(Debug, Clone)]
struct ResponseSnapshot {
    url: String,
    status: u16,
    body: String,
    content_length: usize,
}

/// Runs read-only stateful DAST and business-logic heuristics on in-scope URLs.
pub async fn run_stateful_dast(
    base_url: &str,
    assets: &[Asset],
    config: &AppConfig,
) -> anyhow::Result<StatefulScanResult> {
    let base = Url::parse(base_url)?;
    let client = build_client(config)?;
    let mut result = StatefulScanResult::default();
    let mut visited = HashSet::new();
    let mut request_budget = MAX_STATEFUL_REQUESTS.min(config.concurrency.max(1));
    let mut snapshots = Vec::new();

    for url in candidate_urls(&base, assets) {
        if request_budget == 0 {
            break;
        }
        if !visited.insert(url.clone()) {
            continue;
        }
        request_budget -= 1;
        let Some(snapshot) = fetch_snapshot(&client, &url, config).await else {
            continue;
        };

        let forms = extract_forms(&snapshot.url, &snapshot.body);
        for form in forms {
            result.assets.push(form_asset(&form));
            if form.method == "GET"
                && request_budget > 0
                && let Some(finding) = probe_get_form_reflection(&client, &form, config).await
            {
                request_budget -= 1;
                result.findings.push(finding);
            }
        }

        result.findings.extend(inspect_data_exposure(&snapshot));
        if is_sensitive_endpoint(&snapshot.url) && (200..400).contains(&snapshot.status) {
            result
                .findings
                .push(accessible_sensitive_endpoint(&snapshot));
        }
        snapshots.push(snapshot);
    }

    result.findings.extend(
        run_id_mutation_probe(&client, &base, &snapshots, config, &mut request_budget).await,
    );
    result.findings.extend(
        run_multi_role_differential(&client, &snapshots, config, &mut request_budget).await,
    );

    Ok(result)
}

fn build_client(config: &AppConfig) -> anyhow::Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent(&config.user_agent)
        .build()?)
}

fn candidate_urls(base: &Url, assets: &[Asset]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut urls = Vec::new();
    push_same_origin(base, base.as_str(), &mut seen, &mut urls);
    let mut replayed = 0usize;
    for asset in assets {
        if asset.asset_type != AssetType::Url
            && asset.asset_type != AssetType::Path
            && asset.asset_type != AssetType::Parameter
            && asset.asset_type != AssetType::ApiEndpoint
        {
            continue;
        }
        if asset.discovered_by == "discovery::browser_network" {
            if replayed >= MAX_REPLAY_REQUESTS {
                continue;
            }
            replayed += 1;
        }
        push_same_origin(base, &asset.url, &mut seen, &mut urls);
        if urls.len() >= MAX_STATEFUL_REQUESTS {
            break;
        }
    }
    urls
}

fn push_same_origin(
    base: &Url,
    candidate: &str,
    seen: &mut HashSet<String>,
    urls: &mut Vec<String>,
) {
    let parsed = match Url::parse(candidate).or_else(|_| base.join(candidate)) {
        Ok(url) => url,
        Err(_) => return,
    };
    if !same_origin(base, &parsed) || !matches!(parsed.scheme(), "http" | "https") {
        return;
    }
    let url = parsed.to_string();
    if seen.insert(url.clone()) {
        urls.push(url);
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

async fn fetch_snapshot(
    client: &Client,
    url: &str,
    config: &AppConfig,
) -> Option<ResponseSnapshot> {
    pace_request(config).await;
    let mut request = client.get(url);
    for (name, value) in config.session_headers_for_url(url) {
        request = request.header(name, value);
    }
    let response = request.send().await.ok()?;
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let bytes = response.bytes().await.ok()?;
    let clipped = bytes.len().min(MAX_BODY_BYTES);
    let body = String::from_utf8_lossy(&bytes[..clipped]).to_string();
    Some(ResponseSnapshot {
        url: final_url,
        status,
        content_length: bytes.len(),
        body,
    })
}

fn extract_forms(page_url: &str, body: &str) -> Vec<HtmlForm> {
    let Some(form_re) = FORM_RE.as_ref() else {
        return Vec::new();
    };
    form_re
        .captures_iter(body)
        .filter_map(|captures| {
            let attrs = parse_attrs(captures.name("attrs")?.as_str());
            let method = attrs
                .get("method")
                .map(|method| method.to_ascii_uppercase())
                .unwrap_or_else(|| "GET".to_string());
            let action = attrs
                .get("action")
                .and_then(|action| resolve_form_action(page_url, action))
                .unwrap_or_else(|| page_url.to_string());
            let inputs = extract_inputs(captures.name("body").map(|m| m.as_str()).unwrap_or(""));
            let csrf = inputs.iter().find(|input| is_csrf_input(input)).cloned();
            Some(HtmlForm {
                method,
                action,
                inputs,
                csrf,
            })
        })
        .collect()
}

fn resolve_form_action(page_url: &str, action: &str) -> Option<String> {
    let base = Url::parse(page_url).ok()?;
    base.join(action).ok().map(|url| url.to_string())
}

fn extract_inputs(form_body: &str) -> Vec<FormInput> {
    let Some(input_re) = INPUT_RE.as_ref() else {
        return Vec::new();
    };
    input_re
        .captures_iter(form_body)
        .filter_map(|captures| {
            let attrs = parse_attrs(captures.name("attrs")?.as_str());
            let name = attrs.get("name")?.to_string();
            let input_type = attrs
                .get("type")
                .map(|value| value.to_ascii_lowercase())
                .unwrap_or_else(|| "text".to_string());
            Some(FormInput {
                name,
                input_type,
                value: attrs.get("value").cloned(),
            })
        })
        .collect()
}

fn parse_attrs(attrs: &str) -> HashMap<String, String> {
    let Some(attr_re) = ATTR_RE.as_ref() else {
        return HashMap::new();
    };
    attr_re
        .captures_iter(attrs)
        .filter_map(|captures| {
            Some((
                captures.get(1)?.as_str().to_ascii_lowercase(),
                captures.get(2)?.as_str().to_string(),
            ))
        })
        .collect()
}

fn is_csrf_input(input: &FormInput) -> bool {
    let name = input.name.to_ascii_lowercase();
    name.contains("csrf") || name.contains("token") || name.contains("authenticity")
}

fn form_asset(form: &HtmlForm) -> Asset {
    let input_summary = form
        .inputs
        .iter()
        .map(|input| format!("{}:{}", input.name, input.input_type))
        .collect::<Vec<_>>()
        .join(",");
    let csrf = form
        .csrf
        .as_ref()
        .map(|input| input.name.as_str())
        .unwrap_or("-");
    Asset::new(
        format!(
            "{} {} inputs=[{}] csrf={}",
            form.method, form.action, input_summary, csrf
        ),
        AssetType::ApiEndpoint,
        "cli::stateful_form",
    )
}

async fn probe_get_form_reflection(
    client: &Client,
    form: &HtmlForm,
    config: &AppConfig,
) -> Option<Vulnerability> {
    let input_name = form
        .inputs
        .iter()
        .find(|input| {
            matches!(
                input.input_type.as_str(),
                "text" | "search" | "email" | "url"
            )
        })
        .map(|input| input.name.clone())
        .unwrap_or_else(|| "temu_probe".to_string());
    let mut url = Url::parse(&form.action).ok()?;
    url.query_pairs_mut().append_pair(&input_name, FORM_MARKER);
    if let Some(csrf) = &form.csrf
        && let Some(value) = &csrf.value
    {
        url.query_pairs_mut().append_pair(&csrf.name, value);
    }

    let mut request = client.get(url.as_str());
    for (name, value) in config.session_headers_for_url(url.as_str()) {
        request = request.header(name, value);
    }
    pace_request(config).await;
    let response = request.send().await.ok()?;
    let status = response.status().as_u16();
    let body = response.text().await.ok()?;
    if body.contains(FORM_MARKER) {
        let mut vuln = Vulnerability::new(
            "STATEFUL-FORM-REFLECTION",
            "Form input reflected during stateful workflow probe",
            Severity::Low,
            3.7,
            format!("GET form parameter {input_name} reflected benign marker on status {status}"),
            form.action.clone(),
        );
        vuln.parameter = Some(input_name);
        vuln.remediation = Some(
            "Encode reflected form values and validate user-controlled input consistently."
                .to_string(),
        );
        return Some(vuln);
    }
    None
}

fn inspect_data_exposure(snapshot: &ResponseSnapshot) -> Vec<Vulnerability> {
    let mut findings = Vec::new();
    if let Some(evidence) = first_redacted_match(SECRET_RE.as_ref(), &snapshot.body) {
        findings.push(vulnerability(
            "STATEFUL-SECRET-EXPOSURE",
            "Potential secret exposed in HTML/JavaScript response",
            Severity::High,
            8.1,
            format!("Potential secret pattern found in response body: {evidence}"),
            &snapshot.url,
            "Remove secrets from client-delivered content and rotate exposed credentials.",
        ));
    }
    if let Some(evidence) = first_redacted_match(EMAIL_RE.as_ref(), &snapshot.body)
        .or_else(|| first_redacted_match(CREDIT_CARD_RE.as_ref(), &snapshot.body))
    {
        findings.push(vulnerability(
            "STATEFUL-PII-LIKE-EXPOSURE",
            "PII-like data exposed in response",
            Severity::Medium,
            5.3,
            format!("PII-like pattern found with redacted evidence: {evidence}"),
            &snapshot.url,
            "Reduce exposed personal data, require authorization, and mask sensitive fields.",
        ));
    }
    if let Some(evidence) = first_redacted_match(STACK_TRACE_RE.as_ref(), &snapshot.body) {
        findings.push(vulnerability(
            "STATEFUL-VERBOSE-ERROR",
            "Verbose stack trace or framework debug response",
            Severity::Medium,
            5.0,
            format!("Verbose error/debug marker observed: {evidence}"),
            &snapshot.url,
            "Disable debug mode and return generic errors in production.",
        ));
    }
    findings
}

fn first_redacted_match(regex: Option<&Regex>, body: &str) -> Option<String> {
    let regex = regex?;
    regex
        .find(body)
        .map(|m| redact_evidence(m.as_str()).chars().take(160).collect())
}

fn redact_evidence(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.contains('@') {
        let mut parts = trimmed.split('@');
        let domain = parts.nth(1).unwrap_or("redacted");
        return format!("[REDACTED]@{domain}");
    }
    if trimmed.len() <= 8 {
        return "[REDACTED]".to_string();
    }
    let prefix: String = trimmed.chars().take(4).collect();
    let suffix: String = trimmed
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{prefix}[REDACTED]{suffix}")
}

fn is_sensitive_endpoint(url: &str) -> bool {
    let path = Url::parse(url)
        .ok()
        .map(|url| url.path().to_ascii_lowercase())
        .unwrap_or_default();
    [
        "/admin",
        "/debug",
        "/actuator",
        "/server-status",
        "/server-info",
        "/api-docs",
        "/swagger",
    ]
    .iter()
    .any(|needle| path.contains(needle))
}

fn accessible_sensitive_endpoint(snapshot: &ResponseSnapshot) -> Vulnerability {
    vulnerability(
        "STATEFUL-SENSITIVE-ENDPOINT-ACCESSIBLE",
        "Admin/debug endpoint accessible during stateful scan",
        Severity::Medium,
        5.8,
        format!(
            "Sensitive endpoint returned HTTP {} with {} response bytes",
            snapshot.status, snapshot.content_length
        ),
        &snapshot.url,
        "Restrict admin/debug endpoints to authorized roles or trusted networks.",
    )
}

async fn run_id_mutation_probe(
    client: &Client,
    base: &Url,
    snapshots: &[ResponseSnapshot],
    config: &AppConfig,
    request_budget: &mut usize,
) -> Vec<Vulnerability> {
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    for snapshot in snapshots {
        if *request_budget == 0 || findings.len() >= 5 {
            break;
        }
        let Some(mutated) = mutate_numeric_identifier(&snapshot.url, base) else {
            continue;
        };
        if !seen.insert(mutated.clone()) {
            continue;
        }
        *request_budget -= 1;
        let Some(mutated_snapshot) = fetch_snapshot(client, &mutated, config).await else {
            continue;
        };
        if (200..300).contains(&snapshot.status)
            && (200..300).contains(&mutated_snapshot.status)
            && similar_size(snapshot.content_length, mutated_snapshot.content_length)
        {
            findings.push(vulnerability(
                "STATEFUL-IDOR-BOLA-SIGNAL",
                "Numeric identifier mutation returned a similar successful response",
                Severity::Medium,
                5.4,
                format!(
                    "Original and mutated resource both returned success with similar size ({} vs {} bytes); evidence redacted",
                    snapshot.content_length, mutated_snapshot.content_length
                ),
                &snapshot.url,
                "Enforce object-level authorization on every resource identifier.",
            ));
        }
    }
    findings
}

fn mutate_numeric_identifier(url: &str, base: &Url) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    if !same_origin(base, &parsed) {
        return None;
    }
    if let Some(mutated) = mutate_query_identifier(parsed.clone()) {
        return Some(mutated);
    }
    mutate_path_identifier(parsed)
}

fn mutate_query_identifier(mut url: Url) -> Option<String> {
    let pairs = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let mut changed = false;
    let mut new_pairs = Vec::new();
    for (key, value) in pairs {
        if !changed
            && is_id_name(&key)
            && let Ok(number) = value.parse::<u64>()
        {
            new_pairs.push((key, (number.saturating_add(1)).to_string()));
            changed = true;
        } else {
            new_pairs.push((key, value));
        }
    }
    if !changed {
        return None;
    }
    url.query_pairs_mut().clear().extend_pairs(new_pairs);
    Some(url.to_string())
}

fn mutate_path_identifier(mut url: Url) -> Option<String> {
    let segments = url.path_segments()?.map(str::to_string).collect::<Vec<_>>();
    let mut changed = false;
    let new_segments = segments
        .into_iter()
        .map(|segment| {
            if !changed && segment.chars().all(|c| c.is_ascii_digit()) {
                changed = true;
                segment
                    .parse::<u64>()
                    .map(|value| value.saturating_add(1).to_string())
                    .unwrap_or(segment)
            } else {
                segment
            }
        })
        .collect::<Vec<_>>();
    if !changed {
        return None;
    }
    url.set_path(&new_segments.join("/"));
    Some(url.to_string())
}

fn is_id_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "id" | "user_id" | "uid" | "account_id" | "order_id" | "customer_id"
    )
}

fn similar_size(left: usize, right: usize) -> bool {
    let max = left.max(right).max(1) as f64;
    let diff = left.abs_diff(right) as f64;
    diff / max <= 0.25
}

async fn run_multi_role_differential(
    client: &Client,
    snapshots: &[ResponseSnapshot],
    config: &AppConfig,
    request_budget: &mut usize,
) -> Vec<Vulnerability> {
    let Some(profile) = &config.session_profile else {
        return Vec::new();
    };
    if profile.roles.len() < 2 {
        return Vec::new();
    }
    let mut roles = profile.roles.keys().cloned().collect::<Vec<_>>();
    roles.sort();
    let Some(first) = profile.select_role(&roles[0]) else {
        return Vec::new();
    };
    let Some(second) = profile.select_role(&roles[1]) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for snapshot in snapshots
        .iter()
        .filter(|snapshot| {
            is_sensitive_endpoint(&snapshot.url) || mutate_query_identifier_url(&snapshot.url)
        })
        .take(8)
    {
        if *request_budget < 2 {
            break;
        }
        *request_budget -= 2;
        let first_snapshot =
            fetch_snapshot_with_profile(client, &snapshot.url, config, &first).await;
        let second_snapshot =
            fetch_snapshot_with_profile(client, &snapshot.url, config, &second).await;
        if let (Some(left), Some(right)) = (first_snapshot, second_snapshot)
            && (200..300).contains(&left.status)
            && (200..300).contains(&right.status)
            && similar_size(left.content_length, right.content_length)
        {
            findings.push(vulnerability(
                "STATEFUL-MULTI-ROLE-AUTHZ-SIGNAL",
                "Multiple roles received similar successful response for sensitive resource",
                Severity::Medium,
                5.6,
                format!(
                    "Roles '{}' and '{}' both received HTTP success with similar redacted response size",
                    roles[0], roles[1]
                ),
                &snapshot.url,
                "Review role-based authorization and object-level access checks.",
            ));
        }
    }
    findings
}

fn mutate_query_identifier_url(url: &str) -> bool {
    Url::parse(url).ok().is_some_and(|url| {
        url.query_pairs()
            .any(|(key, value)| is_id_name(&key) && value.parse::<u64>().is_ok())
    })
}

async fn fetch_snapshot_with_profile(
    client: &Client,
    url: &str,
    config: &AppConfig,
    profile: &SessionProfile,
) -> Option<ResponseSnapshot> {
    let mut request = client.request(Method::GET, url);
    for (name, value) in profile.headers_for_url(url) {
        request = request.header(name, value);
    }
    if profile.headers_for_url(url).is_empty() {
        for (name, value) in config.session_headers_for_url(url) {
            request = request.header(name, value);
        }
    }
    pace_request(config).await;
    let response = request.send().await.ok()?;
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let bytes = response.bytes().await.ok()?;
    let clipped = bytes.len().min(MAX_BODY_BYTES);
    Some(ResponseSnapshot {
        url: final_url,
        status,
        content_length: bytes.len(),
        body: String::from_utf8_lossy(&bytes[..clipped]).to_string(),
    })
}

async fn pace_request(config: &AppConfig) {
    if config.rate_limit > 0 {
        tokio::time::sleep(Duration::from_secs_f64(1.0 / config.rate_limit as f64)).await;
    }
}

fn vulnerability(
    id: &str,
    name: &str,
    severity: Severity,
    cvss: f32,
    proof: String,
    url: &str,
    remediation: &str,
) -> Vulnerability {
    let mut vuln = Vulnerability::new(id, name, severity, cvss, proof, url);
    vuln.verified = true;
    vuln.remediation = Some(remediation.to_string());
    vuln
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config() -> AppConfig {
        AppConfig {
            rate_limit: 10,
            timeout_secs: 5,
            concurrency: 8,
            user_agent: "Temu-Test/1.0.0".to_string(),
            output_dir: PathBuf::from("/tmp"),
            rules_dir: PathBuf::from("/tmp"),
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

    #[test]
    fn test_extract_forms_preserves_method_action_inputs_and_csrf() {
        let forms = extract_forms(
            "https://example.com/account",
            r#"
            <form method="post" action="/profile">
              <input type="hidden" name="_csrf" value="abc">
              <input type="email" name="email">
            </form>
            "#,
        );

        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].action, "https://example.com/profile");
        assert_eq!(forms[0].inputs.len(), 2);
        assert_eq!(
            forms[0].csrf.as_ref().map(|input| input.name.as_str()),
            Some("_csrf")
        );
    }

    #[test]
    fn test_redact_evidence_masks_sensitive_values() {
        assert_eq!(
            redact_evidence("alice@example.com"),
            "[REDACTED]@example.com"
        );
        assert_eq!(
            redact_evidence("DB_PASSWORD=supersecret"),
            "DB_P[REDACTED]cret"
        );
    }

    #[test]
    fn test_mutate_numeric_identifier_query_and_path() {
        let base = Url::parse("https://example.com").unwrap();
        assert_eq!(
            mutate_numeric_identifier("https://example.com/api/user?id=7", &base).as_deref(),
            Some("https://example.com/api/user?id=8")
        );
        assert_eq!(
            mutate_numeric_identifier("https://example.com/orders/41", &base).as_deref(),
            Some("https://example.com/orders/42")
        );
        assert!(mutate_numeric_identifier("https://other.example/orders/41", &base).is_none());
    }

    #[tokio::test]
    async fn test_stateful_scan_detects_form_reflection_and_secret_redacted() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"
                <html>
                  <script>const apiKey = "secret-value-12345";</script>
                  <form method="GET" action="/search"><input name="q"></form>
                </html>
            "#,
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/search"))
            .and(query_param("q", FORM_MARKER))
            .respond_with(ResponseTemplate::new(200).set_body_string(FORM_MARKER))
            .mount(&server)
            .await;

        let result = run_stateful_dast(&server.uri(), &[], &test_config())
            .await
            .unwrap();

        assert!(
            result
                .assets
                .iter()
                .any(|asset| asset.discovered_by == "cli::stateful_form")
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.id == "STATEFUL-FORM-REFLECTION")
        );
        let secret = result
            .findings
            .iter()
            .find(|finding| finding.id == "STATEFUL-SECRET-EXPOSURE")
            .expect("secret exposure should be reported");
        assert!(secret.proof.contains("[REDACTED]"));
        assert!(!secret.proof.contains("secret-value-12345"));
    }
}
