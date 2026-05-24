use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use reqwest::{Client, Url};
use serde_json::Value;
use temu_core::{AppConfig, Asset, AssetType, TemuError};
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, info, warn};

const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_JS_BYTES: usize = 1024 * 1024;

static LINK_ATTR_RE: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r#"(?is)\b(?:href|src|action)\s*=\s*["']([^"'#\s][^"']*)["']"#));
static JS_STRING_RE: LazyLock<Result<Regex, regex::Error>> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)["'`]((?:https?://|/|\.{1,2}/|#/)[A-Za-z0-9_./~:%?&=+#,@;(){}\[\]\-$]+)["'`]"#,
    )
});
static SOURCE_MAP_RE: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r#"(?m)sourceMappingURL=([^\s]+)"#));
static DYNAMIC_ROUTE_RE: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r#"(?s)["'`]((?:/|#/)[A-Za-z0-9_./{}:$*?+\-]+)["'`]"#));

#[derive(Debug, Clone)]
struct BrowserDocument {
    body: String,
    network_urls: Vec<String>,
}

/// Crawls an application like a lightweight browser by fetching HTML, linked
/// same-origin JavaScript bundles, and SPA route strings.
///
/// When `browser_crawl_render_js` is enabled, a local Chromium/Chrome binary is
/// used to render the page and collect browser network requests. The crawler
/// still enforces same-origin scope before recording assets.
pub async fn run_browser_crawl(
    base_url: &str,
    config: &AppConfig,
) -> Result<Vec<Asset>, TemuError> {
    if !config.browser_crawl_enabled {
        return Ok(Vec::new());
    }

    let base = Url::parse(base_url).map_err(|e| {
        TemuError::Parse(format!("Invalid browser crawl base URL '{base_url}': {e}"))
    })?;
    let client = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(&config.user_agent)
        .build()
        .map_err(TemuError::from_network)?;

    let max_pages = config.browser_crawl_max_pages.max(1);
    let max_depth = config.browser_crawl_max_depth;
    let mut queue = VecDeque::from([(base.clone(), 0usize)]);
    let mut visited_pages = HashSet::new();
    let mut visited_scripts = HashSet::new();
    let mut discovered = HashSet::new();
    let mut assets = Vec::new();

    while let Some((page_url, depth)) = queue.pop_front() {
        if visited_pages.len() >= max_pages {
            break;
        }
        if !visited_pages.insert(canonical_without_fragment(&page_url)) {
            continue;
        }

        let Some(document) = fetch_page_document(&client, page_url.clone(), config).await else {
            continue;
        };

        for network_url in &document.network_urls {
            if let Ok(url) = Url::parse(network_url)
                && is_same_origin(&base, &url)
            {
                record_url(
                    &mut assets,
                    &mut discovered,
                    url.clone(),
                    "discovery::browser_network",
                );
                if depth < max_depth && should_crawl_as_page(&url) {
                    queue.push_back((url, depth + 1));
                }
            }
        }

        let page_candidates = extract_candidates(&document.body);
        for candidate in page_candidates {
            if let Some(url) = normalize_candidate(&page_url, &candidate)
                && is_same_origin(&base, &url)
            {
                record_url(
                    &mut assets,
                    &mut discovered,
                    url.clone(),
                    "discovery::browser",
                );
                if depth < max_depth && should_crawl_as_page(&url) {
                    queue.push_back((url, depth + 1));
                }
            }
        }

        for script_url in extract_script_urls(&page_url, &document.body, &base) {
            let script_key = canonical_without_fragment(&script_url);
            if !visited_scripts.insert(script_key) {
                continue;
            }

            let Some(js_body) = fetch_text(&client, script_url.clone(), MAX_JS_BYTES).await else {
                continue;
            };
            for candidate in extract_js_candidates(&js_body) {
                if let Some(url) = normalize_candidate(&script_url, &candidate)
                    && is_same_origin(&base, &url)
                {
                    record_url(
                        &mut assets,
                        &mut discovered,
                        url.clone(),
                        "discovery::browser_js",
                    );
                    if depth < max_depth && should_crawl_as_page(&url) {
                        queue.push_back((url, depth + 1));
                    }
                }
            }
        }
    }

    info!(
        "Browser-aware crawl complete: {} assets from {} pages",
        assets.len(),
        visited_pages.len()
    );
    Ok(assets)
}

async fn fetch_text(client: &Client, url: Url, max_bytes: usize) -> Option<String> {
    debug!("Browser-aware crawl fetch {url}");
    let response = match client.get(url.clone()).send().await {
        Ok(response) => response,
        Err(e) => {
            warn!("Browser-aware crawl request failed for {url}: {e}");
            return None;
        }
    };
    if !response.status().is_success() {
        return None;
    }

    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("Browser-aware crawl body read failed for {url}: {e}");
            return None;
        }
    };
    let limited = &bytes[..bytes.len().min(max_bytes)];
    Some(String::from_utf8_lossy(limited).into_owned())
}

async fn fetch_page_document(
    client: &Client,
    url: Url,
    config: &AppConfig,
) -> Option<BrowserDocument> {
    if config.browser_crawl_render_js {
        match render_dom_with_browser(url.clone(), config).await {
            Some(document) => return Some(document),
            None => {
                warn!("Browser render unavailable for {url}; falling back to static fetch");
            }
        }
    }

    fetch_text(client, url, MAX_BODY_BYTES)
        .await
        .map(|body| BrowserDocument {
            body,
            network_urls: Vec::new(),
        })
}

async fn render_dom_with_browser(url: Url, config: &AppConfig) -> Option<BrowserDocument> {
    let browser = resolve_browser_binary(config)?;
    let profile_dir = config.output_dir.join(".cache").join("browser-profile");
    if let Err(e) = std::fs::create_dir_all(&profile_dir) {
        warn!("Failed to create browser profile directory {profile_dir:?}: {e}");
        return None;
    }
    let netlog_path = profile_dir.join(format!(
        "netlog-{}-{}.json",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));

    let mut command = Command::new(browser);
    command
        .arg("--headless")
        .arg("--disable-gpu")
        .arg("--disable-dev-shm-usage")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-background-networking")
        .arg("--disable-extensions")
        .arg("--disable-sync")
        .arg("--disable-translate")
        .arg(format!("--log-net-log={}", netlog_path.display()))
        .arg("--net-log-capture-mode=Default")
        .arg(format!("--user-agent={}", config.user_agent))
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg("--dump-dom")
        .arg(url.as_str());

    let output = match timeout(
        Duration::from_secs(config.timeout_secs.max(1)),
        command.output(),
    )
    .await
    {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            warn!("Browser render failed to start for {url}: {e}");
            return None;
        }
        Err(_) => {
            warn!("Browser render timed out for {url}");
            return None;
        }
    };

    if !output.status.success() || output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Browser render failed for {url}: {}", stderr.trim());
        return None;
    }

    let limited = &output.stdout[..output.stdout.len().min(MAX_BODY_BYTES)];
    let network_urls = parse_netlog_urls(&netlog_path);
    let _ = std::fs::remove_file(&netlog_path);
    Some(BrowserDocument {
        body: String::from_utf8_lossy(limited).into_owned(),
        network_urls,
    })
}

fn parse_netlog_urls(path: &Path) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&content) else {
        return Vec::new();
    };

    let mut urls = HashSet::new();
    collect_urls_from_json(&value, &mut urls);
    let mut urls: Vec<String> = urls.into_iter().collect();
    urls.sort();
    urls
}

fn collect_urls_from_json(value: &Value, urls: &mut HashSet<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(url)) = map.get("url")
                && (url.starts_with("http://") || url.starts_with("https://"))
            {
                urls.insert(url.clone());
            }
            for nested in map.values() {
                collect_urls_from_json(nested, urls);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_urls_from_json(item, urls);
            }
        }
        _ => {}
    }
}

fn resolve_browser_binary(config: &AppConfig) -> Option<PathBuf> {
    if let Some(path) = &config.browser_crawl_browser_path
        && path.is_file()
    {
        return Some(path.clone());
    }

    [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chrome",
        "microsoft-edge",
    ]
    .iter()
    .find_map(|binary| find_executable_in_path(binary))
}

fn find_executable_in_path(binary: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|path| path.join(binary))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn extract_candidates(body: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(regex) = LINK_ATTR_RE.as_ref() {
        candidates.extend(
            regex
                .captures_iter(body)
                .filter_map(|capture| capture.get(1))
                .map(|match_| match_.as_str().to_string()),
        );
    }
    candidates.extend(extract_js_candidates(body));
    candidates
}

fn extract_js_candidates(body: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(regex) = JS_STRING_RE.as_ref() {
        candidates.extend(
            regex
                .captures_iter(body)
                .filter_map(|capture| capture.get(1))
                .map(|match_| match_.as_str().to_string()),
        );
    }
    if let Ok(regex) = DYNAMIC_ROUTE_RE.as_ref() {
        candidates.extend(
            regex
                .captures_iter(body)
                .filter_map(|capture| capture.get(1))
                .map(|match_| match_.as_str().to_string()),
        );
    }
    if let Ok(regex) = SOURCE_MAP_RE.as_ref() {
        candidates.extend(
            regex
                .captures_iter(body)
                .filter_map(|capture| capture.get(1))
                .map(|match_| match_.as_str().to_string()),
        );
    }
    candidates
}

fn extract_script_urls(page_url: &Url, body: &str, base: &Url) -> Vec<Url> {
    let Ok(regex) = LINK_ATTR_RE.as_ref() else {
        return Vec::new();
    };

    regex
        .captures_iter(body)
        .filter_map(|capture| capture.get(1))
        .filter_map(|match_| normalize_candidate(page_url, match_.as_str()))
        .filter(|url| is_same_origin(base, url) && is_javascript_asset(url))
        .collect()
}

fn normalize_candidate(context: &Url, candidate: &str) -> Option<Url> {
    let trimmed = candidate.trim();
    if trimmed.is_empty()
        || trimmed.starts_with("mailto:")
        || trimmed.starts_with("tel:")
        || trimmed.starts_with("javascript:")
        || trimmed.starts_with("data:")
    {
        return None;
    }

    if let Some(route) = trimmed
        .strip_prefix("#/")
        .or_else(|| trimmed.strip_prefix("/#/"))
    {
        let root = format!(
            "{}://{}{}",
            context.scheme(),
            context.host_str()?,
            context
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default()
        );
        return Url::parse(&root)
            .ok()
            .and_then(|origin| origin.join(route.trim_start_matches('/')).ok());
    }

    context.join(trimmed).ok()
}

fn is_same_origin(base: &Url, candidate: &Url) -> bool {
    base.scheme() == candidate.scheme()
        && base.host_str() == candidate.host_str()
        && base.port_or_known_default() == candidate.port_or_known_default()
}

fn should_crawl_as_page(url: &Url) -> bool {
    let path = url.path().to_ascii_lowercase();
    !is_javascript_asset(url)
        && !path.ends_with(".css")
        && !path.ends_with(".png")
        && !path.ends_with(".jpg")
        && !path.ends_with(".jpeg")
        && !path.ends_with(".gif")
        && !path.ends_with(".svg")
        && !path.ends_with(".ico")
        && !path.ends_with(".woff")
        && !path.ends_with(".woff2")
        && !path.ends_with(".map")
}

fn is_javascript_asset(url: &Url) -> bool {
    let path = url.path().to_ascii_lowercase();
    path.ends_with(".js") || path.ends_with(".mjs")
}

fn record_url(
    assets: &mut Vec<Asset>,
    discovered: &mut HashSet<String>,
    mut url: Url,
    discovered_by: &str,
) {
    url.set_fragment(None);
    let url = url.to_string();
    if discovered.insert(url.clone()) {
        assets.push(Asset::new(url, AssetType::Path, discovered_by));
    }
}

fn canonical_without_fragment(url: &Url) -> String {
    let mut normalized = url.clone();
    normalized.set_fragment(None);
    normalized.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config() -> AppConfig {
        AppConfig {
            timeout_secs: 5,
            concurrency: 4,
            rate_limit: 10,
            user_agent: "Temu-Test/1.0".to_string(),
            output_dir: PathBuf::from("/tmp"),
            rules_dir: PathBuf::from("/tmp"),
            dictionaries_dir: PathBuf::from("/tmp"),
            max_recursion_depth: 2,
            wordlist_override: None,
            allow_risky_rules: false,
            browser_crawl_enabled: true,
            browser_crawl_max_pages: 5,
            browser_crawl_max_depth: 2,
            browser_crawl_render_js: false,
            browser_crawl_browser_path: None,
        }
    }

    #[test]
    fn test_extract_js_candidates_finds_spa_routes() {
        let body = r#"
            const routes = ["/api/products", "/#/score-board", "/users/:id"];
            //# sourceMappingURL=main.js.map
        "#;

        let candidates = extract_js_candidates(body);

        assert!(
            candidates
                .iter()
                .any(|candidate| candidate == "/api/products")
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate == "/#/score-board")
        );
        assert!(candidates.iter().any(|candidate| candidate == "/users/:id"));
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate == "main.js.map")
        );
    }

    #[test]
    fn test_collect_urls_from_netlog_json() {
        let value: Value = serde_json::json!({
            "events": [
                {"params": {"url": "http://127.0.0.1:3000/api/products"}},
                {"params": {"nested": {"url": "https://example.com/assets/app.js"}}},
                {"params": {"url": "data:image/png;base64,abc"}}
            ]
        });
        let mut urls = HashSet::new();

        collect_urls_from_json(&value, &mut urls);

        assert!(urls.contains("http://127.0.0.1:3000/api/products"));
        assert!(urls.contains("https://example.com/assets/app.js"));
        assert!(!urls.contains("data:image/png;base64,abc"));
    }

    #[tokio::test]
    async fn test_browser_crawl_extracts_html_and_js_routes() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"
                <html>
                  <a href="/login">Login</a>
                  <form action="/api/contact"></form>
                  <script src="/assets/app.js"></script>
                </html>
                "#,
            ))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/assets/app.js"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"const routes = ["/api/products", "/#/score-board"];"#),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let assets = run_browser_crawl(&server.uri(), &test_config())
            .await
            .expect("crawl should succeed");
        let urls: HashSet<_> = assets.iter().map(|asset| asset.url.as_str()).collect();

        let login_url = format!("{}/login", server.uri());
        let contact_url = format!("{}/api/contact", server.uri());
        let products_url = format!("{}/api/products", server.uri());
        let score_board_url = format!("{}/score-board", server.uri());
        assert!(urls.contains(login_url.as_str()));
        assert!(urls.contains(contact_url.as_str()));
        assert!(urls.contains(products_url.as_str()));
        assert!(urls.contains(score_board_url.as_str()));
    }
}
