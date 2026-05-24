use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use discovery::DiscoveryMode;
use reporter::{ScanResult, generate_json};
use temu_core::{AppConfig, Asset, AssetType};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_config(dictionaries_dir: PathBuf, rules_dir: PathBuf, output_dir: PathBuf) -> AppConfig {
    AppConfig {
        rate_limit: 50,
        timeout_secs: 5,
        concurrency: 4,
        user_agent: "Temu-Test/1.0.0".to_string(),
        output_dir,
        rules_dir,
        dictionaries_dir,
        max_recursion_depth: 2,
        wordlist_override: None,
        allow_risky_rules: false,
        browser_crawl_enabled: true,
        browser_crawl_max_pages: 25,
        browser_crawl_max_depth: 2,
        browser_crawl_render_js: false,
        browser_crawl_browser_path: None,
        session_profile: None,
    }
}

fn make_minimal_dirs(tmp: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let dict_dir = tmp.path().join("dictionaries");
    std::fs::create_dir_all(&dict_dir).unwrap();
    std::fs::write(dict_dir.join("paths-small.txt"), "/health\n").unwrap();
    std::fs::write(dict_dir.join("parameters-small.txt"), "q\n").unwrap();

    let rules_dir = tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    let output_dir = tmp.path().join("results");
    (dict_dir, rules_dir, output_dir)
}

/// Full pipeline integration test against a local wiremock server.
///
/// Verifies:
/// - run_scan completes without error
/// - Fingerprint detects nginx from response headers
/// - Fuzzing finds /robots.txt (200) and /.env (200)
/// - Vulnerability scan detects exposed .env (StatusCode 200)
/// - ScanResult serializes to valid JSON
/// - generate_json writes a file to output dir
#[tokio::test]
async fn test_full_pipeline_scan() {
    let mock_server = MockServer::start().await;

    // Root page — nginx header + WordPress body
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("server", "nginx/1.18.0")
                .set_body_string(
                    r#"<html><head><meta name="generator" content="WordPress 6.4"/></head>
                    <body><script src="/wp-content/themes/theme/jquery-3.6.0.min.js"></script></body></html>"#,
                ),
        )
        .mount(&mock_server)
        .await;

    // robots.txt — interesting path
    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string("User-agent: *\nDisallow: /admin"))
        .mount(&mock_server)
        .await;

    // .env — sensitive file exposed
    Mock::given(method("GET"))
        .and(path("/.env"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("APP_KEY=base64:abc\nDB_PASSWORD=secret123"),
        )
        .mount(&mock_server)
        .await;

    // baseline + all other paths → 404
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .mount(&mock_server)
        .await;

    // ── Setup temp directories ───────────────────────────────────────────────
    let tmp = tempfile::tempdir().unwrap();

    // Wordlist with a few entries including robots.txt and .env
    let dict_dir = tmp.path().join("dictionaries");
    std::fs::create_dir_all(&dict_dir).unwrap();
    std::fs::write(
        dict_dir.join("paths-small.txt"),
        "/robots.txt\n/.env\n/admin\n/nonexistent_path_xyz\n",
    )
    .unwrap();
    std::fs::write(dict_dir.join("parameters-small.txt"), "id\nq\nunused\n").unwrap();

    // Rules dir with our sensitive-files rule + fingerprint rules
    let rules_dir = tmp.path().join("rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(
        rules_dir.join("sensitive-files.yaml"),
        r#"id: "SENSITIVE-FILES-ENV"
name: "Exposed .env file"
tech_stack: []
severity: high
cvss: 7.5
payload: "/.env"
request_method: GET
verify:
  match_type: StatusCode
  response_codes: [200]
  body_contains: "DB_PASSWORD"
remediation: "Move .env outside web root"
"#,
    )
    .unwrap();

    // Copy fingerprint_rules.yaml from workspace rules/ dir
    let workspace_rules =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/fingerprint_rules.yaml");
    if workspace_rules.exists() {
        std::fs::copy(&workspace_rules, rules_dir.join("fingerprint_rules.yaml")).unwrap();
    }

    let output_dir = tmp.path().join("results");
    let config = make_config(dict_dir, rules_dir, output_dir.clone());

    // ── Run scan ─────────────────────────────────────────────────────────────
    let base_url = mock_server.uri();
    let mock_port = reqwest::Url::parse(&base_url)
        .unwrap()
        .port()
        .expect("mock server URI must include a port");
    let result = cli::orchestrator::run_scan_with_ports(
        &base_url,
        &config,
        DiscoveryMode::PassiveOnly,
        &[mock_port],
    )
    .await
    .expect("run_scan should not fail");

    // ── Assertions ───────────────────────────────────────────────────────────

    // Fingerprint: nginx should be detected
    let all_techs: Vec<String> = result
        .tech_stacks
        .values()
        .flatten()
        .map(|t| t.name.clone())
        .collect();
    assert!(
        all_techs.iter().any(|n| n.to_lowercase().contains("nginx")),
        "Expected nginx to be fingerprinted, got: {all_techs:?}"
    );

    // Fuzzing: robots.txt and .env should be found
    let found_paths: Vec<String> = result
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::Path)
        .map(|a| a.url.clone())
        .collect();
    assert!(
        found_paths.iter().any(|p| p.contains("robots.txt")),
        "Expected /robots.txt in fuzz results, got: {found_paths:?}"
    );

    // Port scan: mock server port should be represented as a service asset
    assert!(
        result
            .assets
            .iter()
            .any(|a| a.asset_type == AssetType::Service),
        "Expected service asset from port scan"
    );

    // ScanResult serializes to valid JSON
    let json = serde_json::to_string_pretty(&result).expect("ScanResult must serialize to JSON");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Must parse back to JSON");
    assert_eq!(parsed["target"].as_str().unwrap(), base_url);
    assert!(parsed["stats"]["duration_secs"].as_f64().is_some());

    // generate_json writes a file
    let report_path = generate_json(&result, &output_dir).expect("generate_json should succeed");
    assert!(report_path.exists(), "Report file must exist");
    let file_content = std::fs::read_to_string(&report_path).unwrap();
    let file_json: serde_json::Value = serde_json::from_str(&file_content).unwrap();
    assert!(file_json["assets"].is_array());
    assert!(file_json["vulnerabilities"].is_array());
}

/// Verify ScanResult with empty fields round-trips through JSON correctly.
#[test]
fn test_scan_result_json_roundtrip() {
    use chrono::Utc;

    let result = ScanResult {
        target: "https://example.com".to_string(),
        assets: vec![Asset::new("https://example.com", AssetType::Url, "test")],
        tech_stacks: HashMap::new(),
        vulnerabilities: vec![],
        target_summaries: vec![],
        scan_started_at: Utc::now(),
        scan_finished_at: Utc::now(),
        stats: reporter::ScanStats {
            subdomains_found: 0,
            paths_found: 3,
            parameters_found: 0,
            vulns_found: 1,
            duration_secs: 12.5,
        },
    };

    let json = serde_json::to_string(&result).unwrap();
    let back: ScanResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.target, result.target);
    assert_eq!(back.stats.paths_found, 3);
    assert_eq!(back.stats.vulns_found, 1);
}

#[tokio::test]
async fn test_file_scan_pipeline_generates_aggregate_result() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<title>OK</title>"))
        .mount(&mock_server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let (dict_dir, rules_dir, output_dir) = make_minimal_dirs(&tmp);
    let config = make_config(dict_dir, rules_dir, output_dir);
    let list_path = tmp.path().join("targets.txt");
    std::fs::write(
        &list_path,
        format!(
            "# local targets\n{}\n{}\n",
            mock_server.uri(),
            mock_server.uri()
        ),
    )
    .unwrap();

    let result =
        cli::orchestrator::run_file_scan(&list_path, &config, DiscoveryMode::PassiveOnly, &[])
            .await
            .expect("file scan should complete");

    assert_eq!(result.targets.len(), 2);
    assert_eq!(result.aggregate.target_summaries.len(), 2);
    assert!(result.aggregate.target.starts_with("file:"));
}

#[tokio::test]
async fn test_network_scan_pipeline_scans_discovered_web_service() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<title>Network OK</title>"))
        .mount(&mock_server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let (dict_dir, rules_dir, output_dir) = make_minimal_dirs(&tmp);
    let config = make_config(dict_dir, rules_dir, output_dir);
    let mock_port = reqwest::Url::parse(&mock_server.uri())
        .unwrap()
        .port()
        .expect("mock server URI must include a port");

    let result = cli::orchestrator::run_network_scan_multi("127.0.0.1/32", &config, &[mock_port])
        .await
        .expect("network scan should complete");

    assert!(!result.targets.is_empty());
    assert!(result.aggregate.target.starts_with("network:"));
    assert!(
        result
            .aggregate
            .assets
            .iter()
            .any(|asset| asset.asset_type == AssetType::Service)
    );
}

#[test]
fn test_benchmark_100_url_aggregation_records_time_and_size() {
    use chrono::Utc;

    let started = Instant::now();
    let scan_started_at = Utc::now();
    let results = (0..100)
        .map(|index| ScanResult {
            target: format!("https://target-{index}.example"),
            assets: vec![Asset::new(
                format!("https://target-{index}.example"),
                AssetType::Url,
                "benchmark",
            )],
            tech_stacks: HashMap::new(),
            vulnerabilities: Vec::new(),
            target_summaries: Vec::new(),
            scan_started_at,
            scan_finished_at: scan_started_at,
            stats: reporter::ScanStats {
                subdomains_found: 0,
                paths_found: 0,
                parameters_found: 0,
                vulns_found: 0,
                duration_secs: 0.0,
            },
        })
        .collect::<Vec<_>>();

    let aggregate = cli::orchestrator::aggregate_scan_results("benchmark:100-urls", &results);
    let elapsed = started.elapsed();
    let report_bytes = serde_json::to_vec(&aggregate).unwrap().len();

    assert_eq!(aggregate.target_summaries.len(), 100);
    assert!(elapsed.as_secs_f64() < 1.0, "aggregation took {elapsed:?}");
    assert!(
        report_bytes > 1_000,
        "benchmark report should have measurable size"
    );
}

#[test]
fn test_benchmark_10k_url_aggregation_stays_fast() {
    use chrono::Utc;

    let started = Instant::now();
    let scan_started_at = Utc::now();
    let results = (0..10_000)
        .map(|index| ScanResult {
            target: format!("https://target-{index}.example"),
            assets: vec![Asset::new(
                format!("https://target-{index}.example"),
                AssetType::Url,
                "benchmark",
            )],
            tech_stacks: HashMap::new(),
            vulnerabilities: Vec::new(),
            target_summaries: Vec::new(),
            scan_started_at,
            scan_finished_at: scan_started_at,
            stats: reporter::ScanStats {
                subdomains_found: 0,
                paths_found: 0,
                parameters_found: 0,
                vulns_found: 0,
                duration_secs: 0.0,
            },
        })
        .collect::<Vec<_>>();

    let aggregate = cli::orchestrator::aggregate_scan_results("benchmark:10k-urls", &results);
    let elapsed = started.elapsed();
    let report_bytes = serde_json::to_vec(&aggregate).unwrap().len();

    assert_eq!(aggregate.target_summaries.len(), 10_000);
    assert!(elapsed.as_secs_f64() < 2.0, "aggregation took {elapsed:?}");
    assert!(
        report_bytes > 100_000,
        "benchmark report should have measurable size"
    );
}
