use std::path::PathBuf;

use discovery::{DiscoveryMode, run_discovery};
use temu_core::{AppConfig, Target};

fn make_config(dictionaries_dir: PathBuf) -> AppConfig {
    AppConfig {
        rate_limit: 10,
        timeout_secs: 5,
        concurrency: 4,
        user_agent: "Temu-Test/0.1.0".to_string(),
        output_dir: PathBuf::from("/tmp/temu_test_output"),
        rules_dir: PathBuf::from("/tmp/temu_test_rules"),
        dictionaries_dir,
        wordlist_override: None,
    }
}

#[tokio::test]
async fn test_run_discovery_active_bruteforce_completes_without_error() {
    // Write a tiny wordlist — "localhost" against domain "localhost" produces
    // "localhost.localhost" which won't resolve, but run_discovery must not panic.
    let tmp_dir = tempfile::tempdir().unwrap();
    let wordlist_path = tmp_dir.path().join("subdomains-small.txt");
    std::fs::write(&wordlist_path, "www\napi\nmail\n").unwrap();

    let config = make_config(tmp_dir.path().to_path_buf());

    // Use "localhost" as the target domain — guaranteed to resolve to 127.0.0.1
    let target = Target::new("localhost");

    let result = run_discovery(&target, &config, DiscoveryMode::ActiveBruteforce).await;

    // run_discovery should complete without error even if no subdomains resolve
    // (wordlist word "localhost" + domain "localhost" = "localhost.localhost" which won't resolve)
    assert!(
        result.is_ok(),
        "run_discovery should not return an error, got: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_run_discovery_smart_heuristic_generates_candidates() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let config = make_config(tmp_dir.path().to_path_buf());

    let target = Target::new("localhost");

    // SmartHeuristic should not panic even if no subdomains resolve
    let result = run_discovery(&target, &config, DiscoveryMode::SmartHeuristic).await;
    assert!(result.is_ok(), "SmartHeuristic mode should not return an error");
}
