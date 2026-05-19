use std::collections::HashMap;

use chrono::Utc;
use discovery::{DiscoveryMode, run_discovery};
use fingerprint::run_fingerprint;
use fuzzing::run_fuzzing;
use reporter::types::{ScanResult, ScanStats};
use temu_core::{AppConfig, Asset, AssetType, Target};
use tracing::info;
use verifier::run_verification;
use vulnerability::run_vulnerability_scan;

/// Runs the full scan pipeline against a target URL.
///
/// Pipeline steps:
/// 1. Parse domain from URL → `Target`
/// 2. Discovery: enumerate subdomains + HTTP probe
/// 3. Fingerprint: detect technologies on base URL + all live assets
/// 4. Fuzzing: path discovery on base URL
/// 5. Vulnerability: rule-based scanning on all discovered URLs
/// 6. Build and return `ScanResult`
pub async fn run_scan(
    url: &str,
    config: &AppConfig,
    mode: DiscoveryMode,
) -> anyhow::Result<ScanResult> {
    let started_at = Utc::now();

    let parsed =
        reqwest::Url::parse(url).map_err(|e| anyhow::anyhow!("Invalid URL '{url}': {e}"))?;
    let domain = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {url}"))?
        .to_string();

    eprintln!("[*] Starting scan for {domain} ({url})");

    // ── 1. Discovery ─────────────────────────────────────────────────────────
    let target = Target::new(&domain);
    let discovered = run_discovery(&target, config, mode)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Discovery error (continuing): {e}");
            vec![]
        });
    let subdomains_found = discovered
        .iter()
        .filter(|a| a.asset_type == AssetType::Subdomain)
        .count() as u32;
    eprintln!("[+] Discovery: found {} assets", discovered.len());
    info!("Discovery complete: {} assets", discovered.len());

    // Build list of URLs to fingerprint/fuzz: base URL + all subdomain assets
    let mut live_urls: Vec<String> = vec![url.to_string()];
    for asset in &discovered {
        if asset.asset_type == AssetType::Subdomain {
            let asset_url = if parsed.scheme() == "https" {
                format!("https://{}", asset.url)
            } else {
                format!("http://{}", asset.url)
            };
            live_urls.push(asset_url);
        }
    }

    // ── 2. Fingerprint ───────────────────────────────────────────────────────
    let mut tech_stacks: HashMap<String, Vec<fingerprint::TechStack>> = HashMap::new();
    for target_url in &live_urls {
        match run_fingerprint(target_url, config).await {
            Ok(techs) => {
                if !techs.is_empty() {
                    tech_stacks.insert(target_url.clone(), techs);
                }
            }
            Err(e) => tracing::warn!("Fingerprint error for {target_url}: {e}"),
        }
    }
    let tech_summary: Vec<String> = tech_stacks
        .values()
        .flatten()
        .map(|t| {
            if let Some(v) = &t.version {
                format!("{}/{v}", t.name)
            } else {
                t.name.clone()
            }
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    eprintln!("[+] Fingerprint: {}", tech_summary.join(", "));

    // ── 3. Fuzzing ───────────────────────────────────────────────────────────
    let fuzzing_assets = run_fuzzing(url, config).await.unwrap_or_else(|e| {
        tracing::warn!("Fuzzing error (continuing): {e}");
        vec![]
    });
    let paths_found = fuzzing_assets
        .iter()
        .filter(|a| a.asset_type == AssetType::Path)
        .count() as u32;
    let parameters_found = fuzzing_assets
        .iter()
        .filter(|a| a.asset_type == AssetType::Parameter)
        .count() as u32;
    eprintln!("[+] Fuzzing: found {paths_found} paths, {parameters_found} parameters");
    info!("Fuzzing complete: {paths_found} paths, {parameters_found} parameters");

    // ── 4. Vulnerability scan ────────────────────────────────────────────────
    // Collect all URLs to scan: base URL + discovered paths
    let mut all_assets: Vec<Asset> = vec![Asset::new(url, AssetType::Url, "cli::scan")];
    all_assets.extend(discovered.clone());
    all_assets.extend(fuzzing_assets.clone());

    let all_techs: Vec<fingerprint::TechStack> = tech_stacks.values().flatten().cloned().collect();

    let detected_vulnerabilities = run_vulnerability_scan(&all_assets, &all_techs, config)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Vulnerability scan error (continuing): {e}");
            vec![]
        });
    let vulnerabilities = run_verification(&detected_vulnerabilities, config).await;
    let vulns_found = vulnerabilities.len() as u32;
    eprintln!(
        "[+] Vulnerability: found {vulns_found} issue{}",
        if vulns_found == 1 { "" } else { "s" }
    );

    let finished_at = Utc::now();
    let duration_secs = (finished_at - started_at).num_milliseconds() as f64 / 1000.0;
    eprintln!("[*] Scan completed in {duration_secs:.1}s");

    let mut all_discovered: Vec<Asset> = discovered;
    all_discovered.extend(fuzzing_assets);

    Ok(ScanResult {
        target: url.to_string(),
        assets: all_discovered,
        tech_stacks,
        vulnerabilities,
        scan_started_at: started_at,
        scan_finished_at: finished_at,
        stats: ScanStats {
            subdomains_found,
            paths_found,
            parameters_found,
            vulns_found,
            duration_secs,
        },
    })
}
