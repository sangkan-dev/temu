use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use discovery::{
    DiscoveryMode, PortResult, default_top_ports, run_api_discovery, run_browser_crawl,
    run_discovery, scan_ports, scan_ports_named, scan_ports_passive,
};
use fingerprint::{TechCategory, TechStack, run_fingerprint};
use fuzzing::run_fuzzing;
use hickory_resolver::TokioResolver;
use reporter::types::{CallbackEvent, ScanResult, ScanStats, TargetSummary};
use serde::{Deserialize, Serialize};
use temu_core::{AppConfig, Asset, AssetType, ServiceEvidence, Severity, Target, Vulnerability};
use tracing::info;
use verifier::run_verification;
use vulnerability::{run_network_service_checks, run_vulnerability_scan};

use crate::collaborator::load_callback_events;
use crate::stateful::run_stateful_dast;

const MAX_CIDR_HOSTS: u64 = 1_048_576;
const DEFAULT_NETWORK_CHUNK_SIZE: usize = 256;

/// Optional host-liveness preflight used before service scanning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NetworkLivenessStrategy {
    /// Treat TCP connect scanning as the authoritative liveness signal.
    #[default]
    Tcp,
    /// Require a successful ICMP echo before scanning a host.
    Icmp,
    /// Require an entry in the local ARP cache before scanning a host.
    Arp,
    /// Use ICMP and ARP hints while retaining TCP connect as a fallback.
    Combined,
}

/// Runtime controls for resumable, scope-aware network mapping.
#[derive(Debug, Clone)]
pub struct NetworkScanOptions {
    pub chunk_size: usize,
    pub checkpoint_path: Option<PathBuf>,
    pub resume: bool,
    pub passive_network: bool,
    pub liveness: NetworkLivenessStrategy,
    pub baseline_path: Option<PathBuf>,
}

impl Default for NetworkScanOptions {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_NETWORK_CHUNK_SIZE,
            checkpoint_path: None,
            resume: false,
            passive_network: false,
            liveness: NetworkLivenessStrategy::Tcp,
            baseline_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkCheckpoint {
    cidr: String,
    ports: Vec<u16>,
    next_offset: u64,
    results: Vec<ScanResult>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Copy)]
struct Ipv4NetworkRange {
    network: u32,
    host_count: u64,
}

/// Results from a multi-target scan, including aggregate and per-target reports.
#[derive(Debug, Clone)]
pub struct MultiTargetScanResult {
    pub aggregate: ScanResult,
    pub targets: Vec<ScanResult>,
}

#[derive(Debug, Default)]
struct ErrorSummary {
    errors: Vec<String>,
}

#[derive(Debug, Default)]
struct ServiceReportItems {
    assets: Vec<Asset>,
    techs: Vec<(String, TechStack)>,
    web_urls: Vec<String>,
    services: Vec<ServiceEvidence>,
}

impl ErrorSummary {
    fn push(&mut self, stage: &str, detail: impl std::fmt::Display) {
        self.errors.push(format!("{stage}: {detail}"));
    }

    fn print(&self) {
        if self.errors.is_empty() {
            eprintln!("[+] Error summary: no recoverable errors");
            return;
        }

        eprintln!(
            "[!] Error summary: {} recoverable issue{}",
            self.errors.len(),
            if self.errors.len() == 1 { "" } else { "s" }
        );
        for error in &self.errors {
            eprintln!("    - {error}");
        }
    }
}

/// Runs the full scan pipeline against a target URL.
///
/// Pipeline steps:
/// 1. Parse domain from URL → `Target`
/// 2. Discovery: enumerate subdomains + HTTP probe
/// 3. Fingerprint: detect technologies on base URL + all live assets
/// 4. Browser-aware crawling: extract HTML/JavaScript routes and API paths
/// 5. API discovery: parse OpenAPI/Swagger and probe GraphQL endpoints
/// 6. Fuzzing: path discovery on base URL
/// 7. Vulnerability: rule-based scanning on all discovered URLs
/// 8. Build and return `ScanResult`
pub async fn run_scan(
    url: &str,
    config: &AppConfig,
    mode: DiscoveryMode,
) -> anyhow::Result<ScanResult> {
    run_scan_with_ports(url, config, mode, &default_top_ports()).await
}

/// Runs the full scan pipeline against a target URL with explicit TCP ports.
pub async fn run_scan_with_ports(
    url: &str,
    config: &AppConfig,
    mode: DiscoveryMode,
    ports: &[u16],
) -> anyhow::Result<ScanResult> {
    let started_at = Utc::now();
    let mut error_summary = ErrorSummary::default();

    let parsed =
        reqwest::Url::parse(url).map_err(|e| anyhow::anyhow!("Invalid URL '{url}': {e}"))?;
    let domain = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {url}"))?
        .to_string();

    eprintln!("[*] Starting scan for {domain} ({url})");

    // ── 1. Discovery ─────────────────────────────────────────────────────────
    let discovered = if domain.parse::<IpAddr>().is_ok() {
        Vec::new()
    } else {
        let target = Target::new(&domain);
        match run_discovery(&target, config, mode).await {
            Ok(assets) => assets,
            Err(e) => {
                error_summary.push("discovery", &e);
                tracing::warn!("Discovery error (continuing): {e}");
                Vec::new()
            }
        }
    };
    let subdomains_found = discovered
        .iter()
        .filter(|a| a.asset_type == AssetType::Subdomain)
        .count() as u32;
    eprintln!("[+] Discovery: found {} assets", discovered.len());
    info!("Discovery complete: {} assets", discovered.len());

    // ── 1b. Port scan ───────────────────────────────────────────────────────
    let (service_assets, service_techs, service_evidence) =
        run_port_scan_for_domain(&domain, ports, config).await;
    eprintln!(
        "[+] Port scan: found {} open services",
        service_assets.len()
    );

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
            Err(e) => {
                error_summary.push("fingerprint", format!("{target_url}: {e}"));
                tracing::warn!("Fingerprint error for {target_url}: {e}");
            }
        }
    }
    for (service_url, tech) in service_techs {
        tech_stacks.entry(service_url).or_default().push(tech);
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

    // ── 3. Browser-aware crawling ────────────────────────────────────────────
    let browser_assets = match run_browser_crawl(url, config).await {
        Ok(assets) => assets,
        Err(e) => {
            error_summary.push("browser_crawl", &e);
            tracing::warn!("Browser-aware crawl error (continuing): {e}");
            Vec::new()
        }
    };
    eprintln!(
        "[+] Browser crawl: found {} SPA/API assets",
        browser_assets.len()
    );
    info!(
        "Browser-aware crawl complete: {} assets",
        browser_assets.len()
    );

    // ── 4. API discovery ─────────────────────────────────────────────────────
    let api_assets = match run_api_discovery(url, config).await {
        Ok(assets) => assets,
        Err(e) => {
            error_summary.push("api_discovery", &e);
            tracing::warn!("API discovery error (continuing): {e}");
            Vec::new()
        }
    };
    eprintln!("[+] API discovery: found {} endpoints", api_assets.len());
    info!("API discovery complete: {} assets", api_assets.len());

    // ── 5. Fuzzing ───────────────────────────────────────────────────────────
    let fuzzing_assets = match run_fuzzing(url, config).await {
        Ok(assets) => assets,
        Err(e) => {
            error_summary.push("fuzzing", &e);
            tracing::warn!("Fuzzing error (continuing): {e}");
            Vec::new()
        }
    };
    let paths_found = fuzzing_assets
        .iter()
        .filter(|a| a.asset_type == AssetType::Path)
        .count() as u32
        + browser_assets
            .iter()
            .filter(|a| a.asset_type == AssetType::Path)
            .count() as u32
        + api_assets
            .iter()
            .filter(|a| a.asset_type == AssetType::ApiEndpoint)
            .count() as u32;
    let parameters_found = fuzzing_assets
        .iter()
        .filter(|a| a.asset_type == AssetType::Parameter)
        .count() as u32;
    eprintln!("[+] Fuzzing: found {paths_found} paths, {parameters_found} parameters");
    info!("Fuzzing complete: {paths_found} paths, {parameters_found} parameters");

    // ── 6. Stateful DAST ─────────────────────────────────────────────────────
    let stateful_result = match run_stateful_dast(
        url,
        &all_stateful_surface(&browser_assets, &api_assets, &fuzzing_assets),
        config,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            error_summary.push("stateful_dast", &e);
            tracing::warn!("Stateful DAST error (continuing): {e}");
            Default::default()
        }
    };
    eprintln!(
        "[+] Stateful DAST: found {} workflow assets, {} signal{}",
        stateful_result.assets.len(),
        stateful_result.findings.len(),
        if stateful_result.findings.len() == 1 {
            ""
        } else {
            "s"
        }
    );

    // ── 7. Vulnerability scan ────────────────────────────────────────────────
    // Collect all URLs to scan: base URL + discovered paths
    let mut all_assets: Vec<Asset> = vec![Asset::new(url, AssetType::Url, "cli::scan")];
    all_assets.extend(discovered.clone());
    all_assets.extend(browser_assets.clone());
    all_assets.extend(api_assets.clone());
    all_assets.extend(fuzzing_assets.clone());

    let all_techs: Vec<fingerprint::TechStack> = tech_stacks.values().flatten().cloned().collect();

    let mut detected_vulnerabilities =
        match run_vulnerability_scan(&all_assets, &all_techs, config).await {
            Ok(vulnerabilities) => vulnerabilities,
            Err(e) => {
                error_summary.push("vulnerability", &e);
                tracing::warn!("Vulnerability scan error (continuing): {e}");
                Vec::new()
            }
        };
    detected_vulnerabilities.extend(stateful_result.findings.clone());
    match run_network_service_checks(&service_evidence, config) {
        Ok(network_findings) => detected_vulnerabilities.extend(network_findings),
        Err(e) => {
            error_summary.push("network_rules", &e);
            tracing::warn!("Network rule scan error (continuing): {e}");
        }
    }
    match cve_client::check_cves(&all_techs, config).await {
        Ok(cve_vulnerabilities) => {
            if !cve_vulnerabilities.is_empty() {
                info!(
                    "CVE metadata check found {} version-related issues",
                    cve_vulnerabilities.len()
                );
            }
            detected_vulnerabilities.extend(cve_vulnerabilities);
        }
        Err(e) => {
            error_summary.push("cve", &e);
            tracing::warn!("CVE check error (continuing): {e}");
        }
    }
    if config.oast_wait_secs > 0 && config.oast_callback_url.is_some() {
        eprintln!(
            "[*] Waiting {}s for OAST callback evidence",
            config.oast_wait_secs
        );
        tokio::time::sleep(std::time::Duration::from_secs(config.oast_wait_secs)).await;
    }

    let callback_events = load_oast_callback_events(config);
    detected_vulnerabilities.extend(callback_events_to_findings(&callback_events));

    let vulnerabilities = run_verification(&detected_vulnerabilities, config).await;
    let vulns_found = vulnerabilities.len() as u32;
    eprintln!(
        "[+] Vulnerability: found {vulns_found} issue{}",
        if vulns_found == 1 { "" } else { "s" }
    );

    let finished_at = Utc::now();
    let duration_secs = (finished_at - started_at).num_milliseconds() as f64 / 1000.0;
    eprintln!("[*] Scan completed in {duration_secs:.1}s");
    error_summary.print();

    let mut all_discovered: Vec<Asset> = discovered;
    if let Some(session_asset) = session_profile_asset(config) {
        all_discovered.push(session_asset);
    }
    all_discovered.extend(browser_assets);
    all_discovered.extend(api_assets);
    all_discovered.extend(fuzzing_assets);
    all_discovered.extend(stateful_result.assets);
    all_discovered.extend(service_assets);

    Ok(ScanResult {
        target: url.to_string(),
        assets: all_discovered,
        tech_stacks,
        vulnerabilities,
        services: service_evidence,
        target_summaries: vec![],
        callback_events,
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

fn all_stateful_surface(browser: &[Asset], api: &[Asset], fuzzing: &[Asset]) -> Vec<Asset> {
    let mut assets = Vec::with_capacity(browser.len() + api.len() + fuzzing.len());
    assets.extend_from_slice(browser);
    assets.extend_from_slice(api);
    assets.extend_from_slice(fuzzing);
    assets
}

fn session_profile_asset(config: &AppConfig) -> Option<Asset> {
    let profile = config.session_profile.as_ref()?;
    let scope = profile.base_url_scope.as_deref().unwrap_or("all-targets");
    let validate = if profile.validate_url.is_some() {
        "validate=true"
    } else {
        "validate=false"
    };
    Some(Asset::new(
        format!("authenticated-session scope={scope} {validate}"),
        AssetType::Url,
        "cli::session_profile",
    ))
}

fn load_oast_callback_events(config: &AppConfig) -> Vec<CallbackEvent> {
    let (Some(database_path), Some(correlation_id)) = (
        config.oast_database_path.as_deref(),
        config.oast_correlation_id.as_deref(),
    ) else {
        return Vec::new();
    };

    match load_callback_events(database_path, correlation_id) {
        Ok(events) => events,
        Err(error) => {
            tracing::warn!("Failed to load OAST callback evidence: {error}");
            Vec::new()
        }
    }
}

fn callback_events_to_findings(events: &[CallbackEvent]) -> Vec<Vulnerability> {
    if events.is_empty() {
        return Vec::new();
    }

    let first = &events[0];
    let mut finding = Vulnerability::new(
        "OAST-CALLBACK-EVIDENCE",
        "Out-of-band callback observed",
        Severity::High,
        8.0,
        format!(
            "{} callback event(s) observed for correlation ID {}. First event: {} {} from {} at {}",
            events.len(),
            first.correlation_id,
            first.method,
            first.path,
            first.remote_addr,
            first.received_at.to_rfc3339()
        ),
        first.path.clone(),
    );
    finding.parameter = Some(first.correlation_id.clone());
    finding.verified = true;
    finding.remediation = Some(
        "Investigate the request path that triggered the callback and restrict outbound server-side requests, XML entity resolution, reflected script execution, or log interpolation as applicable."
            .to_string(),
    );
    vec![finding]
}

/// Loads scan targets from a file containing one URL per line.
///
/// Empty lines and lines beginning with `#` are ignored. Every remaining line
/// must be an absolute URL accepted by `reqwest::Url`.
pub fn load_target_list(path: &Path) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    let mut targets = Vec::new();

    for (line_number, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        reqwest::Url::parse(trimmed).map_err(|e| {
            anyhow::anyhow!("Invalid URL on line {}: {trimmed} ({e})", line_number + 1)
        })?;
        targets.push(trimmed.to_string());
    }

    if targets.is_empty() {
        return Err(anyhow::anyhow!("Target list is empty: {:?}", path));
    }

    Ok(targets)
}

/// Runs full scans for every URL in a target list file and aggregates results.
pub async fn run_file_scan(
    list_path: &Path,
    config: &AppConfig,
    mode: DiscoveryMode,
    ports: &[u16],
) -> anyhow::Result<MultiTargetScanResult> {
    let targets = load_target_list(list_path)?;
    let total = targets.len();
    let mut results = Vec::with_capacity(total);

    for (index, target) in targets.iter().enumerate() {
        eprintln!("Scanning target {}/{}: {target}", index + 1, total);
        match run_scan_with_ports(target, config, mode.clone(), ports).await {
            Ok(result) => results.push(result),
            Err(e) => {
                tracing::warn!("Target scan failed for {target}: {e}");
                eprintln!("[!] Target scan failed for {target}: {e}");
            }
        }
    }

    if results.is_empty() {
        return Err(anyhow::anyhow!(
            "All targets in {:?} failed to scan",
            list_path
        ));
    }

    let aggregate_target = format!("file:{}", list_path.display());
    let aggregate = aggregate_scan_results(&aggregate_target, &results);
    Ok(MultiTargetScanResult {
        aggregate,
        targets: results,
    })
}

/// Runs TCP port scanning for an IPv4 CIDR and returns a reportable scan result.
pub async fn run_network_scan(
    cidr: &str,
    config: &AppConfig,
    ports: &[u16],
) -> anyhow::Result<ScanResult> {
    Ok(
        run_network_scan_multi_with_options(cidr, config, ports, &NetworkScanOptions::default())
            .await?
            .aggregate,
    )
}

/// Runs TCP port scanning for an IPv4 CIDR and full scans for discovered web services.
pub async fn run_network_scan_multi(
    cidr: &str,
    config: &AppConfig,
    ports: &[u16],
) -> anyhow::Result<MultiTargetScanResult> {
    run_network_scan_multi_with_options(cidr, config, ports, &NetworkScanOptions::default()).await
}

/// Runs a resumable, chunked network scan with optional passive and liveness controls.
pub async fn run_network_scan_multi_with_options(
    cidr: &str,
    config: &AppConfig,
    ports: &[u16],
    options: &NetworkScanOptions,
) -> anyhow::Result<MultiTargetScanResult> {
    let started_at = Utc::now();
    let range = parse_ipv4_network_range(cidr)?;
    let first_ip = Ipv4Addr::from(range.network);
    if first_ip.is_private() {
        eprintln!("[!] Scanning private network range: {cidr}");
    }
    let chunk_size = options.chunk_size.max(1);
    eprintln!(
        "[*] Starting network scan for {cidr} ({} hosts, {} ports, chunks of {chunk_size})",
        range.host_count,
        ports.len()
    );
    if options.passive_network {
        eprintln!("[*] Passive network mode enabled: connect and greeting collection only");
    }

    let checkpoint = load_network_checkpoint(cidr, ports, options).await?;
    let mut per_target_results = checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.results.clone())
        .unwrap_or_default();
    let mut offset = checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.next_offset)
        .unwrap_or(0);
    let mut empty_host_streak = 0_u32;

    while offset < range.host_count {
        let chunk_end = (offset + chunk_size as u64).min(range.host_count);
        eprintln!(
            "[*] Network chunk {}-{} of {}",
            offset + 1,
            chunk_end,
            range.host_count
        );

        for current_offset in offset..chunk_end {
            let ip = Ipv4Addr::from(range.network + current_offset as u32);
            eprintln!(
                "Scanning target {}/{}: {ip}",
                current_offset + 1,
                range.host_count
            );
            if !host_liveness_allows_scan(ip, options.liveness).await {
                tracing::debug!("Skipping {ip}: selected liveness strategy did not observe host");
                continue;
            }

            let port_results = if options.passive_network {
                scan_ports_passive(IpAddr::V4(ip), ports, config).await
            } else {
                scan_ports(IpAddr::V4(ip), ports, config).await
            };
            if port_results.is_empty() {
                empty_host_streak = empty_host_streak.saturating_add(1);
                adaptive_network_backoff(empty_host_streak).await;
                continue;
            }
            empty_host_streak = 0;
            let ServiceReportItems {
                assets: service_assets,
                techs: service_techs,
                web_urls,
                services,
            } = report_items_from_port_results(IpAddr::V4(ip), &port_results);
            let mut network_findings = run_network_service_checks(&services, config)
                .unwrap_or_else(|error| {
                    tracing::warn!("Network rule scan error for {ip}: {error}");
                    Vec::new()
                });
            network_findings.extend(exposure_combination_findings(&services));

            if web_urls.is_empty() {
                per_target_results.push(service_only_scan_result(
                    &ip.to_string(),
                    service_assets,
                    service_techs,
                    services,
                    network_findings,
                    started_at,
                ));
                continue;
            }

            for web_url in web_urls {
                if options.passive_network {
                    per_target_results.push(service_only_scan_result(
                        &web_url,
                        service_assets.clone(),
                        service_techs.clone(),
                        services.clone(),
                        network_findings.clone(),
                        started_at,
                    ));
                    continue;
                }
                match run_scan_with_ports(&web_url, config, DiscoveryMode::PassiveOnly, &[]).await {
                    Ok(mut result) => {
                        result.assets.extend(service_assets.clone());
                        result.services.extend(services.clone());
                        result.vulnerabilities.extend(network_findings.clone());
                        result.stats.vulns_found = result.vulnerabilities.len() as u32;
                        for (service_url, tech) in &service_techs {
                            result
                                .tech_stacks
                                .entry(service_url.clone())
                                .or_default()
                                .push(tech.clone());
                        }
                        per_target_results.push(result);
                    }
                    Err(error) => {
                        tracing::warn!("Web service scan failed for {web_url}: {error}");
                        eprintln!("[!] Web service scan failed for {web_url}: {error}");
                        per_target_results.push(service_only_scan_result(
                            &web_url,
                            service_assets.clone(),
                            service_techs.clone(),
                            services.clone(),
                            network_findings.clone(),
                            started_at,
                        ));
                    }
                }
            }
        }

        offset = chunk_end;
        if let Some(path) = &options.checkpoint_path {
            let value = NetworkCheckpoint {
                cidr: cidr.to_string(),
                ports: ports.to_vec(),
                next_offset: offset,
                results: per_target_results.clone(),
                updated_at: Utc::now(),
            };
            write_network_checkpoint(path, &value).await?;
        }
    }

    let finished_at = Utc::now();
    let duration_secs = (finished_at - started_at).num_milliseconds() as f64 / 1000.0;
    eprintln!("[*] Network scan completed in {duration_secs:.1}s");

    let mut aggregate = aggregate_scan_results(&format!("network:{cidr}"), &per_target_results);
    aggregate.scan_started_at = started_at;
    aggregate.scan_finished_at = finished_at;
    aggregate.stats.duration_secs = duration_secs;
    if let Some(path) = &options.baseline_path {
        aggregate
            .vulnerabilities
            .extend(detect_service_drift(path, &aggregate).await?);
        aggregate.stats.vulns_found = aggregate.vulnerabilities.len() as u32;
    }

    Ok(MultiTargetScanResult {
        aggregate,
        targets: per_target_results,
    })
}

async fn run_port_scan_for_domain(
    domain: &str,
    ports: &[u16],
    config: &AppConfig,
) -> (Vec<Asset>, Vec<(String, TechStack)>, Vec<ServiceEvidence>) {
    let Ok(builder) = TokioResolver::builder_tokio() else {
        tracing::warn!("Port scan skipped: could not initialize DNS resolver for {domain}");
        return (Vec::new(), Vec::new(), Vec::new());
    };
    let Ok(resolver) = builder.build() else {
        tracing::warn!("Port scan skipped: could not build DNS resolver for {domain}");
        return (Vec::new(), Vec::new(), Vec::new());
    };
    let Ok(response) = resolver.lookup_ip(domain).await else {
        tracing::warn!("Port scan skipped: could not resolve {domain}");
        return (Vec::new(), Vec::new(), Vec::new());
    };
    let Some(ip) = response.iter().next() else {
        return (Vec::new(), Vec::new(), Vec::new());
    };

    let results = scan_ports_named(ip, ports, config, Some(domain)).await;
    let items = report_items_from_port_results(ip, &results);
    (items.assets, items.techs, items.services)
}

fn report_items_from_port_results(ip: IpAddr, results: &[PortResult]) -> ServiceReportItems {
    let mut items = ServiceReportItems::default();
    for result in results {
        let service = result.service.as_deref().unwrap_or("unknown");
        let service_url = format!("tcp://{ip}:{}", result.port);
        if let Some(tech) = tech_from_service(result) {
            items.techs.push((service_url.clone(), tech));
        }
        if let Some(web_url) = web_url_for_service(ip, result.port, service) {
            items.web_urls.push(web_url);
        }
        items.assets.push(Asset::new(
            format!(
                "{service_url} ({service}) product={} version={} confidence={:.2}",
                result.product.as_deref().unwrap_or("unknown"),
                result.version.as_deref().unwrap_or("unknown"),
                result.confidence
            ),
            AssetType::Service,
            "discovery::port_scan",
        ));
        if let Some(evidence) = result.to_service_evidence(ip) {
            items.services.push(evidence);
        }
    }

    items
}

fn web_url_for_service(ip: IpAddr, port: u16, service: &str) -> Option<String> {
    match service {
        "http" if port == 80 => Some(format!("http://{ip}")),
        "http" => Some(format!("http://{ip}:{port}")),
        "https" if port == 443 => Some(format!("https://{ip}")),
        "https" => Some(format!("https://{ip}:{port}")),
        _ => None,
    }
}

/// Combines scan results into a single aggregate report.
pub fn aggregate_scan_results(target: &str, results: &[ScanResult]) -> ScanResult {
    let now = Utc::now();
    let scan_started_at = results
        .iter()
        .map(|result| result.scan_started_at)
        .min()
        .unwrap_or(now);
    let scan_finished_at = results
        .iter()
        .map(|result| result.scan_finished_at)
        .max()
        .unwrap_or(now);

    let mut assets = Vec::new();
    let mut tech_stacks: HashMap<String, Vec<TechStack>> = HashMap::new();
    let mut vulnerabilities = Vec::new();
    let mut services = Vec::new();
    let mut callback_events = Vec::new();
    let mut target_summaries = Vec::new();
    let mut stats = ScanStats {
        subdomains_found: 0,
        paths_found: 0,
        parameters_found: 0,
        vulns_found: 0,
        duration_secs: (scan_finished_at - scan_started_at).num_milliseconds() as f64 / 1000.0,
    };

    for result in results {
        assets.extend(result.assets.clone());
        vulnerabilities.extend(result.vulnerabilities.clone());
        services.extend(result.services.clone());
        callback_events.extend(result.callback_events.clone());
        for (url, techs) in &result.tech_stacks {
            tech_stacks
                .entry(url.clone())
                .or_default()
                .extend(techs.clone());
        }
        stats.subdomains_found += result.stats.subdomains_found;
        stats.paths_found += result.stats.paths_found;
        stats.parameters_found += result.stats.parameters_found;
        stats.vulns_found += result.stats.vulns_found;
        target_summaries.push(TargetSummary {
            target: result.target.clone(),
            assets_total: result.assets.len(),
            vulnerabilities_total: result.vulnerabilities.len(),
            highest_severity: highest_severity(&result.vulnerabilities),
            duration_secs: result.stats.duration_secs,
        });
    }

    target_summaries.sort_by(|a, b| {
        b.vulnerabilities_total
            .cmp(&a.vulnerabilities_total)
            .then(a.target.cmp(&b.target))
    });

    ScanResult {
        target: target.to_string(),
        assets,
        tech_stacks,
        vulnerabilities,
        services,
        target_summaries,
        callback_events,
        scan_started_at,
        scan_finished_at,
        stats,
    }
}

fn service_only_scan_result(
    target: &str,
    assets: Vec<Asset>,
    service_techs: Vec<(String, TechStack)>,
    services: Vec<ServiceEvidence>,
    vulnerabilities: Vec<Vulnerability>,
    started_at: chrono::DateTime<Utc>,
) -> ScanResult {
    let finished_at = Utc::now();
    let mut tech_stacks: HashMap<String, Vec<TechStack>> = HashMap::new();
    for (service_url, tech) in service_techs {
        tech_stacks.entry(service_url).or_default().push(tech);
    }

    ScanResult {
        target: target.to_string(),
        assets,
        tech_stacks,
        stats: ScanStats {
            subdomains_found: 0,
            paths_found: 0,
            parameters_found: 0,
            vulns_found: vulnerabilities.len() as u32,
            duration_secs: (finished_at - started_at).num_milliseconds() as f64 / 1000.0,
        },
        vulnerabilities,
        services,
        target_summaries: Vec::new(),
        callback_events: Vec::new(),
        scan_started_at: started_at,
        scan_finished_at: finished_at,
    }
}

fn highest_severity(vulnerabilities: &[temu_core::Vulnerability]) -> Option<Severity> {
    vulnerabilities
        .iter()
        .map(|vulnerability| vulnerability.severity.clone())
        .max()
}

async fn load_network_checkpoint(
    cidr: &str,
    ports: &[u16],
    options: &NetworkScanOptions,
) -> anyhow::Result<Option<NetworkCheckpoint>> {
    if !options.resume {
        return Ok(None);
    }
    let path = options
        .checkpoint_path
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--resume requires --checkpoint"))?;
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to read network checkpoint {path:?}: {error}"))?;
    let checkpoint: NetworkCheckpoint = serde_json::from_str(&content)
        .map_err(|error| anyhow::anyhow!("Invalid network checkpoint {path:?}: {error}"))?;
    if checkpoint.cidr != cidr || checkpoint.ports != ports {
        return Err(anyhow::anyhow!(
            "Checkpoint scope mismatch: expected CIDR {cidr} and requested ports"
        ));
    }
    eprintln!(
        "[*] Resuming network scan at host offset {} with {} retained result(s)",
        checkpoint.next_offset,
        checkpoint.results.len()
    );
    Ok(Some(checkpoint))
}

async fn write_network_checkpoint(
    path: &Path,
    checkpoint: &NetworkCheckpoint,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let content = serde_json::to_vec_pretty(checkpoint)?;
    let temporary = path.with_extension("tmp");
    tokio::fs::write(&temporary, content).await?;
    tokio::fs::rename(&temporary, path).await?;
    Ok(())
}

async fn host_liveness_allows_scan(ip: Ipv4Addr, strategy: NetworkLivenessStrategy) -> bool {
    match strategy {
        NetworkLivenessStrategy::Tcp | NetworkLivenessStrategy::Combined => true,
        NetworkLivenessStrategy::Icmp => icmp_liveness(ip).await,
        NetworkLivenessStrategy::Arp => arp_cache_contains(ip).await,
    }
}

async fn icmp_liveness(ip: Ipv4Addr) -> bool {
    tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", &ip.to_string()])
        .kill_on_drop(true)
        .output()
        .await
        .is_ok_and(|output| output.status.success())
}

async fn arp_cache_contains(ip: Ipv4Addr) -> bool {
    let Ok(content) = tokio::fs::read_to_string("/proc/net/arp").await else {
        return false;
    };
    let needle = ip.to_string();
    content
        .lines()
        .skip(1)
        .any(|line| line.split_whitespace().next() == Some(needle.as_str()))
}

async fn adaptive_network_backoff(empty_host_streak: u32) {
    if empty_host_streak < 8 {
        return;
    }
    let exponent = (empty_host_streak / 8).min(5);
    let delay_millis = 25_u64.saturating_mul(1_u64 << exponent).min(1_000);
    tracing::debug!(
        "Adaptive network backoff: {empty_host_streak} consecutive hosts without open ports, sleeping {delay_millis}ms"
    );
    tokio::time::sleep(Duration::from_millis(delay_millis)).await;
}

fn exposure_combination_findings(services: &[ServiceEvidence]) -> Vec<Vulnerability> {
    let mut findings = Vec::new();
    for service in services {
        let public = has_signal(service, "publicly_routable");
        let no_tls = service.tls.as_ref().is_none_or(|tls| !tls.detected)
            || has_signal(service, "tls_not_supported");
        let unauthenticated = service.auth_required == Some(false);
        let protocol = service.protocol.as_str();

        let combination = if public
            && matches!(protocol, "postgresql" | "mysql" | "mssql" | "mongodb")
            && no_tls
        {
            Some((
                "NETWORK-RISK-PUBLIC-DATABASE-WEAK-TRANSPORT",
                "Public database service without observed TLS",
                Severity::High,
                8.1,
                "Place the database on a private network segment, enforce TLS, and restrict inbound access.",
            ))
        } else if public && protocol == "redis" && unauthenticated {
            Some((
                "NETWORK-RISK-PUBLIC-REDIS-NO-AUTH",
                "Public Redis service accepts unauthenticated commands",
                Severity::Critical,
                9.8,
                "Remove Redis from public exposure, require authentication, and restrict it to an application segment.",
            ))
        } else if public
            && protocol == "rdp"
            && service
                .banner
                .as_deref()
                .is_some_and(|banner| banner.to_ascii_lowercase().contains("windows server 2008"))
        {
            Some((
                "NETWORK-RISK-PUBLIC-RDP-LEGACY",
                "Public RDP service exposes a legacy operating-system banner",
                Severity::High,
                8.1,
                "Restrict RDP behind a VPN or bastion host, require NLA, and upgrade the operating system.",
            ))
        } else if public
            && (has_signal(service, "administrative_interface")
                || has_signal(service, "remote_management_service")
                || has_signal(service, "message_broker_service"))
        {
            Some((
                "NETWORK-RISK-PUBLIC-MANAGEMENT-SURFACE",
                "Administrative or management service is publicly reachable",
                Severity::Medium,
                6.5,
                "Move management services to a dedicated administrative segment and require an authenticated access proxy.",
            ))
        } else {
            None
        };

        if let Some((id, name, severity, cvss, remediation)) = combination {
            let mut finding = Vulnerability::new(
                id,
                name,
                severity,
                cvss,
                format!(
                    "protocol={} signals={}",
                    service.protocol,
                    service.signals.join(",")
                ),
                &service.endpoint,
            );
            finding.verified = true;
            finding.remediation = Some(remediation.to_string());
            findings.push(finding);
        }
    }
    findings
}

fn has_signal(service: &ServiceEvidence, signal: &str) -> bool {
    service.signals.iter().any(|value| value == signal)
}

async fn detect_service_drift(
    path: &Path,
    current: &ScanResult,
) -> anyhow::Result<Vec<Vulnerability>> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to read baseline {path:?}: {error}"))?;
    let baseline: ScanResult = serde_json::from_str(&content)
        .map_err(|error| anyhow::anyhow!("Invalid baseline report {path:?}: {error}"))?;
    Ok(service_drift_findings(
        &baseline.services,
        &current.services,
    ))
}

fn service_drift_findings(
    baseline: &[ServiceEvidence],
    current: &[ServiceEvidence],
) -> Vec<Vulnerability> {
    let before = baseline
        .iter()
        .map(|service| (service_listener_identity(service), service))
        .collect::<HashMap<_, _>>();
    let after = current
        .iter()
        .map(|service| (service_listener_identity(service), service))
        .collect::<HashMap<_, _>>();
    let mut findings = Vec::new();
    for service in current
        .iter()
        .filter(|service| !before.contains_key(&service_listener_identity(service)))
    {
        let risky = service.signals.iter().any(|signal| {
            matches!(
                signal.as_str(),
                "publicly_routable"
                    | "remote_management_service"
                    | "administrative_interface"
                    | "database_or_cache_service"
                    | "message_broker_service"
            )
        });
        let mut finding = Vulnerability::new(
            "NETWORK-SERVICE-DRIFT-NEW",
            "New network service observed since baseline",
            if risky {
                Severity::Medium
            } else {
                Severity::Info
            },
            if risky { 5.3 } else { 0.0 },
            format!(
                "new_service={} protocol={} product={}",
                service.endpoint,
                service.protocol,
                service.product.as_deref().unwrap_or("unknown")
            ),
            &service.endpoint,
        );
        finding.verified = true;
        finding.remediation = Some(
            "Confirm that the new listener is authorized and apply the expected network segmentation policy."
                .to_string(),
        );
        findings.push(finding);
    }
    for (identity, service) in before
        .iter()
        .filter(|(identity, _)| !after.contains_key(*identity))
    {
        let mut finding = Vulnerability::new(
            "NETWORK-SERVICE-DRIFT-REMOVED",
            "Previously observed network service is no longer reachable",
            Severity::Info,
            0.0,
            format!("removed_service={identity}"),
            &service.endpoint,
        );
        finding.verified = true;
        finding.remediation =
            Some("Confirm that the service removal or outage was intentional.".to_string());
        findings.push(finding);
    }
    for (identity, service) in &after {
        let Some(previous) = before.get(identity) else {
            continue;
        };
        if !observed_service_profile_changed(previous, service) {
            continue;
        }
        let mut finding = Vulnerability::new(
            "NETWORK-SERVICE-DRIFT-CHANGED",
            "Observed network service product or version changed",
            Severity::Low,
            3.7,
            format!(
                "previous_product={} previous_version={} current_product={} current_version={}",
                previous.product.as_deref().unwrap_or("unknown"),
                previous.version.as_deref().unwrap_or("unknown"),
                service.product.as_deref().unwrap_or("unknown"),
                service.version.as_deref().unwrap_or("unknown")
            ),
            &service.endpoint,
        );
        finding.verified = true;
        finding.remediation = Some(
            "Confirm that the observed service upgrade or replacement was authorized.".to_string(),
        );
        findings.push(finding);
    }
    findings
}

fn service_listener_identity(service: &ServiceEvidence) -> String {
    format!("{}|{}", service.endpoint, service.protocol)
}

fn observed_service_profile_changed(previous: &ServiceEvidence, current: &ServiceEvidence) -> bool {
    let product_changed = matches!(
        (&previous.product, &current.product),
        (Some(previous), Some(current)) if previous != current
    );
    let version_changed = matches!(
        (&previous.version, &current.version),
        (Some(previous), Some(current)) if previous != current
    );
    product_changed || version_changed
}

fn parse_ipv4_network_range(cidr: &str) -> anyhow::Result<Ipv4NetworkRange> {
    let (ip, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR must be in A.B.C.D/N format"))?;
    let base: Ipv4Addr = ip.parse()?;
    let prefix: u32 = prefix.parse()?;
    if prefix > 32 {
        return Err(anyhow::anyhow!("CIDR prefix must be <= 32"));
    }
    let host_count = 1_u64 << (32 - prefix);
    if host_count > MAX_CIDR_HOSTS {
        return Err(anyhow::anyhow!(
            "Refusing to scan {host_count} hosts; CIDR range limit is {MAX_CIDR_HOSTS} IPs"
        ));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(Ipv4NetworkRange {
        network: u32::from(base) & mask,
        host_count,
    })
}

#[cfg(test)]
fn expand_ipv4_cidr(cidr: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
    let range = parse_ipv4_network_range(cidr)?;
    Ok((0..range.host_count)
        .map(|offset| Ipv4Addr::from(range.network + offset as u32))
        .collect())
}

fn tech_from_service(service: &PortResult) -> Option<TechStack> {
    let name = service.product.clone()?;
    let category = match service.service.as_deref() {
        Some("mysql" | "postgresql" | "mssql" | "redis" | "mongodb") => TechCategory::Database,
        Some("ssh" | "rdp" | "smb") => TechCategory::OS,
        _ => TechCategory::Other,
    };
    Some(TechStack::new(
        name,
        service.version.clone(),
        service.confidence,
        category,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reporter::types::ScanStats;
    use temu_core::Vulnerability;

    #[test]
    fn test_expand_ipv4_cidr() {
        let ips = expand_ipv4_cidr("192.0.2.0/30").unwrap();
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(192, 0, 2, 0),
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(192, 0, 2, 2),
                Ipv4Addr::new(192, 0, 2, 3),
            ]
        );
        assert!(expand_ipv4_cidr("192.0.2.0/33").is_err());
        assert_eq!(expand_ipv4_cidr("192.0.2.0/16").unwrap().len(), 65_536);
        assert_eq!(
            parse_ipv4_network_range("192.0.2.0/12").unwrap().host_count,
            1_048_576
        );
        assert!(parse_ipv4_network_range("192.0.2.0/11").is_err());
    }

    #[test]
    fn test_tech_from_ssh_service_evidence() {
        let tech = tech_from_service(&PortResult {
            port: 22,
            state: discovery::PortState::Open,
            service: Some("ssh".to_string()),
            product: Some("OpenSSH".to_string()),
            version: Some("9.0".to_string()),
            confidence: 0.99,
            banner: Some("SSH-2.0-OpenSSH_9.0".to_string()),
            handshake: None,
            auth_required: None,
            tls: None,
            signals: Vec::new(),
        })
        .unwrap();
        assert_eq!(tech.name, "OpenSSH");
        assert_eq!(tech.version.as_deref(), Some("9.0"));
        assert!(matches!(tech.category, TechCategory::OS));
    }

    #[test]
    fn test_load_target_list_skips_comments_and_blanks() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("targets.txt");
        std::fs::write(
            &path,
            "\n# staging targets\nhttps://example.com\n  http://127.0.0.1:8080  \n",
        )
        .unwrap();

        let targets = load_target_list(&path).unwrap();

        assert_eq!(
            targets,
            vec![
                "https://example.com".to_string(),
                "http://127.0.0.1:8080".to_string()
            ]
        );
    }

    #[test]
    fn test_service_drift_marks_new_sensitive_listener() {
        let baseline = Vec::new();
        let current = vec![ServiceEvidence {
            endpoint: "tcp://10.0.0.5:5432".to_string(),
            port: 5432,
            protocol: "postgresql".to_string(),
            product: Some("PostgreSQL".to_string()),
            version: Some("17".to_string()),
            confidence: 0.95,
            banner: None,
            handshake: None,
            auth_required: Some(true),
            tls: None,
            signals: vec![
                "private_or_local".to_string(),
                "database_or_cache_service".to_string(),
            ],
        }];

        let findings = service_drift_findings(&baseline, &current);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "NETWORK-SERVICE-DRIFT-NEW");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].verified);
    }

    #[test]
    fn test_service_drift_ignores_profile_missing_from_passive_scan() {
        let baseline = vec![ServiceEvidence {
            endpoint: "tcp://10.0.0.5:6379".to_string(),
            port: 6379,
            protocol: "redis".to_string(),
            product: Some("Redis".to_string()),
            version: Some("8.0".to_string()),
            confidence: 0.95,
            banner: None,
            handshake: None,
            auth_required: Some(false),
            tls: None,
            signals: vec!["database_or_cache_service".to_string()],
        }];
        let mut passive = baseline[0].clone();
        passive.product = None;
        passive.version = None;
        passive.confidence = 0.35;
        passive.signals.push("passive_banner_only".to_string());

        let findings = service_drift_findings(&baseline, &[passive]);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_service_drift_marks_observed_version_change() {
        let baseline = vec![ServiceEvidence {
            endpoint: "tcp://10.0.0.5:6379".to_string(),
            port: 6379,
            protocol: "redis".to_string(),
            product: Some("Redis".to_string()),
            version: Some("7.0".to_string()),
            confidence: 0.95,
            banner: None,
            handshake: None,
            auth_required: Some(false),
            tls: None,
            signals: vec!["database_or_cache_service".to_string()],
        }];
        let mut current = baseline[0].clone();
        current.version = Some("8.0".to_string());

        let findings = service_drift_findings(&baseline, &[current]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "NETWORK-SERVICE-DRIFT-CHANGED");
        assert_eq!(findings[0].url, "tcp://10.0.0.5:6379");
    }

    #[test]
    fn test_public_database_weak_transport_combination_is_prioritized() {
        let services = vec![ServiceEvidence {
            endpoint: "tcp://8.8.8.8:5432".to_string(),
            port: 5432,
            protocol: "postgresql".to_string(),
            product: Some("PostgreSQL".to_string()),
            version: None,
            confidence: 0.95,
            banner: None,
            handshake: None,
            auth_required: Some(true),
            tls: None,
            signals: vec![
                "publicly_routable".to_string(),
                "tls_not_supported".to_string(),
                "database_or_cache_service".to_string(),
            ],
        }];

        let findings = exposure_combination_findings(&services);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].id,
            "NETWORK-RISK-PUBLIC-DATABASE-WEAK-TRANSPORT"
        );
        assert!(findings[0].verified);
    }

    #[test]
    fn test_aggregate_scan_results_sorts_target_summaries_by_vuln_count() {
        let started_at = Utc::now();
        let mut low = Vulnerability::new(
            "LOW-TEST",
            "Low finding",
            Severity::Low,
            2.0,
            "proof",
            "https://a.example",
        );
        low.verified = true;
        let mut high = Vulnerability::new(
            "HIGH-TEST",
            "High finding",
            Severity::High,
            8.0,
            "proof",
            "https://b.example",
        );
        high.verified = true;

        let first = test_scan_result("https://a.example", vec![low], started_at);
        let second = test_scan_result(
            "https://b.example",
            vec![
                high.clone(),
                Vulnerability::new(
                    "INFO-TEST",
                    "Info finding",
                    Severity::Info,
                    0.0,
                    "proof",
                    "https://b.example",
                ),
            ],
            started_at,
        );

        let aggregate = aggregate_scan_results("file:targets.txt", &[first, second]);

        assert_eq!(aggregate.stats.vulns_found, 3);
        assert_eq!(aggregate.target_summaries.len(), 2);
        assert_eq!(aggregate.target_summaries[0].target, "https://b.example");
        assert_eq!(
            aggregate.target_summaries[0].highest_severity,
            Some(Severity::High)
        );
    }

    #[test]
    fn test_callback_events_create_verified_finding() {
        let event = CallbackEvent {
            correlation_id: "cid-123".to_string(),
            protocol: "http".to_string(),
            method: "GET".to_string(),
            path: "/cid-123".to_string(),
            remote_addr: "127.0.0.1:45678".to_string(),
            user_agent: Some("fixture".to_string()),
            received_at: Utc::now(),
        };

        let findings = callback_events_to_findings(&[event]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "OAST-CALLBACK-EVIDENCE");
        assert!(findings[0].verified);
        assert_eq!(findings[0].parameter.as_deref(), Some("cid-123"));
    }

    fn test_scan_result(
        target: &str,
        vulnerabilities: Vec<Vulnerability>,
        started_at: chrono::DateTime<Utc>,
    ) -> ScanResult {
        ScanResult {
            target: target.to_string(),
            assets: vec![Asset::new(target, AssetType::Url, "test")],
            tech_stacks: HashMap::new(),
            stats: ScanStats {
                subdomains_found: 0,
                paths_found: 0,
                parameters_found: 0,
                vulns_found: vulnerabilities.len() as u32,
                duration_secs: 1.0,
            },
            vulnerabilities,
            services: Vec::new(),
            target_summaries: Vec::new(),
            callback_events: Vec::new(),
            scan_started_at: started_at,
            scan_finished_at: started_at,
        }
    }
}
