use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use chrono::Utc;
use discovery::{DiscoveryMode, PortResult, default_top_ports, run_discovery, scan_ports};
use fingerprint::{TechCategory, TechStack, run_fingerprint};
use fuzzing::run_fuzzing;
use hickory_resolver::TokioResolver;
use reporter::types::{ScanResult, ScanStats, TargetSummary};
use temu_core::{AppConfig, Asset, AssetType, Severity, Target};
use tracing::info;
use verifier::run_verification;
use vulnerability::run_vulnerability_scan;

const MAX_CIDR_HOSTS: u64 = 65_536;

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
/// 4. Fuzzing: path discovery on base URL
/// 5. Vulnerability: rule-based scanning on all discovered URLs
/// 6. Build and return `ScanResult`
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
    let (service_assets, service_techs) = run_port_scan_for_domain(&domain, ports, config).await;
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

    // ── 3. Fuzzing ───────────────────────────────────────────────────────────
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

    let detected_vulnerabilities =
        match run_vulnerability_scan(&all_assets, &all_techs, config).await {
            Ok(vulnerabilities) => vulnerabilities,
            Err(e) => {
                error_summary.push("vulnerability", &e);
                tracing::warn!("Vulnerability scan error (continuing): {e}");
                Vec::new()
            }
        };
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
    all_discovered.extend(fuzzing_assets);
    all_discovered.extend(service_assets);

    Ok(ScanResult {
        target: url.to_string(),
        assets: all_discovered,
        tech_stacks,
        vulnerabilities,
        target_summaries: vec![],
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
    Ok(run_network_scan_multi(cidr, config, ports).await?.aggregate)
}

/// Runs TCP port scanning for an IPv4 CIDR and full scans for discovered web services.
pub async fn run_network_scan_multi(
    cidr: &str,
    config: &AppConfig,
    ports: &[u16],
) -> anyhow::Result<MultiTargetScanResult> {
    let started_at = Utc::now();
    let ips = expand_ipv4_cidr(cidr)?;
    if ips.iter().any(|ip| ip.is_private()) {
        eprintln!("[!] Scanning private network range: {cidr}");
    }
    eprintln!(
        "[*] Starting network scan for {cidr} ({} hosts, {} ports)",
        ips.len(),
        ports.len()
    );

    let mut per_target_results = Vec::new();

    for (index, ip) in ips.iter().enumerate() {
        eprintln!("Scanning target {}/{}: {ip}", index + 1, ips.len());
        let port_results = scan_ports(IpAddr::V4(*ip), ports, config).await;
        let (service_assets, service_techs, web_urls) =
            report_items_from_port_results(IpAddr::V4(*ip), &port_results);

        if web_urls.is_empty() {
            if !service_assets.is_empty() {
                per_target_results.push(service_only_scan_result(
                    &ip.to_string(),
                    service_assets,
                    service_techs,
                    started_at,
                ));
            }
            continue;
        }

        for web_url in web_urls {
            match run_scan_with_ports(&web_url, config, DiscoveryMode::PassiveOnly, &[]).await {
                Ok(mut result) => {
                    result.assets.extend(service_assets.clone());
                    for (service_url, tech) in &service_techs {
                        result
                            .tech_stacks
                            .entry(service_url.clone())
                            .or_default()
                            .push(tech.clone());
                    }
                    per_target_results.push(result);
                }
                Err(e) => {
                    tracing::warn!("Web service scan failed for {web_url}: {e}");
                    eprintln!("[!] Web service scan failed for {web_url}: {e}");
                    per_target_results.push(service_only_scan_result(
                        &web_url,
                        service_assets.clone(),
                        service_techs.clone(),
                        started_at,
                    ));
                }
            }
        }
    }

    let finished_at = Utc::now();
    let duration_secs = (finished_at - started_at).num_milliseconds() as f64 / 1000.0;
    eprintln!("[*] Network scan completed in {duration_secs:.1}s");

    let mut aggregate = aggregate_scan_results(&format!("network:{cidr}"), &per_target_results);
    aggregate.scan_started_at = started_at;
    aggregate.scan_finished_at = finished_at;
    aggregate.stats.duration_secs = duration_secs;

    Ok(MultiTargetScanResult {
        aggregate,
        targets: per_target_results,
    })
}

async fn run_port_scan_for_domain(
    domain: &str,
    ports: &[u16],
    config: &AppConfig,
) -> (Vec<Asset>, Vec<(String, TechStack)>) {
    let Ok(builder) = TokioResolver::builder_tokio() else {
        tracing::warn!("Port scan skipped: could not initialize DNS resolver for {domain}");
        return (Vec::new(), Vec::new());
    };
    let Ok(resolver) = builder.build() else {
        tracing::warn!("Port scan skipped: could not build DNS resolver for {domain}");
        return (Vec::new(), Vec::new());
    };
    let Ok(response) = resolver.lookup_ip(domain).await else {
        tracing::warn!("Port scan skipped: could not resolve {domain}");
        return (Vec::new(), Vec::new());
    };
    let Some(ip) = response.iter().next() else {
        return (Vec::new(), Vec::new());
    };

    run_port_scan_for_ip(ip, ports, config).await
}

async fn run_port_scan_for_ip(
    ip: IpAddr,
    ports: &[u16],
    config: &AppConfig,
) -> (Vec<Asset>, Vec<(String, TechStack)>) {
    let results = scan_ports(ip, ports, config).await;
    let (assets, techs, _) = report_items_from_port_results(ip, &results);
    (assets, techs)
}

fn report_items_from_port_results(
    ip: IpAddr,
    results: &[PortResult],
) -> (Vec<Asset>, Vec<(String, TechStack)>, Vec<String>) {
    let mut assets = Vec::new();
    let mut techs = Vec::new();
    let mut web_urls = Vec::new();
    for result in results {
        let service = result.service.as_deref().unwrap_or("unknown");
        let banner = result.banner.as_deref().unwrap_or("");
        let service_url = format!("tcp://{ip}:{}", result.port);
        if let Some(tech) = tech_from_banner(service, banner) {
            techs.push((service_url.clone(), tech));
        }
        if let Some(web_url) = web_url_for_service(ip, result.port, service) {
            web_urls.push(web_url);
        }
        assets.push(Asset::new(
            format!("{service_url} ({service}) {banner}"),
            AssetType::Service,
            "discovery::port_scan",
        ));
    }

    (assets, techs, web_urls)
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
        target_summaries,
        scan_started_at,
        scan_finished_at,
        stats,
    }
}

fn service_only_scan_result(
    target: &str,
    assets: Vec<Asset>,
    service_techs: Vec<(String, TechStack)>,
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
        vulnerabilities: Vec::new(),
        target_summaries: Vec::new(),
        scan_started_at: started_at,
        scan_finished_at: finished_at,
        stats: ScanStats {
            subdomains_found: 0,
            paths_found: 0,
            parameters_found: 0,
            vulns_found: 0,
            duration_secs: (finished_at - started_at).num_milliseconds() as f64 / 1000.0,
        },
    }
}

fn highest_severity(vulnerabilities: &[temu_core::Vulnerability]) -> Option<Severity> {
    vulnerabilities
        .iter()
        .map(|vulnerability| vulnerability.severity.clone())
        .max()
}

fn expand_ipv4_cidr(cidr: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
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

    let base_u32 = u32::from(base);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = base_u32 & mask;

    Ok((0..host_count)
        .map(|offset| Ipv4Addr::from(network + offset as u32))
        .collect())
}

fn tech_from_banner(service: &str, banner: &str) -> Option<TechStack> {
    if service == "ssh" && banner.to_ascii_lowercase().contains("openssh") {
        let version = banner
            .split("OpenSSH_")
            .nth(1)
            .and_then(|rest| rest.split([' ', '\r', '\n']).next())
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        Some(TechStack::new("OpenSSH", version, 0.80, TechCategory::OS))
    } else {
        None
    }
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
        assert!(expand_ipv4_cidr("192.0.2.0/15").is_err());
    }

    #[test]
    fn test_tech_from_ssh_banner() {
        let tech = tech_from_banner("ssh", "SSH-2.0-OpenSSH_9.0").unwrap();
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
            target_summaries: Vec::new(),
            scan_started_at: started_at,
            scan_finished_at: started_at,
        }
    }
}
