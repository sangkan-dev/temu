use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;
use discovery::{DiscoveryMode, default_top_ports, run_discovery, scan_ports};
use fingerprint::{TechCategory, TechStack, run_fingerprint};
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
            Err(e) => tracing::warn!("Fingerprint error for {target_url}: {e}"),
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
    all_discovered.extend(service_assets);

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

/// Runs TCP port scanning for an IPv4 CIDR and returns a reportable scan result.
pub async fn run_network_scan(
    cidr: &str,
    config: &AppConfig,
    ports: &[u16],
) -> anyhow::Result<ScanResult> {
    let started_at = Utc::now();
    let ips = expand_ipv4_cidr(cidr)?;
    eprintln!(
        "[*] Starting network scan for {cidr} ({} hosts, {} ports)",
        ips.len(),
        ports.len()
    );

    let mut assets = Vec::new();
    let mut tech_stacks: HashMap<String, Vec<TechStack>> = HashMap::new();

    for ip in ips {
        let (service_assets, service_techs) =
            run_port_scan_for_ip(IpAddr::V4(ip), ports, config).await;
        assets.extend(service_assets);
        for (service_url, tech) in service_techs {
            tech_stacks.entry(service_url).or_default().push(tech);
        }
    }

    let finished_at = Utc::now();
    let duration_secs = (finished_at - started_at).num_milliseconds() as f64 / 1000.0;
    eprintln!("[*] Network scan completed in {duration_secs:.1}s");

    Ok(ScanResult {
        target: cidr.to_string(),
        assets,
        tech_stacks,
        vulnerabilities: Vec::new(),
        scan_started_at: started_at,
        scan_finished_at: finished_at,
        stats: ScanStats {
            subdomains_found: 0,
            paths_found: 0,
            parameters_found: 0,
            vulns_found: 0,
            duration_secs,
        },
    })
}

async fn run_port_scan_for_domain(
    domain: &str,
    ports: &[u16],
    config: &AppConfig,
) -> (Vec<Asset>, Vec<(String, TechStack)>) {
    let Ok(mut addrs) = tokio::net::lookup_host((domain, 0)).await else {
        tracing::warn!("Port scan skipped: could not resolve {domain}");
        return (Vec::new(), Vec::new());
    };
    let Some(addr) = addrs.next() else {
        return (Vec::new(), Vec::new());
    };

    run_port_scan_for_ip(addr.ip(), ports, config).await
}

async fn run_port_scan_for_ip(
    ip: IpAddr,
    ports: &[u16],
    config: &AppConfig,
) -> (Vec<Asset>, Vec<(String, TechStack)>) {
    let results = scan_ports(ip, ports, config).await;
    let mut assets = Vec::new();
    let mut techs = Vec::new();

    for result in results {
        let service = result.service.as_deref().unwrap_or("unknown");
        let banner = result.banner.as_deref().unwrap_or("");
        let service_url = format!("tcp://{ip}:{}", result.port);
        if let Some(tech) = tech_from_banner(service, banner) {
            techs.push((service_url.clone(), tech));
        }
        assets.push(Asset::new(
            format!("{service_url} ({service}) {banner}"),
            AssetType::Service,
            "discovery::port_scan",
        ));
    }

    (assets, techs)
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
    if host_count > 4096 {
        return Err(anyhow::anyhow!(
            "Refusing to scan {host_count} hosts; use /20 or smaller ranges for now"
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
    }

    #[test]
    fn test_tech_from_ssh_banner() {
        let tech = tech_from_banner("ssh", "SSH-2.0-OpenSSH_9.0").unwrap();
        assert_eq!(tech.name, "OpenSSH");
        assert_eq!(tech.version.as_deref(), Some("9.0"));
        assert!(matches!(tech.category, TechCategory::OS));
    }
}
