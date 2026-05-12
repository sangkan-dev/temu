// Discovery crate — subdomain enumeration, DNS resolution, HTTP probing

pub mod dns;
pub mod heuristic;
pub mod passive;
pub mod probe;
pub mod wordlist;

pub use dns::DnsResolver;
pub use heuristic::generate_candidates;
pub use passive::{fetch_crtsh, fetch_crtsh_with_base};
pub use probe::{ProbeResult, probe_all, probe_http};
pub use wordlist::load_wordlist;

use std::collections::HashSet;

use temu_core::{AppConfig, Asset, AssetType, Target, TemuError};
use tracing::{info, warn};

/// Controls which discovery strategy is used in `run_discovery`.
#[derive(Debug, Clone, Default)]
pub enum DiscoveryMode {
    /// Only passive CT log enumeration (crt.sh). Zero DNS queries sent to the target.
    PassiveOnly,
    /// Wordlist-based DNS bruteforce only (original Sprint 2 behaviour).
    ActiveBruteforce,
    /// Heuristic candidate generation only (no wordlist required).
    SmartHeuristic,
    /// All three methods combined with deduplication before DNS resolution.
    #[default]
    Hybrid,
}

/// Discovers subdomains and live HTTP endpoints for `target`.
///
/// The `mode` parameter selects which enumeration strategies to run:
/// - `PassiveOnly` — crt.sh CT logs only
/// - `ActiveBruteforce` — wordlist DNS bruteforce only
/// - `SmartHeuristic` — heuristic tag generation only
/// - `Hybrid` — all three + deduplication (default)
pub async fn run_discovery(
    target: &Target,
    config: &AppConfig,
    mode: DiscoveryMode,
) -> Result<Vec<Asset>, TemuError> {
    info!(
        "Starting discovery for {} (mode: {:?})",
        target.domain, mode
    );

    let mut hostname_set: HashSet<String> = HashSet::new();

    match mode {
        DiscoveryMode::PassiveOnly => {
            collect_passive(&target.domain, &mut hostname_set).await;
        }
        DiscoveryMode::ActiveBruteforce => {
            collect_bruteforce(target, config, &mut hostname_set).await?;
        }
        DiscoveryMode::SmartHeuristic => {
            collect_heuristic(&target.domain, &mut hostname_set);
        }
        DiscoveryMode::Hybrid => {
            collect_passive(&target.domain, &mut hostname_set).await;
            collect_bruteforce(target, config, &mut hostname_set).await?;
            collect_heuristic(&target.domain, &mut hostname_set);
        }
    }

    info!(
        "Unique candidate hostnames collected: {}",
        hostname_set.len()
    );

    // DNS-resolve and build Subdomain assets
    let resolver = DnsResolver::new().await?;
    let hostname_list: Vec<String> = hostname_set.into_iter().collect();
    let subdomain_assets = resolver
        .bruteforce(&target.domain, &hostname_list, config.concurrency)
        .await;

    info!(
        "DNS resolution complete: {} subdomains alive",
        subdomain_assets.len()
    );

    // HTTP-probe each live subdomain
    let hosts: Vec<String> = subdomain_assets.iter().map(|a| a.url.clone()).collect();
    let probe_results = probe_all(&hosts, config).await;

    let live_count = probe_results.len();
    info!(
        "Found {} subdomains, {} are live (HTTP)",
        subdomain_assets.len(),
        live_count
    );

    let mut all_assets = subdomain_assets;
    for probe in probe_results {
        all_assets.push(Asset::new(probe.url, AssetType::Url, "discovery::probe"));
    }

    Ok(all_assets)
}

async fn collect_passive(domain: &str, set: &mut HashSet<String>) {
    match fetch_crtsh(domain).await {
        Ok(hosts) => {
            info!("Passive (crt.sh): {} hostnames", hosts.len());
            set.extend(hosts);
        }
        Err(e) => {
            warn!("Passive discovery failed (crt.sh): {e}");
        }
    }
}

async fn collect_bruteforce(
    target: &Target,
    config: &AppConfig,
    set: &mut HashSet<String>,
) -> Result<(), TemuError> {
    let wordlist_path = config.dictionaries_dir.join("subdomains-small.txt");
    let wordlist = load_wordlist(&wordlist_path)?;
    info!("Active bruteforce: {} wordlist entries", wordlist.len());
    let labels: Vec<String> = wordlist
        .iter()
        .map(|w| format!("{w}.{}", target.domain))
        .collect();
    set.extend(labels);
    Ok(())
}

fn collect_heuristic(domain: &str, set: &mut HashSet<String>) {
    let candidates = generate_candidates(domain);
    info!("Heuristic generation: {} candidates", candidates.len());
    set.extend(candidates);
}
