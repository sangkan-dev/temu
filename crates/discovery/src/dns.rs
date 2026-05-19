use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use temu_core::{Asset, AssetType, TemuError};

/// Async DNS resolver wrapper with wildcard detection support.
pub struct DnsResolver {
    inner: TokioResolver,
}

impl DnsResolver {
    /// Creates a new `DnsResolver` using the system's default resolver configuration.
    pub async fn new() -> Result<Self, TemuError> {
        let resolver =
            build_tokio_resolver().map_err(|e| TemuError::Dns(format!("Resolver init: {e}")))?;
        Ok(Self { inner: resolver })
    }

    /// Resolves a fully-qualified domain name to a list of IPv4/IPv6 addresses.
    ///
    /// Returns `TemuError::Dns` on NXDOMAIN or any resolution failure.
    pub async fn resolve(&self, fqdn: &str) -> Result<Vec<IpAddr>, TemuError> {
        match self.inner.lookup_ip(fqdn).await {
            Ok(response) => {
                let ips: Vec<IpAddr> = response.iter().collect();
                if ips.is_empty() {
                    Err(TemuError::Dns(format!("No addresses for {fqdn}")))
                } else {
                    Ok(ips)
                }
            }
            Err(e) => Err(TemuError::Dns(format!("Failed to resolve {fqdn}: {e}"))),
        }
    }

    /// Returns the set of wildcard IPs for `domain`, or an empty set if the
    /// domain does not have a wildcard DNS record.
    ///
    /// Detection strategy: resolve a random label that almost certainly does
    /// not exist (`_temu_wildcard_check_.<domain>`). If it resolves, the
    /// domain is a wildcard and we collect those IPs as the filter set.
    pub async fn wildcard_ips(&self, domain: &str) -> HashSet<IpAddr> {
        let probe = format!("_temu_wildcard_check_.{domain}");
        match self.inner.lookup_ip(probe.as_str()).await {
            Ok(response) => {
                let ips: HashSet<IpAddr> = response.iter().collect();
                if !ips.is_empty() {
                    info!("Wildcard DNS detected for {domain} — {ips:?}");
                }
                ips
            }
            Err(_) => HashSet::new(),
        }
    }

    /// Bruteforces subdomains of `domain` using the provided `wordlist`.
    ///
    /// Concurrency is limited by `concurrency` (number of parallel DNS queries).
    /// Results whose IPs are fully covered by the wildcard IP set are discarded.
    pub async fn bruteforce(
        &self,
        domain: &str,
        wordlist: &[String],
        concurrency: usize,
    ) -> Vec<Asset> {
        let wildcard_ips = self.wildcard_ips(domain).await;
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let resolver = Arc::new(self.inner.clone());

        let mut handles = Vec::with_capacity(wordlist.len());

        for (idx, word) in wordlist.iter().enumerate() {
            let fqdn = format!("{word}.{domain}");
            let sem = Arc::clone(&semaphore);
            let res = Arc::clone(&resolver);
            let wildcard = wildcard_ips.clone();

            let handle = tokio::spawn(async move {
                let Ok(_permit) = sem.acquire().await else {
                    warn!("DNS bruteforce worker skipped because semaphore is closed");
                    return None;
                };

                if idx > 0 && idx % 100 == 0 {
                    debug!("DNS bruteforce progress: {idx} subdomains checked");
                }

                match res.lookup_ip(fqdn.as_str()).await {
                    Ok(response) => {
                        let ips: HashSet<IpAddr> = response.iter().collect();
                        if ips.is_empty() {
                            return None;
                        }
                        // Filter out wildcard matches
                        if !wildcard.is_empty() && ips.is_subset(&wildcard) {
                            warn!("Skipping {fqdn} — matches wildcard IPs");
                            return None;
                        }
                        Some(Asset::new(fqdn, AssetType::Subdomain, "discovery::dns"))
                    }
                    Err(_) => None,
                }
            });

            handles.push(handle);
        }

        let mut assets = Vec::new();
        for handle in handles {
            if let Ok(Some(asset)) = handle.await {
                assets.push(asset);
            }
        }

        info!(
            "DNS bruteforce complete: {}/{} subdomains resolved",
            assets.len(),
            wordlist.len()
        );

        assets
    }
}

fn build_tokio_resolver() -> Result<TokioResolver, String> {
    TokioResolver::builder_with_config(ResolverConfig::default(), TokioRuntimeProvider::default())
        .with_options(ResolverOpts::default())
        .build()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_subdomain_type() {
        let asset = Asset::new("www.example.com", AssetType::Subdomain, "discovery::dns");
        assert_eq!(asset.url, "www.example.com");
        assert_eq!(asset.asset_type, AssetType::Subdomain);
        assert_eq!(asset.discovered_by, "discovery::dns");
    }

    #[test]
    fn test_wildcard_filter_logic() {
        use std::collections::HashSet;
        use std::net::IpAddr;

        let wildcard: HashSet<IpAddr> = vec!["1.2.3.4".parse().unwrap()].into_iter().collect();

        // Subset of wildcard → should be filtered
        let resolved: HashSet<IpAddr> = vec!["1.2.3.4".parse().unwrap()].into_iter().collect();
        assert!(resolved.is_subset(&wildcard));

        // Not subset → should be kept
        let resolved2: HashSet<IpAddr> = vec!["5.6.7.8".parse().unwrap()].into_iter().collect();
        assert!(!resolved2.is_subset(&wildcard));
    }

    #[test]
    fn test_fqdn_construction() {
        let domain = "example.com";
        let word = "api";
        let fqdn = format!("{word}.{domain}");
        assert_eq!(fqdn, "api.example.com");
    }
}
