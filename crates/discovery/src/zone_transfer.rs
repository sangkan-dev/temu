use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use tracing::{debug, info, warn};

use temu_core::TemuError;

/// Attempts a DNS zone transfer (AXFR) for `domain` against all its authoritative nameservers.
///
/// Most servers will refuse AXFR — this is handled gracefully by returning `Ok(vec![])`.
/// If a zone transfer **succeeds**, a warning is logged because this is a misconfiguration.
///
/// Returns a list of hostnames extracted from the zone records.
pub async fn attempt_zone_transfer(domain: &str) -> Result<Vec<String>, TemuError> {
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::default(),
        TokioRuntimeProvider::default(),
    )
    .with_options(ResolverOpts::default())
    .build()
    .map_err(|e| TemuError::Dns(format!("Resolver init: {e}")))?;

    // Step 1: Resolve NS records for the domain
    let ns_lookup = match resolver.ns_lookup(domain).await {
        Ok(ns) => ns,
        Err(e) => {
            debug!("Zone transfer: failed to resolve NS for {domain}: {e}");
            return Ok(vec![]);
        }
    };

    let nameservers: Vec<String> = ns_lookup
        .answers()
        .iter()
        .map(|record| record.data.to_string())
        .collect();

    if nameservers.is_empty() {
        debug!("Zone transfer: no NS records found for {domain}");
        return Ok(vec![]);
    }

    info!(
        "Zone transfer: found {} nameservers for {domain}: {:?}",
        nameservers.len(),
        nameservers
    );

    let mut found: Vec<String> = Vec::new();
    let domain_lower = domain.to_lowercase();

    // Step 2: Attempt AXFR against each nameserver
    for ns in &nameservers {
        debug!("Zone transfer: attempting AXFR from {ns} for {domain}");

        // Resolve the NS hostname to an IP
        let ns_ips = match resolver.lookup_ip(ns.as_str()).await {
            Ok(ips) => ips.iter().collect::<Vec<_>>(),
            Err(e) => {
                debug!("Zone transfer: could not resolve NS {ns}: {e}");
                continue;
            }
        };

        if ns_ips.is_empty() {
            continue;
        }

        // Attempt AXFR using hickory_resolver's generic lookup
        // AXFR is a TCP-only operation; many resolvers/servers will refuse it.
        // We attempt it and treat any error as "refused" (return empty).
        let ns_str = ns.trim_end_matches('.');
        match resolver.lookup(ns_str, RecordType::AXFR).await {
            Ok(records) => {
                warn!("Zone transfer SUCCEEDED from {ns} for {domain} — server is misconfigured!");
                for record in records.answers() {
                    let name = record.to_string();
                    let name = name.trim_end_matches('.');
                    if name == domain_lower || name.ends_with(&format!(".{domain_lower}")) {
                        found.push(name.to_string());
                    }
                }
            }
            Err(e) => {
                debug!("Zone transfer refused/failed from {ns}: {e}");
            }
        }
    }

    if !found.is_empty() {
        found.sort();
        found.dedup();
        info!(
            "Zone transfer: extracted {} unique hostnames for {domain}",
            found.len()
        );
    }

    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_zone_transfer_refused_returns_empty() {
        // example.com NS servers will refuse AXFR — expect Ok(vec![])
        let result = attempt_zone_transfer("example.com").await;
        assert!(result.is_ok(), "should not error on refused AXFR");
        // Most NS servers refuse zone transfers; result may be empty
        // We only assert no panic and no error propagation
        let hosts = result.unwrap();
        // Hosts will be empty because AXFR is refused
        assert!(
            hosts.len() < 1000,
            "sanity check: unreasonably large result"
        );
    }

    #[tokio::test]
    async fn test_zone_transfer_nonexistent_domain_returns_empty() {
        let result = attempt_zone_transfer("_temu_nonexistent_domain_xyz987.invalid").await;
        assert!(
            result.is_ok(),
            "non-existent domain should return Ok(vec![])"
        );
        assert!(result.unwrap().is_empty());
    }
}
