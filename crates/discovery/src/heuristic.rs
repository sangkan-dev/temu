use std::collections::HashSet;

const SERVICE_TAGS: &[&str] = &[
    "api", "www", "app", "admin", "mail", "cdn", "static", "dev", "staging", "prod", "test",
    "beta", "alpha", "portal", "dashboard", "git", "gitlab", "jenkins", "monitor", "status",
    "docs", "shop", "store", "mobile", "m", "media", "img", "assets",
];

const ENV_TAGS: &[&str] = &["prod", "dev", "staging", "uat", "test", "qa", "preprod", "sandbox"];

const REGION_TAGS: &[&str] = &["us", "eu", "ap", "sg", "id", "us-east", "us-west", "eu-west"];

const NUMERIC_SUFFIXES: &[&str] = &["1", "2", "3", "01", "02", "03"];

/// Generates heuristic subdomain candidates for `domain` without a wordlist.
///
/// Uses cross-combination of service, environment, region, and numeric tags —
/// inspired by tools like rusub. Returns a deduplicated list of FQDNs.
pub fn generate_candidates(domain: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut candidates: Vec<String> = Vec::new();

    let mut add = |label: &str| {
        let fqdn = format!("{label}.{domain}");
        if seen.insert(fqdn.clone()) {
            candidates.push(fqdn);
        }
    };

    // 1. Single service tags: api.domain, www.domain, …
    for svc in SERVICE_TAGS {
        add(svc);
    }

    // 2. Single env tags: prod.domain, dev.domain, …
    for env in ENV_TAGS {
        add(env);
    }

    // 3. Single region tags: us.domain, eu.domain, …
    for region in REGION_TAGS {
        add(region);
    }

    // 4. Service + env cross: api-prod.domain, app-dev.domain, …
    for svc in SERVICE_TAGS {
        for env in ENV_TAGS {
            add(&format!("{svc}-{env}"));
            add(&format!("{env}-{svc}"));
        }
    }

    // 5. Service + numeric: api1.domain, app01.domain, …
    for svc in SERVICE_TAGS {
        for num in NUMERIC_SUFFIXES {
            add(&format!("{svc}{num}"));
            add(&format!("{svc}-{num}"));
        }
    }

    // 6. Service + region: api-us.domain, app-eu.domain, …
    for svc in SERVICE_TAGS {
        for region in REGION_TAGS {
            add(&format!("{svc}-{region}"));
            add(&format!("{region}-{svc}"));
        }
    }

    // 7. Env + numeric: dev1.domain, staging01.domain, …
    for env in ENV_TAGS {
        for num in NUMERIC_SUFFIXES {
            add(&format!("{env}{num}"));
            add(&format!("{env}-{num}"));
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_candidates_count() {
        let candidates = generate_candidates("example.com");
        assert!(
            candidates.len() >= 200,
            "Expected at least 200 candidates, got {}",
            candidates.len()
        );
    }

    #[test]
    fn test_generate_candidates_no_duplicates() {
        let candidates = generate_candidates("example.com");
        let unique: HashSet<&String> = candidates.iter().collect();
        assert_eq!(candidates.len(), unique.len(), "Found duplicate candidates");
    }

    #[test]
    fn test_generate_candidates_contains_common_patterns() {
        let candidates = generate_candidates("example.com");
        assert!(candidates.contains(&"api.example.com".to_string()));
        assert!(candidates.contains(&"api-prod.example.com".to_string()));
        assert!(candidates.contains(&"prod-api.example.com".to_string()));
        assert!(candidates.contains(&"app-dev.example.com".to_string()));
        assert!(candidates.contains(&"api-us.example.com".to_string()));
        assert!(candidates.contains(&"dev1.example.com".to_string()));
        assert!(candidates.contains(&"staging-01.example.com".to_string()));
    }

    #[test]
    fn test_generate_candidates_all_end_with_domain() {
        let domain = "target.io";
        let candidates = generate_candidates(domain);
        for candidate in &candidates {
            assert!(
                candidate.ends_with(&format!(".{domain}")),
                "Candidate {candidate} does not end with .{domain}"
            );
        }
    }

    #[test]
    fn test_generate_candidates_different_domains() {
        let c1 = generate_candidates("example.com");
        let c2 = generate_candidates("target.io");
        assert_eq!(c1.len(), c2.len(), "Count should be the same regardless of domain");
        assert_ne!(c1[0], c2[0], "Candidates should differ by domain");
    }
}
