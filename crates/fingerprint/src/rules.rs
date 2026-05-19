use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

use rayon::prelude::*;
use regex::Regex;
use reqwest::header::HeaderMap;
use tracing::debug;

use temu_core::TemuError;

use crate::types::{FingerprintRule, TechStack};

/// Loads fingerprint rules from a YAML file at `path`.
pub fn load_fingerprint_rules(path: &Path) -> Result<Vec<FingerprintRule>, TemuError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| TemuError::Config(format!("Cannot read fingerprint rules {:?}: {e}", path)))?;

    let rules: Vec<FingerprintRule> = serde_yaml::from_str(&content)
        .map_err(|e| TemuError::Parse(format!("Invalid fingerprint_rules.yaml: {e}")))?;

    Ok(rules)
}

/// A compiled fingerprint rule — patterns are pre-compiled as Regex for performance.
struct CompiledRule<'a> {
    name: &'a str,
    header_patterns: Vec<(String, Regex)>,
    body_patterns: Vec<Regex>,
    meta_patterns: Vec<(String, Regex)>,
    cookie_patterns: Vec<(String, Regex)>,
}

impl<'a> CompiledRule<'a> {
    fn compile(rule: &'a FingerprintRule) -> Option<Self> {
        let mut header_patterns = Vec::new();
        for (name, pattern) in &rule.headers {
            match Regex::new(pattern) {
                Ok(re) => header_patterns.push((name.to_lowercase(), re)),
                Err(e) => {
                    debug!("Invalid header regex in rule '{}': {e}", rule.name);
                    return None;
                }
            }
        }

        let mut body_patterns = Vec::new();
        for pattern in &rule.body {
            match Regex::new(pattern) {
                Ok(re) => body_patterns.push(re),
                Err(_) => {
                    // Fall back to literal match — wrap in Regex::escape
                    if let Ok(re) = Regex::new(&regex::escape(pattern)) {
                        body_patterns.push(re);
                    }
                }
            }
        }

        let mut meta_patterns = Vec::new();
        for (name, pattern) in &rule.meta {
            match Regex::new(pattern) {
                Ok(re) => meta_patterns.push((name.to_lowercase(), re)),
                Err(e) => {
                    debug!("Invalid meta regex in rule '{}': {e}", rule.name);
                }
            }
        }

        let mut cookie_patterns = Vec::new();
        for (name, pattern) in &rule.cookies {
            match Regex::new(pattern) {
                Ok(re) => cookie_patterns.push((name.to_lowercase(), re)),
                Err(e) => {
                    debug!("Invalid cookie regex in rule '{}': {e}", rule.name);
                }
            }
        }

        Some(Self {
            name: &rule.name,
            header_patterns,
            body_patterns,
            meta_patterns,
            cookie_patterns,
        })
    }

    /// Try to match this rule against the response. Returns detected version string if found.
    fn try_match(
        &self,
        headers: &HeaderMap,
        body: &str,
        cookie_header: &str,
    ) -> Option<Option<String>> {
        debug!("Trying rule: {}", self.name);

        // Check header patterns (ANY match is sufficient)
        for (header_name, re) in &self.header_patterns {
            if let Some(value) = headers
                .get(header_name.as_str())
                .and_then(|v| v.to_str().ok())
                && let Some(caps) = re.captures(value)
            {
                return Some(caps.get(1).map(|m| m.as_str().to_string()));
            }
        }

        // Check body patterns (ANY match is sufficient)
        for re in &self.body_patterns {
            if let Some(caps) = re.captures(body) {
                return Some(caps.get(1).map(|m| m.as_str().to_string()));
            }
        }

        // Check meta patterns
        for (meta_name, re) in &self.meta_patterns {
            if let Some(content) = extract_meta_content(body, meta_name)
                && let Some(caps) = re.captures(&content)
            {
                return Some(caps.get(1).map(|m| m.as_str().to_string()));
            }
        }

        // Check cookie patterns
        for (cookie_name, re) in &self.cookie_patterns {
            if let Some(value) = extract_cookie(cookie_header, cookie_name)
                && re.is_match(&value)
            {
                return Some(None);
            }
        }

        None
    }
}

/// Extracts content of `<meta name="{name}" content="...">` from HTML body.
fn extract_meta_content(body: &str, meta_name: &str) -> Option<String> {
    // Build a regex to match the specific meta tag
    static META_CACHE: LazyLock<std::sync::Mutex<HashMap<String, Regex>>> =
        LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

    let pattern = format!(
        r#"(?i)<meta[^>]+name=["']{}["'][^>]+content=["']([^"']+)["']|<meta[^>]+content=["']([^"']+)["'][^>]+name=["']{}["']"#,
        regex::escape(meta_name),
        regex::escape(meta_name)
    );

    let re = {
        let Ok(mut cache) = META_CACHE.lock() else {
            return None;
        };
        if !cache.contains_key(meta_name) {
            if let Ok(re) = Regex::new(&pattern) {
                cache.insert(meta_name.to_string(), re);
            } else {
                return None;
            }
        }
        cache.get(meta_name).cloned()?
    };

    re.captures(body).and_then(|c| {
        c.get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str().to_string())
    })
}

/// Extracts a cookie value from `Set-Cookie` or `Cookie` header string.
fn extract_cookie(cookie_header: &str, cookie_name: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some((name, value)) = part.split_once('=')
            && name.trim().eq_ignore_ascii_case(cookie_name)
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Matches all fingerprint rules against the given HTTP response.
///
/// Returns deduplicated `TechStack` entries sorted by confidence descending.
/// Processes `implies` chains (one level deep) after initial matching.
pub fn match_all_rules(
    rules: &[FingerprintRule],
    headers: &HeaderMap,
    body: &str,
) -> Vec<TechStack> {
    // Collect Set-Cookie values
    let mut cookie_header = String::new();
    for value in headers.get_all("set-cookie").iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        if !cookie_header.is_empty() {
            cookie_header.push_str("; ");
        }
        cookie_header.push_str(value);
    }

    let mut results: HashMap<String, TechStack> = HashMap::new();

    // First pass: compile and match rules in parallel because regex matching is CPU-bound.
    let matches: Vec<TechStack> = rules
        .par_iter()
        .filter_map(|rule| {
            let compiled = CompiledRule::compile(rule)?;
            let captured_version = compiled.try_match(headers, body, &cookie_header)?;
            Some(TechStack::new(
                rule.name.clone(),
                captured_version,
                rule.confidence,
                rule.category.clone(),
            ))
        })
        .collect();

    for tech in matches {
        debug!(
            "Fingerprint match: {} (confidence: {:.2})",
            tech.name, tech.confidence
        );
        // Keep highest confidence for same name
        results
            .entry(tech.name.clone())
            .and_modify(|existing| {
                if tech.confidence > existing.confidence {
                    *existing = tech.clone();
                }
            })
            .or_insert(tech);
    }

    // Second pass: resolve implies
    apply_implies(rules, &mut results);

    let mut sorted: Vec<TechStack> = results.into_values().collect();
    sorted.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sorted
}

/// For every matched technology that has `implies`, add the implied technologies
/// if they are not already present (using their rule definition for category + confidence).
fn apply_implies(rules: &[FingerprintRule], results: &mut HashMap<String, TechStack>) {
    // Collect implied names from current matches
    let implied: Vec<String> = results
        .values()
        .flat_map(|t| {
            rules
                .iter()
                .filter(|r| r.name == t.name)
                .flat_map(|r| r.implies.clone())
        })
        .collect();

    for implied_name in implied {
        if results.contains_key(&implied_name) {
            continue;
        }
        // Find a rule definition for the implied tech to get its category
        if let Some(implied_rule) = rules.iter().find(|r| r.name == implied_name) {
            let tech = TechStack::new(
                implied_name.clone(),
                None,
                implied_rule.confidence * 0.8, // slightly lower since inferred
                implied_rule.category.clone(),
            );
            results.insert(implied_name, tech);
        } else {
            // No rule found — add with generic category
            let tech = TechStack::new(
                implied_name.clone(),
                None,
                0.70,
                crate::types::TechCategory::Other,
            );
            results.insert(implied_name, tech);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TechCategory;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use std::io::Write;

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    fn nginx_rule() -> FingerprintRule {
        FingerprintRule {
            name: "nginx".to_string(),
            category: TechCategory::WebServer,
            confidence: 0.95,
            headers: {
                let mut m = HashMap::new();
                m.insert("server".to_string(), r"(?i)nginx(?:/([\d.]+))?".to_string());
                m
            },
            body: vec![],
            meta: HashMap::new(),
            cookies: HashMap::new(),
            version: Some("\\1".to_string()),
            implies: vec![],
        }
    }

    fn wordpress_rule() -> FingerprintRule {
        FingerprintRule {
            name: "WordPress".to_string(),
            category: TechCategory::CMS,
            confidence: 0.90,
            headers: HashMap::new(),
            body: vec!["wp-content/".to_string()],
            meta: HashMap::new(),
            cookies: HashMap::new(),
            version: None,
            implies: vec!["PHP".to_string(), "MySQL".to_string()],
        }
    }

    fn php_rule() -> FingerprintRule {
        FingerprintRule {
            name: "PHP".to_string(),
            category: TechCategory::Language,
            confidence: 0.90,
            headers: {
                let mut m = HashMap::new();
                m.insert(
                    "x-powered-by".to_string(),
                    r"(?i)PHP(?:/([\d.]+))?".to_string(),
                );
                m
            },
            body: vec![],
            meta: HashMap::new(),
            cookies: HashMap::new(),
            version: Some("\\1".to_string()),
            implies: vec![],
        }
    }

    fn wordpress_meta_rule() -> FingerprintRule {
        FingerprintRule {
            name: "WordPress".to_string(),
            category: TechCategory::CMS,
            confidence: 0.95,
            headers: HashMap::new(),
            body: vec![],
            meta: {
                let mut m = HashMap::new();
                m.insert(
                    "generator".to_string(),
                    r"(?i)WordPress(?:\s+([\d.]+))?".to_string(),
                );
                m
            },
            cookies: HashMap::new(),
            version: Some("\\1".to_string()),
            implies: vec!["PHP".to_string()],
        }
    }

    #[test]
    fn test_match_rule_header_nginx_with_version() {
        let rules = vec![nginx_rule()];
        let headers = make_headers(&[("server", "nginx/1.18.0")]);
        let result = match_all_rules(&rules, &headers, "");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "nginx");
        assert_eq!(result[0].version, Some("1.18.0".to_string()));
        assert!(result[0].confidence > 0.9);
    }

    #[test]
    fn test_match_rule_header_nginx_no_version() {
        let rules = vec![nginx_rule()];
        let headers = make_headers(&[("server", "nginx")]);
        let result = match_all_rules(&rules, &headers, "");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "nginx");
        assert_eq!(result[0].version, None);
    }

    #[test]
    fn test_match_rule_body_wordpress() {
        let rules = vec![wordpress_rule(), php_rule()];
        let headers = make_headers(&[]);
        let body = r#"<link rel="stylesheet" href="/wp-content/themes/main.css">"#;
        let result = match_all_rules(&rules, &headers, body);

        assert!(
            result.iter().any(|t| t.name == "WordPress"),
            "WordPress not detected"
        );
    }

    #[test]
    fn test_match_rule_meta_generator_wordpress() {
        let rules = vec![wordpress_meta_rule(), php_rule()];
        let headers = make_headers(&[]);
        let body = r#"<meta name="generator" content="WordPress 6.3.1" />"#;
        let result = match_all_rules(&rules, &headers, body);

        let wp = result.iter().find(|t| t.name == "WordPress");
        assert!(wp.is_some(), "WordPress not detected from meta");
        assert_eq!(wp.unwrap().version, Some("6.3.1".to_string()));
    }

    #[test]
    fn test_match_rule_implies_chain() {
        let rules = vec![wordpress_rule(), php_rule()];
        let headers = make_headers(&[]);
        let body = r#"<link href="/wp-content/style.css">"#;
        let result = match_all_rules(&rules, &headers, body);

        // WordPress implies PHP and MySQL — PHP should be auto-added
        assert!(
            result.iter().any(|t| t.name == "WordPress"),
            "WordPress missing"
        );
        assert!(
            result.iter().any(|t| t.name == "PHP"),
            "PHP not implied from WordPress"
        );
    }

    #[test]
    fn test_match_rule_no_match() {
        let rules = vec![nginx_rule()];
        let headers = make_headers(&[("server", "Apache/2.4")]);
        let result = match_all_rules(&rules, &headers, "");

        assert!(result.is_empty(), "nginx should not match Apache header");
    }

    #[test]
    fn test_match_rule_deduplicates_highest_confidence() {
        // Two nginx rules with different confidence — highest should win
        let mut rule2 = nginx_rule();
        rule2.confidence = 0.60;
        let rules = vec![nginx_rule(), rule2];
        let headers = make_headers(&[("server", "nginx/1.20.0")]);
        let result = match_all_rules(&rules, &headers, "");

        let nginx_count = result.iter().filter(|t| t.name == "nginx").count();
        assert_eq!(nginx_count, 1, "nginx should appear only once after dedup");
        assert!(
            result[0].confidence >= 0.95,
            "highest confidence should win"
        );
    }

    #[test]
    fn test_load_fingerprint_rules_valid() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let yaml = r#"
- name: TestTech
  category: WebServer
  confidence: 0.9
  headers:
    Server: "testtech"
"#;
        tmp.write_all(yaml.as_bytes()).unwrap();
        let rules = load_fingerprint_rules(tmp.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "TestTech");
    }

    #[test]
    fn test_load_fingerprint_rules_missing_file() {
        let result = load_fingerprint_rules(Path::new("/nonexistent/fingerprint_rules.yaml"));
        assert!(result.is_err());
    }
}
