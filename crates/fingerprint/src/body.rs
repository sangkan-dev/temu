use std::sync::LazyLock;

use regex::Regex;

use crate::types::{TechCategory, TechStack};

static RE_WORDPRESS_META: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*([\d.]+)?"#)
        .unwrap()
});
static RE_JQUERY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"jquery[.-]([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js").unwrap());
static RE_BOOTSTRAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"bootstrap(?:\.([\d]+\.[\d]+\.[\d]+))?\.min\.(css|js)").unwrap());

/// Detects technologies from HTTP response body HTML.
pub fn fingerprint_from_body(body: &str) -> Vec<TechStack> {
    let mut results: Vec<TechStack> = Vec::new();

    // WordPress: generator meta tag
    if let Some(caps) = RE_WORDPRESS_META.captures(body) {
        let version = caps.get(1).map(|m| m.as_str().to_string());
        results.push(TechStack::new("WordPress", version, 0.95, TechCategory::CMS));
    } else if body.contains("wp-content/") || body.contains("wp-includes/") {
        // WordPress path patterns without version
        results.push(TechStack::new("WordPress", None, 0.85, TechCategory::CMS));
    }

    // jQuery
    if let Some(caps) = RE_JQUERY.captures(body) {
        let version = caps.get(1).map(|m| m.as_str().to_string());
        results.push(TechStack::new("jQuery", version, 0.90, TechCategory::Library));
    }

    // Bootstrap
    if RE_BOOTSTRAP.is_match(body) {
        let version = RE_BOOTSTRAP
            .captures(body)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        results.push(TechStack::new(
            "Bootstrap",
            version,
            0.85,
            TechCategory::Framework,
        ));
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_wordpress_meta_generator() {
        let body = r#"<meta name="generator" content="WordPress 6.3.1" />"#;
        let result = fingerprint_from_body(body);
        assert_eq!(result[0].name, "WordPress");
        assert_eq!(result[0].version, Some("6.3.1".to_string()));
        assert_eq!(result[0].category, TechCategory::CMS);
    }

    #[test]
    fn test_detect_wordpress_path_pattern() {
        let body = r#"<link rel="stylesheet" href="/wp-content/themes/main.css">"#;
        let result = fingerprint_from_body(body);
        assert!(result.iter().any(|t| t.name == "WordPress"));
    }

    #[test]
    fn test_detect_jquery() {
        let body = r#"<script src="/js/jquery-3.6.0.min.js"></script>"#;
        let result = fingerprint_from_body(body);
        assert!(result.iter().any(|t| t.name == "jQuery"));
        let jquery = result.iter().find(|t| t.name == "jQuery").unwrap();
        assert_eq!(jquery.version, Some("3.6.0".to_string()));
    }

    #[test]
    fn test_detect_bootstrap() {
        let body = r#"<link href="/css/bootstrap.min.css" rel="stylesheet">"#;
        let result = fingerprint_from_body(body);
        assert!(result.iter().any(|t| t.name == "Bootstrap"));
    }

    #[test]
    fn test_empty_body() {
        let result = fingerprint_from_body("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_tech_detected() {
        let result = fingerprint_from_body("<html><body>Hello World</body></html>");
        assert!(result.is_empty());
    }
}
