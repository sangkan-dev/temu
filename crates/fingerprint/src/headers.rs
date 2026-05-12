use std::sync::LazyLock;

use regex::Regex;
use reqwest::header::HeaderMap;

use crate::types::{TechCategory, TechStack};

static RE_NGINX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)nginx(?:/(\d+[\d.]+))?").unwrap());
static RE_APACHE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Apache(?:/(\d+[\d.]+))?").unwrap());
static RE_IIS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Microsoft-IIS(?:/(\d+[\d.]+))?").unwrap());
static RE_PHP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)PHP(?:/(\d+[\d.]+))?").unwrap());
static RE_ASPNET_VER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d+[\d.]+)").unwrap());

fn capture_version(re: &Regex, value: &str) -> Option<String> {
    re.captures(value)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Detects technologies from HTTP response headers.
pub fn fingerprint_from_headers(headers: &HeaderMap) -> Vec<TechStack> {
    let mut results: Vec<TechStack> = Vec::new();

    // Server header
    if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
        if RE_NGINX.is_match(server) {
            results.push(TechStack::new(
                "nginx",
                capture_version(&RE_NGINX, server),
                0.95,
                TechCategory::WebServer,
            ));
        } else if RE_APACHE.is_match(server) {
            results.push(TechStack::new(
                "Apache",
                capture_version(&RE_APACHE, server),
                0.95,
                TechCategory::WebServer,
            ));
        } else if RE_IIS.is_match(server) {
            results.push(TechStack::new(
                "IIS",
                capture_version(&RE_IIS, server),
                0.95,
                TechCategory::WebServer,
            ));
        } else if !server.is_empty() {
            // Generic server header
            results.push(TechStack::new(server, None, 0.60, TechCategory::WebServer));
        }
    }

    // X-Powered-By header
    if let Some(powered) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
        if RE_PHP.is_match(powered) {
            results.push(TechStack::new(
                "PHP",
                capture_version(&RE_PHP, powered),
                0.90,
                TechCategory::Language,
            ));
        } else if powered.to_lowercase().contains("asp.net") {
            results.push(TechStack::new(
                "ASP.NET",
                None,
                0.90,
                TechCategory::Framework,
            ));
        } else if powered.to_lowercase().contains("express") {
            results.push(TechStack::new(
                "Express",
                None,
                0.85,
                TechCategory::Framework,
            ));
        }
    }

    // X-AspNet-Version
    if let Some(v) = headers.get("x-aspnet-version").and_then(|v| v.to_str().ok()) {
        let version = RE_ASPNET_VER
            .find(v)
            .map(|m| m.as_str().to_string());
        results.push(TechStack::new(
            "ASP.NET",
            version,
            0.95,
            TechCategory::Framework,
        ));
    }

    // WAF / CDN detection (moved to waf.rs but also checked here for header-only signals)
    if headers.contains_key("cf-ray") {
        results.push(TechStack::new(
            "Cloudflare",
            None,
            0.95,
            TechCategory::WAF,
        ));
    }
    if headers.contains_key("x-sucuri-id") {
        results.push(TechStack::new("Sucuri", None, 0.95, TechCategory::WAF));
    }
    if let Some(cdn) = headers.get("x-cdn").and_then(|v| v.to_str().ok()) {
        if cdn.to_lowercase().contains("incapsula") {
            results.push(TechStack::new(
                "Imperva Incapsula",
                None,
                0.90,
                TechCategory::CDN,
            ));
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

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

    #[test]
    fn test_detect_nginx_with_version() {
        let headers = make_headers(&[("server", "nginx/1.18.0")]);
        let result = fingerprint_from_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "nginx");
        assert_eq!(result[0].version, Some("1.18.0".to_string()));
        assert_eq!(result[0].category, TechCategory::WebServer);
        assert!(result[0].confidence > 0.9);
    }

    #[test]
    fn test_detect_apache_with_version() {
        let headers = make_headers(&[("server", "Apache/2.4.51 (Ubuntu)")]);
        let result = fingerprint_from_headers(&headers);
        assert_eq!(result[0].name, "Apache");
        assert_eq!(result[0].version, Some("2.4.51".to_string()));
    }

    #[test]
    fn test_detect_iis() {
        let headers = make_headers(&[("server", "Microsoft-IIS/10.0")]);
        let result = fingerprint_from_headers(&headers);
        assert_eq!(result[0].name, "IIS");
        assert_eq!(result[0].version, Some("10.0".to_string()));
    }

    #[test]
    fn test_detect_php_from_powered_by() {
        let headers = make_headers(&[("x-powered-by", "PHP/8.1.12")]);
        let result = fingerprint_from_headers(&headers);
        assert_eq!(result[0].name, "PHP");
        assert_eq!(result[0].version, Some("8.1.12".to_string()));
    }

    #[test]
    fn test_detect_aspnet_from_powered_by() {
        let headers = make_headers(&[("x-powered-by", "ASP.NET")]);
        let result = fingerprint_from_headers(&headers);
        assert_eq!(result[0].name, "ASP.NET");
        assert_eq!(result[0].category, TechCategory::Framework);
    }

    #[test]
    fn test_detect_express() {
        let headers = make_headers(&[("x-powered-by", "Express")]);
        let result = fingerprint_from_headers(&headers);
        assert_eq!(result[0].name, "Express");
    }

    #[test]
    fn test_detect_cloudflare() {
        let headers = make_headers(&[("cf-ray", "7a1b2c3d4e5f-IAD")]);
        let result = fingerprint_from_headers(&headers);
        assert!(result.iter().any(|t| t.name == "Cloudflare"));
    }

    #[test]
    fn test_empty_headers() {
        let headers = HeaderMap::new();
        let result = fingerprint_from_headers(&headers);
        assert!(result.is_empty());
    }

    #[test]
    fn test_detect_aspnet_version_header() {
        let headers = make_headers(&[("x-aspnet-version", "4.0.30319")]);
        let result = fingerprint_from_headers(&headers);
        assert!(result.iter().any(|t| t.name == "ASP.NET" && t.version.is_some()));
    }
}
