use reqwest::header::HeaderMap;

use crate::types::{TechCategory, TechStack};

/// Attempts to detect a WAF from response headers, status code, and body.
///
/// Returns `Some(TechStack)` if a WAF signature is detected, `None` otherwise.
pub fn detect_waf(headers: &HeaderMap, status: u16, body: &str) -> Option<TechStack> {
    // Cloudflare — cf-ray header
    if headers.contains_key("cf-ray") {
        return Some(TechStack::new("Cloudflare", None, 0.95, TechCategory::WAF));
    }

    // Sucuri
    if headers.contains_key("x-sucuri-id") || headers.contains_key("x-sucuri-cache") {
        return Some(TechStack::new("Sucuri", None, 0.95, TechCategory::WAF));
    }

    // Imperva Incapsula
    if headers
        .get("x-cdn")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("incapsula"))
        .unwrap_or(false)
        || headers.contains_key("x-iinfo")
    {
        return Some(TechStack::new(
            "Imperva Incapsula",
            None,
            0.90,
            TechCategory::WAF,
        ));
    }

    // AWS WAF / Shield
    if headers
        .get("x-amzn-requestid")
        .is_some()
        && status == 403
    {
        return Some(TechStack::new("AWS WAF", None, 0.70, TechCategory::WAF));
    }

    // Generic 403 with "Access Denied" body — likely a WAF
    if status == 403
        && (body.contains("Access Denied")
            || body.contains("access denied")
            || body.contains("Request blocked"))
    {
        return Some(TechStack::new("WAF (generic)", None, 0.50, TechCategory::WAF));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    fn hdr(pairs: &[(&str, &str)]) -> HeaderMap {
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
    fn test_detect_cloudflare() {
        let headers = hdr(&[("cf-ray", "7abc-IAD")]);
        let result = detect_waf(&headers, 200, "");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "Cloudflare");
    }

    #[test]
    fn test_detect_sucuri() {
        let headers = hdr(&[("x-sucuri-id", "12345")]);
        let result = detect_waf(&headers, 200, "");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "Sucuri");
    }

    #[test]
    fn test_detect_generic_403() {
        let headers = HeaderMap::new();
        let result = detect_waf(&headers, 403, "Access Denied - Request blocked by WAF");
        assert!(result.is_some());
    }

    #[test]
    fn test_no_waf_detected() {
        let headers = hdr(&[("server", "nginx/1.18.0")]);
        let result = detect_waf(&headers, 200, "<html>Normal page</html>");
        assert!(result.is_none());
    }
}
