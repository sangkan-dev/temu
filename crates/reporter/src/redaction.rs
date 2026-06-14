use std::sync::LazyLock;

use regex::Regex;

use crate::types::ScanResult;

static SECRET_ASSIGNMENT_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)((?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["']?)([A-Za-z0-9_./+=-]{8,})(["']?)"#,
    )
    .ok()
});
static DIRECT_SECRET_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?s)(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"#).ok()
});
static EMAIL_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"#).ok());
static CREDIT_CARD_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"\b(?:\d[ -]*?){13,19}\b"#).ok());

/// Returns a cloned scan result with sensitive evidence redacted for reports.
pub fn redact_scan_result(result: &ScanResult) -> ScanResult {
    let mut redacted = result.clone();
    for vulnerability in &mut redacted.vulnerabilities {
        vulnerability.proof = redact_sensitive_text(&vulnerability.proof);
    }
    for service in &mut redacted.services {
        service.banner = service.banner.as_deref().map(redact_sensitive_text);
        service.handshake = service.handshake.as_deref().map(redact_sensitive_text);
    }
    redacted
}

/// Redacts common secrets and PII-like values in report evidence.
pub fn redact_sensitive_text(value: &str) -> String {
    let mut redacted = value.to_string();
    if let Some(regex) = SECRET_ASSIGNMENT_RE.as_ref() {
        redacted = regex
            .replace_all(&redacted, |captures: &regex::Captures<'_>| {
                format!(
                    "{}<REDACTED>{}",
                    captures
                        .get(1)
                        .map(|part| part.as_str())
                        .unwrap_or_default(),
                    captures
                        .get(3)
                        .map(|part| part.as_str())
                        .unwrap_or_default()
                )
            })
            .to_string();
    }
    for regex in [
        DIRECT_SECRET_RE.as_ref(),
        EMAIL_RE.as_ref(),
        CREDIT_CARD_RE.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        redacted = regex
            .replace_all(&redacted, |captures: &regex::Captures<'_>| {
                mask_value(captures.get(0).map(|m| m.as_str()).unwrap_or_default())
            })
            .to_string();
    }
    redacted
}

fn mask_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.contains('@') {
        let domain = trimmed.split('@').nth(1).unwrap_or("redacted");
        return format!("[REDACTED]@{domain}");
    }
    if trimmed.len() <= 8 {
        return "[REDACTED]".to_string();
    }
    let prefix: String = trimmed.chars().take(4).collect();
    let suffix: String = trimmed
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{prefix}[REDACTED]{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ScanResult, ScanStats};
    use chrono::Utc;
    use std::collections::HashMap;
    use temu_core::{ServiceEvidence, Severity, Vulnerability};

    #[test]
    fn test_redact_sensitive_text_masks_secret_and_email() {
        let value = "token=secret-token-123 alice@example.com";
        let redacted = redact_sensitive_text(value);
        assert!(redacted.contains("token=<REDACTED>"));
        assert!(!redacted.contains("secret-token-123"));
        assert!(!redacted.contains("alice@example.com"));
    }

    #[test]
    fn test_redact_scan_result_masks_vulnerability_proof() {
        let result = ScanResult {
            target: "https://example.com".to_string(),
            assets: vec![],
            tech_stacks: HashMap::new(),
            vulnerabilities: vec![Vulnerability::new(
                "TEST",
                "Test",
                Severity::High,
                8.0,
                "api_key=supersecret12345",
                "https://example.com",
            )],
            services: vec![ServiceEvidence {
                endpoint: "tcp://127.0.0.1:6379".to_string(),
                port: 6379,
                protocol: "redis".to_string(),
                product: Some("Redis".to_string()),
                version: None,
                confidence: 0.98,
                banner: Some("token=service-secret-123".to_string()),
                handshake: Some("password=service-password-123".to_string()),
                auth_required: Some(false),
                tls: None,
                signals: vec!["unauthenticated_command_accepted".to_string()],
            }],
            target_summaries: vec![],
            callback_events: vec![],
            scan_started_at: Utc::now(),
            scan_finished_at: Utc::now(),
            stats: ScanStats {
                subdomains_found: 0,
                paths_found: 0,
                parameters_found: 0,
                vulns_found: 1,
                duration_secs: 0.0,
            },
        };
        let redacted = redact_scan_result(&result);
        assert!(
            !redacted.vulnerabilities[0]
                .proof
                .contains("supersecret12345")
        );
        assert!(
            redacted.vulnerabilities[0]
                .proof
                .contains("api_key=<REDACTED>")
        );
        assert_eq!(
            redacted.services[0].banner.as_deref(),
            Some("token=<REDACTED>")
        );
        assert_eq!(
            redacted.services[0].handshake.as_deref(),
            Some("password=<REDACTED>")
        );
    }
}
