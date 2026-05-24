use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Defines the scanning scope via include/exclude regex patterns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    /// Regex patterns for URLs/domains that are in scope.
    pub include_patterns: Vec<String>,
    /// Regex patterns for URLs/domains that must be excluded.
    pub exclude_patterns: Vec<String>,
}

/// The primary scan target, identified by domain, resolved IPs, and scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// Primary domain name (e.g. "staging.company.com").
    pub domain: String,
    /// Resolved IP addresses for the domain.
    pub ip_list: Vec<IpAddr>,
    /// Scope definition for this target.
    pub scope: Scope,
}

impl Target {
    /// Creates a new `Target` with no IPs and a default (open) scope.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            ip_list: Vec::new(),
            scope: Scope::default(),
        }
    }
}

/// Classifies the kind of discovered asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    Subdomain,
    Path,
    Parameter,
    Ip,
    Url,
    Service,
    ApiEndpoint,
}

impl fmt::Display for AssetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetType::Subdomain => write!(f, "Subdomain"),
            AssetType::Path => write!(f, "Path"),
            AssetType::Parameter => write!(f, "Parameter"),
            AssetType::Ip => write!(f, "IP"),
            AssetType::Url => write!(f, "URL"),
            AssetType::Service => write!(f, "Service"),
            AssetType::ApiEndpoint => write!(f, "API Endpoint"),
        }
    }
}

/// A single discovered asset (subdomain, path, parameter, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    /// The full URL or identifier for this asset.
    pub url: String,
    /// The type of this asset.
    pub asset_type: AssetType,
    /// Name of the module that discovered this asset.
    pub discovered_by: String,
    /// Timestamp when this asset was discovered.
    pub discovered_at: DateTime<Utc>,
}

impl Asset {
    /// Creates a new `Asset` with the current timestamp.
    pub fn new(
        url: impl Into<String>,
        asset_type: AssetType,
        discovered_by: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            asset_type,
            discovered_by: discovered_by.into(),
            discovered_at: Utc::now(),
        }
    }
}

/// CVSS-aligned severity classification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

/// A detected or inferred vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Unique rule identifier (e.g. "SQLI-MYSQL-TIME").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Severity level.
    pub severity: Severity,
    /// CVSS base score (0.0–10.0).
    pub cvss_score: f32,
    /// Evidence string (e.g. matched payload or timing delta).
    pub proof: String,
    /// Target URL where the vulnerability was found.
    pub url: String,
    /// Vulnerable parameter name, if applicable.
    pub parameter: Option<String>,
    /// Whether the finding has been confirmed by the verifier.
    pub verified: bool,
    /// Timestamp of detection.
    pub detected_at: DateTime<Utc>,
    /// Suggested remediation advice.
    pub remediation: Option<String>,
}

impl Vulnerability {
    /// Creates a new unverified `Vulnerability` with the current timestamp.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        severity: Severity,
        cvss_score: f32,
        proof: impl Into<String>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            severity,
            cvss_score,
            proof: proof.into(),
            url: url.into(),
            parameter: None,
            verified: false,
            detected_at: Utc::now(),
            remediation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "Critical");
        assert_eq!(Severity::High.to_string(), "High");
        assert_eq!(Severity::Medium.to_string(), "Medium");
        assert_eq!(Severity::Low.to_string(), "Low");
        assert_eq!(Severity::Info.to_string(), "Info");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_asset_type_display() {
        assert_eq!(AssetType::Subdomain.to_string(), "Subdomain");
        assert_eq!(AssetType::Path.to_string(), "Path");
        assert_eq!(AssetType::Parameter.to_string(), "Parameter");
        assert_eq!(AssetType::Ip.to_string(), "IP");
        assert_eq!(AssetType::Url.to_string(), "URL");
        assert_eq!(AssetType::Service.to_string(), "Service");
        assert_eq!(AssetType::ApiEndpoint.to_string(), "API Endpoint");
    }

    #[test]
    fn test_target_new() {
        let target = Target::new("example.com");
        assert_eq!(target.domain, "example.com");
        assert!(target.ip_list.is_empty());
    }

    #[test]
    fn test_asset_serialize_deserialize() {
        let asset = Asset::new("https://example.com/admin", AssetType::Path, "fuzzing");
        let json = serde_json::to_string(&asset).expect("serialization failed");
        let decoded: Asset = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(decoded.url, "https://example.com/admin");
        assert_eq!(decoded.asset_type, AssetType::Path);
        assert_eq!(decoded.discovered_by, "fuzzing");
    }

    #[test]
    fn test_vulnerability_serialize_deserialize() {
        let vuln = Vulnerability::new(
            "SQLI-MYSQL-TIME",
            "Time-based SQL injection (MySQL)",
            Severity::Critical,
            9.8,
            "Response delayed 5.2s with payload ' OR SLEEP(5) --",
            "https://example.com/api/users?id=1",
        );
        let json = serde_json::to_string(&vuln).expect("serialization failed");
        let decoded: Vulnerability = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(decoded.id, "SQLI-MYSQL-TIME");
        assert_eq!(decoded.severity, Severity::Critical);
        assert!(!decoded.verified);
    }

    #[test]
    fn test_scope_default() {
        let scope = Scope::default();
        assert!(scope.include_patterns.is_empty());
        assert!(scope.exclude_patterns.is_empty());
    }

    #[test]
    fn test_severity_serde_rename() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");
        let decoded: Severity = serde_json::from_str("\"high\"").unwrap();
        assert_eq!(decoded, Severity::High);
    }

    #[test]
    fn test_asset_type_serde_rename() {
        let json = serde_json::to_string(&AssetType::Subdomain).unwrap();
        assert_eq!(json, "\"subdomain\"");
        let decoded: AssetType = serde_json::from_str("\"url\"").unwrap();
        assert_eq!(decoded, AssetType::Url);
        let decoded: AssetType = serde_json::from_str("\"service\"").unwrap();
        assert_eq!(decoded, AssetType::Service);
        let decoded: AssetType = serde_json::from_str("\"api_endpoint\"").unwrap();
        assert_eq!(decoded, AssetType::ApiEndpoint);
    }
}
