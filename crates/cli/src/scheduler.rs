use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use temu_core::Severity;

/// Configuration for a repeatable scheduled single-target scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetProfile {
    pub name: String,
    pub url: String,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    #[serde(default)]
    pub scope_host: Option<String>,
    #[serde(default)]
    pub rate_limit: Option<u32>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default)]
    pub output_dir: Option<PathBuf>,
    #[serde(default)]
    pub session_profile: Option<PathBuf>,
    #[serde(default)]
    pub rules_repo_url: Option<String>,
    #[serde(default)]
    pub allow_risky_rules: bool,
    #[serde(default)]
    pub fail_on_severity: Option<Severity>,
    #[serde(default)]
    pub webhook_url: Option<String>,
}

fn default_interval_secs() -> u64 {
    3600
}

/// Loads a scheduled target profile from TOML, JSON, or YAML.
pub fn load_target_profile(path: &Path) -> anyhow::Result<TargetProfile> {
    let content = std::fs::read_to_string(path)?;
    let profile = match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => serde_json::from_str(&content)?,
        Some("yaml" | "yml") => serde_yaml::from_str(&content)?,
        _ => toml::from_str(&content)?,
    };
    Ok(profile)
}

/// Ensures a profile scan cannot drift outside its declared hostname scope.
pub fn validate_scope(profile: &TargetProfile) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(&profile.url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Profile URL has no hostname"))?;
    if let Some(scope_host) = &profile.scope_host
        && host != scope_host
        && !host.ends_with(&format!(".{scope_host}"))
    {
        anyhow::bail!("Profile target host {host} is outside declared scope {scope_host}");
    }
    Ok(())
}

/// Returns true when findings meet a configured cron failure threshold.
pub fn violates_exit_policy(findings: &[temu_core::Vulnerability], threshold: &Severity) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity >= *threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use temu_core::Vulnerability;

    #[test]
    fn test_profile_scope_and_exit_policy() {
        let profile = TargetProfile {
            name: "prod".to_string(),
            url: "https://api.example.com".to_string(),
            interval_secs: 60,
            scope_host: Some("example.com".to_string()),
            rate_limit: None,
            timeout_secs: None,
            ports: None,
            output_dir: None,
            session_profile: None,
            rules_repo_url: None,
            allow_risky_rules: false,
            fail_on_severity: Some(Severity::High),
            webhook_url: None,
        };
        let findings = vec![Vulnerability::new(
            "TEST",
            "Test",
            Severity::High,
            8.0,
            "proof",
            &profile.url,
        )];

        assert!(validate_scope(&profile).is_ok());
        assert!(violates_exit_policy(&findings, &Severity::High));
    }
}
